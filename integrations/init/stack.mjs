// scopehaven init --stack NAME: init with a stack connector (integrations/connectors, scopehaven-connector/1).
//
//   ./scopehaven init --stack supabase --base-url http://127.0.0.1:54321 --env ids.env --observer-env observers.env [init options]
//   node integrations/init/stack.mjs --stack supabase ...        (the same, before init's --stack hook is merged)
//
// What the connector adds to init, in order:
//   1. Before any request: the connector's credential slot (unless --credential is given) and, for each observer it will
//      wire, the observer's tcp://127.0.0.1:PORT endpoint in the authorization record's hosts, so the record that init
//      seals already covers the observer.
//   2. Init itself (cli.mjs main) with --no-run: authorization, GET probes, the starter profile.
//   3. The backend row wired: the connector's absence observer (for Supabase, pg-wal over the record's table) joins the
//      profile, and the backend check gets the connector's clauses (record-row-unchanged: no committed change to the foreign
//      record's row in the check's window; record-table-unchanged: none to its table). The table, key and id come from the
//      record path when it follows one of the connector's record templates (PostgREST: /rest/v1/{table}?{key}=eq.{id}), and
//      otherwise from --record-table TABLE[:KEY] with the last path segment as the id (--record-id to override).
//   4. With --app-dir and a policy importer (Supabase: row-level security in supabase/migrations), the importer's matrix,
//      unconfirmed, beside the profile (policy-matrix.json); confirming checks from it stays a named person's step.
//   5. stack-report.json: the connector (stack, schema, sha256), what was wired and why, what was not and why, the refusal
//      forms init saw against the connector's, the default packs and the reset command.
//   6. Unless --no-run: check-config, roe check and the starter assessment, with the identities' and the observer's
//      credentials in the child's environment only, then the first decided row as init prints it.
//
// Options added to init's (every init option is passed through):
//   --stack NAME          a shipped connector: integrations/connectors/catalog/NAME.json
//   --observer-env FILE   0600 env file with the observer's credential (SCOPEHAVEN_TARGET_<ID>_<suffix>, for Supabase
//                         SCOPEHAVEN_TARGET_<ID>_DB_WAL=user:password); without it no observer is wired and the backend row
//                         stays inconclusive, as plain init leaves it
//   --observer-port N     the observer's loopback port, if not the connector's default (Supabase: 54322)
//   --record-table T[:K]  the table (and key column, default id) behind the foreign record, when its path is an app route
//   --record-id ID        the foreign record's key value, when it is not the path's last segment
//   --app-dir DIR         the app's folder, for the connector's policy importer and its unlogged-table findings
//   --twin-write M:P:S:J  the record owner's own write, METHOD:PATH:STATUS:JSON, when the record path is an app route (on a
//                         PostgREST record init drafts it: a PATCH of the key to its own value, answered 204)
//
// Exit status as init's: 0 set up, no FAIL row; 1 set up, a FAIL row; 2 stopped before any request; 3 could not finish.
import { spawn } from 'node:child_process';
import { constants, realpathSync } from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import { lstat, open, readFile, readdir, realpath, rename, unlink } from 'node:fs/promises';
import { join, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { InitError, readCredentialFile } from './envfile.mjs';
import { loopbackOrigin, safePath } from './probe.mjs';
import { summarizeRun, formatFirstRow } from './findings.mjs';
import { loadConnector, matchRecord, ConnectorError, LIVE_CHECK_FILES } from '../connectors/spec.mjs';
import { DEFAULT_ACTIONS } from './authorization.mjs';
import { validateTargetFile } from '../../src/contracts.mjs';
import { checkAuthorization, windowGuard } from '../../src/authorization.mjs';
import { readAuthorizationFile } from '../roe/file.mjs';

export const STACK_REPORT_SCHEMA = 'scopehaven-init-stack/1';
const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const STACK_VALUE_FLAGS = ['--stack', '--observer-env', '--observer-port', '--record-table', '--record-id', '--app-dir', '--twin-write'];
const STACK_BOOL_FLAGS = ['--no-twin'];
const IDENT = /^[A-Za-z_][A-Za-z0-9_]{0,62}$/;
const credentialName = (targetId, suffix) => `SCOPEHAVEN_TARGET_${targetId.toUpperCase().replace(/[^A-Z0-9]+/g, '_')}_${suffix}`.slice(0, 128);
const OBSERVER_IDS = { 'pg-wal': 'wal', 'pg-snapshot': 'pg', 'smtp-sink': 'smtp', 'egress-recorder': 'egress' };

// Splits argv into the connector's options and init's. Init's own flags are left as given, in order.
export function splitArgs(argv) {
  const stack = {}, init = [];
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (STACK_BOOL_FLAGS.includes(flag)) { if (stack[flag]) throw new InitError('usage', `${flag} is given twice`); stack[flag] = true; continue; }
    if (STACK_VALUE_FLAGS.includes(flag)) {
      const value = argv[i + 1];
      if (typeof value !== 'string' || value.startsWith('--')) throw new InitError('usage', `${flag} needs a value`);
      if (Object.hasOwn(stack, flag)) throw new InitError('usage', `${flag} is given twice`);
      stack[flag] = value; i += 1; continue;
    }
    init.push(flag);
  }
  return { stack, init };
}
const flagValue = (argv, flag) => { const at = argv.indexOf(flag); return at === -1 ? undefined : argv[at + 1]; };
const withFlag = (argv, flag, value) => { const at = argv.indexOf(flag); if (at === -1) return [...argv, flag, value]; const copy = [...argv]; copy[at + 1] = value; return copy; };

// The table, key and id behind the backend check's record.
export function recordTarget(connector, path, { recordTable, recordId } = {}) {
  const matched = matchRecord(connector, path);
  // A record path that follows a connector template names its table, key and id itself: an override would make the twin
  // write, and the backend row watch, another column or row than the path names.
  if (matched && (recordTable !== undefined || recordId !== undefined)) throw new InitError('usage', `${path} follows the connector's record template, which names its table, key and id; leave out --record-table and --record-id`);
  if (matched) return { ...matched, from: 'the record path (a connector record template)' };
  if (!recordTable) return null;
  const [table, key = 'id', ...extraKey] = recordTable.split(':');
  const [schema, name, ...extraName] = table.includes('.') ? table.split('.') : ['public', table];
  if (extraKey.length || extraName.length || ![schema, name, key].every(part => IDENT.test(part ?? ''))) throw new InitError('usage', '--record-table is TABLE, SCHEMA.TABLE or TABLE:KEY, each a plain identifier');
  let id = recordId;
  if (id === undefined) {
    const last = path.split('?')[0].split('/').filter(Boolean).at(-1);
    try { id = decodeURIComponent(last ?? ''); } catch { id = ''; }
  }
  if (typeof id !== 'string' || !id || id.length > 200) throw new InitError('usage', '--record-id is the foreign record\'s key value (1 to 200 characters)');
  return { schema, table: name, key, id, from: recordId === undefined ? '--record-table, with the id from the record path\'s last segment' : '--record-table and --record-id' };
}

// The connector's clauses for the backend row over one observed record. Which of the connector's clauses apply follows the
// pairing rules (src/http-pairing.mjs):
//   - record-row-unchanged pins the record's resource, so it needs the owner's write twin to show the pin selects; it is used
//     when there is one;
//   - record-table-unchanged pins nothing. On a check that expects a refusal status it needs no twin. On one that expects a
//     2xx (PostgREST's 200 []) the allowed-use guard holds it back unless the actor's own control shows a write, so there it is
//     used only when no twin exists, and reads inconclusive, as the row clause would without its twin.
export function backendClauses(connector, record, { twin = false, refusal = false } = {}) {
  const source = connector.observers.find(o => o.type === connector.backendRow.observer).source;
  const allowed = connector.backendRow.clauses;
  const row = { kind: 'effect.none', select: { source, name: record.table, resource: `${record.table}/${record.id}` } };
  const table = { kind: 'effect.none', select: { source, name: record.table } };
  const out = [];
  if (twin && allowed.includes('record-row-unchanged')) out.push(row);
  if ((refusal || !twin) && allowed.includes('record-table-unchanged')) out.push(table);
  return out.length ? out : [row];
}

// The observer the backend row reads, from the connector's defaults.
// No ignore entry: init --stack never adds one (an unlogged table stays watched; unloggedTableFindings says why).
export function observerEntry(connector, { targetId, record, port }) {
  const spec = connector.observers.find(o => o.type === connector.backendRow.observer);
  return { id: OBSERVER_IDS[spec.type] ?? spec.type, type: spec.type, ...spec.defaults, ...(port === undefined ? {} : { port }),
    credentialEnv: credentialName(targetId, spec.credentialEnvSuffix), tables: [{ table: record.table, key: record.key, ...(record.schema && record.schema !== 'public' ? { schema: record.schema } : {}) }] };
}

// The allowed-use twin that shows the backend row's selector selects something (src/http-pairing.mjs): the record's owner
// writes its own record, and the observer must see that write. On a PostgREST record it rewrites the row with the key set to
// its own value (PATCH answers 204; Postgres logs the row's update, and the table's UPDATE triggers run, so a trigger may
// still change a column such as updated_at). It is sent before the
// backend check, so its write is never in or after that check's window. Returns the check, or null when the record's owner
// is not a declared actor (one identity: the foreign record belongs to no one the profile knows).
export const TWIN_ID = 'A-WRITES-OWN-RECORD';
// The twin's request before init runs, from the flags: { method, path, viaTemplate } or null. It must equal what writeTwin
// builds after init, so the sealed actions name the request the run sends.
export function plannedTwin(connector, { backendPath, write, twoIdentities, noTwin }) {
  if (noTwin || !twoIdentities || !backendPath) return null;
  if (write) return { method: write.method, path: write.path, viaTemplate: false, bodySha256: write.bodySha256 };
  return matchRecord(connector, backendPath) ? { method: 'PATCH', path: backendPath, viaTemplate: true } : null;
}
export function writeTwin(connector, { record, backend, owner, write }) {
  if (!owner) return null;
  const source = connector.observers.find(o => o.type === connector.backendRow.observer).source;
  const viaTemplate = write === undefined;
  const matched = viaTemplate ? matchRecord(connector, backend.path) : null;
  if (viaTemplate && !matched) return null;
  // The template twin writes exactly the key the path names, to the value the path names.
  if (viaTemplate && (matched.table !== record.table || matched.key !== record.key || matched.id !== record.id)) throw new InitError('profile', 'the observed record differs from the one the record path names; nothing was wired');
  const twin = viaTemplate ? { method: 'PATCH', path: backend.path, body: { [matched.key]: matched.id }, status: 204 } : write;
  return { id: TWIN_ID, title: viaTemplate ? `Identity ${owner.toUpperCase()} writes its own record (allowed use; its key set to its own value)` : `Identity ${owner.toUpperCase()} writes its own record (allowed use)`,
    category: 'Access', severity: 'control', actorId: owner, method: twin.method, path: twin.path, body: twin.body, evidenceRequirement: 'response',
    assertions: [{ kind: 'status.equals', expected: twin.status }],
    effects: [{ kind: 'effect.exists', select: { source, name: record.table, resource: `${record.table}/${record.id}` } }] };
}

// --twin-write METHOD:PATH:STATUS:JSON for an app route (the owner's own write of the record), parsed and bounded.
export function parseTwinWrite(text) {
  const m = /^(POST|PUT|PATCH):(\/[^:\s]*):([0-9]{3}):(\{.*\})$/s.exec(text ?? '');
  if (!m) throw new InitError('usage', '--twin-write is METHOD:PATH:STATUS:JSON, for example PATCH:/api/notes/12:200:{"title":"same title"}');
  let body;
  try { body = JSON.parse(m[4]); } catch { throw new InitError('usage', '--twin-write\'s body is not JSON'); }
  const status = Number(m[3]);
  if (status < 200 || status > 299) throw new InitError('usage', '--twin-write\'s status is the 2xx the app answers its owner');
  if (!safePath(m[2])) throw new InitError('usage', '--twin-write\'s path must be an absolute path on the app with no "//", "." or ".." segment, space or fragment');
  if (body === null || typeof body !== 'object' || Array.isArray(body) || Buffer.byteLength(JSON.stringify(body)) > 8192) throw new InitError('usage', '--twin-write\'s body is a JSON object of at most 8 KiB');
  return { method: m[1], path: m[2], status, body, bodySha256: createHash('sha256').update(JSON.stringify(body)).digest('hex') };
}

// The authorization's permitted actions when a write twin will be sent: init's read-only default, plus that one write, named,
// so the record init seals covers every request the run makes (the twin is a write, and the default says "no writes").
export function twinActions(twin) {
  const reads = DEFAULT_ACTIONS.replace(/; no writes$/, '');
  return `${reads}, plus one allowed-use write: identity A's ${twin.method} ${twin.path} of its own record (${twin.viaTemplate ? 'it sets the key column to its own value; the table\'s UPDATE triggers still run, for example an updated_at stamp' : `the --twin-write body with sha256 ${twin.bodySha256.slice(0, 16)}`}); no other writes`;
}

// Wires the backend row into a starter target file (pure). Returns { manifest, wired } or throws InitError.
export function wireBackend(manifest, connector, { record, observerConfig, twin = null }) {
  const next = structuredClone(manifest);
  const target = next.targets[0];
  const check = target.checks.find(c => c.evidenceRequirement === 'backend');
  if (!check) throw new InitError('profile', 'the starter profile has no backend check to wire');
  target.observers = [...(target.observers ?? []).filter(o => o.id !== observerConfig.id), observerConfig];
  check.effects = backendClauses(connector, record, { twin: Boolean(twin), refusal: check.assertions[0]?.kind === 'status.in' });
  check.title = connector.backendRow.title;
  if (twin) {
    target.checks = target.checks.filter(c => c.id !== twin.id);
    target.checks.splice(target.checks.findIndex(c => c.evidenceRequirement === 'backend' || c.severity !== 'control'), 0, twin);
  }
  try { validateTargetFile(next); } catch (error) { throw new InitError('profile', `the wired profile does not validate (${String(error?.message ?? error).slice(0, 300)}); targets.json was left as init wrote it`); }
  return { manifest: next, wired: { check: check.id, observer: observerConfig.id, type: observerConfig.type, clauses: check.effects.length, twin: twin?.id ?? null } };
}

async function writePrivate(path, content) {
  const temporary = `${path}.${randomBytes(8).toString('hex')}.tmp`;
  try {
    const handle = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    try { await handle.writeFile(content); } finally { await handle.close(); }
    await rename(temporary, path);
  } finally { await unlink(temporary).catch(() => {}); }
}
function runChild(script, args, env) {
  return new Promise(done => {
    const child = spawn(process.execPath, [script, ...args], { cwd: ROOT, env, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    child.on('close', code => done({ code, stdout, stderr }));
    child.on('error', () => done({ code: -1, stdout, stderr: 'could not start' }));
  });
}
const lastJson = text => { const at = text.indexOf('{'); if (at === -1) return null; try { return JSON.parse(text.slice(at)); } catch { return null; } };

// A migration file, by its extension in any case (0003.SQL is one).
const isSql = name => name.toLowerCase().endsWith('.sql');

// The app's .sql files under the given paths (a folder, read to depth 4, or one file; regular files, bounded), as
// { id, content }, sorted by path within each folder. files.skipped counts what the bounds left unread (a .sql file over
// 4 MiB, anything past the 2000th file, a folder deeper than four, a symbolic link or other entry that is neither a file nor
// a folder, a given path whose real path leaves the app folder, anything that could not be read other than a path that does
// not exist), and files.readRoots names each given path that was read (a folder listed, or a file
// read), so a check can refuse to rest on a scan that left anything unread or never reached the folder it needs.
export async function declarationFiles(connector, appDir, paths = connector.policyImporter?.paths ?? []) {
  const files = [], readRoots = new Set();
  let skipped = 0;
  const appReal = await realpath(appDir).catch(() => null);
  const insideApp = async at => { const real = await realpath(at).catch(() => null); return Boolean(appReal && real && (real === appReal || real.startsWith(`${appReal}${sep}`))); };
  const walk = async (dir, rel, depth) => {
    let entries = [];
    try { if (!(await lstat(dir)).isDirectory()) return; entries = (await readdir(dir, { withFileTypes: true })).sort((a, b) => (a.name < b.name ? -1 : 1)); }
    catch (error) { if (error?.code !== 'ENOENT') skipped++; return; }
    if (depth === 0) readRoots.add(rel);
    for (const e of entries) {
      if (files.length >= 2000) { skipped++; return; }
      const path = join(dir, e.name), id = rel ? `${rel}/${e.name}` : e.name;
      if (e.isSymbolicLink()) skipped++;
      else if (e.isDirectory()) { if (depth < 4) await walk(path, id, depth + 1); else skipped++; }
      else if (!e.isFile()) skipped++;
      else if (isSql(e.name)) {
        try { const stat = await lstat(path); if (stat.size <= 4 * 1024 * 1024) files.push({ id, content: await readFile(path), kind: 'sql' }); else skipped++; } catch { skipped++; }
      }
    }
  };
  for (const rel of paths) {
    const at = resolve(appDir, rel);
    let stat = null;
    try { stat = await lstat(at); } catch (error) { if (error?.code !== 'ENOENT') skipped++; }
    // A linked folder above the scan path would make its files read as the app's own: the path must stay inside the app folder.
    if (stat && !stat.isSymbolicLink() && !(await insideApp(at))) { skipped++; continue; }
    if (stat?.isSymbolicLink()) skipped++;
    else if (stat && !stat.isDirectory() && !(stat.isFile() && isSql(rel))) skipped++;
    else if (stat?.isFile() && isSql(rel)) {
      if (stat.size > 4 * 1024 * 1024) skipped++;
      else { try { files.push({ id: rel, content: await readFile(at), kind: 'sql' }); readRoots.add(rel); } catch { skipped++; } }
    } else if (stat) await walk(at, rel, 0);
  }
  return Object.assign(files, { skipped, readRoots });
}

// SQL as the use check reads it: lower case, without double quotes, spaces or line breaks, so NET.HTTP_POST, "net"."http_post" and
// net . http_post all read net.http_post.
const folded = text => text.toLowerCase().replace(/["\s]/g, '');

// What the live copy says about pg_net, read with the observer's own role (pg_catalog only): the extension, functions outside
// pg_net's and Supabase's hook schemas whose source names it, triggers that run a function of those schemas (database
// webhooks), and pg_cron, whose jobs the role cannot read. Returns { checked, used, why }.
// Functions counted: every function outside pg_net's and Supabase's hook schemas and the catalogs, except Supabase's own
// extensions.grant_pg_net_access (the event trigger that grants pg_net's functions to the API roles when pg_net is created;
// it names them, it sends nothing). A function counts when its source names a pg_net or hook function, qualified or not, or
// when it depends on one (pg_depend: a SQL-standard BEGIN ATOMIC body keeps its calls there, with prosrc empty). Views and
// other objects that depend on one count too.
const PG_NET_CALL = "'net[[:space:]\"]*\\.[[:space:]\"]*http_|supabase_functions[[:space:]\"]*\\.[[:space:]\"]*http_request|\\mhttp_(post|get|delete|collect_response)[[:space:]]*\\('";
const PLATFORM_FUNCTIONS = "('net', 'supabase_functions', 'pg_catalog', 'information_schema')";
export const PG_NET_USE_SQL = "select (select count(*) from pg_extension where extname = 'pg_net'), "
  + `(select count(*) from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname not in ${PLATFORM_FUNCTIONS} `
  + "and not (n.nspname = 'extensions' and p.proname = 'grant_pg_net_access') "
  + `and (p.prosrc ~* ${PG_NET_CALL} or exists (select 1 from pg_depend d join pg_proc c on d.refclassid = 'pg_proc'::regclass and d.refobjid = c.oid `
  + "join pg_namespace cn on cn.oid = c.pronamespace where d.classid = 'pg_proc'::regclass and d.objid = p.oid and cn.nspname in ('net', 'supabase_functions')))), "
  + "(select count(*) from pg_trigger t join pg_proc p on p.oid = t.tgfoid join pg_namespace n on n.oid = p.pronamespace where not t.tgisinternal and n.nspname in ('net', 'supabase_functions')), "
  + "(select count(*) from pg_extension where extname = 'pg_cron'), "
  + "(select count(*) from pg_depend d join pg_proc c on d.refclassid = 'pg_proc'::regclass and d.refobjid = c.oid join pg_namespace cn on cn.oid = c.pronamespace "
  + "where cn.nspname in ('net', 'supabase_functions') and d.deptype <> 'e' and d.classid <> 'pg_proc'::regclass), "
  // The table the finding covers is pg_net's own queue, and only while it is unlogged (the WAL never carries it).
  + "(select count(*) from pg_class c join pg_namespace n on n.oid = c.relnamespace where n.nspname = 'net' and c.relname = 'http_request_queue' and c.relpersistence = 'u')";
// With pg_cron installed, its jobs are read too when the operator granted the observer role SELECT on cron.job; otherwise a job
// may call pg_net unseen. pg_cron turns on row-level security for cron.job (each role sees its own jobs), so the count is used
// only when the role sees every row: row security off on the table, or the role a superuser or BYPASSRLS. cronJobs: the number
// of jobs whose command names pg_net, or null when they could not all be read.
export const PG_CRON_USE_SQL = `select (select count(*) from cron.job where command ~* ${PG_NET_CALL}), `
  + "(select not c.relrowsecurity or r.rolsuper or r.rolbypassrls from pg_class c, pg_roles r where c.oid = 'cron.job'::regclass and r.rolname = current_user)";
// The job count from PG_CRON_USE_SQL's row, or null unless the role saw every job.
export function cronJobsOf(row) {
  const n = Number(row?.[0]), all = row?.[1] === true || row?.[1] === 't' || row?.[1] === 'true';
  return all && Number.isInteger(n) ? n : null;
}
export function pgNetUse(row, cronJobs = null) {
  const [extension, functions, triggers, cron, others, unlogged] = (row ?? []).map(Number);
  if (![extension, functions, triggers, cron, others, unlogged].every(Number.isInteger)) return { checked: false, used: null, why: 'the live check could not be read' };
  // The finding is about pg_net's own unlogged queue: with no pg_net, or a queue that is not unlogged, there is no use to report.
  if (!extension) return { checked: true, used: null, why: 'pg_net is not installed (a later install would bring its unlogged queue back, so the observer keeps no entry for it)' };
  if (unlogged !== 1) return { checked: true, used: null, why: 'net.http_request_queue is not an unlogged table on this copy, so the WAL carries it' };
  if (others) return { checked: true, used: true, why: `the copy has ${others} other object${others === 1 ? '' : 's'} (a view, a default, a policy) that depend on a pg_net function` };
  if (functions || triggers) return { checked: true, used: true, why: `the copy has ${functions} function${functions === 1 ? '' : 's'} and ${triggers} trigger${triggers === 1 ? '' : 's'} that call pg_net` };
  if (cron && cronJobs === null) return { checked: true, used: null, why: 'pg_cron is installed and the observer role cannot read every job (grant it SELECT on cron.job and BYPASSRLS, since cron.job has row-level security), so a job may call pg_net' };
  if (cron && cronJobs > 0) return { checked: true, used: true, why: `the copy has ${cronJobs} pg_cron job${cronJobs === 1 ? '' : 's'} that call pg_net` };
  return { checked: true, used: false, why: 'pg_net is installed and nothing in the copy calls it' };
}
// check: the sealed record's window guard (windowGuard(record).check), made before the connection and before each query, so
// nothing reaches the copy's database after the window ends; its refusal propagates (the caller stops with exit 3).
// connect: pg-wire's pgConnect (tests inject one).
export async function livePgNet(observerConfig, credential, check, { connect } = {}) {
  const at = credential.indexOf(':');
  if (at < 1) return { checked: false, used: null, why: 'the observer credential is not user:password' };
  let db;
  try {
    const pgConnect = connect ?? (await import('../observers/pg-wire.mjs')).pgConnect;
    check();
    db = await pgConnect({ host: observerConfig.host, port: observerConfig.port, database: observerConfig.database, user: credential.slice(0, at), password: credential.slice(at + 1) });
    check();
    const [result] = await db.query(PG_NET_USE_SQL);
    const row = result?.rows?.[0];
    let cronJobs = null;
    if (Number(row?.[3]) > 0) { check(); try { const [jobs] = await db.query(PG_CRON_USE_SQL); cronJobs = cronJobsOf(jobs?.rows?.[0]); } catch {} }
    return pgNetUse(row, cronJobs);
  } catch (error) {
    if (error?.name === 'AuthorizationError') throw error;
    return { checked: false, used: null, why: `the live check failed (${String(error?.code ?? error?.message ?? 'error').slice(0, 80)})` };
  } finally { try { await db?.close(); } catch {} }
}
// The sealed record must cover the live check as it is about to run: the target, the observer's endpoint and the window.
// now: the clock (tests inject one).
export async function liveCheckGuard(recordFile, target, observerConfig, { now = () => new Date() } = {}) {
  const record = await readAuthorizationFile(recordFile);
  checkAuthorization(record, { ...target, observers: [...(target.observers ?? []), observerConfig] }, { now: now() });
  return windowGuard(record, { now: () => now().getTime() }).check;
}

// The scan a finding rests on, so a later run can tell whether the files changed: sha256 over the sorted ids and contents.
const scanDigest = files => { const h = createHash('sha256'); for (const f of [...files].sort((a, b) => (a.id < b.id ? -1 : 1))) h.update(`${f.id}\0${f.content.length}\0`).update(f.content); return h.digest('hex'); };
export const WATCHED_UNTIL = 'so the queue is left watched and windows read partial (table-not-in-wal) until its requests are observed on the wire (an egress recorder under a confined run)';
// What the file scan and the live check say about each unlogged platform table the observer cannot read (pg_net's request
// queue). init --stack never ignores one on these checks (an inference is not an observation, and
// the app's own server code or an API exposing the net schema are seen by neither): each stays watched, and the finding is the
// reason its windows read partial. use: 'unused' (every file read, none names it, and the live check under the record found it
// installed, unlogged and called by nothing), 'used', or 'unknown'. files.skipped / files.readRoots: declarationFiles.
// checkedAt: when the live check ran, on the clock its guard used; null when it did not run or did not read the catalog.
export function unloggedTableFindings(spec, files, live = {}, { checkedAt = null } = {}) {
  return (spec.unloggedTables ?? []).map(g => {
    const users = files.filter(f => g.usedBy.some(u => folded(f.content.toString('utf8')).includes(folded(u)))).map(f => f.id);
    const check = live[g.live];
    const scan = !files.length ? 'no --app-dir declarations to check' : !files.readRoots?.has(LIVE_CHECK_FILES[g.live].scan) ? `${LIVE_CHECK_FILES[g.live].scan} was not read in --app-dir`
      : files.skipped ? `the file scan left ${files.skipped} entr${files.skipped === 1 ? 'y' : 'ies'} unread (over 4 MiB, past 2000 files, deeper than four folders, a symbolic link or other non-file, a path outside the app folder, or unreadable)` : null;
    const use = users.length || check?.used === true ? 'used' : !scan && check?.checked && check.used === false ? 'unused' : 'unknown';
    const said = use === 'unused' ? `${g.live} installed but unused per the migrations and the catalog` : users.length ? `named in ${users.slice(0, 3).join(', ')}` : check?.used === true ? check.why : scan ?? `${check?.why ?? 'its live check did not run'}`;
    return { entry: g.entry, use, why: `${said}, ${WATCHED_UNTIL}`, files: { checked: files.length, skipped: files.skipped ?? 0, named: users.slice(0, 3), ...(files.length ? { scanDigest: scanDigest(files) } : {}) },
      live: check ? { checked: check.checked, used: check.used, why: check.why } : null, checkedAt: check?.checked && checkedAt ? checkedAt.toISOString() : null };
  });
}

// The stack's identity rules as a draft (Supabase: the actor capture block and supabaseRules), with placeholders only: the
// install needs a superuser on the disposable copy and changes its schema, and the principals are each identity's auth uid,
// which init does not read. Nothing here joins the profile (src/contracts.mjs refuses supabaseRules without an installed
// capture's digest).
export function rulesDraft(connector, { targetId, record, actors }) {
  const rules = connector.rules?.supabaseRules;
  if (!rules || !record) return null;
  return { note: `Draft, not wired: ${rules.needs} Fill the placeholders, install the capture (integrations/observers/pg-actor.mjs), put its block and installedSha256 on the pg-wal or pg-snapshot observer as actorCapture, then add supabaseRules to the target.`,
    actorCapture: { block: { testCopy: true, installCredentialEnv: credentialName(targetId, 'PG_SUPERUSER'), tables: [{ table: record.table, key: record.key, ...(record.schema && record.schema !== 'public' ? { schema: record.schema } : {}) }],
      actor: { from: 'jwt-claims' }, principals: Object.fromEntries(actors.map(a => [`<auth uid of ${a}>`, a])) }, installedSha256: '<the digest the installation records>' },
    supabaseRules: { tool: '<the name of the server-side tool that writes with the service role>', serviceRoles: rules.serviceRoles } };
}

// The connector's policy importer over the app folder: an unconfirmed matrix, or why there is none.
async function importPolicy(connector, appDir, id) {
  const p = connector.policyImporter;
  if (!p) return { written: false, why: 'the connector has no policy importer' };
  if (p.source !== 'rls') return { written: false, why: `the ${p.source} importer takes one file; run ./scopehaven policy import ${p.source} by hand` };
  const files = await declarationFiles(connector, appDir);
  if (!files.length) return { written: false, skipped: files.skipped, why: files.skipped ? `no .sql file was read under ${p.paths.join(', ')} in --app-dir: the scan left ${files.skipped} entr${files.skipped === 1 ? 'y' : 'ies'} unread (a link, a non-file, a path outside the app folder, or unreadable)` : `no .sql files under ${p.paths.join(', ')} in --app-dir` };
  const { importRls } = await import('../policy-import/rls.mjs');
  const { summarize } = await import('../policy-import/matrix.mjs');
  const matrix = importRls(files, { application: id, roles: p.roles ?? [], bypassRoles: p.bypassRoles ?? [] });
  return { written: true, matrix, summary: summarize(matrix), files: files.length, skipped: files.skipped };
}

async function stampClock(out, runId, summary, code) {
  try {
    const clocks = await import(pathToFileURL(join(ROOT, 'integrations/init/clocks.mjs')).href);
    if (typeof clocks.initClock !== 'function') return;
    // Only the clock's own stages (clocks.mjs STAGES): an unknown stage would stop the onboarding receipt.
    const head = typeof clocks.productHead === 'function' ? clocks.productHead(ROOT) ?? undefined : undefined;
    const clock = clocks.initClock(() => new Date(), head === undefined ? {} : { head });
    clock.setOut(out); clock.runSaved(runId, summary); await clock.flush(code);
  } catch {}
}

export async function runStack(argv, io = {}) {
  const { stdout = process.stdout, env = process.env } = io;
  const say = line => stdout.write(`${line}\n`);
  let sent = false;
  try {
    const { stack: s, init } = splitArgs(argv);
    if (!s['--stack']) throw new InitError('usage', '--stack needs a connector name');
    // Help is init's own; nothing is sent.
    if (init.includes('--help')) { const main = io.main ?? (await import('./cli.mjs')).main; return main(init, io); }
    const { connector, sha256 } = await loadConnector(s['--stack']);
    const connectorStamp = { stack: connector.stack, schema: connector.schema, sha256 };
    say(`ScopeHaven init --stack ${connector.stack}: ${connector.title}.`);
    if (connector.kind !== 'http') {
      say(`      The ${connector.stack} connector is a ${connector.kind} connector: init sets up an HTTP app's profile. ${connector.kind === 'payments' ? 'Run the payments pack (./scopehaven payments run) with the connector\'s provider settings.' : 'Point the framework\'s base URL at the egress recorder and run the class templates (integrations/connectors/README.md).'}`);
      return 2;
    }
    const here = env.SCOPEHAVEN_INIT_CWD || process.cwd();
    // The starter run reads the identities again after init, so --stack takes the env file as a flag.
    if (!init.includes('--no-run') && flagValue(init, '--env') === undefined) throw new InitError('missing', 'with --stack, give --env FILE as a flag (the starter run reads the identities from it after init writes)');
    // The folder init writes is named by the target id, and init asks for it when it is not a flag: --stack reads that folder
    // after init, so the id is a flag too (an answer typed at the prompt would leave --stack reading another folder).
    if (flagValue(init, '--id') === undefined) throw new InitError('missing', 'with --stack, give --id as a flag (the stack reads the folder init writes for that id)');
    // An observer's credential name and endpoint are fixed before init asks anything, so with --observer-env the answers they
    // depend on are flags, not prompts.
    if (s['--observer-env'] !== undefined) {
      const missing = ['--id', '--base-url', '--env', '--record-a', '--record-b'].filter(flag => flagValue(init, flag) === undefined);
      if (missing.length) throw new InitError('missing', `with --observer-env, give ${missing.join(', ')} as flags: the observer's credential name, endpoint and record are fixed before init seals the record`);
    }
    const id = flagValue(init, '--id');
    const baseUrl = flagValue(init, '--base-url');
    const port = s['--observer-port'] === undefined ? undefined : Number(s['--observer-port']);
    if (port !== undefined && !(Number.isInteger(port) && port > 0 && port < 65536)) throw new InitError('usage', '--observer-port is a TCP port');
    const absence = connector.observers.find(o => o.type === connector.backendRow?.observer);
    const observerEnv = s['--observer-env'] === undefined ? null : await readCredentialFile(resolve(here, s['--observer-env']));
    const credentialEnv = absence?.credentialEnvSuffix ? credentialName(id, absence.credentialEnvSuffix) : null;
    const wire = Boolean(absence && observerEnv && observerEnv.keys.includes(credentialEnv));
    if (observerEnv && !wire) say(`      The observer env file has no ${credentialEnv}; the backend row is not wired and stays inconclusive.`);
    if (!observerEnv && absence) say(`      No --observer-env: the backend row is not wired (${absence.type} needs ${credentialEnv}); see ${connector.stack}.json observers[].setup.`);
    if (observerEnv && observerEnv.keys.some(k => k !== credentialEnv)) throw new InitError('env-file', `the observer env file holds only ${credentialEnv}; keep the identities in --env`);
    const observerPort = port ?? absence?.defaults.port;
    // The backend check's record and the twin, worked out from the flags as init will draft them: with two identities the
    // backend check reads A's record, with one the foreign record B. The observer joins the record only when that record can
    // be wired, and a twin's write is named in the record's actions.
    const ids = flagValue(init, '--env') === undefined ? null : await readCredentialFile(resolve(here, flagValue(init, '--env')));
    const twoIdentities = ids?.keys.length === 2;
    const backendPath = flagValue(init, twoIdentities ? '--record-a' : '--record-b');
    const twinWrite = s['--twin-write'] === undefined ? undefined : parseTwinWrite(s['--twin-write']);
    const wireable = wire && backendPath !== undefined && Boolean(recordTarget(connector, backendPath, { recordTable: s['--record-table'], recordId: s['--record-id'] }));
    if (wire && !wireable) say(`      The backend record ${backendPath ?? '(not given)'} is not one of the connector's record templates and no --record-table was given, so no observer is wired or authorized.`);
    const planned = wireable ? plannedTwin(connector, { backendPath, write: twinWrite, twoIdentities, noTwin: Boolean(s['--no-twin']) }) : null;
    const twinWriteUnused = twinWrite !== undefined && !planned ? (s['--no-twin'] ? '--no-twin was given' : !wireable ? 'no observer is wired' : 'one identity: the record has no declared owner') : null;
    if (twinWriteUnused) say(`      --twin-write not sent: ${twinWriteUnused}.`);
    // 1. The connector's slot, the observer's endpoint and the twin's write, before init seals the record.
    let args = init.includes('--credential') ? init : [...init, '--credential', connector.identity.credential];
    if (planned) {
      if (flagValue(init, '--actions') !== undefined) throw new InitError('usage', `init --stack sends one allowed-use write (${planned.method} ${planned.path}) and names it in the authorization's actions itself; leave --actions out, or give --no-twin`);
      const actions = twinActions(planned);
      // init keeps at most 400 characters of the actions (authorization.mjs), and the record must name the whole write.
      if (actions.length > 400) throw new InitError('usage', `the write twin's path is too long to name in the authorization's actions (${actions.length} of 400 characters); give --no-twin`);
      args = withFlag(args, '--actions', actions);
      say(`      Write twin: ${planned.method} ${planned.path} (identity A's own record), named in the authorization's permitted actions.`);
    }
    if (wireable) {
      if (!baseUrl) throw new InitError('missing', 'with --stack and --observer-env, give --base-url as a flag, so the observer\'s endpoint joins the authorization record before it is sealed');
      const { origin } = loopbackOrigin(baseUrl);
      const hosts = (flagValue(init, '--hosts') ?? origin).split(',').map(h => h.trim()).filter(Boolean);
      const endpoint = `tcp://127.0.0.1:${observerPort}`;
      if (!hosts.includes(endpoint)) hosts.push(endpoint);
      args = withFlag(args, '--hosts', hosts.join(','));
      say(`      Observer: ${absence.type} on ${endpoint} (${credentialEnv}, from the observer env file; value in memory only), added to the authorization hosts.`);
    }
    const gateway = connector.identity.gatewayHeaders ?? [];
    // 2. Init itself, stopping after it writes.
    const main = io.main ?? (await import('./cli.mjs')).main;
    const initArgs = args.includes('--no-run') ? args : [...args, '--no-run'];
    const code = await main(initArgs, io);
    if (code !== 0) return code;
    sent = true;
    const out = resolve(here, flagValue(init, '--out') ?? join(ROOT, 'data', 'init', id));
    const files = { profile: join(out, 'targets.json'), report: join(out, 'init-report.json'), record: join(out, 'authorization.json'), stack: join(out, 'stack-report.json'), policy: join(out, 'policy-matrix.json'), rules: join(out, 'stack-rules.draft.json'), evidence: join(out, 'evidence') };
    const manifest = JSON.parse(await readFile(files.profile, 'utf8'));
    const report = JSON.parse(await readFile(files.report, 'utf8'));
    const target = manifest.targets[0];
    const backend = target.checks.find(c => c.evidenceRequirement === 'backend');

    // 3. The backend row.
    say(`[stack] Wiring the ${connector.stack} connector.`);
    const stackReport = { schema: STACK_REPORT_SCHEMA, target: target.id, connector: connectorStamp, wired: [], notWired: [], watched: [], assumptions: [], refusals: {}, gatewayHeaders: [], policy: null, packs: connector.packs, reset: connector.reset, limits: connector.limits };
    if (twinWriteUnused) stackReport.notWired.push({ what: '--twin-write', why: twinWriteUnused });
    // The use check reads its entries' own scan paths (migrations and the seed), the policy importer its own.
    const scan = [...new Set((absence?.unloggedTables ?? []).flatMap(g => g.scan))];
    const declarations = s['--app-dir'] === undefined ? [] : await declarationFiles(connector, resolve(here, s['--app-dir']), scan);
    let finalManifest = manifest;
    const record = backend ? recordTarget(connector, backend.path, { recordTable: s['--record-table'], recordId: s['--record-id'] }) : null;
    if (!backend) stackReport.notWired.push({ what: 'backend row', why: 'the starter profile has no backend check' });
    else if (!wire) stackReport.notWired.push({ what: 'backend row', why: observerEnv ? `the observer env file has no ${credentialEnv}` : `no --observer-env (needs ${credentialEnv})` });
    else if (wireable && backend.path !== backendPath) throw new InitError('profile', 'the drafted backend check reads another record than the flags named, so the authorization would not describe the run; nothing was wired');
    else if (!record || !wireable) stackReport.notWired.push({ what: 'backend row', why: `${backend.path} is not one of the connector's record templates; give --record-table TABLE[:KEY]` });
    else {
      const observer = observerEntry(connector, { targetId: target.id, record, port });
      // A platform ignore list (the observer's own checked-in list for platform: supabase) is applied because the stack
      // declares the platform, not because anything here observed it; the report names it and its bytes.
      if (observer.platform && observer.platform !== 'none') {
        const list = join(ROOT, 'integrations', 'observers', 'ignore-lists', `${observer.platform}.json`);
        stackReport.platformIgnoreList = { platform: observer.platform, file: `integrations/observers/ignore-lists/${observer.platform}.json`, sha256: createHash('sha256').update(await readFile(list)).digest('hex'), why: 'declared by the stack (the connector\'s observer defaults), as the observer applies it to any run on that platform; it never covers an observed table' };
      }
      // What the wiring takes as given rather than observes: the connector's declared timings (a window is complete only if the
      // app commits within settleMs of answering), the functions the live check does not count, and a template twin's key.
      const timings = Object.fromEntries(['settleMs', 'barrierMs'].filter(k => observer[k] !== undefined).map(k => [k, observer[k]]));
      if (Object.keys(timings).length) stackReport.assumptions.push({ what: 'observer timings', value: timings, why: 'declared by the connector\'s observer defaults, not observed: a window counts as complete when the app commits within settleMs of answering, so a later commit falls outside it' });
      // The live checks behind the unlogged-table findings, on the copy, with the observer's own role, under the sealed record:
      // it is checked against the observer's endpoint and the window first, and the window again before each query. A record
      // that no longer covers it stops the stack (exit 3) before the database is reached.
      const live = {}, liveClock = io.liveCheckNow ?? (() => new Date());
      let checkedAt = null;
      if ((absence.unloggedTables ?? []).some(g => g.live === 'pg_net') && declarations.length) {
        let check;
        try { check = await liveCheckGuard(files.record, target, observer, { now: liveClock }); } catch (error) { throw new InitError('authorization', `the sealed record does not cover the live pg_net check (${String(error?.code ?? error?.name ?? 'error').slice(0, 60)}); nothing was sent to the database`); }
        checkedAt = liveClock();
        try { live.pg_net = await livePgNet(observer, observerEnv.values.get(credentialEnv), check, io.liveConnect ? { connect: io.liveConnect } : {}); }
        catch (error) { if (error?.name === 'AuthorizationError') throw new InitError('authorization', `the record's window ended during the live pg_net check (${error.code}); nothing more was sent`); throw error; }
      }
      // Never an ignore entry: each unlogged table stays watched, and the checks' finding is the reason its windows read partial.
      stackReport.watched = unloggedTableFindings(absence, declarations, live, { checkedAt });
      if (live.pg_net?.checked) stackReport.assumptions.push({ what: 'functions the live pg_net check does not count', value: ['net', 'supabase_functions', 'pg_catalog', 'information_schema', 'extensions.grant_pg_net_access'], why: 'taken as pg_net\'s and the platform\'s own; an app function placed in one of these schemas is not seen, nor is a call built at run time (dynamic EXECUTE of a formatted name), which neither the source match nor the dependency check reads' });
      for (const w of stackReport.watched) say(`      ${w.entry}: ${w.why}.`);
      // The backend check reads the record of the profile's other actor: with two identities that is A's record, so A is the
      // owner whose own write shows the selector selects. Only the twin the record's actions name is wired.
      const owner = target.actors.b ? 'a' : null;
      const twin = planned ? writeTwin(connector, { record, backend, owner, write: twinWrite }) : null;
      if (planned && !(twin && twin.method === planned.method && twin.path === planned.path)) throw new InitError('profile', 'the drafted twin differs from the write the authorization names; nothing was wired');
      if (s['--record-table'] !== undefined && !String(s['--record-table']).includes(':')) stackReport.assumptions.push({ what: 'the record key column', value: record.key, why: '--record-table gave no :KEY, so the key column is taken as id' });
      if (s['--record-table'] !== undefined && s['--record-id'] === undefined) stackReport.assumptions.push({ what: 'the record id', value: record.id, why: 'taken from the record path\'s last segment (no --record-id)' });
      if (twin && planned.viaTemplate) stackReport.assumptions.push({ what: 'the write twin selects one row', value: `${record.table}.${record.key}`, why: 'the record template names the key column; if it is not unique, the PATCH writes every row identity A can see that matches, and the table\'s update triggers run on each' });
      if (!twin) stackReport.notWired.push({ what: 'write twin', why: s['--no-twin'] ? '--no-twin' : owner ? 'the record path is an app route; give --twin-write METHOD:PATH:STATUS:JSON (the owner\'s own write of the record)' : 'one identity: the foreign record has no declared owner' });
      const result = wireBackend(manifest, connector, { record, observerConfig: observer, twin });
      finalManifest = result.manifest;
      stackReport.wired.push({ ...result.wired, table: `${record.schema ?? 'public'}.${record.table}`, key: record.key, recordFrom: record.from, endpoint: `tcp://127.0.0.1:${observer.port}` });
      await writePrivate(files.profile, `${JSON.stringify(finalManifest, null, 2)}\n`);
      say(`      ${result.wired.check}: ${result.wired.clauses} effect clause${result.wired.clauses === 1 ? '' : 's'} on ${observer.type} (${record.schema ?? 'public'}.${record.table}, key ${record.key}; ${record.from}).`);
      const pinned = finalManifest.targets[0].checks.find(c => c.id === result.wired.check).effects.some(e => Object.hasOwn(e.select, 'resource'));
      if (twin) say(`      ${twin.id}: the allowed-use twin, sent first: ${twin.method} ${twin.path}, expecting ${twin.assertions[0].expected} and the write on ${observer.type}.`);
      else if (pinned) say('      No write twin: the backend row\'s record pin is not shown to select, so its absence reads inconclusive (selector-unpaired).');
      else if (backend.assertions[0]?.kind === 'status.in') say(`      No write twin: the check expects a refusal, so it judges the whole table (no committed change to ${record.table} in its window), which needs none.`);
      else say(`      No write twin: the check expects a 2xx answer, so it judges the whole table, and the allowed-use guard holds that clause back without the owner's own write: the backend row reads inconclusive.`);
    }
    if (!wire && !record && backend && s['--record-table'] === undefined && !matchRecord(connector, backend.path)) say('      The record path is an app route: with an observer, give --record-table TABLE[:KEY] so the observer knows which row it is.');
    // How each prohibition was judged, against the stack's declared refusal forms.
    const declared = new Set(connector.refusals.map(r => (r.status >= 200 && r.status < 300 ? r.body : 'status')));
    const SHAPE = { 'empty-list': 'empty-array', null: 'null', refusal: 'status', 'refusal-leak-seen': 'status' };
    for (const [checkId, how] of Object.entries(report.prohibitions ?? {})) stackReport.refusals[checkId] = { judged: how, declaredByStack: declared.has(SHAPE[how] ?? how) };
    for (const g of gateway) {
      const name = credentialName(target.id, g.envSuffix);
      stackReport.gatewayHeaders.push({ header: g.header, env: name, required: g.required, sent: false, why: 'an actor carries one credential today; the gateway-header hook is proposed for src/ (connectors/README.md)' });
    }
    const draftRules = rulesDraft(connector, { targetId: target.id, record, actors: Object.values(target.actors).filter(a => a.credentialEnv).map(a => a.principalId) });
    if (draftRules) {
      await writePrivate(files.rules, `${JSON.stringify(draftRules, null, 2)}\n`);
      stackReport.notWired.push({ what: 'supabaseRules', why: 'drafted in stack-rules.draft.json; the actor capture is installed by a superuser on the copy, so init does not wire it' });
      say('      Supabase identity rules: drafted in stack-rules.draft.json, not wired (the actor capture needs a superuser install on the copy).');
    }
    if (gateway.length) say(`      Gateway header${gateway.length === 1 ? '' : 's'} ${gateway.map(g => g.header).join(', ')}: declared, not sent (needs the src/ gateway-header hook); the probes above answered without ${gateway.length === 1 ? 'it' : 'them'}.`);
    // 4. The policy importer.
    if (s['--app-dir'] !== undefined) {
      const policy = await importPolicy(connector, resolve(here, s['--app-dir']), target.applicationId);
      if (policy.written) {
        await writePrivate(files.policy, `${JSON.stringify(policy.matrix, null, 2)}\n`);
        stackReport.policy = { source: connector.policyImporter.source, files: policy.files, skipped: policy.skipped, summary: policy.summary, confirmed: false };
        say(`      Policy: ${connector.policyImporter.source} matrix from ${policy.files} file${policy.files === 1 ? '' : 's'}${policy.skipped ? ` (${policy.skipped} entr${policy.skipped === 1 ? 'y' : 'ies'} left unread, so the matrix may be partial)` : ''}, unconfirmed in policy-matrix.json (draft and confirm with ./scopehaven policy).`);
      } else { stackReport.policy = { source: connector.policyImporter?.source ?? null, written: false, skipped: policy.skipped ?? 0, why: policy.why }; say(`      Policy: not imported (${policy.why}).`); }
    }
    await writePrivate(files.stack, `${JSON.stringify(stackReport, null, 2)}\n`);
    if (connector.packs.length) say(`      Default packs for ${connector.stack}: ${connector.packs.join(', ')} (./scopehaven pack).`);
    if (connector.reset) say(`      Reset the copy: ${connector.reset.argv.join(' ')} in the app folder (${connector.reset.note})`);

    if (init.includes('--no-run')) { say('Stopped after writing (--no-run).'); return 0; }
    // 6. check-config, roe check and the starter assessment.
    const childEnv = { ...env, ...Object.fromEntries(ids.values), ...(observerEnv ? Object.fromEntries(observerEnv.values) : {}) };
    const config = await runChild(join(ROOT, 'src/cli.mjs'), ['--check-config', '--config', files.profile], childEnv);
    const configJson = lastJson(config.stdout);
    if (config.code !== 0 || !configJson?.targets?.some(t => t.id === target.id)) throw new InitError('check-config', `check-config refused the wired profile: ${(config.stderr || config.stdout).split('\n').find(Boolean)?.slice(0, 400) ?? 'no output'}`);
    const roe = await runChild(join(ROOT, 'integrations/roe/cli.mjs'), ['check', files.record, '--config', files.profile, '--target', target.id], childEnv);
    if (roe.code !== 0) { const j = lastJson(roe.stdout) ?? lastJson(roe.stderr); throw new InitError('roe', `roe check refused the wired profile (${j?.code ?? 'unknown'}): ${j?.message ?? ''}`); }
    say('[stack] check-config and roe check passed on the wired profile; starter assessment.');
    const assess = await runChild(join(ROOT, 'src/cli.mjs'), ['--config', files.profile, '--target', target.id, '--authorization', files.record, '--out', files.evidence], childEnv);
    const assessJson = lastJson(assess.stdout);
    if (!assessJson?.id) throw new InitError('assess', `the assessment did not save a run: ${(assess.stderr || assess.stdout).split('\n').find(Boolean)?.slice(0, 400) ?? 'no output'}`);
    const runFile = join(files.evidence, 'runs', `${assessJson.id}.json`);
    const run = JSON.parse(await readFile(runFile, 'utf8'));
    const summary = summarizeRun(run.core);
    const backendRow = backend ? run.core.results.find(r => r.id === backend.id) : null;
    say(`      Run ${assessJson.id}: ${summary.counts.FAIL} FAIL, ${summary.counts.INCONCLUSIVE} INCONCLUSIVE, ${summary.counts['not exercised']} not exercised. Scope: ${assessJson.scope}`);
    if (backendRow) say(`      Backend row ${backendRow.id}: ${backendRow.status === 'fail' ? 'FAIL' : backendRow.status === 'pass' ? 'decided, no change to the record in its window' : backendRow.status === 'inconclusive' ? 'INCONCLUSIVE' : 'not exercised'} (backend evidence ${backendRow.backendEvidence}).`);
    say('');
    for (const line of formatFirstRow(summary.first)) say(line);
    say(`  run file: ${runFile}`);
    say(`  stack report: ${files.stack}`);
    // The onboarding clock (integrations/init/clocks.mjs), when it ships: the stack's own starter run is the run it
    // times. A clock that is missing or fails never changes the result.
    await stampClock(out, assessJson.id, summary, summary.counts.FAIL ? 1 : 0);
    if (summary.counts.FAIL) say(`Exit 1: the starter run has ${summary.counts.FAIL} FAIL row${summary.counts.FAIL === 1 ? '' : 's'}.`);
    return summary.counts.FAIL ? 1 : 0;
  } catch (error) {
    const known = error instanceof InitError || error instanceof ConnectorError;
    stdout.write(`init --stack stopped (${known ? error.code ?? 'connector' : 'error'}): ${known ? error.message : String(error?.message ?? error).slice(0, 300)}\n`);
    return sent ? 3 : 2;
  }
}

const invokedDirectly = () => { try { return realpathSync(resolve(process.argv[1])) === realpathSync(fileURLToPath(import.meta.url)); } catch { return false; } };
if (process.argv[1] && invokedDirectly()) process.exitCode = await runStack(process.argv.slice(2));
