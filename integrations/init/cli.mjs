// scopehaven init (v0): from an app already running on loopback to a first decided row.
//
//   ./scopehaven init --base-url http://127.0.0.1:3000 --env ids.env [options]
//
// Steps, each printed as it runs:
//   1. Authorization first: five questions draft the record for the local copy (authorization.mjs). It is sealed only
//      when the operator confirms they are authorized to test this copy (interactive "yes" or --confirm-authorization).
//      Nothing is sent to the app before that, and every probe after it is checked against the record and its window.
//   2. Probes (probe.mjs, GET only): login routes, the session-derived who-am-I route, the credential slot and each
//      identity's own record. Asks when it cannot find one.
//   3. Writes the two-actor starter profile (profile.mjs), the allowed-use twin of each prohibition, the observer
//      candidates found from environment variable names (observers.mjs) and any inference drafts (hooks.mjs).
//   4. Runs check-config, roe check and the starter assessment, and prints the first FAIL row, or the first
//      INCONCLUSIVE row with its fired check, and the files it wrote.
//
// Options (every one can also be answered interactively):
//   --base-url URL          the app on loopback (http://127.0.0.1:PORT or http://localhost:PORT)
//   --env FILE              0600 env file with each identity's credential as SCOPEHAVEN_TARGET_<APP>_A and _B (one key: one identity)
//   --id ID                 target id (default: app)
//   --whoami PATH           the who-am-I route, if the probe does not find it
//   --credential SLOT       bearer | cookie:NAME | header:NAME, if the probe does not find it
//   --record-a PATH         a record identity A owns (for example /api/notes/12)
//   --record-b PATH         a record identity B owns (with one identity: a record of another tenant)
//   --client TEXT  --hosts LIST  --actions TEXT  --data-class TEXT  --contact "NAME, ROLE"   the five questions
//   --hours N               authorization window (default 8, at most 72)
//   --confirm-authorization I am authorized to test this local copy (seals the record)
//   --app-env FILE          the app's .env file; init reads its variable NAMES only
//   --use-observer NAME     consent to read NAME's value in memory to check it points at loopback (repeatable)
//   --openapi FILE          an OpenAPI 3 JSON document to draft GET checks from (unconfirmed)
//   --session FILE          a recorded session of identity A (0600 HAR or JSON-lines request log) for the session drafter
//   --out DIR               where to write (default: data/init/<id>)
//   --force                 replace files a previous init wrote in --out
//   --no-run                stop after writing; do not run check-config, roe check or the assessment
//   --yes                   never ask; every missing answer is listed in one error
//   --stack NAME            the per-stack connector path (integrations/init/stack.mjs), when the checkout has it
//
// Exit status: 0 set up and the starter run has no FAIL row; 1 set up and the starter run has a FAIL row; 2 stopped
// before any request (a missing answer, a refused input, or an authorization not confirmed); 3 could not finish (the
// app did not answer as needed, or a check refused the profile).
//
// Every run appends its stage stamps to init-stamps.jsonl in --out (stage names, times, codes, run and check ids, counts, the product
// head; never a credential, path, host or value). Timed
// onboardings (onboarding.mjs): init start --out DIR --label LABEL --owned yes|no --operator-role ROLE before opening the
// docs; init review --out DIR --run RUN_ID --check CHECK_ID --holds yes|no --reviewer-role ROLE for each FAIL row;
// init receipt --out DIR for both clocks (first decided row; first FAIL that holds on review); init table DIR... for
// the timing table.
import { spawn } from 'node:child_process';
import { constants, existsSync, readFileSync, realpathSync } from 'node:fs';
import { mkdir, open, readFile, rename, unlink } from 'node:fs/promises';
import { createInterface } from 'node:readline/promises';
import { randomBytes } from 'node:crypto';
import { basename, join, resolve, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkAuthorization, windowGuard } from '../../src/authorization.mjs';
import { InitError, readCredentialFile, appEnvNames, environmentNames, sessionSecrets, sessionUnchanged, holdsSecret } from './envfile.mjs';
import { loopbackOrigin, parseSlot, slotLabel, makeProber, findLoginRoutes, findChatRoutes, findWhoami, whoamiMiss, probeRecord, probeAs, recordValues, recordPredicate, safePath } from './probe.mjs';
import { validateTargetFile } from '../../src/contracts.mjs';
import { buildProfile, ID } from './profile.mjs';
import { QUESTIONS, DEFAULT_ACTIONS, DEFAULT_DATA_CLASS, parseContact, draftAuthorization, sealAuthorization } from './authorization.mjs';
import { observerCandidates, observerDrafts, pointsAtLoopback } from './observers.mjs';
import { openApiDraft, laneDDrafts } from './hooks.mjs';
import { summarizeRun, formatFirstRow } from './findings.mjs';
import { initClock, productHead } from './clocks.mjs';
import { ONBOARDING_COMMANDS, onboardingCommand } from './onboarding.mjs';

export const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const VALUE_FLAGS = ['--base-url', '--env', '--id', '--whoami', '--credential', '--record-a', '--record-b', '--client', '--hosts', '--actions', '--data-class', '--contact',
  '--hours', '--app-env', '--openapi', '--session', '--out'];
const REPEAT_FLAGS = ['--use-observer'];
// Files that make a folder an init or onboarding folder (stamps may go there before init has checked its inputs).
const INIT_MARKERS = ['init-stamps.jsonl', 'authorization.draft.json', 'init-report.json'];
const BOOL_FLAGS = ['--confirm-authorization', '--force', '--no-run', '--yes', '--help'];

export function parseArgs(argv) {
  const options = { '--use-observer': [] };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (BOOL_FLAGS.includes(flag)) { if (options[flag]) throw new InitError('usage', `${flag} is given twice`); options[flag] = true; continue; }
    const value = argv[i + 1];
    if (![...VALUE_FLAGS, ...REPEAT_FLAGS].includes(flag)) throw new InitError('usage', `unknown option ${String(flag).slice(0, 40)}`);
    if (typeof value !== 'string' || value.startsWith('--')) throw new InitError('usage', `${flag} needs a value`);
    if (REPEAT_FLAGS.includes(flag)) options[flag].push(value);
    else { if (Object.hasOwn(options, flag)) throw new InitError('usage', `${flag} is given twice`); options[flag] = value; }
    i += 1;
  }
  return options;
}

// Writes a private file (0600). Without force an existing file is never replaced.
async function writePrivate(path, content, force) {
  if (!force) {
    let handle;
    try { handle = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600); }
    catch (error) { throw new InitError('output', error?.code === 'EEXIST' ? `${path} already exists; use --force to replace what a previous init wrote, or choose another --out` : `${path} could not be created`); }
    try { await handle.writeFile(content); } finally { await handle.close(); }
    return;
  }
  const temporary = `${path}.${randomBytes(8).toString('hex')}.tmp`;
  try {
    const handle = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    try { await handle.writeFile(content); } finally { await handle.close(); }
    await rename(temporary, path);
  } finally { await unlink(temporary).catch(() => {}); }
}

// Runs a ScopeHaven entry point as a child with the identities' credentials in its environment (memory only).
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

// hooksRoot: where the inference hook modules are looked up (tests point it at a stub).
export async function main(argv, io = {}) {
  // Lane K's connector path (integrations/init/stack.mjs) owns --stack; it calls back into this main with --no-run.
  // runStack must strip --stack before it calls main again, or main hands off to it once more.
  if (argv.includes('--stack')) {
    const out = io.stdout ?? process.stdout;
    if (!existsSync(fileURLToPath(new URL('./stack.mjs', import.meta.url)))) { out.write('init stopped (usage): --stack needs integrations/init/stack.mjs (the per-stack connectors), which this checkout does not have\n'); return 2; }
    let stack;
    // Nothing has been sent yet, so a module that fails to load is a stop before any request (2).
    // Only an error's code or name is printed: a connector's message can quote a connection string or a credential.
    const named = error => (typeof error?.code === 'string' && /^[A-Za-z0-9_-]{1,60}$/.test(error.code) ? error.code : typeof error?.name === 'string' && /^[A-Za-z]{1,60}$/.test(error.name) ? error.name : 'error');
    try { stack = await import('./stack.mjs'); } catch (error) { out.write(`init stopped (stack): integrations/init/stack.mjs could not be loaded (${named(error)})\n`); return 2; }
    if (typeof stack.runStack !== 'function') { out.write('init stopped (stack): integrations/init/stack.mjs exports no runStack\n'); return 2; }
    // The exit status keeps init's meaning: a throw from the connector path, or a status outside 0 to 3, reads 3 (could not finish),
    // never 1, which says the starter run has a FAIL row.
    // main travels in io: the connector path must not import this entry module while its top-level await is pending (an unsettled
    // top-level await exits 13 before any request).
    try { const code = await stack.runStack(argv, { ...io, main }); return [0, 1, 2, 3].includes(code) ? code : 3; }
    catch (error) { out.write(`init stopped (stack): the connector path failed (${named(error)})\n`); return 3; }
  }
  if (ONBOARDING_COMMANDS.includes(argv[0])) return onboardingCommand(argv, { ...io, root: ROOT });
  const clock = initClock(io.now ?? (() => new Date()), { head: io.head !== undefined ? io.head : productHead(ROOT) });
  const code = await steps(argv, io, clock);
  await clock.flush(code, { say: line => (io.stdout ?? process.stdout).write(`${line}\n`) });
  return code;
}

async function steps(argv, { stdout = process.stdout, stdin = process.stdin, env = process.env, ask: injectedAsk, now = () => new Date(), hooksRoot } = {}, clock) {
  const say = line => stdout.write(`${line}\n`);
  let rl = null;
  // Set once probing starts: the exit status says whether anything was sent.
  let prober = null;
  try {
    const o = parseArgs(argv);
    if (o['--help']) { say(HELP()); return 0; }
    // Stamps go to --out as soon as it is known, so a run that stops on its inputs is still stamped, but before init has checked its
    // inputs only into a folder that is already an init or onboarding folder (it holds stamps or init's own drafts).
    if (o['--out'] !== undefined) { const early = resolve(env.SCOPEHAVEN_INIT_CWD || process.cwd(), o['--out']); if (INIT_MARKERS.some(name => existsSync(join(early, name)))) clock.setOut(early); }
    // Flags that name app paths or the credential slot are checked before anything is drafted or sent.
    const checkPath = (flag, path) => { if (!safePath(path)) throw new InitError('usage', `${flag} must be an absolute path on the app (for example /api/me), with no "//", "." or ".." segment, space or fragment`); return path; };
    for (const flag of ['--whoami', '--record-a', '--record-b']) if (o[flag] !== undefined) checkPath(flag, o[flag]);
    if (o['--credential'] !== undefined) parseSlot(o['--credential']);
    const interactive = !o['--yes'] && (injectedAsk || stdin.isTTY);
    // Without a terminal, every missing answer is named at once, not one per run.
    if (!interactive) {
      const missing = ['--base-url', '--env', '--client', '--contact', '--record-a', '--record-b'].filter(flag => o[flag] === undefined);
      if (missing.length) throw new InitError('missing', `with --yes or without a terminal, init needs ${missing.join(', ')}${o['--confirm-authorization'] ? '' : ' (and --confirm-authorization, or it stops after drafting the record)'}. Every answer as flags: ./scopehaven init --yes --base-url http://127.0.0.1:3000 --env ids.env --id myapp --record-a /api/notes/12 --record-b /api/notes/31 --client "My company" --contact "Your Name, Role" --confirm-authorization`);
    }
    const ask = async (flag, prompt, fallback) => (o[flag] !== undefined ? o[flag] : askRaw(flag, prompt, fallback));
    const askRaw = async (flag, prompt, fallback) => {
      if (!interactive) { if (fallback !== undefined) return fallback; throw new InitError('missing', `${flag} is required with --yes or without a terminal (${prompt})`); }
      if (injectedAsk) { const answer = await injectedAsk(flag, prompt, fallback); return answer === '' || answer === undefined ? fallback : answer; }
      rl ??= createInterface({ input: stdin, output: stdout });
      const answer = (await rl.question(`${prompt}${fallback !== undefined ? ` [${fallback}]` : ''} `)).trim();
      return answer === '' ? fallback : answer;
    };
    // An empty answer at a terminal is asked again (three times), never a stop after the authorization was confirmed.
    const required = async (flag, prompt, fallback) => {
      for (let attempt = 0; attempt < 3; attempt++) {
        const v = await ask(flag, prompt, fallback);
        if (v !== undefined && v !== '') return v;
        if (!interactive || o[flag] !== undefined) break;
        say(`      ${flag} needs an answer.`);
      }
      throw new InitError('missing', `${flag} needs an answer`);
    };

    // The folder the operator ran the command from (the launcher changes into the project folder first).
    const here = env.SCOPEHAVEN_INIT_CWD || process.cwd();
    // Paths as the operator would type them: relative when inside the current folder, quoted when they hold a space.
    const shown = path => { const rel = relative(here, path); const p = rel && !rel.startsWith('..') ? rel : path; return /\s/.test(p) ? `'${p}'` : p; };
    say('ScopeHaven init: local app on loopback, read-only probes, nothing leaves this machine.');
    const { origin, port } = loopbackOrigin(await required('--base-url', 'Base URL of the running app (loopback)?'));
    const envFile = resolve(here, await required('--env', 'Env file (0600) with each identity\'s credential as SCOPEHAVEN_TARGET_<APP>_A and _B?'));
    const credentials = await readCredentialFile(envFile);
    if (credentials.keys.length > 2) throw new InitError('env-file', 'the env file holds more than two SCOPEHAVEN_TARGET_ keys; v0 drafts two identities, so keep only A and B in it');
    const two = credentials.keys.length === 2;
    clock.stamp('identities-read', { identities: credentials.keys.length });
    say(`[1/6] Identities: ${credentials.keys.length} from the env file (${credentials.keys.join(', ')}); values stay in memory.`);
    if (!two) say('      Note: one identity. Cross-tenant checks run from one side only; add a second identity in another tenant for the full starter profile.');
    // A recorded session is checked (private, readable, JSON or JSON lines) before anything is drafted or sent. Its
    // credential-like values are kept in memory only, to keep them out of every proposal init writes.
    const session = o['--session'] === undefined ? undefined : resolve(here, o['--session']);
    const secrets = new Set(credentials.values.values());
    let sessionIdentity = null;
    if (session) {
      const read = await sessionSecrets(session);
      for (const value of read.secrets) secrets.add(value);
      // The path and the file name are kept out of every proposal too.
      secrets.add(session);
      if (basename(session).length >= 8) secrets.add(basename(session));
      sessionIdentity = read.identity;
      say(`      Session file: ${shown(session)} (passed to the session drafter by path; never copied).`);
    }
    // Files given as flags are read (names only for --app-env) before anything is drafted or sent.
    const appNames = o['--app-env'] ? await appEnvNames(resolve(here, o['--app-env'])) : [];
    if (o['--openapi'] !== undefined) { try { await readFile(resolve(here, o['--openapi'])); } catch { throw new InitError('usage', '--openapi names a file that could not be read'); } }
    const id = await required('--id', 'Target id (letters, digits, - or _)?', 'app');
    if (!ID.test(id)) throw new InitError('usage', '--id is 1 to 80 letters, digits, "_" or "-"');
    const identities = credentials.keys.map((credentialEnv, i) => ({ alias: i ? 'b' : 'a', principalId: `identity-${i ? 'b' : 'a'}`, credentialEnv, value: credentials.values.get(credentialEnv) }));
    const out = resolve(here, o['--out'] ?? join(ROOT, 'data', 'init', id));
    await mkdir(out, { recursive: true, mode: 0o700 });
    clock.setOut(out);

    // 1. Authorization record from five questions; sealed only on confirmation.
    say('[2/6] Authorization for this local copy (five questions; the record is checked before every request).');
    const answers = {
      client: await required('--client', QUESTIONS[0].prompt),
      hosts: String(await required('--hosts', QUESTIONS[1].prompt, origin)).split(',').map(h => h.trim()).filter(Boolean),
      actions: await required('--actions', QUESTIONS[2].prompt, DEFAULT_ACTIONS),
      dataClass: await required('--data-class', QUESTIONS[3].prompt, DEFAULT_DATA_CLASS),
      contact: parseContact(await required('--contact', QUESTIONS[4].prompt)),
    };
    if (!answers.contact.name) throw new InitError('missing', '--contact needs a name');
    if (!answers.hosts.includes(origin)) throw new InitError('authorization', `the hosts do not include the app's origin ${origin}; init would not be allowed to probe it`);
    const hours = Number(o['--hours'] ?? 8);
    if (!Number.isFinite(hours) || hours <= 0 || hours > 72) throw new InitError('usage', '--hours is a number of hours from 0 to 72');
    const { draft, roeText } = draftAuthorization({ id, origin, answers, identities: identities.map(i => i.principalId), now: now(), hours });
    const files = { roe: join(out, 'rules-of-engagement.md'), draft: join(out, 'authorization.draft.json'), record: join(out, 'authorization.json'), profile: join(out, 'targets.json'),
      observers: join(out, 'observers.draft.json'), report: join(out, 'init-report.json'), policy: join(out, 'policy-draft.json'), inference: join(out, 'inference-draft.json'), evidence: join(out, 'evidence') };
    // A previous complete run is replaced only with --force, and that is decided before anything is written. The rules
    // file and the draft are init's own drafts: each run rewrites them, and a record sealed by an earlier run is removed
    // first, so a sealed record never outlives the answers it was sealed from.
    const later = [files.profile, files.observers, files.report, files.policy, files.inference].filter(path => existsSync(path));
    if (later.length && !o['--force']) throw new InitError('output', `${shown(later[0])} is from an earlier init; use --force to replace that run's files, or choose another --out`);
    if (existsSync(files.record)) { await unlink(files.record); say(`      Removed the record an earlier run sealed (${shown(files.record)}); it is sealed again only on confirmation.`); }
    await writePrivate(files.roe, roeText, true);
    await writePrivate(files.draft, `${JSON.stringify(draft, null, 2)}\n`, true);
    say(`      Drafted ${shown(files.roe)} and ${shown(files.draft)}.`);
    clock.stamp('authorization-drafted');
    let confirmed = Boolean(o['--confirm-authorization']);
    if (!confirmed && interactive) confirmed = String(await ask('--confirm-authorization', `Type yes to confirm ${answers.contact.name} is authorized to test this local copy (${origin}) under those rules:`, 'no')).toLowerCase() === 'yes';
    if (!confirmed) {
      say(`Stopped before any request: the authorization record is drafted but not confirmed. Review ${shown(files.roe)}, then rerun the same command with --confirm-authorization.`);
      return 2;
    }
    const record = sealAuthorization(draft);
    await writePrivate(files.record, `${JSON.stringify(record, null, 2)}\n`, false);
    say(`      Sealed ${shown(files.record)} (unkeyed checksum, not a signature).`);
    clock.stamp('authorization-sealed');
    // Every probe runs under the record: the target, origin and accounts must be covered now, and the window is checked
    // again before each request.
    checkAuthorization(record, { id, applicationId: id, origin, actors: Object.fromEntries(identities.map(i => [i.alias, { principalId: i.principalId, credentialEnv: i.credentialEnv }])) }, { now: now() });
    const guard = windowGuard(record);
    prober = makeProber({ port, beforeRequest: guard.check });

    // 2. Probes.
    clock.stamp('probe-start');
    say(`[3/6] Probing ${origin} (GET only, no redirects followed, no response stored).`);
    const started = Date.now();
    const elapsed = () => `${((Date.now() - started) / 1000).toFixed(1)} s`;
    const login = await findLoginRoutes(prober);
    say(login.found.length ? `      Login or session routes: ${login.found.map(r => `${r.path} (${r.status})`).join(', ')}` : '      No login route recognized; that is fine, init uses the sessions in your env file.');
    const chat = await findChatRoutes(prober, login.control);
    if (chat.length) say(`      Assistant or agent routes: ${chat.map(r => `${r.path} (${r.status})`).join(', ')}. Not drafted: assistant-turn checks need a message and a planted value (docs/ONBOARDING.md).`);
    let slot = o['--credential'] ? parseSlot(o['--credential']) : undefined;
    say(`      Looking for the who-am-I route${o['--whoami'] ? ` at ${o['--whoami']}` : ''}${slot ? ` via ${slotLabel(slot)}` : ''} (a dev server may compile routes on first use; ${elapsed()} so far)...`);
    let search = await findWhoami(prober, { valueA: identities[0].value, valueB: identities[1]?.value, slot, whoami: o['--whoami'] });
    if (!search.found) say(`      Not found after ${elapsed()}: ${whoamiMiss(search.tried)}.`);
    if (!search.found && interactive) {
      say('      Tell init where the who-am-I route is.');
      const path = checkPath('--whoami', await required('--whoami', 'Who-am-I route (a session-derived route such as /api/me)?'));
      slot = parseSlot(await required('--credential', 'How does the app take the session? bearer, cookie:NAME or header:NAME', slot ? slotLabel(slot) : 'bearer'));
      search = await findWhoami(prober, { valueA: identities[0].value, valueB: identities[1]?.value, slot, whoami: path });
      if (!search.found) say(`      Not found: ${whoamiMiss(search.tried)}.`);
    }
    if (!search.found) throw new InitError('whoami', 'no who-am-I route named each identity with its own value (details above)');
    const whoami = search.found;
    clock.stamp('whoami-found');
    identities[0].identityValue = whoami.valueA;
    if (two) identities[1].identityValue = whoami.valueB;
    say(`      Who-am-I: ${whoami.path} via ${slotLabel(whoami.slot)}; identity field ${whoami.pointer}${whoami.anonymousStatus ? ` (signed out it answers ${whoami.anonymousStatus})` : ''} (${elapsed()}).`);

    const records = {};
    for (const [key, owner] of two ? [['a', identities[0]], ['b', identities[1]]] : [['a', identities[0]], ['b', null]]) {
      const flag = `--record-${key}`;
      const prompt = owner ? `Path of a record identity ${key.toUpperCase()} owns (for example /api/notes/12)?` : 'Path of a record identity A does not own (another tenant\'s, for example /api/notes/99)?';
      let path = await required(flag, prompt);
      for (let attempt = 0; ; attempt++) {
        checkPath(flag, path);
        // A route scoped to the session (the same path for both) answers each identity with its own data, so the
        // cross-tenant checks would read B's own answer as A's record: a false FAIL.
        if (key === 'b' && path === records.a.path) {
          const why = '--record-b is the same path as --record-a; give a path that names one record A owns and one B owns (for example /api/notes/12 and /api/notes/31), not a route that lists the signed-in user\'s own records';
          if (!interactive || o[flag] !== undefined || attempt >= 2) throw new InitError('record', why);
          say(`      ${why}.`); path = await required(flag, prompt); continue;
        }
        if (!owner) { records[key] = { path }; break; }
        const probe = await probeRecord(prober, path, { slot: whoami.slot, value: owner.value });
        if (probe.ownerStatus >= 200 && probe.ownerStatus < 300) {
          records[key] = { path, ownerStatus: probe.ownerStatus, anonymousRedirect: probe.anonymousRedirect, anonymous: probe.anonymous,
            predicate: probe.ownerBody === undefined ? null : recordPredicate(probe.ownerBody), values: probe.ownerBody === undefined ? [] : recordValues(probe.ownerBody) };
          break;
        }
        const why = `${path} answered identity ${key.toUpperCase()} with ${probe.ownerStatus ?? 'no response'}, so it is not a record that identity can open`;
        if (!interactive || o[flag] !== undefined || attempt >= 2) throw new InitError('record', why);
        say(`      ${why}.`);
        path = await required(flag, prompt);
      }
    }
    clock.stamp('records-probed');
    say(`      Records: A ${records.a.path} (${records.a.ownerStatus}); ${two ? `B ${records.b.path} (${records.b.ownerStatus})` : `foreign ${records.b.path}`}.`);
    // No record value or record predicate may be, hold or sit inside a credential (an app that echoes the session token
    // as a record id would otherwise put it into the profile).
    const credentialish = v => [...secrets].some(secret => secret && (v === secret || v.includes(secret) || (v.length >= 8 && secret.includes(v))));
    for (const record of Object.values(records)) {
      if (Array.isArray(record.values)) record.values = record.values.filter(v => !credentialish(v));
      if (record.predicate && typeof record.predicate.value === 'string' && credentialish(record.predicate.value)) record.predicate = null;
    }
    // Each tenant's own record values, without any value both records carry (a shared value tells no tenant apart).
    if (two) {
      const reading = v => v.toLowerCase().replace(/[^a-z0-9]/g, '');
      const shared = new Set(records.a.values.map(reading).filter(r => records.b.values.map(reading).includes(r)));
      for (const key of ['a', 'b']) records[key].values = records[key].values.filter(v => !shared.has(reading(v)));
    }
    // The prohibited reads, once each, so the profile judges each the way the app refuses it (a status, or a 2xx with
    // the other tenant's values filtered out). GET only, under the confirmed record.
    const reads = { anonReadsA: records.a.anonymous };
    if (two) reads.bReadsA = await probeAs(prober, records.a.path, { slot: whoami.slot, value: identities[1].value });
    reads.aReadsB = await probeAs(prober, records.b.path, { slot: whoami.slot, value: identities[0].value });
    const leaks = [];
    for (const [name, read, ownerValues] of [['B reading A\'s record', reads.bReadsA, records.a.values], ['A reading B\'s record', two ? reads.aReadsB : null, records.b.values], ['a signed-out read of A\'s record', reads.anonReadsA, records.a.values]]) {
      if (!read || !(read.status >= 200 && read.status < 300)) continue;
      const text = JSON.stringify(read.body ?? null);
      const shownValues = (ownerValues ?? []).filter(v => text.includes(v));
      if (shownValues.length) { read.leaked = true; leaks.push(name); say(`      Candidate FAIL before the run: ${name} answered ${read.status} with ${shownValues.length} of the owner's record value${shownValues.length === 1 ? '' : 's'}; its check expects a refusal, so the run decides it.`); }
    }

    // 3. Profile, twins, observers, inference drafts.
    say('[4/6] Writing the starter profile.');
    const { profile, twins, judged } = buildProfile({ id, name: `${id} (local copy)`, origin, whoami: { path: whoami.path, pointer: whoami.pointer, status: whoami.status }, records, reads, slot: whoami.slot,
      identities: identities.map(i => ({ principalId: i.principalId, credentialEnv: i.credentialEnv, identityValue: i.identityValue })), signInRedirectStatus: records.a.anonymousRedirect });
    const manifest = { schemaVersion: 1, targets: [profile] };
    try { validateTargetFile(manifest); } catch (error) { throw new InitError('profile', `the drafted profile does not validate (${String(error?.message ?? error).slice(0, 300)}); nothing was written for it`); }
    await writePrivate(files.profile, `${JSON.stringify(manifest, null, 2)}\n`, o['--force']);
    clock.stamp('profile-written', { checks: profile.checks.length });
    say(`      ${shown(files.profile)}: ${profile.checks.length} GET checks, ${twins.length} prohibitions each with its allowed-use twin where one exists.`);
    const HOW = { 'empty-list': 'an empty list, so it must stay empty', null: 'null, so it must stay null', content: 'a body without the owner\'s values, so it is judged by the other tenant\'s values' };
    for (const [checkId, how] of Object.entries(judged)) {
      if (HOW[how]) say(`      ${checkId}: answered 2xx with ${HOW[how]} (judged by content, not status).`);
      if (how === 'refusal-unjudged-2xx') say(`      Note: ${checkId} answered 2xx during discovery with a body one identity cannot judge; it expects a refusal status. Review its row, or add a second identity.`);
    }

    // Observer candidates come from the app's .env (--app-env). Without one, this shell's names are listed as a hint,
    // labelled: they may be the operator's own tools' settings, and init asks about none of them.
    const SHELL = 'this shell (may be your own tools\' settings, not the app\'s; give --app-env for the app\'s)';
    const candidates = o['--app-env'] ? observerCandidates(appNames).map(c => ({ ...c, source: 'the app .env' }))
      : observerCandidates(environmentNames(env)).map(c => ({ ...c, source: SHELL }));
    const accepted = [];
    for (const c of candidates) {
      say(`      Observer candidate: ${c.observer} from ${c.names.join(', ')} in ${c.source} (${c.why}).`);
      const name = c.names[0];
      const consent = o['--use-observer'].includes(name) || (interactive && c.source !== SHELL && o['--use-observer'].length === 0
        && String(await askRaw('--use-observer', `Use ${name}'s value to check it points at loopback? It is read in memory only and never written. yes/no`, 'no')).toLowerCase() === 'yes');
      if (!consent) continue;
      const loop = c.source !== SHELL || env[name] === undefined ? null : pointsAtLoopback(env[name]);
      say(`        ${name}: ${loop === null ? 'not set in this environment (names from the app .env are names only)' : loop ? 'points at loopback' : 'does NOT point at loopback; observe a local copy only'}.`);
      accepted.push(c);
    }
    const drafts = observerDrafts(id, accepted);
    await writePrivate(files.observers, `${JSON.stringify({ note: 'Placeholders only; no environment value is written here. Fill them in, move the observer into targets.json, add its tcp:// endpoint to the authorization record, and add effect assertions (docs/ONBOARDING.md).', candidates, drafts }, null, 2)}\n`, o['--force']);

    let policy = null;
    if (o['--openapi']) {
      policy = await openApiDraft(resolve(here, o['--openapi']), profile);
      await writePrivate(files.policy, `${JSON.stringify(policy, null, 2)}\n`, o['--force']);
      say(`      OpenAPI: ${policy.draft.checks.length} GET checks drafted, ${policy.draft.notDrafted.length} not drafted, unconfirmed in ${shown(files.policy)} (confirm with ./scopehaven policy confirm).`);
    }
    const laneD = await laneDDrafts({ profile, openapi: o['--openapi'] ? resolve(here, o['--openapi']) : undefined, session, ...(hooksRoot ? { root: hooksRoot } : {}) });
    const available = laneD.filter(m => m.available);
    // Hooks reopen the session file by path; a file swapped after init checked it withholds every proposal and every
    // hook error text, since those could hold the other file's credentials.
    const swapped = Boolean(session) && !(await sessionUnchanged(session, sessionIdentity));
    if (swapped) say('      The session file changed while the hooks read it, so no proposal or hook error is shown or written.');
    // A hook's error text can quote the input it failed on: the full text is checked, then a shortened form printed.
    const errorText = m => (swapped || holdsSecret(m.error, secrets) ? 'error withheld: it may hold a credential value' : m.error.slice(0, 300));
    say(`      Inference: ${available.length ? available.map(m => `${m.module} ${m.error ? `failed (${errorText(m)})` : `${m.checks.length} drafted`}`).join('; ') : 'not available yet (hook left in integrations/init/hooks.mjs)'}.`);
    // Proposals are written only when they hold no credential value from the env file or the session file.
    const proposals = available.filter(m => !m.error).map(m => swapped ? { module: m.module, withheld: 'the session file changed after init checked it, so it was not written' } : holdsSecret(m, secrets)
      ? { module: m.module, withheld: 'its output held a credential value or the path from the env file or the session file, so it was not written' }
      : { module: m.module, confirmed: false, checks: m.checks, notDrafted: m.notDrafted, warnings: m.warnings, ...(m.draft !== undefined ? { draft: m.draft } : {}), ...(m.binding !== undefined ? { binding: m.binding } : {}), ...(m.confirm ? { confirm: m.confirm } : {}) });
    for (const p of proposals.filter(p => p.withheld)) say(`      ${p.module}: not written (${p.withheld}).`);
    if (proposals.some(p => !p.withheld && p.checks.length)) say(`      Inference proposals, unconfirmed: ${shown(files.inference)} (a named person confirms them; init never merges them).`);
    if (proposals.length) await writePrivate(files.inference, `${JSON.stringify({ schema: 'scopehaven-init-inference/0', session: session ? 'given (path not recorded)' : 'none', proposals }, null, 2)}\n`, o['--force']);
    const report = { schema: 'scopehaven-init-report/0', target: id, origin, credentialSlot: slotLabel(whoami.slot), whoami: { path: whoami.path, pointer: whoami.pointer }, loginRoutes: login.found,
      identities: identities.map(i => ({ alias: i.alias, principalId: i.principalId, credentialEnv: i.credentialEnv })),
      records: Object.fromEntries(Object.entries(records).map(([k, r]) => [k, { path: r.path, ownerStatus: r.ownerStatus, recordPredicate: r.predicate?.pointer ?? null, declaredValues: r.values?.length ?? 0 }])),
      prohibitions: judged, candidateFails: leaks, chatRoutes: chat, twins, observerCandidates: candidates.map(c => ({ observer: c.observer, names: c.names, source: c.source })),
      openapi: policy ? { drafted: policy.draft.checks.length, notDrafted: policy.draft.notDrafted.length } : null, laneD: laneD.map(m => ({ module: m.module, available: m.available })), session: Boolean(session), probeRequests: prober.sent() };
    await writePrivate(files.report, `${JSON.stringify({ ...report, timing: clock.snapshot() }, null, 2)}\n`, o['--force']);

    if (o['--no-run']) { say('Stopped after writing (--no-run).'); printNext(say, shown, files, credentials.keys, id, envFile); return 0; }

    // 4. check-config, roe check, starter assessment.
    const childEnv = { ...env, ...Object.fromEntries(identities.map(i => [i.credentialEnv, i.value])) };
    say('[5/6] check-config and roe check.');
    const config = await runChild(join(ROOT, 'src/cli.mjs'), ['--check-config', '--config', files.profile], childEnv);
    const configJson = lastJson(config.stdout);
    const target = configJson?.targets?.find(t => t.id === id);
    if (config.code !== 0 || !target) throw new InitError('check-config', `check-config refused the profile: ${(config.stderr || config.stdout).split('\n').find(Boolean)?.slice(0, 400) ?? 'no output'}`);
    say(`      check-config: configuration valid, ${target.checks} checks, credentials ${target.credentialsReady ? 'ready' : `missing (${(target.missingCredentialRefs ?? []).join(', ')})`}.`);
    const roe = await runChild(join(ROOT, 'integrations/roe/cli.mjs'), ['check', files.record, '--config', files.profile, '--target', id], childEnv);
    const roeJson = lastJson(roe.stdout) ?? lastJson(roe.stderr);
    if (roe.code !== 0) throw new InitError('roe', `roe check refused the run (${roeJson?.code ?? 'unknown'}): ${roeJson?.message ?? ''}`);
    say(`      roe check: authorized until ${roeJson.validUntil}.`);
    clock.stamp('config-checked');

    say('[6/6] Starter assessment.');
    const assess = await runChild(join(ROOT, 'src/cli.mjs'), ['--config', files.profile, '--target', id, '--authorization', files.record, '--out', files.evidence], childEnv);
    const assessJson = lastJson(assess.stdout);
    if (!assessJson?.id) throw new InitError('assess', `the assessment did not save a run: ${(assess.stderr || assess.stdout).split('\n').find(Boolean)?.slice(0, 400) ?? 'no output'}`);
    const runFile = join(files.evidence, 'runs', `${assessJson.id}.json`);
    const run = JSON.parse(await readFile(runFile, 'utf8'));
    const summary = summarizeRun(run.core);
    clock.runSaved(assessJson.id, summary);
    // The report again, now with the starter run and this run's timing (init's own file from this same run).
    try { await writePrivate(files.report, `${JSON.stringify({ ...report, starterRun: { id: assessJson.id, counts: summary.counts, failChecks: summary.failIds }, timing: clock.snapshot() }, null, 2)}\n`, true); }
    catch { say(`      Note: ${shown(files.report)} was not updated with the starter run; the run and its exit status are unaffected.`); }
    say(`      Run ${assessJson.id}: ${summary.counts.FAIL} FAIL, ${summary.counts.INCONCLUSIVE} INCONCLUSIVE, ${summary.counts['not exercised']} not exercised. Scope: ${assessJson.scope}`);
    say('');
    for (const line of formatFirstRow(summary.first)) say(line);
    say(`  run file: ${shown(runFile)}`);
    say(`  profile:  ${shown(files.profile)}`);
    say('');
    printNext(say, shown, files, credentials.keys, id, envFile);
    // A FAIL row is a finding: the exit status says so, as assess's does, apart from init's own errors (3).
    if (summary.counts.FAIL) say(`Exit 1: the starter run has ${summary.counts.FAIL} FAIL row${summary.counts.FAIL === 1 ? '' : 's'}.`);
    return summary.counts.FAIL ? 1 : 0;
  } catch (error) {
    const known = error instanceof InitError || error?.name === 'AuthorizationError';
    clock.stopped(known ? error.code : 'error');
    stdout.write(`init stopped (${known ? error.code : 'error'}): ${known ? error.message : String(error?.message ?? error).slice(0, 300)}\n`);
    // 2: stopped before any request reached the app; 3: could not finish after requests were sent.
    return !prober || prober.sent() === 0 ? 2 : 3;
  } finally { rl?.close(); }
}

// Commands to copy. Absolute paths: the launcher changes into the project folder before it runs anything.
function printNext(say, shown, files, keys, id, envFile) {
  const q = path => (/\s/.test(path) ? `'${path}'` : path);
  say('Next:');
  say(`  rerun the assessment: set -a; . ${q(envFile)}; set +a; ${q(join(ROOT, 'scopehaven'))} assess --config ${q(files.profile)} --target ${id} --authorization ${q(files.record)}`);
  say(`  add an observer so backend rows can be decided: ${shown(files.observers)} and docs/ONBOARDING.md ("Observe what the app recorded")`);
  say(`  credentials referenced: ${keys.join(', ')} (from your env file; never written by init)`);
}

// The help text is this file's header comment, so it lists every option and the exit status.
const HELP = () => {
  const lines = readFileSync(fileURLToPath(import.meta.url), 'utf8').split('\n');
  const end = lines.findIndex(line => !line.startsWith('//'));
  return lines.slice(0, end).map(line => line.replace(/^\/\/ ?/, '')).join('\n').trimEnd();
};

const invokedDirectly = () => { try { return realpathSync(resolve(process.argv[1])) === realpathSync(fileURLToPath(import.meta.url)); } catch { return false; } };
if (process.argv[1] && invokedDirectly()) process.exitCode = await main(process.argv.slice(2));
