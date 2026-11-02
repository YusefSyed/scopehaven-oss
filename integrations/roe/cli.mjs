// The authorization record's two operator steps; it sends no request.
//
//   node integrations/roe/cli.mjs seal DRAFT.json OUT.json
//     Adds the integrity checksum (sha256) to a filled-in draft, validates it and writes a new file
//     (mode 0600; an existing file is never overwritten).
//   node integrations/roe/cli.mjs check RECORD.json --config TARGETS.json --target ID [--at ISO_INSTANT] [--wait-url URL]
//     The check assess, the gate and the dashboard make before a run of that configured target: the target, every
//     endpoint the run contacts (with the owned model tap's upstream when SCOPEHAVEN_MODEL_TAP_UPSTREAM is set, as
//     those runs count it), every credentialed actor and the window (now, or --at, read as the record's instants are).
//     --wait-url: the GitHub Action's readiness URL, which its wait contacts before the run; its origin (localhost is
//     dialled as 127.0.0.1) must be one of the record's origins, or the check refuses it (authorization-origin).
//     Prints the stamp and the end of the window (validUntil, so the GitHub Action's wait stops sending when it ends)
//     and exits 0, or prints the refusal code and exits 2. A refusal never prints a field value or a path. A
//     sequence's hold-gate upstream is not known here: the sequence command checks it.
//
// The checksum is unkeyed: it shows an edit made without recomputing it. It is not a signature.
import { constants, realpathSync } from 'node:fs';
import { open } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { checksumAuthorization, checkAuthorization, validateAuthorization, instantMs, AuthorizationError } from '../../src/authorization.mjs';
import { parseLoopbackUrl } from '../github-action/wait-for.mjs';
import { readAuthorizationFile } from '../../src/authorization-file.mjs';
import { loadProfiles } from '../../src/registry.mjs';
import { ownedTapConfig } from '../../src/http-model-identity.mjs';

const USAGE = 'Usage: cli.mjs seal DRAFT.json OUT.json | check RECORD.json --config TARGETS.json --target ID [--at ISO_INSTANT] [--wait-url URL]';
// The check's options after the record: each named at most once, each with a value that is not another option.
const CHECK_OPTIONS = ['--config', '--target', '--at', '--wait-url'];
const checkOptions = args => {
  const options = {};
  for (let i = 0; i < args.length; i += 2) {
    const name = args[i], value = args[i + 1];
    if (!CHECK_OPTIONS.includes(name) || Object.hasOwn(options, name) || typeof value !== 'string' || value.startsWith('--')) return null;
    options[name] = value;
  }
  return options['--config'] && options['--target'] ? options : null;
};
export async function main(argv, { stdout = process.stdout, stderr = process.stderr, env = process.env } = {}) {
  const [command, ...rest] = argv;
  try {
    if (command === 'seal' && rest.length === 2) {
      const sealed = checksumAuthorization(await readAuthorizationFile(resolve(rest[0])));
      validateAuthorization(sealed);
      let handle;
      try { handle = await open(resolve(rest[1]), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600); }
      catch { throw new AuthorizationError('authorization-io', 'the output file could not be created (an existing file is never overwritten)'); }
      try { await handle.writeFile(`${JSON.stringify(sealed, null, 2)}\n`); } finally { await handle.close(); }
      stdout.write(`${JSON.stringify({ sealed: true, id: sealed.id, sha256: sealed.sha256 }, null, 2)}\n`);
      return 0;
    }
    const options = command === 'check' && typeof rest[0] === 'string' && !rest[0].startsWith('--') ? checkOptions(rest.slice(1)) : null;
    if (options) {
      const record = await readAuthorizationFile(resolve(rest[0]));
      let profiles;
      try { profiles = await loadProfiles(resolve(options['--config'])); }
      catch { throw new AuthorizationError('authorization-io', 'the target configuration could not be read or is invalid'); }
      const profile = profiles.find(target => target.id === options['--target']);
      if (!profile) throw new AuthorizationError('authorization-target', 'the configuration has no target with that id');
      // --at is read as the record's own instants are: a real calendar instant (an invalid one is authorization-clock).
      const now = options['--at'] === undefined ? new Date() : new Date(instantMs(options['--at']));
      const stamp = checkAuthorization(record, profile, { now, alsoContacts: [ownedTapConfig(env)?.upstream].filter(upstream => upstream !== undefined) });
      // The Action's wait contacts --wait-url before the run, so the record must cover its origin too.
      if (options['--wait-url'] !== undefined) {
        let waitOrigin;
        try { waitOrigin = `http://127.0.0.1:${parseLoopbackUrl(options['--wait-url']).port}`; }
        catch { throw new AuthorizationError('authorization-origin', 'the wait URL is not a loopback URL the wait can use, so the record cannot cover it'); }
        if (!validateAuthorization(record).origins.includes(waitOrigin)) throw new AuthorizationError('authorization-origin', 'the wait URL\'s origin is not one the record allows: the wait would contact an endpoint the record does not cover');
      }
      stdout.write(`${JSON.stringify({ authorized: true, at: now.toISOString(), validUntil: validateAuthorization(record).validUntil, stamp }, null, 2)}\n`);
      return 0;
    }
    stderr.write(`${USAGE}\n`);
    return 2;
  } catch (error) {
    const known = error instanceof AuthorizationError;
    stderr.write(`${JSON.stringify({ authorized: false, code: known ? error.code : 'authorization-io', message: known ? error.message : 'a file could not be read or written' })}\n`);
    return 2;
  }
}
// Run as a script, compared by real path: under a symlinked path (on macOS /var is a link to /private/var) the module's
// URL is the real one, and a string comparison would skip main and exit 0 without checking anything.
const invokedDirectly = () => { try { return realpathSync(resolve(process.argv[1])) === realpathSync(fileURLToPath(import.meta.url)); } catch { return false; } };
if (process.argv[1] && invokedDirectly()) process.exitCode = await main(process.argv.slice(2));
