// The build a run or a signed file names: producer.release beside evaluatorHash in a run's core, and in a DSSE
// statement's producer. evaluatorHash says which grading rules ran; this says which copy of ScopeHaven ran them, so a reviewer can map
// a result to a release. { source, version, commit, manifestSha256 }, from the first that answers:
//   release-manifest  an install's RELEASE-MANIFEST.json (packaging/build-release.mjs): its version and commit, and the file's sha256
//   git               a checkout's HEAD, and the version in package.json
//   unknown           neither: commit reads 'unknown', and nothing fails
// It is what this copy says about itself, so an edited copy can say anything: ./scopehaven doctor checks a release copy's files against
// the manifest, and a checkout's HEAD says nothing of uncommitted edits. It is read once, when this module loads, because a checkout
// moved later is not the code this process is running. Runs are stamped outside the HTTP, synthetic, conversation and sequence evaluators'
// files, so naming a build moves none of those identities and no contract view digest; two builds of one rule set still compare.
// (src/registry.mjs, the seam, is one of the sources the refund identity digests, as any edit to it is.)
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { closeSync, constants, existsSync, fstatSync, lstatSync, openSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const MANIFEST = 'RELEASE-MANIFEST.json', MANIFEST_SCHEMA = 'scopehaven-release-manifest/1', MANIFEST_LIMIT = 16 * 1024 * 1024;
const UNKNOWN = 'unknown';
const VERSION = /^\d+\.\d+\.\d+$/, COMMIT = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const release = (source, version, commit, manifestSha256) => ({ source, version, commit, manifestSha256 });

// A regular file, never through a symlink; null when it cannot be read as one.
function readRegular(path, limit) {
  let fd;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const stat = fstatSync(fd);
    return stat.isFile() && stat.size <= limit ? readFileSync(fd) : null;
  } catch { return null; } finally { if (fd !== undefined) closeSync(fd); }
}
const present = path => { try { lstatSync(path); return true; } catch { return false; } };

function packageVersion(root) {
  try { const { version } = JSON.parse(readRegular(join(root, 'package.json'), 1024 * 1024)); return VERSION.test(version) ? version : UNKNOWN; } catch { return UNKNOWN; }
}

// HEAD of the checkout holding this folder, or null. git is not started unless a .git sits at or above the folder (on a Mac without the
// Command Line Tools /usr/bin/git only offers an installer), and a copy that repository does not track, unpacked inside somebody's
// project, must not name their commit. GIT_* is dropped so a git hook's GIT_DIR cannot point this at another repository, and fsmonitor is
// off because ls-files would otherwise run the command that repository's config names, at every load of this module.
function checkoutHead(root) {
  for (let dir = root; !existsSync(join(dir, '.git')); dir = dirname(dir)) if (dirname(dir) === dir) return null;
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('GIT_')));
  const git = (...args) => spawnSync('git', ['-c', 'core.fsmonitor=false', ...args], { cwd: root, env, encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'] });
  if (git('ls-files', '--error-unmatch', 'package.json').status !== 0) return null;
  const head = git('rev-parse', '--verify', 'HEAD^{commit}');
  return head.status === 0 && COMMIT.test(head.stdout.trim()) ? head.stdout.trim() : null;
}

// Never throws: a run with no way to name its build still runs, and reads `unknown`.
export function readRelease(root = ROOT) {
  const version = packageVersion(root);
  try {
    // A manifest that is there says this is a release copy, so a broken one reads unknown; it never falls through to some other HEAD.
    if (present(join(root, MANIFEST))) {
      const bytes = readRegular(join(root, MANIFEST), MANIFEST_LIMIT), manifest = bytes && JSON.parse(bytes.toString('utf8'));
      if (manifest?.schema !== MANIFEST_SCHEMA || !VERSION.test(manifest.version) || !COMMIT.test(manifest.commit)) return release(UNKNOWN, version, UNKNOWN, null);
      return release('release-manifest', manifest.version, manifest.commit, createHash('sha256').update(bytes).digest('hex'));
    }
    const head = checkoutHead(root);
    if (head) return release('git', version, head, null);
  } catch {}
  return release(UNKNOWN, version, UNKNOWN, null);
}

export const PRODUCER_RELEASE = Object.freeze(readRelease());

// Stamps a run just produced by this process, in place: pinned families are tracked by object identity. A saved run is never stamped
// again, because it may have been made by another build.
export function stampProducer(run) {
  run.producer = { release: { ...PRODUCER_RELEASE } };
  return run;
}
