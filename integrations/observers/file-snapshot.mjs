// File snapshot, report-only in this version.
// Lists the files an application writes under declared roots at two points of a run and reports what was added, changed or
// removed between them. It is not an observer of the effect rules: it makes no window, no effect event and no verdict, so a
// declared `files` channel still reads not observed (docs/KNOWN-LIMITS.md) and every row reads as it did without it. The
// report sits beside a run, never inside it, so no sealed record, run digest or evaluator identity changes.
//
// files.json: { "roots": [{ "alias": "exports", "path": "/abs/dir" }], "exclude"?: ["*.tmp", "cache/**"],
//               "maxFiles"?: 20000, "maxFileBytes"?: 67108864 }
// - A root is an absolute path to a directory that is not itself a symlink. Aliases are plain identifiers, and resources
//   read `<alias>/<path under the root>`.
// - The walk never follows a symlink: a symlink is listed by a digest of its link text, never by its target's content.
//   Only regular files are read (opened without following links and without blocking, then checked to still be a regular
//   file), so a FIFO, socket or device is listed as present and never opened.
// - Content is read into a sha256 digest, never kept. A file read while it changes (its size, mtime or inode differs before and after)
//   is read again, up to 3 times; then the snapshot fails (`no-consistent-read`) rather than report a torn state.
// - Bounds: 1 to 16 roots, up to 32 exclude patterns, maxFiles (1 to 100000) across all roots, maxFileBytes (1 to 1 GiB) per
//   file, 64 directory levels. Past a bound the snapshot fails with its reason (`file-limit`, `file-too-large`, `too-deep`).
// - Net-only: a file written and removed between the two snapshots is not seen.
import { lstatSync, readdirSync, readlinkSync, openSync, readSync, fstatSync, closeSync, constants } from 'node:fs';
import { createHash } from 'node:crypto';
import { isAbsolute, join, resolve } from 'node:path';

export const FILE_SNAPSHOT_SCHEMA = 'scopehaven-file-report/1';
export const FILE_SNAPSHOT_LIMITS = Object.freeze({ roots: 16, exclude: 32, maxFiles: 100000, maxFileBytes: 1024 * 1024 * 1024, depth: 64, changes: 1000, readAttempts: 3,
  defaultMaxFiles: 20000, defaultMaxFileBytes: 64 * 1024 * 1024 });
const ALIAS = /^[A-Za-z_][A-Za-z0-9_-]{0,63}$/;
const KEYS = ['exclude', 'maxFileBytes', 'maxFiles', 'roots'];

// A glob over the path under a root: `**` any run of characters, `*` and `?` within one path segment.
function globRegex(pattern) {
  let out = '';
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i];
    if (c === '*' && pattern[i + 1] === '*') { out += '.*'; i++; if (pattern[i + 1] === '/') i++; }
    else if (c === '*') out += '[^/]*';
    else if (c === '?') out += '[^/]';
    else out += c.replace(/[\\^$.|+()[\]{}]/g, '\\$&');
  }
  return new RegExp(`^${out}$`);
}

export function validateFileSnapshotConfig(config) {
  const bad = reason => { throw new Error(`files.json: ${reason}.`); };
  if (!config || typeof config !== 'object' || Array.isArray(config)) bad('must be an object');
  for (const key of Object.keys(config)) if (!KEYS.includes(key)) bad(`unknown key "${String(key).slice(0, 40)}"`);
  const { roots, exclude = [], maxFiles = FILE_SNAPSHOT_LIMITS.defaultMaxFiles, maxFileBytes = FILE_SNAPSHOT_LIMITS.defaultMaxFileBytes } = config;
  if (!Array.isArray(roots) || !roots.length || roots.length > FILE_SNAPSHOT_LIMITS.roots) bad(`roots lists 1 to ${FILE_SNAPSHOT_LIMITS.roots} directories`);
  const aliases = new Set(), paths = new Set();
  for (const root of roots) {
    if (!root || typeof root !== 'object' || Object.keys(root).sort().join(',') !== 'alias,path') bad('each root is exactly { "alias", "path" }');
    if (typeof root.alias !== 'string' || !ALIAS.test(root.alias) || aliases.has(root.alias)) bad('each root alias is a distinct identifier (letters, digits, "_" or "-", up to 64)');
    if (typeof root.path !== 'string' || !isAbsolute(root.path) || root.path.includes('\0')) bad(`root "${root.alias}" needs an absolute path`);
    let st;
    try { st = lstatSync(root.path); } catch { bad(`root "${root.alias}" is not a readable directory`); }
    if (st.isSymbolicLink() || !st.isDirectory()) bad(`root "${root.alias}" must be a directory, not a symlink`);
    const full = resolve(root.path);
    for (const other of paths) if (full === other || full.startsWith(`${other}/`) || other.startsWith(`${full}/`)) bad(`root "${root.alias}" overlaps another root`);
    aliases.add(root.alias); paths.add(full);
  }
  if (!Array.isArray(exclude) || exclude.length > FILE_SNAPSHOT_LIMITS.exclude || !exclude.every(p => typeof p === 'string' && p.length >= 1 && p.length <= 200 && !p.startsWith('/'))) bad(`exclude lists up to ${FILE_SNAPSHOT_LIMITS.exclude} relative patterns`);
  if (!Number.isInteger(maxFiles) || maxFiles < 1 || maxFiles > FILE_SNAPSHOT_LIMITS.maxFiles) bad(`maxFiles is an integer from 1 to ${FILE_SNAPSHOT_LIMITS.maxFiles}`);
  if (!Number.isInteger(maxFileBytes) || maxFileBytes < 1 || maxFileBytes > FILE_SNAPSHOT_LIMITS.maxFileBytes) bad(`maxFileBytes is an integer from 1 to ${FILE_SNAPSHOT_LIMITS.maxFileBytes}`);
  return Object.freeze({ roots: roots.map(r => Object.freeze({ alias: r.alias, path: resolve(r.path) })), exclude: [...exclude], excludeRe: exclude.map(globRegex), maxFiles, maxFileBytes });
}

class SnapshotFailure extends Error { constructor(reason) { super(reason); this.reason = reason; } }
const sameStat = (a, b) => a.size === b.size && a.mtimeNs === b.mtimeNs && a.ino === b.ino;

// One regular file's digest, read without following a link and without blocking; null when it changed while read.
function hashFile(path, maxFileBytes) {
  const before = lstatSync(path, { bigint: true });
  if (!before.isFile()) return { changed: true };
  if (before.size > BigInt(maxFileBytes)) throw new SnapshotFailure('file-too-large');
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const opened = fstatSync(fd, { bigint: true });
    if (!opened.isFile() || !sameStat(before, opened)) return { changed: true };
    const hash = createHash('sha256'), buf = Buffer.alloc(1024 * 1024);
    let n, total = 0;
    while ((n = readSync(fd, buf, 0, buf.length, null)) > 0) { hash.update(buf.subarray(0, n)); total += n; if (total > maxFileBytes) throw new SnapshotFailure('file-too-large'); }
    const after = lstatSync(path, { bigint: true });
    if (!sameStat(before, after) || BigInt(total) !== after.size) return { changed: true };
    return { size: total, sha256: hash.digest('hex') };
  } finally { closeSync(fd); }
}

// A snapshot: { ok: true, at, entries: Map(resource -> { type, size?, sha256 }) } or { ok: false, at, reason }.
export function takeFileSnapshot(config) {
  const at = new Date().toISOString(), entries = new Map();
  const excluded = rel => config.excludeRe.some(re => re.test(rel));
  try {
    for (const root of config.roots) {
      const walk = (dir, rel, depth) => {
        if (depth > FILE_SNAPSHOT_LIMITS.depth) throw new SnapshotFailure('too-deep');
        let names;
        try { names = readdirSync(dir).sort(); } catch { throw new SnapshotFailure('unreadable'); }
        for (const name of names) {
          const childRel = rel ? `${rel}/${name}` : name, path = join(dir, name);
          if (excluded(childRel)) continue;
          let st;
          try { st = lstatSync(path); } catch (error) { if (error.code === 'ENOENT') continue; throw new SnapshotFailure('unreadable'); }
          if (st.isDirectory()) { walk(path, childRel, depth + 1); continue; }
          if (entries.size >= config.maxFiles) throw new SnapshotFailure('file-limit');
          const resource = `${root.alias}/${childRel}`;
          if (st.isSymbolicLink()) { let text = ''; try { text = readlinkSync(path); } catch {} entries.set(resource, { type: 'symlink', sha256: createHash('sha256').update(text).digest('hex') }); continue; }
          if (!st.isFile()) { entries.set(resource, { type: 'special', sha256: null }); continue; }
          let read = { changed: true };
          for (let attempt = 0; attempt < FILE_SNAPSHOT_LIMITS.readAttempts && read.changed; attempt++) {
            try { read = hashFile(path, config.maxFileBytes); } catch (error) { if (error instanceof SnapshotFailure) throw error; if (error.code === 'ENOENT') { read = null; break; } throw new SnapshotFailure('unreadable'); }
          }
          if (read === null) continue; // removed while the walk ran: absent at this snapshot
          if (read.changed) throw new SnapshotFailure('no-consistent-read');
          entries.set(resource, { type: 'file', size: read.size, sha256: read.sha256 });
        }
      };
      walk(root.path, '', 0);
    }
  } catch (error) {
    if (error instanceof SnapshotFailure) return { ok: false, at, reason: error.reason };
    throw error;
  }
  return { ok: true, at, entries };
}

// The report of two snapshots: what was added, changed or removed (net), bounded, with no file content.
export function fileReport(config, start, end, { sequenceId = null, runFile = null } = {}) {
  const base = { schema: FILE_SNAPSHOT_SCHEMA, reportOnly: true,
    note: 'Report only: these file changes are not a verdict, decide no check, and do not make a files channel observed. Net change between two snapshots: a file written and removed between them is not listed.',
    sequenceId, runFile, roots: config.roots.map(r => r.alias), exclude: config.exclude,
    start: { at: start.at, ok: start.ok, ...(start.ok ? { files: start.entries.size } : { reason: start.reason }) },
    end: { at: end.at, ok: end.ok, ...(end.ok ? { files: end.entries.size } : { reason: end.reason }) } };
  if (!start.ok || !end.ok) return { ...base, coverage: 'failed', changes: [], omitted: 0 };
  const changes = [];
  for (const [resource, now] of end.entries) {
    const was = start.entries.get(resource);
    if (!was) changes.push({ operation: 'insert', resource, type: now.type, ...(now.size !== undefined ? { size: now.size } : {}), sha256: now.sha256 });
    else if (was.type !== now.type || was.sha256 !== now.sha256) changes.push({ operation: 'update', resource, type: now.type, ...(now.size !== undefined ? { size: now.size } : {}), sha256: now.sha256 });
  }
  for (const [resource, was] of start.entries) if (!end.entries.has(resource)) changes.push({ operation: 'delete', resource, type: was.type, sha256: was.sha256 });
  return { ...base, coverage: 'net-only', changes: changes.slice(0, FILE_SNAPSHOT_LIMITS.changes), omitted: Math.max(0, changes.length - FILE_SNAPSHOT_LIMITS.changes) };
}
