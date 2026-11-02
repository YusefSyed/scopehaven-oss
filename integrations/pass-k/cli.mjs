#!/usr/bin/env node
// pass^k command line, local files only:
//   annotate --sarif ABS_IN --out ABS_NEW --k K (--gate ABS_GATE_JSON | --run ABS_RUN_JSON)
//     writes a copy of a Scopehaven SARIF log with the pass^k column added: the
//     column of a schema-2 gate summary (same k, same run), or the column of one
//     saved run (store record {core, sha256}, or `scopehaven export --format json`).
//   column --run ABS_RUN_JSON --k K
//     prints the pass^k column of one saved run.
// The new file is at most 8 MiB, as src/export-cli.mjs allows, and is written
// exclusively (O_CREAT|O_EXCL|O_NOFOLLOW, mode 0600) and published with a hard link,
// so an existing file is never overwritten. Its parent must be private (mode 0700,
// owned by this user, not a symlink), as src/export-cli.mjs requires. Inputs are
// bounded regular files opened without following a symlink and without blocking (a
// FIFO is refused at once), and a run's sha256 is checked before use. Any error
// prints one fixed code and exits 2. No target is run, no environment variable is
// read and no network call is made; the output names no local path.
import { constants } from 'node:fs';
import { lstat, open, link, unlink } from 'node:fs/promises';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createHash, randomUUID } from 'node:crypto';
import { digest } from '../../src/domain.mjs';
import { PassKError, PASS_K_ERRORS, PASS_K_MAX, normalizePassK, sarifWithPassK, singleRunColumn } from './passk.mjs';

export const CLI_ERRORS = Object.freeze(['invalid-options', 'input-unreadable', 'invalid-sarif', 'invalid-gate', 'invalid-run', 'k-mismatch', 'output-directory-not-private', 'output-exists', 'output-write-error', 'output-too-large']);
const MAX_INPUT_BYTES = 8 * 1024 * 1024;
const MAX_OUTPUT_BYTES = 8 * 1024 * 1024;
const COMMANDS = Object.freeze({ annotate: ['--sarif', '--out', '--k', '--gate', '--run'], column: ['--run', '--k'] });
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const need = (ok, code) => { if (!ok) throw new PassKError(code); };
const codeOf = error => error instanceof PassKError && (CLI_ERRORS.includes(error.code) || PASS_K_ERRORS.includes(error.code)) ? `pass-k-${error.code}` : 'pass-k-invalid';

function parse(argv) {
  need(Array.isArray(argv) && argv.length >= 1 && Object.hasOwn(COMMANDS, argv[0]), 'invalid-options');
  const command = argv[0], flags = COMMANDS[command], options = {};
  for (let i = 1; i < argv.length; i += 2) {
    const flag = argv[i], value = argv[i + 1];
    need(flags.includes(flag) && !Object.hasOwn(options, flag) && typeof value === 'string' && value.length > 0 && !value.startsWith('--'), 'invalid-options');
    options[flag] = value;
  }
  const required = command === 'annotate' ? ['--sarif', '--out', '--k'] : ['--run', '--k'];
  need(required.every(flag => Object.hasOwn(options, flag)), 'invalid-options');
  if (command === 'annotate') need(Object.hasOwn(options, '--gate') !== Object.hasOwn(options, '--run'), 'invalid-options');
  need(Object.keys(options).every(flag => flag === '--k' || isAbsolute(options[flag])), 'invalid-options');
  need(/^[1-9][0-9]{0,2}$/.test(options['--k']) && Number(options['--k']) <= PASS_K_MAX, 'invalid-k');
  return { command, k: Number(options['--k']), sarif: options['--sarif'], out: options['--out'], gate: options['--gate'], run: options['--run'] };
}

async function readJson(path, code) {
  let handle;
  try {
    // O_NONBLOCK: opening a FIFO never waits for a writer; fstat then refuses it.
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    need((await handle.stat()).isFile(), 'input-unreadable');
    const chunks = [], buffer = Buffer.alloc(65536); let size = 0;
    while (true) {
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, size);
      if (!bytesRead) break;
      size += bytesRead; need(size <= MAX_INPUT_BYTES, 'input-unreadable');
      chunks.push(Buffer.from(buffer.subarray(0, bytesRead)));
    }
    try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { throw new PassKError(code); }
  } catch (error) { if (error instanceof PassKError) throw error; throw new PassKError('input-unreadable'); }
  finally { await handle?.close(); }
}

// A store record { core, sha256 }, or an exported run (store.get output with its integrity block).
function runFrom(input) {
  if (object(input) && object(input.core)) {
    need(typeof input.sha256 === 'string' && digest(input.core) === input.sha256, 'invalid-run');
    return input.core;
  }
  need(object(input) && object(input.integrity), 'invalid-run');
  const { integrity, notes, ...core } = input;
  need(typeof integrity.sha256 === 'string' && digest(core) === integrity.sha256, 'invalid-run');
  return core;
}

async function writeExclusive(path, text) {
  let stat;
  try { stat = await lstat(dirname(path)); } catch { throw new PassKError('output-directory-not-private'); }
  need(stat.isDirectory() && !stat.isSymbolicLink() && stat.uid === process.getuid() && (stat.mode & 0o7777) === 0o700, 'output-directory-not-private');
  const temporary = join(dirname(path), `.${randomUUID()}.pass-k.tmp`);
  try {
    let handle;
    try { handle = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600); }
    catch { throw new PassKError('output-write-error'); }
    // A write, sync or close failure (a full disk, a file size limit) is an output write error.
    try { try { await handle.writeFile(text); await handle.sync(); } finally { await handle.close(); } } catch { throw new PassKError('output-write-error'); }
    // Exclusive publication: link never replaces an existing file.
    try { await link(temporary, path); } catch (error) { throw new PassKError(error.code === 'EEXIST' ? 'output-exists' : 'output-write-error'); }
  } finally { await unlink(temporary).catch(() => {}); }
}

export async function main(argv, { stdout = process.stdout } = {}) {
  try {
    const options = parse(argv);
    if (options.command === 'column') {
      const column = singleRunColumn(runFrom(await readJson(options.run, 'invalid-run')), options.k);
      stdout.write(`${JSON.stringify(column, null, 2)}\n`);
      return 0;
    }
    let column;
    if (options.gate !== undefined) {
      const gate = await readJson(options.gate, 'invalid-gate');
      need(object(gate) && gate.schemaVersion === 2 && object(gate.current), 'invalid-gate');
      column = normalizePassK(gate.current.passK);
      need(column !== null && gate.current.runId === column.runIds[0], 'invalid-gate');
      need(column.k === options.k, 'k-mismatch');
    } else column = singleRunColumn(runFrom(await readJson(options.run, 'invalid-run')), options.k);
    const annotated = sarifWithPassK(await readJson(options.sarif, 'invalid-sarif'), column);
    const content = Buffer.from(`${JSON.stringify(annotated, null, 2)}\n`);
    need(content.length <= MAX_OUTPUT_BYTES, 'output-too-large');
    await writeExclusive(options.out, content);
    stdout.write(`${JSON.stringify({ ok: true, command: 'annotate', k: column.k, source: column.source, runId: column.runIds[0], bytes: content.length, sha256: createHash('sha256').update(content).digest('hex') })}\n`);
    return 0;
  } catch (error) {
    stdout.write(`${JSON.stringify({ ok: false, error: codeOf(error) })}\n`);
    return 2;
  }
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) process.exitCode = await main(process.argv.slice(2));
