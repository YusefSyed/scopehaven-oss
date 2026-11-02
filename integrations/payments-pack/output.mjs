// Writing a payments run: <run-id>.json and <run-id>.html, created exclusively (an existing file is never replaced).
// Exporting a saved one: json, html or sarif, signed by default exactly as `scopehaven export` signs (src/export-cli.mjs).
import { open, mkdir, writeFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import { basename, dirname, isAbsolute, join } from 'node:path';
import { createHash } from 'node:crypto';
import { renderPaymentsReport, renderPaymentsSarif } from './report.mjs';
import { PAYMENTS_RUN_SCHEMA, PAYMENTS_SCOPE, comparePaymentsRuns } from './pack.mjs';
import { digest } from '../../src/domain.mjs';
import { assertRuntime } from '../../src/runtime.mjs';
import { SUBJECT_NAME } from '../attest/verify.mjs';
import { assertExportDirectory, defaultSigningKeyDir, loadSigningKey, publish, sarifSigning, signBeside, stampHtml } from '../../src/export-cli.mjs';

// A missing directory (and any missing parent) is made 0700, whatever the umask; an existing one is kept as it is, never chmodded.
export async function writeRun(directory, run, comparison = null) {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const base = join(directory, run.id);
  await writeFile(`${base}.json`, `${JSON.stringify(comparison ? { ...run, comparison } : run, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  await writeFile(`${base}.html`, renderPaymentsReport(run, comparison), { flag: 'wx', mode: 0o600 });
  return { json: `${base}.json`, html: `${base}.html` };
}
export const summarize = (run, files, comparison) => ({ id: run.id, target: run.targetId, build: run.build, counts: run.counts,
  failed: run.rows.filter(r => r.status !== 'pass').map(r => ({ id: r.id, status: r.status })), authorization: run.authorization, report: files.html, run: files.json,
  ...(comparison ? { comparison: { verdict: comparison.verdict, reason: comparison.reason, rows: comparison.rows.map(({ id, label }) => ({ id, label })) } } : {}), scope: run.scope });

// A pack or a saved run: a regular file, never through a symlink or a FIFO, at most 4 MiB, parsed as JSON (the
// authorization record has its own reader, src/authorization-file.mjs). Errors never echo the file's contents.
const MAX_JSON_BYTES = 4 * 1024 * 1024;
export async function readPaymentsJson(path, what) {
  const unreadable = () => Object.assign(new Error(`${what} is not a readable JSON file (a regular file, not a symlink, at most 4 MiB).`), { exit: 2 });
  let handle;
  try { handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK); } catch { throw unreadable(); }
  try {
    if (!(await handle.stat()).isFile()) throw unreadable();
    // At most one byte past the limit, so an oversized (or growing) file is never read whole.
    const buffer = Buffer.alloc(MAX_JSON_BYTES + 1);
    let length = 0;
    for (let n; length < buffer.length && (n = (await handle.read(buffer, length, buffer.length - length, length)).bytesRead) > 0;) length += n;
    if (length > MAX_JSON_BYTES) throw unreadable();
    try { return JSON.parse(buffer.toString('utf8', 0, length)); } catch { throw unreadable(); }
  } finally { await handle.close(); }
}

// The export of a saved payments run. A run is exported only when it is a payments run whose checksum still matches its body
// (an unkeyed check: it catches a careless edit, not a recomputed one), with exactly a run's fields and the pack's scope, each
// row's status the one the pack's own rules give its assertions, reach and settlement, and counts that are its rows' statuses.
// So a status flipped in the file is refused even when the checksum is recomputed. The export copies every status as saved and
// recomputes none, so it can never upgrade a label. A comparison stored in the run file (`payments run
// --baseline` adds one) is outside that checksum, so it is never exported: with a baseline run, the comparison is recomputed by
// comparePaymentsRuns, which checks both runs' checksums and the pack. Then json is the comparison document and html the report
// with its before-and-after section; sarif is of one run only.
export const PAYMENTS_EXPORT_FORMATS = Object.freeze(['json', 'html', 'sarif']);
export const PAYMENTS_COMPARISON_FORMATS = Object.freeze(['json', 'html']);
export const PAYMENTS_RUN_REFUSED = 'payments-run-refused';
const EXPORT_LIMIT = 8 * 1024 * 1024;
const RUN_ID = /^pay-[0-9]{14}-[0-9a-f]{8}$/, CHECK_ID = /^[A-Za-z0-9_-]{1,64}$/, STATUSES = ['pass', 'fail', 'inconclusive'], ROLES = ['boundary', 'control'];
// Every field runPaymentsPack writes, and no other.
const RUN_FIELDS = ['schema', 'id', 'targetId', 'applicationId', 'name', 'build', 'packSha256', 'startedAt', 'finishedAt', 'scope', 'provider', 'authorization', 'counts', 'rows', 'settlement', 'sha256'];
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
const refused = detail => Object.assign(new Error(`${PAYMENTS_RUN_REFUSED}: ${detail}`), { code: PAYMENTS_RUN_REFUSED });
// The pack's own rule for a row's status (pack.mjs worst): any failed assertion fails it, any undecided one leaves it inconclusive.
const worst = statuses => statuses.includes('fail') ? 'fail' : statuses.includes('inconclusive') ? 'inconclusive' : 'pass';
// A row as runPaymentsPack writes it. Its status is the worst of its assertions'. A pass needs the check request answered
// (otherwise its passes are withheld), and a boundary with a settlement finding is withheld, never a pass (a control keeps
// its verdict and carries a tag). So a status flipped in an edited file, even with the checksum recomputed, is refused.
function readableRow(r) {
  if (!plain(r) || typeof r.id !== 'string' || !CHECK_ID.test(r.id) || !STATUSES.includes(r.status) || !ROLES.includes(r.severity) || typeof r.rule !== 'string'
    || !Array.isArray(r.standards) || !plain(r.request) || !Array.isArray(r.assertions) || !r.assertions.length || !r.assertions.every(a => plain(a) && STATUSES.includes(a.status))) return false;
  if (r.status !== worst(r.assertions.map(a => a.status))) return false;
  if (!Array.isArray(r.settlement) || !r.settlement.every(f => plain(f) && f.effect === (r.severity === 'control' ? 'tag' : 'withheld'))) return false;
  return r.status !== 'pass' || (plain(r.reach) && r.reach.reached === true && (r.severity === 'control' || !r.settlement.length));
}

// The run the export may render, from a parsed run file: the run itself (any stored comparison removed), or a refusal.
export function savedPaymentsRun(value, what = 'the run') {
  if (!plain(value) || value.schema !== PAYMENTS_RUN_SCHEMA) throw refused(`${what} is not a payments run (${PAYMENTS_RUN_SCHEMA})`);
  const { comparison: _, ...run } = value, { sha256, ...body } = run;
  if (typeof run.id !== 'string' || !RUN_ID.test(run.id)) throw refused(`${what} has no payments run id`);
  if (typeof sha256 !== 'string' || digest(body) !== sha256) throw refused(`${what} was edited after it was produced (its sha256 no longer matches its body)`);
  const fields = Object.hasOwn(run, 'producer') ? [...RUN_FIELDS, 'producer'] : RUN_FIELDS; // Older saved runs have no producer.
  if (Object.keys(run).length !== fields.length || !fields.every(k => Object.hasOwn(run, k))) throw refused(`${what} does not have exactly the fields a payments run has`);
  if (run.scope !== PAYMENTS_SCOPE) throw refused(`${what} does not state the payments pack's scope`);
  const checks = run.rows;
  if (!Array.isArray(checks) || !checks.length || !checks.every(readableRow) || new Set(checks.map(r => r.id)).size !== checks.length)
    throw refused(`${what} has no readable rows, or a row's status is not what its assertions, reach and settlement give`);
  if (!plain(run.counts) || Object.keys(run.counts).length !== STATUSES.length || STATUSES.some(s => run.counts[s] !== checks.filter(r => r.status === s).length))
    throw refused(`${what}'s counts are not its rows' statuses`);
  if (!plain(run.provider) || run.provider.livemode !== false || typeof run.provider.kind !== 'string') throw refused(`${what} does not say its provider was in test mode`);
  if (!Number.isFinite(Date.parse(run.startedAt)) || !Number.isFinite(Date.parse(run.finishedAt))) throw refused(`${what} has no start and finish times`);
  return run;
}

// sign: the library default signs only when asked (a key directory, or sign: true), as exportRun() does; the `payments export`
// command signs unless --unsigned. The key is read or made once the runs are known good and their bytes are rendered, so a refused
// run makes no key, and a refused key leaves no file behind.
export async function exportPaymentsRun({ run: input, baseline: baselineInput, format, outputFile, signingKeyDir, sign = signingKeyDir !== undefined }) {
  assertRuntime();
  const comparing = baselineInput !== undefined;
  if (!(comparing ? PAYMENTS_COMPARISON_FORMATS : PAYMENTS_EXPORT_FORMATS).includes(format) || typeof outputFile !== 'string' || !isAbsolute(outputFile)) throw new Error('Invalid export options.');
  if (typeof sign !== 'boolean' || (signingKeyDir !== undefined && (!sign || typeof signingKeyDir !== 'string' || !isAbsolute(signingKeyDir)))) throw new Error('Invalid export options.');
  const name = basename(outputFile), envelopeName = `${name}.dsse.json`;
  if (sign && (!SUBJECT_NAME.test(name) || !SUBJECT_NAME.test(envelopeName))) throw new Error('Invalid export options.');
  const run = savedPaymentsRun(input, 'the run'), baseline = comparing ? savedPaymentsRun(baselineInput, 'the baseline run') : null;
  // A baseline is an earlier, different run: never the run itself, and finished before the run started.
  if (comparing && (baseline.id === run.id || baseline.sha256 === run.sha256 || !(Date.parse(baseline.finishedAt) <= Date.parse(run.startedAt))))
    throw refused('the baseline run must be a different run that finished before this run started');
  await assertExportDirectory(dirname(outputFile));
  const comparison = comparing ? comparePaymentsRuns(baseline, run) : null;
  let text, log;
  try {
    if (format === 'sarif') log = renderPaymentsSarif(run);
    else text = format === 'html' ? renderPaymentsReport(run, comparison) : `${JSON.stringify(comparing ? comparison : run, null, 2)}\n`;
  } catch { throw refused('the run could not be rendered'); }
  // The size is known before any key is read or made (the stamp or the signing block adds a few hundred bytes, checked again below).
  if (Buffer.byteLength(text ?? JSON.stringify(log, null, 2)) > EXPORT_LIMIT) throw new Error('Export exceeds its limit.');
  const signer = sign ? await loadSigningKey(signingKeyDir ?? defaultSigningKeyDir()) : null;
  if (log) {
    if (signer) log.runs[0].properties.signing = sarifSigning(signer.keyid);
    text = `${JSON.stringify(log, null, 2)}\n`;
  }
  // The HTML report carries the "Signed evidence" stamp inside the signed bytes, before its closing tag (the report ends with a
  // newline, which stays last). The JSON stays the record or the comparison as computed.
  if (signer && format === 'html') { const end = text.endsWith('\n') ? '\n' : ''; text = `${stampHtml(text.slice(0, text.length - end.length), signer.keyid, envelopeName)}${end}`; }
  const content = Buffer.from(text);
  if (content.length > EXPORT_LIMIT) throw new Error('Export exceeds its limit.');
  await publish(outputFile, content);
  const signature = signer ? await signBeside(outputFile, content, signer) : null;
  return { saved: true, runId: run.id, ...(comparing ? { baselineRunId: baseline.id, document: format === 'json' ? 'comparison' : 'report-with-comparison' } : {}), format,
    bytes: content.length, sha256: createHash('sha256').update(content).digest('hex'), signature };
}
