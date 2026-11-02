// The drift summary of a scheduled re-run. It reads one regression-gate
// summary (integrations/regression-gate/gate.mjs: the current run gated against the last
// successful run) and says what moved since then: a regression, an improvement, a change
// that needs review, or no change. An unchanged run reads "no change", never "fixed": only
// a row the comparison itself labels fixed or restored counts as one.
//
// Exit codes (the CLI): 0 no change, improved, or no baseline yet (the first run);
// 1 a regression, or a change the comparison could not verify; 2 the gate failed to run,
// the summary is unreadable, or the runs are not comparable.
//
// Pure, plus a small CLI. Nothing is sent anywhere: the summary is written to stdout or a file.
import { readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';

export const DRIFT_SCHEMA = 'scopehaven-drift/1';
export const DRIFT_STATUSES = Object.freeze(['no-change', 'improved', 'regression', 'needs-review', 'no-baseline', 'incomparable', 'error']);
const RESTORED = Object.freeze(['fixed', 'contract-restored', 'local-control-restored']);
const REVIEW = Object.freeze(['unverified', 'blocked-by-controls', 'not-applicable', 'incompatible']);
const count = (labels, names) => names.reduce((n, name) => n + (Number.isSafeInteger(labels?.[name]) && labels[name] > 0 ? labels[name] : 0), 0);

export function driftOf(summary) {
  const base = { schema: DRIFT_SCHEMA };
  if (summary === null || typeof summary !== 'object' || summary.schemaVersion !== 1 || ![0, 1, 2].includes(summary.exitCode)) return { ...base, status: 'error', exitCode: 2, reason: 'the gate summary is unreadable' };
  if (summary.exitCode === 2) return { ...base, status: 'error', exitCode: 2, reason: `the gate did not run (${Array.isArray(summary.reasons) ? summary.reasons.join(', ') : 'unknown'})` };
  const current = summary.current ?? {}, comparison = summary.comparison;
  const run = { runId: current.runId ?? null, targetId: current.targetId ?? null, counts: current.counts ?? null, gateOutcome: summary.outcome, gateReasons: summary.reasons ?? [] };
  if (!comparison || comparison.requested !== true) return { ...base, status: 'no-baseline', exitCode: 0, run, reason: 'no earlier successful run to compare with; this run becomes the baseline' };
  if (comparison.compatibility !== 'compatible') return { ...base, status: 'incomparable', exitCode: 2, run, baselineRunId: comparison.baselineRunId ?? null, reason: 'the runs are not comparable, so no drift is reported' };
  const labels = comparison.labels ?? {};
  const regressed = count(labels, ['regression']), restored = count(labels, RESTORED), review = count(labels, REVIEW);
  const status = regressed ? 'regression' : review ? 'needs-review' : restored ? 'improved' : 'no-change';
  return { ...base, status, exitCode: regressed || review ? 1 : 0, run, baselineRunId: comparison.baselineRunId ?? null, regressed, restored, needsReview: review,
    labels: Object.fromEntries(Object.entries(labels).filter(([, n]) => Number.isSafeInteger(n) && n > 0)), restorationLabel: comparison.restorationLabel ?? null };
}

const HEADLINE = {
  'no-change': () => '**No change** since the last successful run.',
  improved: d => `**Improved:** ${d.restored} check${d.restored === 1 ? '' : 's'} labelled ${d.restorationLabel ? `"${d.restorationLabel}"` : 'restored'} since the last successful run.`,
  regression: d => `**Regression:** ${d.regressed} check${d.regressed === 1 ? '' : 's'} regressed since the last successful run.`,
  'needs-review': d => `**Needs review:** ${d.needsReview} check${d.needsReview === 1 ? '' : 's'} changed in a way the comparison could not verify.`,
  'no-baseline': () => '**No baseline yet:** this is the first run; it becomes the baseline.',
  incomparable: () => '**Not comparable:** the runs differ in application, suite or context, so no drift is reported.',
  error: d => `**Not run:** ${d.reason}.`,
};
// Markdown for a job summary or a local file. It states the scope and never says secure or certified.
export function driftMarkdown(d) {
  const lines = ['### Scopehaven drift', '', HEADLINE[d.status](d)];
  if (d.run?.runId) lines.push('', `Current run \`${d.run.runId}\` on \`${d.run.targetId}\`${d.baselineRunId ? `, against \`${d.baselineRunId}\`` : ''}. Gate: ${d.run.gateOutcome}${d.run.gateReasons.length ? ` (${d.run.gateReasons.join(', ')})` : ''}.`);
  if (d.run?.counts) lines.push('', `Checks: ${d.run.counts.pass} passed, ${d.run.counts.fail} failed, ${d.run.counts.inconclusive} inconclusive, ${d.run.counts.error} errors, ${d.run.counts.not_applicable} not applicable.`);
  if (d.labels && Object.keys(d.labels).length) lines.push('', '| Transition | Checks |', '| --- | ---: |', ...Object.entries(d.labels).map(([label, n]) => `| ${label} | ${n} |`));
  lines.push('', 'Built-in synthetic target; no customer system, model or external service. No notification is sent.');
  return `${lines.join('\n')}\n`;
}

function main(argv) {
  const options = {};
  for (let i = 0; i < argv.length; i += 2) {
    if (!['--summary', '--markdown'].includes(argv[i]) || typeof argv[i + 1] !== 'string' || Object.hasOwn(options, argv[i])) { process.stderr.write('usage: drift.mjs --summary gate-summary.json [--markdown out.md]\n'); return 2; }
    options[argv[i]] = argv[i + 1];
  }
  if (!options['--summary']) { process.stderr.write('usage: drift.mjs --summary gate-summary.json [--markdown out.md]\n'); return 2; }
  let summary = null;
  try { summary = JSON.parse(readFileSync(resolve(options['--summary']), 'utf8')); } catch { summary = null; }
  const d = driftOf(summary), text = driftMarkdown(d);
  if (options['--markdown']) writeFileSync(resolve(options['--markdown']), text, { mode: 0o600 }); else process.stdout.write(text);
  return d.exitCode;
}
if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) process.exitCode = main(process.argv.slice(2));
