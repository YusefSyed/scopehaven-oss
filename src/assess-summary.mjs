// What a person reads after `assess`: every check that did not pass, anything else that keeps the run from being clean,
// and how to see the findings. It goes to stderr, so the JSON on stdout stays the machine-readable result. Observed values
// come from the target, so they appear only for the owned synthetic fixture (a real app's values must not land in CI logs),
// and control characters are stripped either way.
import { join } from 'node:path';

const SYNTHETIC_ORIGIN = 'synthetic-local-http';
const clean = text => String(text ?? '').replace(/[\u0000-\u001f\u007f-\u009f  ]+/g, ' ').trim().slice(0, 160);
const quoted = text => `'${String(text).replaceAll("'", `'\\''`)}'`;

export function assessSummary(run, { directory, defaultData, command = './scopehaven', notClean = [] } = {}) {
  const results = run.results ?? [], total = run.checksTotal ?? results.length, { pass = 0, fail = 0, inconclusive = 0, error = 0 } = run.counts ?? {};
  const notApplicable = total - pass - fail - inconclusive - error;
  const notPassed = results.filter(result => ['fail', 'inconclusive', 'error'].includes(result.status));
  const lines = [`\n${pass} of ${total} checks passed on ${clean(run.targetId)}: ${fail} failed, ${inconclusive} inconclusive, ${error} error${notApplicable > 0 ? `, ${notApplicable} not applicable` : ''}.`];
  const seen = new Set(), showValues = run.evidenceOrigin === SYNTHETIC_ORIGIN;
  for (const result of notPassed) {
    lines.push(`  ${result.status.toUpperCase()} ${clean(result.id)} ${clean(result.title)}`);
    if (!showValues) continue;
    const actual = clean(result.assertions?.find(assertion => assertion.status === result.status)?.actual);
    if (actual && !seen.has(actual)) { seen.add(actual); lines.push(`       ${actual}`); }
  }
  for (const reason of notClean) lines.push(`Not clean: ${clean(reason)}`);
  if (notPassed.length || notClean.length) {
    const data = directory === defaultData ? '' : ` --data ${quoted(directory)}`;
    lines.push(`See every finding: ${command} export --run ${run.id} --format html --out ${quoted(join(directory, `report-${String(run.id).slice(0, 8)}.html`))}${data}`);
  }
  return `${lines.join('\n')}\n`;
}
