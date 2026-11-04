// What a person reads after `assess`: every failing check, then how to see the findings. It goes to stderr, so the JSON on
// stdout stays the machine-readable result. Observed values come from the target, so they appear only for the owned
// synthetic fixture (a real app's values must not land in CI logs), and control characters are stripped either way.
const SYNTHETIC_ORIGIN = 'synthetic-local-http';
const clean = text => String(text ?? '').replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]+/g, ' ').trim().slice(0, 160);

export function assessSummary(run, { directory, defaultData, command = './scopehaven' } = {}) {
  const results = run.results ?? [], total = run.checksTotal ?? results.length, { pass = 0, fail = 0, inconclusive = 0, error = 0 } = run.counts ?? {};
  const notPassed = results.filter(result => ['fail', 'inconclusive', 'error'].includes(result.status));
  const lines = [`\n${pass} of ${total} checks passed on ${clean(run.targetId)}: ${fail} failed, ${inconclusive} inconclusive, ${error} error.`];
  const seen = new Set(), showValues = run.evidenceOrigin === SYNTHETIC_ORIGIN;
  for (const result of notPassed) {
    lines.push(`  ${result.status.toUpperCase()} ${clean(result.id)} ${clean(result.title)}`);
    if (!showValues) continue;
    const actual = clean(result.assertions?.find(assertion => assertion.status === result.status)?.actual);
    if (actual && !seen.has(actual)) { seen.add(actual); lines.push(`       ${actual}`); }
  }
  if (notPassed.length) {
    lines.push(directory === defaultData
      ? `See every finding: ${command} start, then open the private launch page it prints.`
      : `See every finding: ${command} export --run ${run.id} --format html --out /absolute/new/report.html --data '${String(directory).replaceAll("'", `'\\''`)}'`);
  }
  return `${lines.join('\n')}\n`;
}
