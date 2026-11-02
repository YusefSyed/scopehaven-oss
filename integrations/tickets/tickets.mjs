// Offline ticket export: one saved run, or one comparison, as tickets a
// team can import by hand: a Jira CSV file or GitHub-issue markdown. Pure and
// deterministic: the same run (and baseline) always give identical bytes. No network:
// no Jira or GitHub API, nothing is filed anywhere.
//
// One ticket per finding:
//   Open                a check that fails in the run;
//   Resolved candidate  a check whose comparison transition is a repair (fixed,
//                       contract-restored, local-control-restored), only when every one of
//                       core's conditions for crediting a repair holds: the comparison is
//                       core's own for this pair (recomputed by the gate's
//                       validateComparison), compatible, with every required allowed-use
//                       control passing; the candidate has no new failures; no model
//                       identity was unreadable; and, where core records model attribution,
//                       the repair is credited to the application, for the pair and for this
//                       row. It carries core's restoration label, copied, never upgraded;
//   Unverified change   the same transition when any of those does not hold, with the reason.
// Every ticket carries a dedupe key, sha256 of the JSON array [check id, application id,
// policy hash, profile hash, target context, target label]. The profile hash is core's
// identity of the target profile, which compareRuns requires to match, so every pair that
// can resolve shares it and a repair keeps its failure's key; across builds of one target it
// is stable, and two targets (another origin, a local and a forwarded one, two forwarded
// targets with the same label) never share it. The target id is not in the key: in the owned
// demo it names the build (demo-vulnerable, demo-repaired), and the profile hash already
// separates targets.
// Every description starts with the fixed lines (status, scope, the certification line,
// evidence hashes, identity, and for a comparison its caveats), which are never cut; the
// check's own text follows. Human notes are excluded, as in every other export.
import { createHash } from 'node:crypto';
import { digest } from '../../src/domain.mjs';
import { scopeStatement } from '../../src/report.mjs';
import { CERTIFICATION_STATEMENT } from '../../src/sarif.mjs';
import { validateComparison } from '../regression-gate/gate.mjs';

export const TICKET_FORMATS = Object.freeze(['jira-csv', 'github-md']);
export const TICKET_COLUMNS = Object.freeze(['Summary', 'Description', 'Labels', 'Priority', 'Dedupe Key', 'Scopehaven Status']);
export const REPAIR_TRANSITIONS = Object.freeze(['fixed', 'contract-restored', 'local-control-restored']);
const PRIORITY = Object.freeze({ critical: 'Highest', high: 'High', medium: 'Medium', low: 'Low', control: 'Medium' });
const LIMITS = Object.freeze({ tickets: 2000, field: 8000, summary: 255, title: 200 });
const text = (value, fallback) => (typeof value === 'string' && value.trim() ? value.trim() : fallback);
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
// Bidirectional controls can reorder what a reader sees; they are removed. Cuts never split a character.
const BIDI = /[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g;
const clean = value => String(value).replace(BIDI, '');
const cut = (value, n) => Array.from(value).slice(0, Math.max(0, n)).join('');

// The identity a ticket belongs to: the application and target under one policy.
// A legacy synthetic run without a stored profile hash gets the one core's comparison fills in.
export const profileHashOf = run => (Object.hasOwn(run, 'profileHash') ? run.profileHash ?? null
  : run.evidenceOrigin === 'synthetic-local-http' ? digest({ applicationId: run.applicationId, suiteHash: run.suiteHash, policyHash: run.policyHash, fixtureHash: run.fixtureHash }) : null);
export const ticketIdentity = run => ({ applicationId: run.applicationId ?? null, policyHash: run.policyHash ?? null, profileHash: profileHashOf(run), targetId: run.targetId ?? null,
  targetContext: run.targetContext ?? 'local-app', targetLabel: run.targetLabel ?? null });
export const dedupeKey = (checkId, run) => {
  const id = ticketIdentity(run);
  return createHash('sha256').update(JSON.stringify([checkId, id.applicationId, id.policyHash, id.profileHash, id.targetContext, id.targetLabel])).digest('hex');
};

// Why a repair transition on a validated comparison is not credited as a repair, or null when
// every condition holds.
export function resolutionBlocker(comparison, row) {
  if (comparison.compatible !== true || comparison.controlsPass !== true) return 'the comparison is not verified: the runs are not comparable, or a required allowed-use control did not pass';
  if ((comparison.summary?.newFailures ?? 0) !== 0) return `the candidate has ${comparison.summary.newFailures} new failure${comparison.summary.newFailures === 1 ? '' : 's'}`;
  const a = comparison.modelAttribution;
  if (a?.state === 'not-recorded' && Array.isArray(a.malformed) && a.malformed.length) return 'a model identity was present but could not be read';
  if (a?.state === 'recorded' && a.repairCreditedToApp !== true) return 'core does not credit the repair to the application';
  if (row?.attribution !== undefined && row.attribution !== 'app') return `core credits this change to ${String(row.attribution)}, not the application`;
  return null;
}

// The ticket list for a run, or for a candidate run compared with a baseline (comparison:
// the result of core compareRuns(baseline, candidate)). The comparison is checked against a
// fresh compareRuns of the same pair; a forged, edited or mismatched one is refused.
export function ticketsFor(run, { baseline = null, comparison = null } = {}) {
  if (!object(run) || typeof run.id !== 'string' || !Array.isArray(run.results)) throw new Error('A ticket export needs a saved run.');
  if ((baseline === null) !== (comparison === null)) throw new Error('A comparison needs its baseline and core\'s comparison result.');
  const checked = comparison === null ? null : validateComparison(comparison, baseline, run);
  const rows = new Map((checked?.rows ?? []).map(row => [row.id, row]));
  const tickets = [];
  for (const row of run.results) {
    const compared = rows.get(row.id) ?? null, transition = compared?.transition ?? null;
    const repaired = transition !== null && REPAIR_TRANSITIONS.includes(transition);
    if (row.status !== 'fail' && !repaired) continue;
    const reason = row.status === 'fail' ? null : resolutionBlocker(checked, compared);
    const status = row.status === 'fail' ? 'Open' : reason === null ? 'Resolved candidate' : 'Unverified change';
    tickets.push(ticket(run, row, { status, reason, transition, comparison: checked, baseline }));
  }
  if (tickets.length > LIMITS.tickets) throw new Error('Too many tickets for one export.');
  return tickets;
}

function ticket(run, row, { status, reason, transition, comparison, baseline }) {
  const severity = text(row.severity, 'unspecified'), control = severity === 'control', id = ticketIdentity(run);
  const title = cut(clean(text(row.title, row.id)), LIMITS.title);
  const failed = (Array.isArray(row.assertions) ? row.assertions : []).filter(a => a?.status === 'fail' && typeof a.name === 'string').map(a => a.name);
  const a = comparison?.modelAttribution;
  // Fixed lines: never cut.
  const fixed = [
    `Check ${row.id}: ${title}.`,
    `Status: ${status}${status === 'Resolved candidate' ? ` (${text(comparison.restorationLabel, 'repair')}; transition ${transition})` : status === 'Unverified change' ? ` (transition ${transition}; no repair is claimed: ${reason})` : ''}.`,
    `Scope: ${scopeStatement(run)}`,
    CERTIFICATION_STATEMENT,
    `Evidence: run ${run.id}; integrity sha256 ${run.integrity?.sha256 ?? 'not recorded'}${typeof row.evidenceDigest === 'string' ? `; check evidence ${row.evidenceDigest}` : ''}.`,
    `Identity: application ${id.applicationId ?? 'not recorded'}; target ${id.targetId ?? 'not recorded'} (${id.targetContext}${id.targetLabel ? `, ${id.targetLabel}` : ''}); profile ${id.profileHash ?? 'not recorded'}; suite ${run.suiteId ?? 'unknown'} ${run.suiteHash ?? ''}; policy ${id.policyHash ?? 'unknown'}; evaluator ${run.evaluatorHash ?? 'unknown'}.`,
    ...(baseline ? [
      `Compared with baseline run ${baseline.id}${comparison.compatible ? '' : ' (not comparable)'}${comparison.controlsPass ? '' : '; required allowed-use controls did not all pass'}.`,
      ...(typeof comparison.evidenceScope === 'string' ? [`Evidence scope: ${comparison.evidenceScope}`] : []),
      ...(typeof a?.note === 'string' ? [`Model attribution: ${a.note}`] : []),
      ...(Array.isArray(a?.caveats) ? a.caveats.filter(c => typeof c === 'string').slice(0, 5).map(c => `Caveat: ${c}`) : []),
    ] : []),
    // Every limitation the run states, never cut.
    ...(Array.isArray(run.limitations) ? run.limitations.filter(l => typeof l === 'string').map(l => `Limitation: ${l}`) : []),
  ].map(clean);
  // The check's own text, cut to what is left.
  const variable = [
    `Expected: ${text(row.expected, 'No expected behaviour was recorded.')}`,
    `Observed: ${text(row.summary, typeof row.observed === 'string' ? row.observed : 'No observation summary was recorded.')}`,
    ...(failed.length ? [`Failed assertions: ${failed.slice(0, 5).join('; ')}${failed.length > 5 ? `; and ${failed.length - 5} more` : ''}.`] : []),
    ...(row.remediation && typeof row.remediation.title === 'string' ? [`Remediation: ${row.remediation.title}`] : []),
  ].map(clean).join('\n');
  const head = fixed.join('\n');
  const labels = ['scopehaven', control ? 'allowed-use-control' : 'prohibited-behaviour', `severity-${severity}`, `category-${text(row.category, 'uncategorized')}`, `scopehaven-${status.toLowerCase().replace(/\s+/g, '-')}`]
    .map(label => label.toLowerCase().replace(/[^a-z0-9._-]+/g, '-').slice(0, 60));
  return {
    checkId: row.id,
    summary: cut(clean(`[Scopehaven] ${row.id}: ${title}`), LIMITS.summary),
    description: `${head}\n${cut(variable, LIMITS.field - Array.from(head).length - 1)}`,
    labels: [...new Set(labels)],
    priority: Object.hasOwn(PRIORITY, severity) ? PRIORITY[severity] : 'Medium',
    dedupeKey: dedupeKey(row.id, run),
    status,
  };
}

// RFC 4180 CSV, every cell quoted (a semicolon locale cannot split one). A cell that a
// spreadsheet would read as a formula (=, +, -, @ after any leading space, or a leading tab
// or CR) gets a leading apostrophe, so opening the file never runs anything.
const cell = value => {
  let v = clean(value);
  if (/^\s*[=+\-@]/.test(v) || /^[\t\r]/.test(v)) v = `'${v}`;
  return `"${v.replace(/"/g, '""')}"`;
};
export function renderJiraCsv(tickets) {
  const rows = [TICKET_COLUMNS, ...tickets.map(t => [t.summary, t.description, t.labels.join(' '), t.priority, t.dedupeKey, t.status])];
  return `${rows.map(r => r.map(cell).join(',')).join('\r\n')}\r\n`;
}

// GitHub-issue markdown: one issue draft per ticket, separated by rules. Text is inert: every
// free-text field is inside a fenced code block longer than any backtick run it holds, so
// nothing in it renders, links, mentions or references. Outside the fence there are only
// fixed words and the ticket's number, the status, the priority, the labels and the dedupe
// key; the check id stays inside the fence, so an id like GH-12 never links to an issue.
const fenceFor = body => '`'.repeat(Math.max(3, ...[...body.matchAll(/`+/g)].map(m => m[0].length + 1)));
export function renderGithubMarkdown(tickets) {
  const head = `# Scopehaven tickets (${tickets.length})\n\nIssue drafts for manual filing. Nothing here was sent anywhere.\n`;
  const body = tickets.map((t, i) => {
    const content = `${t.summary}\n\n${t.description}`, fence = fenceFor(content);
    return `\n---\n\n## Scopehaven ticket ${i + 1}\n\n<!-- scopehaven-dedupe-key: ${t.dedupeKey} -->\n\n**Status:** ${t.status}  \n**Priority:** ${t.priority}  \n**Labels:** ${t.labels.map(l => `\`${l}\``).join(' ')}\n\n${fence}text\n${content}\n${fence}\n`;
  }).join('');
  return `${head}${body}`;
}

export function renderTickets(run, { format, baseline = null, comparison = null } = {}) {
  if (!TICKET_FORMATS.includes(format)) throw new Error(`Unknown ticket format. Use ${TICKET_FORMATS.join(' or ')}.`);
  const tickets = ticketsFor(run, { baseline, comparison });
  return format === 'jira-csv' ? renderJiraCsv(tickets) : renderGithubMarkdown(tickets);
}
