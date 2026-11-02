import { allowedUse, allowedUseLabel, allowedUseControlIds, comparisonAllowedUse, ALLOWED_USE_PURPOSE } from './allowed-use.mjs';
import { CONTROL_CUSTODY_LIMIT } from './custody.mjs';
import { ADMISSION_FINDING, restsOnAdmissions } from './app-log-verdicts.mjs';
// The stated scope of an absence pass an egress recorder or SMTP sink decided (presentation only, outside every hash).
import { absenceScopeEntries, absenceScopeRule, ABSENCE_SCOPE_RULE } from './absence-scope.mjs';
// A confined launch's record, when the run carries a valid one (presentation only, outside every hash).
import { confinementOf } from './confinement-record.mjs';
import { unpairedForwardedPasses } from './forwarded-pairing.mjs';
// The declared-channel rule for absence: which absence passes do not count, read from the saved run (outside every hash).
import { channelReadings, channelStatement, channelSentence, unlistedSentence } from './channels.mjs';
// Typed claims and the residual: what each verdict rests on, and what the run did not show (outside every hash).
import { claimTypes, claimCounts, residualOf, CLAIM_RULE, CLAIM_TYPES, RESIDUAL_NOTE } from './residual.mjs';
// Coverage: which actors with a boundary check have a required allowed-use control, read from the saved run, and the
// operator's pre-run coverage report when the exporter is given its inventory, contract and profile (computed by the exporter from
// integrations/coverage-report and handed here as lines, so this module imports nothing of it). Presentation only: it feeds no
// verdict, count, comparison, gate outcome or hash.
export const escape = value => String(value ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
// One scope sentence shared by the HTML report, SARIF and comparison exports.
export const scopeStatement = run => run.scopeLabel || (run.evidenceOrigin === "synthetic-local-http" ? "Owned synthetic fixture. No live language model or customer system assessed." : "Evidence scope not supplied; no safety claim.");
// Plain-language allowed-use line; display rounding only, stored counts stay exact.
// "Fixed" stays reserved for the owned synthetic fixture. Any other restoration
// count prints with its scope description beside it, so it can't be quoted
// without its evidence limits. The observed label already
// states its scope, and an incompatible pair claims no restoration at all.
const restorationText = ({ restorationLabel: label, restorationDescription: description }) => label === 'Fixed' ? 'fixed'
  : label === 'Unverified changes' ? label
  : label === 'No verified repair' ? 'restored. No verified repair: this pair restored nothing, introduced a new failure, or left rows unverified or not applicable.'
  : label.includes('; backend observed where marked') || !description ? `${label}.` : `${label}. ${description}`;
// A forwarded run's boundary passes with no passing same-route required control (src/forwarded-pairing.mjs): the forwarder may have answered them.
const forwardedPairingParagraph = run => {
  const unpaired = unpairedForwardedPasses(run), remote = run.targetContext === 'operator-remote';
  return unpaired.length ? `<p><strong>Not clean ${remote ? 'on the remote target' : 'through the forwarder'}:</strong> ${escape(unpaired.join(', '))} passed with no required control on the same route that passed, so ${remote ? 'a gateway in front of the target' : 'the forwarder'} may have answered ${unpaired.length === 1 ? 'it' : 'them'} itself. The gate reads ${remote ? 'remote-pass-unpaired' : 'forwarded-pass-unpaired'}.</p>` : ''; };
// A run's boundary absence passes that its declared channels do not support (src/channels.mjs): they read inconclusive.
const readingText = reading => `${reading.id} (${reading.reasons.join(', ')})`;
const channelParagraph = run => {
  const withheld = channelReadings(run);
  return withheld.length ? `<p><strong>Not clean on declared channels:</strong> ${escape(withheld.map(readingText).join(', '))} passed an absence check, but a channel the profile declares was not observed in ${withheld.length === 1 ? 'its' : 'their'} window, or a declared observer's window carried an effect the check's clauses do not select, or the run's confinement did not show that no undeclared way out exists, so ${withheld.length === 1 ? 'it reads' : 'they read'} inconclusive. The gate reads ${escape([...new Set(withheld.flatMap(r => r.reasons))].join(', '))}.</p>` : ''; };
const rowChannelHtml = (row, withheld) => {
  const reading = withheld.find(r => r.id === row.id);
  return reading ? `<p><strong>Read as inconclusive</strong> on the declared channels: ${escape(reading.reasons.join(', '))}. The sealed status is ${escape(row.status)}; the gate, SARIF and the comparison read it as inconclusive.</p>` : ''; };
// The run's channel declaration, or the statement that it declares none (HTTP connector runs only); part of the residual.
function channelsHtml(run) {
  const statement = channelStatement(run);
  if (!statement) return '';
  if (!statement.declared) return `<h3>Declared channels</h3><p>${escape(statement.note)}</p>`;
  const confinement = statement.readable ? `Confinement: declared ${statement.confinement}; this run is ${statement.tier === 'confined' ? 'a confined launch' : 'not a confined launch'}.${statement.gap ? ` Absence passes read channels-undeclared: ${statement.gap}.` : ''}` : `${statement.gap}; every absence pass reads channels-undeclared.`;
  return `<h3>Declared channels</h3><p>${escape(confinement)}</p>${statement.unlisted.map(entry => `<p>${escape(unlistedSentence(entry))}</p>`).join('')}${statement.channels.length ? `<ul>${statement.channels.map(entry => `<li>${escape(channelSentence(entry))}</li>`).join('')}</ul>` : ''}<p><small>${escape(statement.rule)}</small></p>`;
}
// One line of claim counts for the cover, and one row's claim (src/residual.mjs).
export const claimCountsText = counts => `Claims: ${CLAIM_TYPES.map(type => `${counts[type]} ${type}`).join(' · ')}.`;
const claimHtml = claim => claim ? `<p><b>Claim:</b> ${escape(claim.type)}. ${escape(claim.basis)}</p>` : '';
const listOrNone = (items, none) => items.length ? `<ul>${items.map(item => `<li>${escape(item)}</li>`).join('')}</ul>` : `<p>${escape(none)}</p>`;
// The residual (src/residual.mjs): channels, checks that read inconclusive and why, allowed-use pairing, observers that did not run.
// Coverage read from the run alone. An actor is covered when a required allowed-use control (src/allowed-use.mjs: requiredControlIds,
// or severity "control" in older synthetic runs) ran as that actor; an actor whose rows are all boundary checks is a gap, because a
// fix that refuses that actor everything would leave every one of its checks passing. The actor is the HTTP connector's trace
// actor id (conversations write the same field), or the one principal every attempt of a synthetic row ran as; a row with neither,
// or whose attempts ran as several principals (a cross-actor canary), is counted and not placed.
export const COVERAGE_GAP = 'No allowed-use control for this actor: a fix that refuses this actor everything would read as a fix.';
export const COVERAGE_RULE = 'Coverage is read from the saved run, outside every verdict: for each actor with a boundary check, whether a required allowed-use control ran as that actor. It changes no verdict, count, comparison, gate outcome or hash.';
export const COVERAGE_NEEDS_FILES = 'The full pre-run coverage report (which actions the suite checks on the forbidden side and on the allowed side) needs the operator\'s inventory, stated contract and profile: ./scopehaven export ... --coverage-inventory ABSOLUTE_JSON --coverage-contract ABSOLUTE_JSON --coverage-targets ABSOLUTE_JSON.';
const COVERAGE_NO_ACTORS = 'No row of this run records its actor, so per-actor coverage is not read.';
const plainValue = value => value !== null && typeof value === 'object' && !Array.isArray(value);
export function rowActorId(row) {
  const entries = plainValue(row) && Array.isArray(row.trace) ? row.trace.filter(entry => plainValue(entry) && plainValue(entry.data)) : [];
  if (!entries.length) return null;
  if (typeof entries[0].data.actorId === 'string' && entries[0].data.actorId) return entries[0].data.actorId;
  const principals = new Set(entries.map(entry => plainValue(entry.data.actor) && typeof entry.data.actor.principalId === 'string' ? entry.data.actor.principalId : '').filter(Boolean));
  return principals.size === 1 ? [...principals][0] : null;
}
export function coverageOf(run) {
  const rows = (Array.isArray(run?.results) ? run.results : []).filter(row => plainValue(row) && typeof row.id === 'string');
  const { basis, ids } = allowedUseControlIds(run), required = new Set(ids), actors = new Map();
  let rowsWithoutActor = 0;
  for (const row of rows) {
    if (row.status === 'not_applicable') continue; // declared not applicable: nothing ran, so nothing to cover
    const actorId = rowActorId(row);
    if (actorId === null) { rowsWithoutActor++; continue; }
    if (!actors.has(actorId)) actors.set(actorId, { actorId, boundaryChecks: [], allowedUseControls: [] });
    const entry = actors.get(actorId);
    if (required.has(row.id)) entry.allowedUseControls.push(row.id);
    else if (row.severity !== 'control') entry.boundaryChecks.push(row.id);
  }
  const listed = [...actors.values()].filter(a => a.boundaryChecks.length).sort((a, b) => a.actorId.localeCompare(b.actorId));
  return { basis, actors: listed, actorsWithoutAllowedUse: listed.filter(a => !a.allowedUseControls.length).map(a => a.actorId), rowsWithoutActor, gap: COVERAGE_GAP, rule: COVERAGE_RULE };
}
const checksText = ids => `${ids.length} boundary check${ids.length === 1 ? '' : 's'} (${ids.join(', ')})`;
const actorLine = (label, a) => a.allowedUseControls.length
  ? `<li>${escape(`${label}${a.actorId}: ${checksText(a.boundaryChecks)}; allowed-use controls: ${a.allowedUseControls.join(', ')}.`)}</li>`
  : `<li class="coverage-gap">${escape(`${label}${a.actorId}: ${checksText(a.boundaryChecks)}; no allowed-use control. ${COVERAGE_GAP}`)}</li>`;
// The pre-run report the exporter computed from the operator's files ({ report, warnings, lines }, the lines from coverageLines), or
// the sentence that it needs them.
const coverageReportHtml = coverage => coverage?.report ? `<ul>${[...(coverage.warnings ?? []), ...(coverage.lines ?? [])].map(line => `<li>${escape(line)}</li>`).join('')}</ul>` : `<p>${escape(COVERAGE_NEEDS_FILES)}</p>`;
function coverageHtml(run, coverage) {
  const c = coverageOf(run);
  const actors = c.actors.length ? `<ul>${c.actors.map(a => actorLine('', a)).join('')}</ul>${c.rowsWithoutActor ? `<p><small>${escape(`${c.rowsWithoutActor} row${c.rowsWithoutActor === 1 ? ' records' : 's record'} no single actor and ${c.rowsWithoutActor === 1 ? 'is' : 'are'} not placed.`)}</small></p>` : ''}` : `<p>${escape(COVERAGE_NO_ACTORS)}</p>`;
  return `<h3>Coverage: allowed-use controls per actor</h3><p>${escape(COVERAGE_RULE)}</p>${actors}<h3>Pre-run coverage report</h3>${coverageReportHtml(coverage)}`;
}
// Coverage and residual are one section: the pre-run coverage part first, then what the run did not show.
function residualHtml(run, coverage) {
  const r = residualOf(run), c = r.controls;
  const unpaired = [...c.notPassed.map(id => `${id}: a required allowed-use control that did not pass.`),
    ...(c.unpairedPasses ? c.unpairedPasses.checks.map(id => `${id}: passed with no required control on the same route that passed (${c.unpairedPasses.reason}).`) : []),
    ...c.unpairedSelectors.map(s => `${s.id}, ${s.assertion}: ${s.reason}.`)];
  const controls = r.channels?.controls ?? [];
  return `<section class="residual"><h2>Coverage and residual</h2>${coverageHtml(run, coverage)}<h3>Residual</h3><p>${escape(r.note)}</p>${channelsHtml(run)}`
    + (controls.length ? `<ul>${controls.map(x => `<li>${escape(`${x.id}: an allowed-use control whose absence the declared channels do not support (${x.reasons.join(', ')}).`)}</li>`).join('')}</ul>` : '')
    + `<h3>Checks that read inconclusive</h3>${listOrNone(r.inconclusive.map(e => `${e.id} (${e.status === e.reads ? e.status : `${e.status}, read ${e.reads}`}): ${e.reasons.join(', ')}${e.assertions.length ? `. Unsettled: ${e.assertions.join('; ')}` : ''}.`), 'None.')}`
    + `<h3>Allowed-use controls not paired</h3>${listOrNone(unpaired, `None of ${c.required} required control${c.required === 1 ? '' : 's'}.`)}`
    + `<h3>Observers not running or incomplete</h3>${listOrNone(r.observers.map(o => `${o.type} ${o.id}: ${[o.failedIn.length ? `could not report in ${o.failedIn.join(', ')}` : '', o.missingIn.length ? `no window in ${o.missingIn.join(', ')}` : '', o.partialIn.length ? `a partial window in ${o.partialIn.join(', ')}` : ''].filter(Boolean).join('; ')}.`), r.observersDeclared === null ? 'Observers are not read for this evidence origin.' : r.observersDeclared ? 'None of the declared observers missed a window or ran incomplete.' : 'No observers declared.')}`
    + `<p><small>${escape(CLAIM_RULE)}</small></p></section>`;
}
const allowedUseParagraph = summary => `<p>${escape(allowedUseLabel(summary))} <small>${escape(ALLOWED_USE_PURPOSE)}</small></p>`;
// Record custody of observed-effect clauses (src/custody.mjs), shared by the HTML report, SARIF,
// the comparison export and (as its own copy) the served dashboard. Custody says who can write the
// record a clause was decided from; it says nothing about whether that record is accurate.
const CUSTODY_LABELS = Object.freeze({ 'subject-writable': 'the application can write this record', 'observer-held': 'held by the observer; the application cannot write it', independent: 'held outside the application, in the request path' });
export const custodyLabel = value => value === null || value === undefined ? 'no observer decided this clause' : Object.hasOwn(CUSTODY_LABELS, value) ? CUSTODY_LABELS[value] : 'unrecognized custody';
export const CUSTODY_RULE = 'In a boundary check, a pass of an observed effect needs an observer that decided it and keeps its record outside the application; one decided only by records the application can write reads inconclusive.';
export const custodyLimit = row => row?.severity === 'control' ? CONTROL_CUSTODY_LIMIT : CUSTODY_RULE;
// The effect assertions of one row that carry custody, in row order.
export const custodyEntries = row => (Array.isArray(row?.assertions) ? row.assertions : []).filter(a => a && typeof a === 'object' && Object.hasOwn(a, 'custody'))
  .map(a => ({ assertion: a.name, custody: a.custody, ...(a.custodyReason ? { custodyReason: a.custodyReason, custodyUpgrade: a.custodyUpgrade } : {}),
    // An app-log admission (src/app-log-verdicts.mjs): the application's own action log decided this fail, against it.
    ...(a.appLog?.finding ? { appLog: a.appLog.finding, appLogSource: a.appLog.log } : {}) }));
export const custodySentence = entry => `${entry.assertion}: ${custodyLabel(entry.custody)}.${entry.custodyReason ? ` Read as inconclusive (${entry.custodyReason}). ${entry.custodyUpgrade}` : ''}${entry.appLog ? ` Failed by an admission: the application's own action log (app log ${entry.appLogSource}) records it, so it fails against the application (${entry.appLog}); no observer held outside the application decided it.` : ''}`;
// The label of a fail an app-log admission decided: on the clause, and on a row whose fail rests only on admissions.
export const ADMISSION_LABEL = 'fail (app-admission)';
export const assertionStatusLabel = a => a?.status === 'fail' && a?.appLog?.finding === ADMISSION_FINDING ? ADMISSION_LABEL : a?.status;
export const rowStatusLabel = row => restsOnAdmissions(row) ? ADMISSION_LABEL : row?.status;
// The routing tier (declared, not shown exclusive; or confined) and the time bound, for each such pass of the row (src/absence-scope.mjs).
function absenceScopeHtml(row, run) {
  const entries = absenceScopeEntries(row, run);
  return entries.length ? `<h3>Absence scope</h3><ul>${entries.map(entry => `<li>${escape(entry.note)}</li>`).join('')}</ul><p><small>${escape(absenceScopeRule(run))}</small></p>` : '';
}
// What a confined launch allowed and refused (src/confinement-record.mjs); nothing here decides a verdict.
function confinementSectionHtml(run) {
  const c = confinementOf(run);
  if (!c) return '';
  const sinks = c.sinks.map(s => `${s.type} ${s.observerId} (port ${s.port})`).join(', ') || 'none';
  const iface = c.selfTest.interfaceAddress;
  const ifaceText = !iface ? 'this machine has no non-loopback IPv4 address' : iface.outcome === 'admitted' ? `the rule admitted a connection to ${iface.host}:${iface.port} (nothing listened there), so ScopeHaven checked that it was the only listener on each sink port` : iface.outcome === 'refused' ? `a connection to ${iface.host}:${iface.port} was refused` : `${iface.host}:${iface.port} was ${iface.outcome}`;
  const allow = c.allow.length ? c.allow.map(a => `localhost:${a.port} (${a.reason})`).join(', ') : 'none';
  const denials = c.denials.collected ? `${c.denials.count} refused connection${c.denials.count === 1 ? '' : 's'} logged by the kernel while the application ran${c.denials.selfTestSeen && c.denials.markerSeen ? ' (the log was read through to a marker sent after the run; the sandbox throttles repeated reports, so even then the count is a lower bound)' : ' (the log lagged past the reader\'s wait before or after the run, so this count may be short)'}` : 'not collected';
  return `<h2>Confinement</h2><table class="identity"><tbody>${[['Tier', 'confined'], ['Mechanism', c.mechanism], ['Covers', c.covers], ['Allowed sinks', sinks], ['Allowlist', allow],
    ['Origin', `127.0.0.1:${c.origin.port}: every listener on that port was in the launched process tree when checked, before the first request${c.exitedAt ? `; the application exited by itself at ${c.exitedAt}, after the run ended` : ''}`],
    ['Self-test', `before the application started, a connection to 127.0.0.1:${c.selfTest.canaryPort} (a port the profile does not allow) was refused (${c.selfTest.error})${c.selfTest.otherFamily ? `; [::1]:${c.selfTest.otherFamily.port} (an allowed port on the other loopback family) was ${c.selfTest.otherFamily.outcome === 'refused' ? 'refused' : 'probed; this machine has no IPv6 loopback'}` : ''}; interface address: ${ifaceText}`],
    ['Sink ports', `listed ${c.sinkListeners.checks} time${c.sinkListeners.checks === 1 ? '' : 's'} (before the launch, about once a second during the run, and at stop); every listener was ScopeHaven's own process`], ['Kernel denials', denials], ['Profile sha256', c.profileDigest],
    ['Application', `${c.command.executable} (${c.command.argc} argument${c.command.argc === 1 ? '' : 's'})`]].map(([label, value]) => `<tr><th>${escape(label)}</th><td>${escape(value)}</td></tr>`).join('')}</tbody></table>`
    + `${c.denials.sample.length ? `<pre>${escape(c.denials.sample.join('\n'))}</pre>` : ''}<ul>${c.limits.map(l => `<li><small>${escape(l)}</small></li>`).join('')}</ul>`;
}
// pg_net on the wire: the declaration each pg-wal window rests on, word for word, beside its coverage (src/effect-events.mjs collectWindow).
// Rows whose windows carry none render nothing here.
const declaredWindows = windows => (Array.isArray(windows) ? windows : []).filter(w => w && typeof w === 'object' && w.source === 'sql-wal' && w.declaration && typeof w.declaration === 'object');
const declarationSentence = (w, where = '') => {
  const list = names => (Array.isArray(names) && names.length ? names.join(', ') : 'none');
  return `${where}${w.instanceId}: ${w.coverage}${w.reason ? ` (${w.reason})` : ''}. Program roles declared as the operator's: ${list(w.declaration.programRoles)}. Request roles: ${list(w.declaration.requestRoles)}. Refused as reachable by the application: ${w.declaration.refused === null ? 'not read' : list(w.declaration.refused)}. Checked: ${w.declaration.checked ? 'yes' : 'no'}.`;
};
function wireDeclarationHtml(row) {
  const windows = declaredWindows((Array.isArray(row?.trace) ? row.trace : []).flatMap(entry => (entry && typeof entry === 'object' && Array.isArray(entry.data?.windows) ? entry.data.windows : [])));
  return windows.length ? `<h3>pg_net custody declaration</h3><ul>${windows.map(w => `<li>${escape(declarationSentence(w))}</li>`).join('')}</ul>` : '';
}
// The Limits part's sections (the template calls this one name): the confinement record, then the pg_net declarations between checks.
const confinementHtml = run => confinementSectionHtml(run) + settlementDeclarationsHtml(run);
// The same, for the windows the settlement seals between and after checks (gaps) and at each check's barrier: every declaration a run
// carries is shown, not only the checks' own.
export function settlementDeclarationsHtml(run) {
  const s = run?.settlement;
  const entries = [...(Array.isArray(s?.gaps) ? s.gaps : []).map(g => [`Gap ${g.after === null ? 'before the first check' : `after ${g.after}`}`, g.windows]),
    ...(Array.isArray(s?.barriers) ? s.barriers : []).map(b => [`Barrier after ${b.after}`, b.windows])]
    .flatMap(([label, windows]) => declaredWindows(windows).map(w => declarationSentence(w, `${label}, `)));
  return entries.length ? `<h2>pg_net custody declarations between checks</h2><ul>${entries.map(e => `<li>${escape(e)}</li>`).join('')}</ul>` : '';
}
function custodyHtml(row) {
  const entries = custodyEntries(row);
  return (entries.length ? `<h3>Record custody</h3><ul>${entries.map(entry => `<li>${escape(custodySentence(entry))}</li>`).join('')}</ul><p><small>${escape(custodyLimit(row))}</small></p>` : '')
    + wireDeclarationHtml(row);
}
// Cover identities match this report to its saved evidence. They do not change verdicts.
const identityRows = run => [['Run', run.id], ['Application', run.applicationId], ['Build', run.build], ['Target', run.targetId], ['Created', run.createdAt], ['Evidence origin', run.evidenceOrigin],
  ['Suite', run.suiteId], ['Suite hash', run.suiteHash], ['Policy hash', run.policyHash], ['Fixture hash', run.fixtureHash], ['Evaluator hash', run.evaluatorHash], ['Profile hash', run.profileHash],
  ['Evidence integrity (sha256)', run.integrity?.sha256]].filter(([, value]) => typeof value === 'string' && value);
const identityTable = run => `<table class="identity"><tbody>${identityRows(run).map(([label, value]) => `<tr><th>${escape(label)}</th><td>${escape(value)}</td></tr>`).join('')}</tbody></table>`;
// Browser print layout: cover, findings, then limits. No script, font or image is loaded.
const PRINT_CSS = '.identity th{width:30%;color:#536875;font-weight:600}.identity td{overflow-wrap:anywhere}@page{margin:16mm}@media print{body{margin:0;max-width:none;padding:0;font-size:10.5pt}.cover{break-after:page}.limits,.residual{break-before:page}article{break-inside:avoid-page}h2,h3{break-after:avoid}details{display:none}pre{font-size:8pt}}';
export function renderReport(run, { coverage } = {}) {
  const withheld = channelReadings(run), claims = claimTypes(run);
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Scopehaven assessment ${escape(run.id)}</title><style>body{font:16px/1.6 system-ui;margin:40px auto;max-width:1050px;padding:0 24px;color:#132c40}h1,h2{line-height:1.2}article{border-top:1px solid #ccd9df;margin-top:28px;padding-top:12px}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f1f5f7;padding:16px}table{border-collapse:collapse;width:100%}td,th{padding:9px;text-align:left;border-bottom:1px solid #dfe8ed}small{color:#536875}.coverage-gap{color:#b91c1c}${PRINT_CSS}</style><section class="cover"><h1>Scopehaven assessment</h1><p>${escape(run.targetName)} · ${escape(run.createdAt)}</p><p><strong>${escape(scopeStatement(run))}</strong></p><p>${escape(run.counts.pass)} passed · ${escape(run.counts.fail)} failed · ${escape(run.counts.inconclusive)} inconclusive · ${escape(run.counts.error)} errors · ${escape(run.counts.not_applicable || 0)} not applicable</p>${allowedUseParagraph(allowedUse(run))}${forwardedPairingParagraph(run)}${channelParagraph(run)}<p>${escape(claimCountsText(claimCounts(claims)))}</p><p>These are observed checks, not a safety certification.</p>${identityTable(run)}</section>${run.results.map(r => `<article><h2>${escape(r.id)} · ${escape(r.title)}</h2><p><strong>${escape(rowStatusLabel(r).toUpperCase())}</strong>${typeof r.decision === 'string' && r.decision !== r.status ? ` · ${escape(r.decision)}` : ''} · ${escape(r.severity)}</p>${claimHtml(claims.find(c => c.id === r.id))}${rowChannelHtml(r, withheld)}<p><b>Expected:</b> ${escape(r.expected)}</p><p><b>Observed:</b> ${escape(typeof r.observed === "string" ? r.observed : JSON.stringify(r.observed))}</p><table><thead><tr><th>Assertion</th><th>Result</th><th>Evidence</th></tr></thead><tbody>${r.assertions.map(a => `<tr><td>${escape(a.name)}</td><td>${escape(assertionStatusLabel(a))}</td><td>${escape(a.actual)}</td></tr>`).join('')}</tbody></table>${custodyHtml(r)}${absenceScopeHtml(r, run)}<h3>${escape(r.remediation.title)}</h3><p>${escape(r.remediation.why)}</p><ol>${r.remediation.steps.map(s => `<li>${escape(s)}</li>`).join('')}</ol><p><b>Human note:</b> ${escape(run.notes?.[r.id]?.note || 'No note recorded.')}</p><details><summary>Observed trace</summary><pre>${escape(JSON.stringify(r.trace, null, 2))}</pre></details></article>`).join('')}${residualHtml(run, coverage)}<section class="limits"><h2>Limits</h2><p><strong>${escape(scopeStatement(run))}</strong></p>${confinementHtml(run)}<h2>Scope and provenance</h2><pre>${escape(JSON.stringify({ runId: run.id, ...(run.authorization ? { authorization: run.authorization } : {}), applicationId: run.applicationId, build: run.build, targetBuildHash: run.targetBuildHash, targetConfigHash: run.targetConfigHash, suiteHash: run.suiteHash, policyHash: run.policyHash, fixtureHash: run.fixtureHash, evaluatorHash: run.evaluatorHash, evidenceOrigin: run.evidenceOrigin, profileHash: run.profileHash, contextId: run.contextId, requiredControlIds: run.requiredControlIds, buildIdentity: run.buildIdentity, assessmentProfile: run.assessmentProfile, runtimeMode: run.runtimeMode, assertionSchemaVersion: run.assertionSchemaVersion, provenance: run.provenance, evidenceIntegrity: run.integrity }, null, 2))}</pre><ul>${run.limitations.map(l => `<li>${escape(l)}</li>`).join('')}</ul><p>These are observed checks, not a safety certification.</p><p><small>Evidence hash covers the run core, excluding editable human notes. It is a local integrity checksum, not an independently signed attestation.</small></p></section></html>`;
}

const comparisonIdentityKeys = ['targetId', 'targetName', 'build', 'applicationId', 'suiteId', 'suiteHash', 'policyHash', 'fixtureVersion', 'fixtureHash', 'evaluatorHash', 'profileHash', 'evidenceOrigin', 'targetBuildHash', 'createdAt'];
// Custody of a compared row's observed-effect clauses, copied from each saved run (only when either run carries any).
const resultOf = (run, id) => (Array.isArray(run?.results) ? run.results : []).find(r => r?.id === id);
function rowCustody(baseline, candidate, id) {
  const before = resultOf(baseline, id), after = resultOf(candidate, id), b = custodyEntries(before), c = custodyEntries(after);
  return b.length || c.length ? { custody: { baseline: b, candidate: c, note: custodyLimit(after ?? before) } } : {};
}
// The stated scope of each side's absence passes an egress recorder or SMTP sink decided (only when either run carries any).
function rowAbsenceScope(baseline, candidate, id) {
  const b = absenceScopeEntries(resultOf(baseline, id), baseline).map(e => e.note), c = absenceScopeEntries(resultOf(candidate, id), candidate).map(e => e.note);
  return b.length || c.length ? { absenceScope: { baseline: b, candidate: c, note: [...new Set([absenceScopeRule(baseline), absenceScopeRule(candidate)])].join(' ') } } : {};
}
// Each side's claim for a compared row (src/residual.mjs).
function rowClaims(baseline, candidate, id, claims) {
  const b = claims.baseline.find(c => c.id === id), c = claims.candidate.find(x => x.id === id);
  return b || c ? { claim: { baseline: b ? { type: b.type, basis: b.basis } : null, candidate: c ? { type: c.type, basis: c.basis } : null } } : {};
}
// Each side's declared-channel reasons for a row (only when either side has any).
function rowChannels(baseline, candidate, id) {
  const b = channelReadings(baseline).find(r => r.id === id)?.reasons ?? [], c = channelReadings(candidate).find(r => r.id === id)?.reasons ?? [];
  return b.length || c.length ? { channels: { baseline: b, candidate: c } } : {};
}
const runIdentity = run => ({ runId: run.id, ...(run.authorization ? { authorization: run.authorization } : {}), ...Object.fromEntries(comparisonIdentityKeys.map(key => [key, run[key] ?? null])), counts: run.counts ?? null, evidenceIntegritySha256: run.integrity?.sha256 ?? null, scope: scopeStatement(run) });
/** Export projection of a core compareRuns result; labels are copied, never recomputed or upgraded. */
export function comparisonDocument(baseline, candidate, comparison, { coverage } = {}) {
  const verified = comparison.compatible === true && comparison.controlsPass === true;
  const claims = { baseline: claimTypes(baseline), candidate: claimTypes(candidate) };
  return { schemaVersion: 1, document: 'scopehaven-comparison/1',
    certification: 'These are observed checks, not a safety certification.',
    interpretation: 'A row is labelled fixed only when both runs share compatible suite, policy, fixture, evaluator and profile identities and every required allowed-use control passes in the candidate. Otherwise rows stay incompatible, unverified or blocked by controls. A baseline fail that rests only on the application\'s own action log (an app-log admission) is never labelled fixed or restored; it reads unverified.',
    verdict: verified ? 'comparable-controls-passed' : 'not-verified',
    baseline: runIdentity(baseline), candidate: runIdentity(candidate),
    comparison: { compatible: comparison.compatible, controlsPass: comparison.controlsPass, restorationLabel: comparison.restorationLabel, restorationDescription: comparison.evidenceScope, evidenceScope: comparison.evidenceScope,
      reasons: [...comparison.reasons], summary: { ...comparison.summary }, rows: comparison.rows.map(row => ({ ...row, ...rowCustody(baseline, candidate, row.id), ...rowAbsenceScope(baseline, candidate, row.id), ...rowChannels(baseline, candidate, row.id), ...rowClaims(baseline, candidate, row.id, claims) })),
      // Who a verdict change is credited to, when the subject can be served by a model (copied as computed).
      ...(comparison.modelAttribution ? { modelAttribution: structuredClone(comparison.modelAttribution) } : {}) },
    allowedUse: comparisonAllowedUse(baseline, candidate, comparison),
    // What each side did not show (src/residual.mjs), and its claim counts; copied as computed, never upgrading a label.
    claims: { baseline: claimCounts(claims.baseline), candidate: claimCounts(claims.candidate), rule: CLAIM_RULE },
    residual: { baseline: residualOf(baseline), candidate: residualOf(candidate) },
    // Coverage beside the residual: each side's actors without a required allowed-use control (their union on top, since a
    // comparison cannot tell a fix from a refusal for an actor neither run controls), and the pre-run report when given.
    coverage: comparisonCoverage(baseline, candidate, coverage) };
}
function comparisonCoverage(baseline, candidate, coverage) {
  const b = coverageOf(baseline), c = coverageOf(candidate);
  return { actorsWithoutAllowedUse: [...new Set([...b.actorsWithoutAllowedUse, ...c.actorsWithoutAllowedUse])].sort(), baseline: b, candidate: c,
    report: coverage?.report ? { warnings: [...(coverage.warnings ?? [])], lines: [...(coverage.lines ?? [])], report: structuredClone(coverage.report) } : null,
    ...(coverage?.report ? {} : { needs: COVERAGE_NEEDS_FILES }), gap: COVERAGE_GAP, rule: COVERAGE_RULE };
}
function comparisonCoverageHtml(cov) {
  if (!cov) return '';
  const side = (label, c) => c.actors.length ? c.actors.map(a => actorLine(`${label}: `, a)).join('') : `<li>${escape(`${label}: ${COVERAGE_NO_ACTORS}`)}</li>`;
  const report = cov.report ? `<ul>${[...cov.report.warnings, ...cov.report.lines].map(line => `<li>${escape(line)}</li>`).join('')}</ul>` : `<p>${escape(cov.needs)}</p>`;
  return `<h3>Coverage: allowed-use controls per actor</h3><p>${escape(COVERAGE_RULE)}</p><ul>${side('Candidate', cov.candidate)}${side('Baseline', cov.baseline)}</ul><h3>Pre-run coverage report</h3>${report}`;
}
const repairTransitions = ['fixed', 'contract-restored', 'local-control-restored'];
const attributionLabels = { app: 'Application change', model: 'Model change', confounded: 'Model and application may both have changed', unexplained: 'Run-to-run variation',
  'model-unverified': 'Model not observed comparably', 'held-across-model-change': 'Held across a model change', 'failed-across-model-change': 'Failed across a model change', 'no-change': 'No change', incompatible: 'Not comparable' };
const attributionLabel = value => Object.hasOwn(attributionLabels, value) ? attributionLabels[value] : 'Unrecognized attribution';
function modelAttributionHtml(attribution) {
  if (attribution?.state === 'recorded') return `<h2>Model attribution</h2><p>Verdict changes are attributed to: ${escape(attribution.flipCause ? attributionLabel(attribution.flipCause) : 'nobody (the runs are not comparable)')}. Model ${escape(attribution.relation)} (${escape(attribution.strength)}); application ${escape(attribution.app?.basis)}.${attribution.repairCreditedToApp ? ' The repairs are credited to the application.' : ''}</p>${(attribution.caveats || []).map(caveat => `<p><small>${escape(caveat)}</small></p>`).join('')}<p><small>${escape(attribution.scope)}</small></p>`;
  if (attribution?.state === 'not-recorded') return `<h2>Model attribution</h2><p>${escape(attribution.note)}${attribution.malformed?.length ? ` A model identity was present but could not be read (${escape(attribution.malformed.join(', '))}).` : ''}</p>`;
  return '';
}
function comparisonAllowedUseHtml(entry) {
  if (!entry) return '';
  const listed = entry.newlyOverBlocked.length ? `Newly over-blocked controls (pass in baseline, fail in candidate${entry.comparable ? '' : '; runs are not comparable, so this is not a verified regression'}): ${entry.newlyOverBlocked.join(', ')}.` : 'No allowed-use control went from pass to fail.';
  const admitted = entry.newlyFailedByAdmission?.length ? ` Newly failed by an app-log admission, not over-blocking (the application's own action log records a forbidden action): ${entry.newlyFailedByAdmission.join(', ')}.` : '';
  return `<p>Candidate: ${escape(allowedUseLabel(entry.candidate))}<br>Baseline: ${escape(allowedUseLabel(entry.baseline))}<br>${escape(listed + admitted)} <small>${escape(ALLOWED_USE_PURPOSE)}</small></p>`;
}
function comparisonCustodyHtml(rows) {
  const marked = rows.filter(row => row.custody && typeof row.custody === 'object');
  if (!marked.length) return '';
  const side = entries => Array.isArray(entries) && entries.length ? entries.map(custodySentence).join(' ') : 'no observed-effect clauses';
  return `<h2>Record custody</h2><ul>${marked.map(row => `<li>${escape(row.id)}. Candidate: ${escape(side(row.custody.candidate))} Baseline: ${escape(side(row.custody.baseline))}</li>`).join('')}</ul><p><small>${escape(CUSTODY_RULE)} ${escape(CONTROL_CUSTODY_LIMIT)}</small></p>`;
}
function comparisonChannelsHtml(rows) {
  const marked = rows.filter(row => row.channels && typeof row.channels === 'object');
  if (!marked.length) return '';
  const side = reasons => Array.isArray(reasons) && reasons.length ? `read inconclusive (${reasons.join(', ')})` : 'not withheld on declared channels';
  return `<h2>Declared channels</h2><ul>${marked.map(row => `<li>${escape(row.id)}. Candidate: ${escape(side(row.channels.candidate))}. Baseline: ${escape(side(row.channels.baseline))}.</li>`).join('')}</ul>`;
}
function comparisonAbsenceScopeHtml(rows) {
  const marked = rows.filter(row => row.absenceScope && typeof row.absenceScope === 'object');
  if (!marked.length) return '';
  const side = notes => Array.isArray(notes) && notes.length ? notes.join(' ') : 'no absence pass an egress recorder or SMTP sink decided';
  const note = typeof marked[0].absenceScope.note === 'string' ? marked[0].absenceScope.note : ABSENCE_SCOPE_RULE;
  return `<h2>Absence scope</h2><ul>${marked.map(row => `<li>${escape(row.id)}. Candidate: ${escape(side(row.absenceScope.candidate))} Baseline: ${escape(side(row.absenceScope.baseline))}</li>`).join('')}</ul><p><small>${escape(note)}</small></p>`;
}
// What each side did not show, in brief (the full residual of each run is in the comparison JSON and each run's report).
function comparisonResidualHtml(doc) {
  if (!doc.residual || !doc.claims) return '';
  const side = (label, r, counts) => {
    const notShown = r.channels?.declared ? [...r.channels.unobserved.map(c => `${c.id} not observed in ${c.rows.join(', ')}`), ...r.channels.unaccounted.map(c => `${c.id} carried an unaccounted effect in ${c.rows.join(', ')}`),
      ...r.channels.unlisted.map(u => `observer ${u.observer}, which no channel lists, recorded an effect in ${u.rows.join(', ')}`), ...r.channels.controls.map(x => `allowed-use control ${x.id}'s absence not supported (${x.reasons.join(', ')})`), ...(r.channels.gap ? [r.channels.gap] : [])] : [];
    const channels = r.channels === null ? '' : !r.channels.declared ? ' Channels undeclared.' : notShown.length ? ` Channels: ${notShown.join('; ')}.` : ' Every declared channel observed.';
    const unpaired = r.controls.notPassed.length + (r.controls.unpairedPasses?.checks.length ?? 0) + r.controls.unpairedSelectors.length;
    return `<li>${escape(label)}: ${escape(claimCountsText(counts))} ${escape(r.inconclusive.length ? `Read inconclusive: ${r.inconclusive.map(e => `${e.id} (${e.reasons.join(', ')})`).join(', ')}.` : 'No check reads inconclusive.')}${escape(channels)} ${escape(unpaired ? `${unpaired} allowed-use pairing item${unpaired === 1 ? '' : 's'} did not hold.` : 'Allowed-use pairing held.')} ${escape(r.observers.length ? `Observers not running or incomplete: ${r.observers.map(o => `${o.type} ${o.id}`).join(', ')}.` : r.observersDeclared === null ? 'Observers are not read for this evidence origin.' : r.observersDeclared ? 'Every declared observer ran in full.' : 'No observers declared.')}</li>`;
  };
  return `<h2>Coverage and residual</h2>${comparisonCoverageHtml(doc.coverage)}<h3>Residual</h3><ul>${side('Candidate', doc.residual.candidate, doc.claims.candidate)}${side('Baseline', doc.residual.baseline, doc.claims.baseline)}</ul><p><small>${escape(RESIDUAL_NOTE)} ${escape(doc.claims.rule)}</small></p>`;
}
export function renderComparisonReport(doc) {
  const { baseline, candidate, comparison } = doc, summary = comparison.summary;
  const verdict = doc.verdict === 'comparable-controls-passed' ? 'Comparable runs. Every required allowed-use control passed in the candidate.' : 'Not verified. No row in this comparison establishes a verified repair.';
  const fields = ['runId', ...comparisonIdentityKeys, 'evidenceIntegritySha256'];
  const identityRows = fields.map(key => `<tr><td>${escape(key)}</td><td>${escape(baseline[key])}</td><td>${escape(candidate[key])}</td><td>${baseline[key] === candidate[key] ? 'same' : 'differs'}</td></tr>`).join('');
  const attributed = comparison.rows.some(row => typeof row.attribution === 'string'), unreadable = comparison.modelAttribution?.malformed?.length > 0;
  const claimed = comparison.rows.some(row => row.claim && typeof row.claim === 'object'), claimText = claim => claim?.type ?? 'not recorded';
  const counts = run => run.counts ? `${run.counts.pass} passed · ${run.counts.fail} failed · ${run.counts.inconclusive} inconclusive · ${run.counts.error} errors · ${run.counts.not_applicable || 0} not applicable` : 'Counts unavailable';
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Scopehaven comparison ${escape(baseline.runId)} to ${escape(candidate.runId)}</title><style>body{font:16px/1.6 system-ui;margin:40px auto;max-width:1050px;padding:0 24px;color:#132c40}h1,h2{line-height:1.2}table{border-collapse:collapse;width:100%}td,th{padding:9px;text-align:left;border-bottom:1px solid #dfe8ed;overflow-wrap:anywhere}small{color:#536875}.coverage-gap{color:#b91c1c}</style><h1>Scopehaven comparison</h1><p><strong>${escape(candidate.scope)}</strong></p><p>${escape(comparison.evidenceScope)}</p><p><strong>${escape(verdict)}</strong></p>${comparison.reasons.length ? `<h2>Reasons</h2><ul>${comparison.reasons.map(reason => `<li>${escape(reason)}</li>`).join('')}</ul>` : ''}<p>${escape(summary.fixed)} ${escape(restorationText(comparison))} · ${escape(summary.stillFailing)} still failing · ${escape(summary.newFailures)} new failures · ${escape(summary.preservedPasses)} preserved passes · ${escape(summary.unverified)} unverified · ${escape(summary.notApplicable || 0)} not applicable</p>${comparisonAllowedUseHtml(doc.allowedUse)}<p>${escape(doc.interpretation)} ${escape(doc.certification)}</p><h2>Run identities</h2><p>Baseline: ${escape(baseline.targetName)} · ${escape(counts(baseline))}<br>Candidate: ${escape(candidate.targetName)} · ${escape(counts(candidate))}</p><table><thead><tr><th>Field</th><th>Baseline</th><th>Candidate</th><th>Match</th></tr></thead><tbody>${identityRows}</tbody></table>${modelAttributionHtml(comparison.modelAttribution)}<h2>Checks</h2><table><thead><tr><th>Check</th><th>Title</th><th>Before</th><th>After</th><th>Transition</th>${attributed ? '<th>Attribution</th>' : ''}${claimed ? '<th>Claim (before / after)</th>' : ''}</tr></thead><tbody>${comparison.rows.map(row => `<tr><td>${escape(row.id)}</td><td>${escape(row.title)}</td><td>${escape(row.before)}</td><td>${escape(row.after)}</td><td>${escape(row.transition)}${repairTransitions.includes(row.transition) && (unreadable || (attributed && row.attribution !== 'app')) ? ' (not credited to the application)' : ''}</td>${attributed ? `<td>${escape(attributionLabel(row.attribution))}</td>` : ''}${claimed ? `<td>${escape(`${claimText(row.claim?.baseline)} / ${claimText(row.claim?.candidate)}`)}</td>` : ''}</tr>`).join('')}</tbody></table>${comparisonResidualHtml(doc)}${comparisonCustodyHtml(comparison.rows)}${comparisonAbsenceScopeHtml(comparison.rows)}${comparisonChannelsHtml(comparison.rows)}<p><small>Target build and configuration identities are expected to differ between a baseline and its repair. Suite, policy, fixture, evaluator and profile identities must match. Evidence hashes are local integrity checksums, not independently signed attestations.</small></p></html>`;
}
