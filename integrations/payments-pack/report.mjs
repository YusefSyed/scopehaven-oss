// The payments pack's HTML report: one self-contained page per run (no script, no external asset), and the
// before/after comparison when a baseline is given. Every value is escaped; an agent's reply is shown as text.
// Its SARIF 2.1.0 projection (renderPaymentsSarif) is below the report.
import { escape } from '../../src/report.mjs';
import { SARIF_SCHEMA, SARIF_VERSION, CERTIFICATION_STATEMENT, MAPPING_STATEMENT } from '../../src/sarif.mjs';
import { digest } from '../../src/domain.mjs';
import packageInfo from '../../package.json' with { type: 'json' };
import { LLM06, PAYMENTS_SCOPE } from './pack.mjs';

const money = (amount, currency) => `${(amount / 100).toFixed(2)} ${currency ? String(currency).toUpperCase() : '(currency unknown)'}`;
const BADGE = { pass: '#1f7a3a', fail: '#b42318', inconclusive: '#8a6100', 'verified repair': '#1f7a3a', 'still passing': '#475467', 'no verified repair': '#b42318', 'control holds': '#1f7a3a', 'control broken': '#b42318', regression: '#b42318', 'not decided': '#8a6100', 'passes now, baseline not decided': '#8a6100' };
const badge = text => `<span class="badge" style="background:${BADGE[text] ?? '#475467'}">${escape(text)}</span>`;

function ledgerBlock(row) {
  const refunds = row.ledger?.refunds ?? [], charges = row.ledger?.charges ?? [];
  const lines = refunds.length
    ? `<table><thead><tr><th>Refund</th><th>Charge</th><th>Amount</th><th>To original method</th><th>Request #</th></tr></thead><tbody>${refunds.map(r => `<tr><td><code>${escape(r.id)}</code></td><td><code>${escape(r.charge)}</code></td><td>${escape(money(r.amount, r.currency))}</td><td>${r.toOriginalMethod ? 'yes' : '<strong>no</strong>'}</td><td>${escape(r.requestSeq)}</td></tr>`).join('')}</tbody></table>`
    : '<p>No new refund was committed in this window.</p>';
  const refused = (row.ledger?.asks ?? []).filter(a => !a.committed);
  const refusedLine = refused.length ? `<p>Refused by the provider, still the agent's request: ${refused.map(a => `<code>${escape(a.charge)}</code> ${escape(a.amount === null ? 'unknown amount' : money(a.amount, a.currency))}${a.toOriginalMethod ? '' : ' to another destination'}`).join(', ')}.</p>` : '';
  const payouts = row.ledger?.payouts ?? [];
  const payoutLine = payouts.length ? `<p><strong>${escape(payouts.length)} payout${payouts.length === 1 ? '' : 's'}</strong> to a destination outside any charge (request ${payouts.map(p => escape(p.requestSeq)).join(', ')}).</p>` : '';
  return `${lines}${refusedLine}${payoutLine}<p class="muted">${escape(row.ledger?.attempts ?? 0)} refund request${row.ledger?.attempts === 1 ? '' : 's'} reached the provider${charges.length ? `; ${escape(charges.length)} new charge${charges.length === 1 ? '' : 's'}` : ''}. Window coverage: ${escape(row.coverage)}${row.coverageReason ? ` (${escape(row.coverageReason)})` : ''}.</p>`;
}

function rowCard(row) {
  return `<section class="row ${escape(row.status)}">
<h3>${badge(row.status)} <code>${escape(row.id)}</code> <span class="muted">${escape(row.severity === 'control' ? 'allowed-use control' : 'boundary')} · as ${escape(row.principalId)}</span></h3>
<p class="rule"><strong>Rule.</strong> ${escape(row.rule)}</p>
<div class="cols"><div><h4>What the agent said</h4><blockquote>${escape(row.agentSaid || '(no reply)')}</blockquote><p class="muted">${escape(row.request.method)} ${escape(row.request.path)} → ${escape(row.replyStatus ?? 'no answer')}</p></div>
<div><h4>What the ledger shows</h4>${ledgerBlock(row)}</div></div>
${row.reach && !row.reach.reached ? `<p class="fix"><strong>Not reached.</strong> ${escape(row.reach.basis)}</p>` : ''}
<ul class="assertions">${row.assertions.map(a => `<li>${badge(a.status)} <code>${escape(a.assertion)}${a.charge ? ` ${escape(a.charge)}` : ''}</code>: ${escape(a.basis)}</li>`).join('')}</ul>
${(row.settlement ?? []).length ? `<p class="muted">Settlement: ${row.settlement.map(f => `<span class="tag">${escape(f.code)} · ${escape(f.assertion)} · ${escape(f.effect === 'tag' ? 'tag (a control keeps its verdict)' : 'pass withheld')}</span>`).join(' ')}</p>` : ''}
<p class="muted">${row.standards.map(s => `<span class="tag">${escape(s)}</span>`).join(' ')}</p>
${row.status !== 'pass' && row.fix ? `<p class="fix"><strong>Suggested fix.</strong> ${escape(row.fix)}</p>` : ''}
</section>`;
}

function comparisonBlock(c) {
  if (!c) return '';
  return `<section class="compare"><h2>Before and after ${badge(c.verdict)}</h2>
<p>${escape(c.reason)} Baseline <code>${escape(c.baseline.id)}</code>${c.baseline.build ? ` (build ${escape(c.baseline.build)})` : ''} → this run <code>${escape(c.candidate.id)}</code>${c.candidate.build ? ` (build ${escape(c.candidate.build)})` : ''}.</p>
${c.compatible ? `<table><thead><tr><th>Check</th><th>Before</th><th>After</th><th>Label</th></tr></thead><tbody>${c.rows.map(r => `<tr><td><code>${escape(r.id)}</code></td><td>${escape(r.baseline ?? '—')}</td><td>${escape(r.candidate)}</td><td>${badge(r.label)}</td></tr>`).join('')}</tbody></table>`
    : '<p>The runs are not comparable, so no row is labelled.</p>'}
<p class="muted">A failing boundary that passes now is a verified repair only when both runs used the same pack and every allowed-use control still passes: an agent that refuses everything also stops the bad refunds.</p></section>`;
}

export function renderPaymentsReport(run, comparison = null) {
  const a = run.authorization;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ScopeHaven payments report · ${escape(run.name)}</title>
<style>body{font:15px/1.5 -apple-system,system-ui,sans-serif;max-width:980px;margin:24px auto;padding:0 16px;color:#101828;background:#fff}
h1{font-size:22px;margin:0 0 4px}h2{font-size:18px;margin:28px 0 8px}h3{font-size:16px;margin:0 0 8px}h4{font-size:13px;text-transform:uppercase;letter-spacing:.04em;color:#475467;margin:8px 0 4px}
.muted{color:#475467;font-size:13px}.badge{color:#fff;border-radius:4px;padding:1px 7px;font-size:12px;font-weight:600;white-space:nowrap}
.tag{border:1px solid #d0d5dd;border-radius:4px;padding:0 6px;font-size:12px}.row{border:1px solid #d0d5dd;border-left-width:5px;border-radius:6px;padding:12px 16px;margin:12px 0}
.row.fail{border-left-color:#b42318}.row.pass{border-left-color:#1f7a3a}.row.inconclusive{border-left-color:#8a6100}
.cols{display:grid;grid-template-columns:1fr 1fr;gap:16px}@media(max-width:700px){.cols{grid-template-columns:1fr}}
blockquote{margin:0;padding:8px 12px;background:#f2f4f7;border-radius:4px;white-space:pre-wrap;overflow-wrap:anywhere}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;border-bottom:1px solid #eaecf0;padding:4px 6px}
.fix{background:#fffaeb;border-radius:4px;padding:6px 10px}.summary span{margin-right:14px}code{font-size:12.5px;overflow-wrap:anywhere}ul.assertions{padding-left:18px;margin:8px 0}</style></head><body>
<h1>${escape(run.name)}</h1>
<p class="muted">Run <code>${escape(run.id)}</code> · target <code>${escape(run.targetId)}</code>${run.build ? ` · build <code>${escape(run.build)}</code>` : ''} · ${escape(run.startedAt)}</p>
<p><strong>Scope.</strong> ${escape(run.scope || PAYMENTS_SCOPE)} Verdicts come from the ${escape(run.provider.kind.replace('stripe-shaped ', ''))} (${escape(run.provider.host)}, livemode false), never from the agent's reply or the app's own records.</p>
<p class="muted">${a ? `Authorized by record <code>${escape(a.id)}</code> (sha256 ${escape(String(a.sha256).slice(0, 12))}…, an unkeyed integrity checksum, not a signature). The run refuses to start without a record that covers its target, app origin and test accounts.` : 'No authorization record.'} Pack sha256 ${escape(String(run.packSha256).slice(0, 12))}… · run sha256 ${escape(String(run.sha256).slice(0, 12))}….</p>
<p class="summary">${badge(run.counts.fail ? 'fail' : run.counts.inconclusive ? 'inconclusive' : 'pass')} <span>${escape(run.counts.pass)} pass</span><span>${escape(run.counts.fail)} fail</span><span>${escape(run.counts.inconclusive)} inconclusive</span></p>
${comparisonBlock(comparison)}
<h2>Checks</h2>
${run.rows.map(rowCard).join('\n')}
<h2>Limits</h2>
<ul class="muted"><li>A Stripe-shaped test-mode subset: charges, refunds and payouts. No payment intents, customers, disputes or webhooks.</li>
<li>Each row's window closes when the app's witness route sends the window's nonce through its payment client; a window it does not close reads inconclusive. A row passes only when the app answered its check request with a 2xx.</li>
<li>Settlement: after the last check the run waits the settle once more, takes a final mark and reads the gaps between checks${run.settlement ? ` (${escape(run.settlement.gaps.length)} gap windows: ${escape(run.settlement.gaps.filter(g => g.coverage === 'complete').length)} complete, ${escape(run.settlement.gaps.reduce((n, g) => n + g.refundRequests, 0))} refund requests between checks, ${escape(run.settlement.afterFinalMark.refunds.length)} refunds committed after the final mark)` : ''}. A refund recorded after a check's window that could change its verdict withholds a boundary's pass; a control keeps its verdict and carries a tag. Effects after the run are outside every window.</li>
<li>The saved run is a report of what the observer saw. The windows that decided it live only in the observer's process; this file is not a portable proof.</li>
<li>Synthetic customers, tokens and payment methods. No live money, no real provider, no production assurance.</li></ul>
</body></html>
`;
}

// SARIF 2.1.0 projection of one saved payments run (scopehaven-payments-run/1), in src/sarif.mjs's shape and scope wording. Pure
// and deterministic: the same run always gives the same bytes. Each result's kind is the row's saved status (pass, fail, or
// inconclusive as kind open), which the pack decided from the payments double's provider ledger when the run was made; nothing is
// recomputed here, so no label can be upgraded. The agent's reply is not carried, since no verdict rests on it. Standards: the pack
// names OWASP LLM06:2025 on its rows as reviewer vocabulary; a boundary row carries it as a relevant taxonomy reference, and an
// allowed-use control carries none (src/sarif.mjs never tags a control either). The run is one integrations/payments-pack/output.mjs
// savedPaymentsRun accepted: a payments run with readable rows and counts that are its rows' statuses. The scope stated is the pack's
// own (PAYMENTS_SCOPE, which savedPaymentsRun requires), never text read from the file. The location-scope sentence repeats
// src/sarif.mjs's LOCATION_SCOPE, which that module does not export.
const SARIF_OUTCOMES = Object.freeze({ pass: { kind: 'pass', label: 'PASS' }, fail: { kind: 'fail', label: 'FAIL' }, inconclusive: { kind: 'open', label: 'INCONCLUSIVE' } });
const SARIF_FAIL_LEVELS = Object.freeze({ boundary: 'error', control: 'warning' });
const OWASP_LLM_2025 = Object.freeze({ name: 'OWASP Top 10 for LLM Applications', version: '2025', organization: 'OWASP' });
const LLM06_ID = 'LLM06:2025';
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;
const plainObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const words = (value, fallback) => typeof value === 'string' && value.trim() ? value : fallback;
const sentence = value => /[.!?]$/.test(value) ? value : `${value}.`;
const pascal = id => id.split(/[-_]+/).filter(Boolean).map(w => w[0].toUpperCase() + w.slice(1)).join('') || id;
const count = list => Array.isArray(list) ? list.length : 0;
const tally = statuses => {
  const counts = {};
  for (const status of statuses) { const key = typeof status === 'string' ? status : 'unrecognized'; counts[key] = (counts[key] || 0) + 1; }
  return Object.fromEntries(Object.keys(counts).sort().map(key => [key, counts[key]]));
};
const scalars = value => plainObject(value) ? Object.fromEntries(Object.entries(value).filter(([, v]) => v === null || ['string', 'number', 'boolean'].includes(typeof v))) : null;
export const PAYMENTS_VERDICT_SOURCE = "Each row's status is copied from the saved run, where the payments pack decided it from the payments double's provider ledger, never from the agent's reply or the app's own records. This export recomputes and upgrades nothing.";
const PAYMENTS_LIMITATIONS = Object.freeze([
  'A Stripe-shaped test-mode subset: charges, refunds and payouts. No payment intents, customers, disputes or webhooks.',
  "Each row's window closes when the app's witness route sends the window's nonce through its payment client; a window it does not close reads inconclusive. A row passes only when the app answered its check request with a 2xx.",
  "A refund recorded after a check's window that could change its verdict withholds a boundary's pass; a control keeps its verdict and carries a tag. Effects after the run are outside every window.",
  "The windows that decided each row lived only in the observer's process: the saved run is a report of what the observer saw, not a portable proof.",
  'Synthetic customers, tokens and payment methods. No live money, no real provider, no production assurance.']);

export function renderPaymentsSarif(run) {
  const checks = run.rows, applicationId = words(run.applicationId, 'unidentified-application'), targetId = words(run.targetId, 'unidentified-target');
  const mapped = row => row.severity === 'boundary' && Array.isArray(row.standards) && row.standards.includes(LLM06);
  const tagged = checks.some(mapped);
  const rules = checks.map(row => {
    const control = row.severity === 'control', standard = mapped(row);
    return {
      id: row.id,
      name: pascal(row.id),
      shortDescription: { text: sentence(words(row.rule, row.id)) },
      fullDescription: { text: `Expected: ${sentence(words(row.rule, 'No rule was recorded'))} Judged from the payments provider ledger.` },
      help: { text: words(row.fix, 'No remediation guidance was recorded for this check.') },
      defaultConfiguration: { level: SARIF_FAIL_LEVELS[row.severity] },
      ...(standard ? { relationships: [{ target: { id: LLM06_ID, index: 0, toolComponent: { name: OWASP_LLM_2025.name, index: 0 } }, kinds: ['relevant'] }] } : {}),
      properties: { category: 'Payments', severity: row.severity, checkRole: control ? 'allowed-use-control' : 'prohibited-behaviour',
        tags: control ? ['allowed-use-control', 'payments'] : ['security', 'payments', ...(standard ? [`OWASP-${LLM06_ID}`] : [])],
        standards: standard ? { owaspLlm2025: [LLM06_ID], cwe: [] }
          : { owaspLlm2025: [], cwe: [], note: control ? 'An allowed-use control carries no standards mapping.' : 'No reviewed standards mapping for this check.' } },
    };
  });
  const targetName = `${applicationId}/${targetId}`;
  const logicalLocations = [
    { name: applicationId, fullyQualifiedName: applicationId, kind: 'namespace' },
    { name: targetId, fullyQualifiedName: targetName, kind: 'module', parentIndex: 0 },
    ...checks.map(row => ({ name: row.id, fullyQualifiedName: `${targetName}/${row.id}`, kind: 'member', parentIndex: 1 })),
  ];
  const results = checks.map((row, index) => {
    const outcome = SARIF_OUTCOMES[row.status], control = row.severity === 'control';
    const named = status => row.assertions.filter(a => a?.status === status && typeof a.assertion === 'string').map(a => `${a.assertion}${typeof a.charge === 'string' ? ` ${a.charge}` : ''}`);
    const detail = row.status === 'fail' ? named('fail') : row.status === 'inconclusive' ? named('inconclusive') : [];
    const detailText = detail.length ? ` ${row.status === 'fail' ? 'Failed' : 'Unverified'} assertions: ${detail.slice(0, 5).join('; ')}${detail.length > 5 ? `; and ${detail.length - 5} more` : ''}.` : '';
    const notReached = plainObject(row.reach) && row.reach.reached === false ? ` Not reached: ${sentence(words(row.reach.basis, 'the check request got no 2xx answer'))}` : '';
    const coverage = typeof row.coverage === 'string' && row.coverage !== 'complete' ? ` Window coverage: ${row.coverage}${typeof row.coverageReason === 'string' ? ` (${row.coverageReason})` : ''}.` : '';
    const ledger = plainObject(row.ledger) ? row.ledger : {};
    const settlement = Array.isArray(row.settlement) ? row.settlement.filter(plainObject) : [];
    // The settlement caveat the HTML report shows beside the row: a control's tags (it keeps its verdict), a boundary's withheld pass.
    const settled = settlement.map(f => `${f.code} on ${f.assertion}`);
    const settledText = settled.length ? ` ${control ? 'Settlement tags' : 'Pass withheld by settlement'}: ${settled.slice(0, 5).join('; ')}${settled.length > 5 ? `; and ${settled.length - 5} more` : ''}${control ? ' (a control keeps its verdict)' : ''}.` : '';
    return {
      ruleId: row.id,
      ruleIndex: index,
      kind: outcome.kind,
      level: outcome.kind === 'fail' ? SARIF_FAIL_LEVELS[row.severity] : 'none',
      message: { text: `${outcome.label}: ${sentence(words(row.rule, row.id))} Decided from the payments provider ledger.${detailText}${notReached}${coverage}${settledText}` },
      locations: [{ logicalLocations: [{ index: index + 2, name: row.id, fullyQualifiedName: logicalLocations[index + 2].fullyQualifiedName, kind: 'member' }] }],
      fingerprints: { 'scopehavenPaymentsCheck/v1': digest({ applicationId, targetId, checkId: row.id }) },
      properties: { scopehavenStatus: row.status, severity: row.severity, checkRole: control ? 'allowed-use-control' : 'prohibited-behaviour',
        principalId: typeof row.principalId === 'string' ? row.principalId : null,
        request: { method: typeof row.request.method === 'string' ? row.request.method : null, path: typeof row.request.path === 'string' ? row.request.path : null },
        replyStatus: Number.isSafeInteger(row.replyStatus) ? row.replyStatus : null, reached: plainObject(row.reach) && typeof row.reach.reached === 'boolean' ? row.reach.reached : null,
        coverage: typeof row.coverage === 'string' ? row.coverage : null, coverageReason: typeof row.coverageReason === 'string' ? row.coverageReason : null,
        assertions: tally(row.assertions.map(a => a?.status)),
        ...(settlement.length ? { settlement: settlement.map(f => ({ code: f.code ?? null, assertion: f.assertion ?? null, effect: f.effect ?? null })) } : {}),
        ledger: { refundsCommitted: count(ledger.refunds), refundRequests: Number.isSafeInteger(ledger.attempts) ? ledger.attempts : 0,
          refusedAsks: Array.isArray(ledger.asks) ? ledger.asks.filter(a => plainObject(a) && a.committed === false).length : 0, payouts: count(ledger.payouts), newCharges: count(ledger.charges) },
        verdictSource: 'provider-ledger' },
    };
  });
  const s = plainObject(run.settlement) ? run.settlement : null, gaps = Array.isArray(s?.gaps) ? s.gaps.filter(plainObject) : [];
  const after = plainObject(s?.afterFinalMark) ? s.afterFinalMark : {};
  const properties = {
    runId: run.id, schema: run.schema, targetId: run.targetId ?? null, applicationId: run.applicationId ?? null, name: run.name ?? null, build: run.build ?? null,
    packSha256: run.packSha256 ?? null, startedAt: run.startedAt ?? null, finishedAt: run.finishedAt ?? null,
    provider: { kind: run.provider.kind, host: run.provider.host ?? null, livemode: run.provider.livemode },
    authorization: scalars(run.authorization),
    ...(plainObject(run.authorization) ? { authorizationNote: "The record's sha256 is an unkeyed integrity checksum, not a signature. The run refused to start without a record that covers its target, app origin and test accounts." } : {}),
    checksTotal: checks.length, counts: Object.fromEntries(Object.keys(run.counts).sort().map(key => [key, run.counts[key]])),
    evidenceIntegrity: { algorithm: 'SHA-256', sha256: run.sha256, scope: 'An unkeyed checksum of the canonical JSON of every run field but sha256 (a comparison stored beside the run is outside it). It catches a careless edit, not one that recomputes it.' },
    scope: PAYMENTS_SCOPE, certification: CERTIFICATION_STATEMENT, verdictSource: PAYMENTS_VERDICT_SOURCE,
    settlement: s ? { finalMark: s.finalMark === true, settleMs: Number.isSafeInteger(s.settleMs) ? s.settleMs : null, gapWindows: gaps.length, gapWindowsComplete: gaps.filter(g => g.coverage === 'complete').length,
      refundRequestsBetweenChecks: gaps.reduce((n, g) => n + (Number.isSafeInteger(g.refundRequests) ? g.refundRequests : 0), 0), refundsAfterFinalMark: count(after.refunds), payoutsAfterFinalMark: count(after.payouts),
      unplacedRefunds: Number.isSafeInteger(s.unplacedRefunds) ? s.unplacedRefunds : null, unplacedPayouts: Number.isSafeInteger(s.unplacedPayouts) ? s.unplacedPayouts : null } : null,
    limitations: [...PAYMENTS_LIMITATIONS],
    locationScope: 'Logical locations only (application, target and check). No source-file location is claimed.',
    outcomeMapping: { fail: 'kind fail; level error for a boundary, warning for an allowed-use control', pass: 'kind pass; level none', inconclusive: 'kind open; level none' },
    standards: { statement: MAPPING_STATEMENT, relationship: 'relevant', source: 'The pack names OWASP LLM06:2025 on its rows; a boundary row carries it, an allowed-use control carries none.',
      identity: 'Outside the pack and run checksums; tags never change run comparability.' },
  };
  return {
    $schema: SARIF_SCHEMA,
    version: SARIF_VERSION,
    runs: [{
      tool: { driver: { name: 'Scopehaven', fullName: 'Scopehaven payments pack: refund and payout checks of an AI agent, judged from a payments provider ledger', version: packageInfo.version, semanticVersion: packageInfo.version, rules } },
      automationDetails: { id: `scopehaven/payments/${applicationId}/${targetId}/${run.id}` },
      invocations: [{ executionSuccessful: true, ...(ISO_UTC.test(run.startedAt ?? '') ? { startTimeUtc: run.startedAt } : {}), ...(ISO_UTC.test(run.finishedAt ?? '') ? { endTimeUtc: run.finishedAt } : {}) }],
      ...(tagged ? { taxonomies: [{ ...OWASP_LLM_2025, taxa: [{ id: LLM06_ID }] }] } : {}),
      logicalLocations,
      results,
      properties,
    }],
  };
}
