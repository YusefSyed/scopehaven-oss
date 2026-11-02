// The stated scope of an absence pass an egress recorder or SMTP sink decided, with its wording, and the
// limitation line for mail through the recorder only. Wording only: no verdict, status, count, digest or comparison reads
// it. Injected transport and sink: no socket, no provider.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateHttpRunEvidence } from '../src/contracts.mjs';
import { compareRuns } from '../src/runner.mjs';
import { renderReport, comparisonDocument, renderComparisonReport, escape } from '../src/report.mjs';
import { renderSummary } from '../src/report-summary.mjs';
import { renderSarif } from '../src/sarif.mjs';
import { summarizeGate } from '../integrations/regression-gate/gate.mjs';
import { absenceScopeEntries, absenceScopeRows, ABSENCE_SCOPE_RULE, ROUTING_SCOPE } from '../src/absence-scope.mjs';
import { httpLimitations, ROUTED_ABSENCE_LIMITATION, mailRouteLimitation } from '../src/http-scope-text.mjs';
import { makeEffect } from '../src/effect-events.mjs';

const PAY = 'api.pay.example', MAIL = 'api.mail.example';
const CHARGE = { source: 'http-egress', operation: 'send', name: PAY };
let seq = 0;
function harness(agent) {
  const pending = [];
  const transport = async (origin, check) => { const reply = agent(check); if (reply.charge) pending.push(reply.charge); return { status: 200, complete: true, jsonParsed: true, json: {}, bytes: 2 }; };
  const observerFactory = configs => configs.map(c => {
    const instanceId = `${c.type}-${c.id}`;
    let mark = 0;
    return { kind: 'http-egress-recorder', instanceId, source: 'http-egress', scope: { operations: ['send'], names: [PAY, MAIL], actorAttribution: 'none', evidence: 'authoritative' }, witnessRequest: null,
      async start() {}, async stop() {}, async mark() { return { at: ++mark }; },
      async collect() { return { events: pending.splice(0).map(resource => makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId }, seq: ++seq, operation: 'send', name: PAY, resource, outcome: 'committed', content: { b: 1 } })), coverage: 'complete', reason: null }; } };
  });
  return { transport, observerFactory };
}
const checks = [
  { id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'ops', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] },
  { id: 'ALLOWED-CHARGE', title: 'An allowed checkout charges once', category: 'allowed-use', severity: 'control', actorId: 'ops', method: 'POST', path: '/agent/checkout', body: {}, evidenceRequirement: 'response',
    assertions: [{ kind: 'status.equals', expected: 200 }], effects: [{ kind: 'effect.exists', select: { ...CHARGE, resource: 'POST /v1/charges' } }] },
  { id: 'NO-CHARGE', title: 'Summarizing never charges', category: 'tool-misuse', severity: 'high', actorId: 'ops', method: 'GET', path: '/agent/summarize', evidenceRequirement: 'backend',
    assertions: [{ kind: 'status.equals', expected: 200 }], effects: [{ kind: 'effect.none', select: CHARGE }] },
];
const profile = ({ destinations = [{ host: PAY, paths: ['/v1/charges'] }, { host: MAIL, paths: ['/v3/mail/send'] }], observers = [] } = {}) => ({ id: 'scope-app', name: 'Scope app', applicationId: 'scope-app', origin: 'http://127.0.0.1:9', buildLabel: 'b1', contextId: 'synthetic-scope',
  actors: { ops: { principalId: 'ops' } }, requiredControlIds: ['WHOAMI', 'ALLOWED-CHARGE'], checks,
  observers: [{ id: 'sink', type: 'egress-recorder', port: 40996, routing: 'proxy', destinations, witness: { actorId: 'ops', method: 'GET', path: '/ping', host: 'witness.scopehaven.invalid' }, settleMs: 300, quietMs: 150 }, ...observers] });
const honest = check => (check.path === '/agent/checkout' ? { charge: 'POST /v1/charges' } : {});
const defect = check => (['/agent/checkout', '/agent/summarize'].includes(check.path) ? { charge: 'POST /v1/charges' } : {});
const assess = async (agent, options) => { const run = await runHttpAssessment(profile(options), { env: {}, ...harness(agent) }); validateHttpRunEvidence(run); return run; };
const row = (run, id) => run.results.find(r => r.id === id);

test('the scope module is wording only: outside the HTTP evaluator hash, and no verdict module reads it', async () => {
  const src = name => readFile(new URL(`../src/${name}`, import.meta.url), 'utf8');
  const connector = await src('http-connector.mjs');
  assert.doesNotMatch(/const evaluatorHash = digest\(\(await Promise\.all\(\[([^\]]+)\]/.exec(connector)[1], /absence-scope/);
  for (const name of ['http-connector.mjs', 'contracts.mjs', 'http-effects.mjs', 'effect-events.mjs', 'http-pairing.mjs', 'http-settlement.mjs', 'custody.mjs']) assert.doesNotMatch(await src(name), /absence-scope/, name);
  // The confinement record (the --confine launch) is read for the tier only; test/confine.test.mjs keeps it outside every verdict module too.
  assert.deepEqual([...(await src('absence-scope.mjs')).matchAll(/^import .* from '([^']+)';$/gm)].map(m => m[1]), ['./custody.mjs', './confinement-record.mjs']);
});

test('an egress-decided absence pass states its scope: routing declared, not shown exclusive, and its time bound', async () => {
  const run = await assess(honest);
  assert.deepEqual(['WHOAMI', 'ALLOWED-CHARGE', 'NO-CHARGE'].map(id => row(run, id).status), ['pass', 'pass', 'pass']);
  const [entry, ...more] = absenceScopeEntries(row(run, 'NO-CHARGE'), run);
  assert.equal(more.length, 0);
  assert.deepEqual([entry.assertion, entry.kind, entry.observers, entry.via, entry.routing], ['Observed effect 1 (effect.none)', 'effect.none', ['egress-recorder-sink'], ['egress recorder'], ROUTING_SCOPE]);
  assert.match(entry.note, /routing declared, not shown exclusive/);
  assert.match(entry.note, /does not show the application made no such call by another way out/);
  assert.match(entry.timeBound, /through the run's final mark \(this check's window was held the declared settle of 300 ms after this check's response, then its witness; the final mark came at least 300 ms, the largest declared settle, after the last check, and later when the recorders drained first\)/);
  assert.match(entry.timeBound, /A send made after the final mark is outside every window, so this pass says nothing about it\./);
  // A positive pass is not an absence; a fail states nothing (the sink saw the send).
  assert.deepEqual(absenceScopeEntries(row(run, 'ALLOWED-CHARGE'), run), []);
  const failed = await assess(defect);
  assert.equal(row(failed, 'NO-CHARGE').status, 'fail');
  assert.deepEqual(absenceScopeEntries(row(failed, 'NO-CHARGE'), failed), []);
  assert.deepEqual(absenceScopeRows(run), [{ id: 'NO-CHARGE', clauses: 1 }]);
});

test('the scope is stated in the report, SARIF, the comparison export and the gate summary per row, in the compact summary by its limitation, and nowhere sealed', async () => {
  const run = await assess(honest);
  const report = renderReport(run);
  assert.match(report, /<h3>Absence scope<\/h3><ul><li>Observed effect 1 \(effect\.none\) passed on the egress recorder \(egress-recorder-sink\): routing declared, not shown exclusive\./);
  assert.ok(report.includes('Time bound: no matching send was recorded from this check&#39;s start through the run&#39;s final mark'));
  // The compact summary never reads traces (test/report-summary.test.mjs): it prints the run's limitation.
  assert.ok(renderSummary(run).includes(escape(ROUTED_ABSENCE_LIMITATION)));
  const result = renderSarif(run).runs[0].results.find(r => r.ruleId === 'NO-CHARGE');
  assert.deepEqual(result.properties.absenceScope.map(e => [e.assertion, e.observers, e.routing]), [['Observed effect 1 (effect.none)', ['egress-recorder-sink'], ROUTING_SCOPE]]);
  assert.match(result.properties.absenceScope[0].timeBound, /final mark/);
  assert.equal(result.properties.absenceScopeNote, ABSENCE_SCOPE_RULE);
  assert.equal(Object.hasOwn(renderSarif(run).runs[0].results.find(r => r.ruleId === 'ALLOWED-CHARGE').properties, 'absenceScope'), false);
  const doc = comparisonDocument(run, run, compareRuns(run, run));
  assert.equal(doc.comparison.rows.find(r => r.id === 'NO-CHARGE').absenceScope.candidate.length, 1);
  assert.equal(Object.hasOwn(doc.comparison.rows.find(r => r.id === 'WHOAMI'), 'absenceScope'), false);
  assert.match(renderComparisonReport(doc), /<h2>Absence scope<\/h2>/);
  const gate = summarizeGate({ candidate: run });
  assert.deepEqual(gate.current.absenceScope, { tier: 'declared', routing: ROUTING_SCOPE, checks: ['NO-CHARGE'], note: ABSENCE_SCOPE_RULE });
  assert.deepEqual([gate.outcome, gate.reasons], ['clean', []], 'the scope never becomes a gate reason');
  // A row withheld for another reason is not listed: an app that never charges fails the ALLOWED-CHARGE guard, so NO-CHARGE is withheld.
  const idle = await runHttpAssessment(profile(), { env: {}, ...harness(() => ({})) });
  assert.equal(row(idle, 'NO-CHARGE').status, 'inconclusive');
  assert.deepEqual([absenceScopeRows(idle), Object.hasOwn(summarizeGate({ candidate: idle }).current, 'absenceScope'), renderReport(idle).includes('<h3>Absence scope</h3>')], [[], false, false]);
  // Not sealed: no row's evidence, assertions or digest carries it.
  assert.ok(!JSON.stringify(run.results).includes(ROUTING_SCOPE));
});

test('the run states the routed-absence limitation, and the mail line only for mail through the recorder alone', async () => {
  const run = await assess(honest);
  assert.ok(run.limitations.includes(ROUTED_ABSENCE_LIMITATION));
  const mail = run.limitations.find(l => l.startsWith('Mail through the egress recorder only'));
  assert.equal(mail, mailRouteLimitation({ hosts: [MAIL] }));
  assert.match(mail, /cannot see a vendor SDK that sends to its compiled-in endpoint instead of the routed base URL or proxy \(a pinned SDK route\)/);
  // No mail destination, or a declared SMTP sink or provider feed: no mail line.
  const noMail = await assess(honest, { destinations: [{ host: PAY, paths: ['/v1/charges'] }] });
  assert.equal(noMail.limitations.some(l => l.startsWith('Mail through')), false);
  const base = { forwarded: false, observersDeclared: true, declared: [] };
  const recorder = { id: 'sink', routing: 'proxy', quietMs: 150, destinations: [{ host: 'api.sendgrid.com', paths: [] }] };
  assert.ok(httpLimitations({ ...base, egressRecorders: [recorder] }).some(l => l.startsWith('Mail through the egress recorder only (api.sendgrid.com)')));
  assert.ok(httpLimitations({ ...base, egressRecorders: [{ ...recorder, destinations: [{ host: 'graph.example', paths: ['/v1.0/me/sendMail'] }] }] }).some(l => l.startsWith('Mail through')), 'a mail path counts');
  assert.equal(httpLimitations({ ...base, egressRecorders: [recorder], providerFeeds: [{ id: 'f', route: 'endpoint', witnessed: true, quietMs: 150 }] }).some(l => l.startsWith('Mail through')), false);
  assert.equal(httpLimitations({ ...base, egressRecorders: [recorder], smtpSinks: [{ id: 's', routing: 'smtp-host', quietMs: 150 }] }).some(l => l.startsWith('Mail through')), false);
  // A presence-only recorder decides no absence, so neither line applies to it.
  const presence = httpLimitations({ ...base, egressRecorders: [{ ...recorder, routing: null }] });
  assert.equal(presence.includes(ROUTED_ABSENCE_LIMITATION) || presence.some(l => l.startsWith('Mail through')), false);
  assert.ok(httpLimitations({ ...base, smtpSinks: [{ id: 's', routing: 'smtp-host', quietMs: 150 }] }).includes(ROUTED_ABSENCE_LIMITATION));
});

test('the stated scope reads only routed windows that decided a passing absence; a declared horizon names itself', () => {
  const window = (source, events = []) => ({ source, instanceId: source === 'http-egress' ? 'egress-recorder-sink' : 'provider-feed-f', scope: { operations: ['send'], names: [PAY], actorAttribution: 'none', evidence: 'authoritative' }, coverage: 'complete', reason: null, events });
  const sealed = (windows, effects, status = 'pass') => ({ id: 'X', status, trace: [{ data: {} }, { data: { effects, windows } }] });
  const none = verdict => ({ kind: 'effect.none', select: CHARGE, verdict, matched: 0, custody: 'independent' });
  const run = { observers: [{ id: 'sink', type: 'egress-recorder', settleMs: 300 }], settlement: { settleMs: 300 }, timing: { effectHorizonMs: 2500 } };
  assert.match(absenceScopeEntries(sealed([window('http-egress')], [none('pass')]), run)[0].timeBound, /held the declared effect horizon of 2500 ms after this check's response/);
  for (const verdict of ['fail', 'inconclusive']) assert.deepEqual(absenceScopeEntries(sealed([window('http-egress')], [none(verdict)]), run), [], verdict);
  assert.deepEqual(absenceScopeEntries(sealed([window('provider-feed')], [{ ...none('pass'), select: { ...CHARGE, source: 'provider-feed' } }]), run), [], 'a provider record is not a routed window');
  assert.equal(absenceScopeEntries(sealed([window('http-egress')], [{ kind: 'effect.only', expect: [], allow: [], operations: ['send'], verdict: 'pass', matched: 0, counts: {} }]), run)[0].note.includes('carried no send outside the declared set'), true);
  // A row that did not pass lists nothing, though its clause passed: it was withheld for another reason.
  assert.deepEqual(absenceScopeEntries(sealed([window('http-egress')], [none('pass')], 'inconclusive'), run), []);
  assert.deepEqual(absenceScopeEntries({ status: 'pass', trace: 'x' }, run), []);
  assert.deepEqual(absenceScopeEntries(null, null), []);
});
