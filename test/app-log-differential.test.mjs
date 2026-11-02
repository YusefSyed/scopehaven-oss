// What an app log may change: over the existing example corpus (the onboarding profiles in docs/profiles
// and the collateral refund-only profile), each profile is run against the same example app build three times: as shipped, with
// an app log declared on the app's own action log with "use": "record", and with "use": "admission".
//   record     every row's status, decision, backend evidence and assertions (custody, settlement, attribution and pairing tags
//              included) are identical; only the run record's appLogs entry, data.appLogWindows and the limitation line differ;
//   admission  the only differences are admissions: a clause that did not fail as shipped now fails carrying app-log-unobserved-
//              admission, its row may then fail and lose backend observation, and nothing else moves (never toward a pass).
// The run without the declaration carries no app-log field at all. The leaky-owner-audit build (the app audits a cross-company
// refund under the order owner's name, while its action log names who did it) shows an admission. Loopback, synthetic data, a
// fixed-text assistant: no model, no provider.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateHttpRunEvidence } from '../src/contracts.mjs';
import { createObservedSupportApp, bindExampleProfile } from '../examples/observed-support-app.mjs';

const CORPUS = [
  ...['sqlite-audit', 'http-audit', 'sqlite-snapshot', 'egress-recorder', 'response-only'].map(name => ({ name, path: `../docs/profiles/${name}.example.json`, builds: ['secure', 'leaky'] })),
  { name: 'refund-only', path: '../integrations/collateral/refund-only.profile.json', builds: ['refund-plus-discount'] },
  ...['sqlite-audit', 'http-audit'].map(name => ({ name, path: `../docs/profiles/${name}.example.json`, builds: ['leaky-owner-audit'], admits: true })),
];
// The example app's action log (examples/observed-support-app.mjs): { id, event, actor, target, result, ts }.
const APP_LOG = { id: 'actions', use: 'record', log: { file: { path: '/bound/by/bindExampleProfile' } },
  fields: { action: '/event', outcome: '/result', actor: '/actor', at: '/ts', id: '/id' }, outcomes: { committed: ['ok'] },
  rules: [
    { action: 'refund.create', operation: 'insert', vocabulary: 'named', name: 'refund.create', resource: { from: '/target' }, observedAs: ['sql-audit-table', 'http-audit-log'] },
    { action: 'payment.sent', operation: 'send', vocabulary: 'egress', name: 'payments.example', resource: 'POST *', observedAs: ['http-egress'] },
    { action: 'discount.create', operation: 'insert', vocabulary: 'named', name: 'discounts' },
    { action: 'subscription.cancel', operation: 'update', vocabulary: 'named', name: 'subscriptions' },
  ],
  logActors: { 'agent-a': 'agent-a', 'agent-b': 'agent-b' } };
const decisions = run => ({ counts: run.counts, rows: run.results.map(r => ({ id: r.id, status: r.status, decision: r.decision ?? null, backendEvidence: r.backendEvidence, summary: r.summary, assertions: r.assertions,
  effects: r.trace[1]?.data?.effects ?? null, claims: r.trace[1]?.data?.claims ?? null })) });
const admittedAssertion = a => a?.status === 'fail' && a?.appLog?.finding === 'app-log-unobserved-admission';
// Every difference between the shipped run and the admission run is an admission; returns how many clauses were admitted.
function onlyAdmissions(plain, declared) {
  let admitted = 0;
  assert.equal(declared.results.length, plain.results.length);
  plain.results.forEach((p, i) => {
    const d = declared.results[i];
    assert.equal(d.id, p.id);
    const rowAdmitted = d.assertions.some(admittedAssertion);
    assert.ok(d.status === p.status || (rowAdmitted && d.status === 'fail'), `${p.id}: ${p.status} -> ${d.status}`);
    assert.ok(d.backendEvidence === p.backendEvidence || rowAdmitted, `${p.id}: backend evidence`);
    assert.equal(d.decision ?? null, p.decision ?? null, `${p.id}: decision`);
    assert.equal(d.assertions.length, p.assertions.length);
    d.assertions.forEach((a, j) => {
      const b = p.assertions[j];
      if (admittedAssertion(a)) { assert.notEqual(b.status, 'fail', `${p.id} ${a.name}: a custody fail is never re-labelled`); admitted++; return; }
      if (a.name === 'Trusted backend observation available' && rowAdmitted) return;
      assert.deepEqual(a, b, `${p.id} ${a.name}`);
    });
  });
  return admitted;
}
const appLogFields = run => [Object.hasOwn(run, 'appLogs'), run.results.some(r => Object.hasOwn(r.trace[1]?.data ?? {}, 'appLogWindows')), run.limitations.some(l => l.startsWith('App action logs'))];

for (const { name, path, builds, admits = false } of CORPUS) for (const build of builds) {
  test(`${name} on ${build}: "record" changes no verdict, "admission" changes only by admissions`, async t => {
    const file = JSON.parse(await readFile(new URL(path, import.meta.url), 'utf8'));
    const principals = new Set(Object.values(file.targets[0].actors).map(a => a.principalId));
    const declare = use => { const withLog = structuredClone(file); withLog.targets[0].appLogs = [{ ...structuredClone(APP_LOG), use, logActors: Object.fromEntries(Object.entries(APP_LOG.logActors).filter(([p]) => principals.has(p))) }]; return withLog; };
    const withLog = declare('record');
    const egress = (file.targets[0].observers ?? []).some(o => o.type === 'egress-recorder');
    // One app per run, so both start from the same state.
    const run = async profile => {
      const app = await createObservedSupportApp({ build, egress }); t.after(() => app.close());
      const result = await runHttpAssessment(bindExampleProfile(profile, app).targets[0], { env: app.env });
      validateHttpRunEvidence(result);
      return result;
    };
    const plain = await run(file), declared = await run(withLog), admitting = await run(declare('admission'));
    assert.deepEqual(decisions(declared), decisions(plain));
    const admitted = onlyAdmissions(plain, admitting);
    if (admits) assert.ok(admitted > 0, 'the action log names who refunded the other company\'s order: an admission');
    assert.deepEqual(appLogFields(plain), [false, false, false], 'an undeclared run carries no app-log field');
    assert.deepEqual(appLogFields(declared).slice(0, 1), [true]);
    assert.ok(declared.limitations.some(l => l.startsWith('App action logs (actions)')));
    // Every observed row carries one app-log window; the corpus' write checks put the app's own actions in them.
    const windows = declared.results.filter(r => r.trace[1]).map(r => r.trace[1].data.appLogWindows);
    assert.ok(windows.every(list => list.length === 1 && list[0].source === 'app-log' && list[0].scope.evidence === 'presence-only'));
    if (windows.length) assert.ok(windows.some(list => list[0].events.length > 0), 'the app log was read');
  });
}
