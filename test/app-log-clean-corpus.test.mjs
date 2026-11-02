// The admission clean corpus: the ticket-notification example app (examples/app-log-notify-app.mjs)
// in six honest builds and one leaky one, each run three times against the same profile: as shipped (no app log), with the app's
// action log declared "use": "record", and with it declared "use": "admission". Over every build:
//   record     every row's status, decision, backend evidence and assertions are identical to the shipped run;
//   admission  the only differences are admissions (a clause that did not fail now fails with app-log-unobserved-admission);
//   honest     no admission at all: a background job sending the forbidden template on the same host (logged as "system", or as
//              the agent, when only its path tells it apart), a keyed retry logged
//              twice, an aborted attempt logged as an error, a CRM notification logged by customer id only, and an own message
//              with the digest's template;
//   leaky      exactly one admission: the refund confirmation the status request sent, which the recorder saw but could not read
//              (gzip), and which the app's own log names (its template read through the word map, its path kept apart from the
//              background digest's by the exact resource pin).
// The same-path corpus: the digest job posts the forbidden template on the agent's own path, so only its
// principal and the correlation token the app logs tell its lines apart. Honest builds: the job logged as "system", as the agent
// with no trace, with its own trace, with the request's inherited trace, mixed with its own trace, mixed with the inherited
// trace (named in the run, but not in the status window), and twice in the status window (once as itself, once as the agent with
// its own trace: only the token tells that line apart); an own allowed message; a keyed retry logged
// twice (one application); an aborted attempt. None is admitted. The leaky build is admitted on both status clauses: the
// effect.none and the effect.only whose background allow (allowBackground) never excuses the agent. At the custody tier the
// profile with allowBackground reads exactly as the same profile with the expanded shape-only allow written by hand.
// Loopback, synthetic data, no model, no provider.
import test from 'node:test';
import assert from 'node:assert/strict';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateHttpRunEvidence } from '../src/contracts.mjs';
import { correlationToken } from '../src/egress-rules.mjs';
// The recorder's port comes from below the OS's automatic range where the host leaves room (integrations/observers/fixtures/free-port.mjs):
// a port the OS hands out on its own may be one another process still sends late requests to, which leave the window partial
// (egress-unrouted-request).
import { freePorts } from '../integrations/observers/fixtures/free-port.mjs';
import { createNotifyApp, notifyProfile, notifySamePathProfile, NOTIFY_APP_LOG, NOTIFY_SAME_PATH_APP_LOG, NOTIFY_HONEST_BUILDS, NOTIFY_LEAKY_BUILDS, SAME_PATH_HONEST_BUILDS, SAME_PATH_LEAKY_BUILDS } from '../examples/app-log-notify-app.mjs';

const ADMISSION = 'app-log-unobserved-admission';
const admitted = a => a?.status === 'fail' && a?.appLog?.finding === ADMISSION;
const decisions = run => ({ counts: run.counts, rows: run.results.map(r => ({ id: r.id, status: r.status, decision: r.decision ?? null, backendEvidence: r.backendEvidence, summary: r.summary, assertions: r.assertions,
  effects: r.trace[1]?.data?.effects ?? null })) });
// Every difference between the shipped run and the admission run is an admission; returns the admitted assertions.
function onlyAdmissions(plain, declared) {
  const found = [];
  assert.equal(declared.results.length, plain.results.length);
  plain.results.forEach((p, i) => {
    const d = declared.results[i];
    assert.equal(d.id, p.id);
    const rowAdmitted = d.assertions.some(admitted);
    assert.ok(d.status === p.status || (rowAdmitted && d.status === 'fail'), `${p.id}: ${p.status} -> ${d.status}`);
    assert.ok(d.backendEvidence === p.backendEvidence || rowAdmitted, `${p.id}: backend evidence`);
    assert.ok((d.decision ?? null) === (p.decision ?? null) || (rowAdmitted && d.decision === 'fail'), `${p.id}: decision`);
    assert.equal(d.assertions.length, p.assertions.length);
    d.assertions.forEach((a, j) => {
      const b = p.assertions[j];
      if (admitted(a)) { assert.notEqual(b.status, 'fail', `${p.id} ${a.name}: a custody fail is never re-labelled`); found.push({ row: p.id, name: a.name, before: b.status }); return; }
      if (a.name === 'Trusted backend observation available' && rowAdmitted) return;
      assert.deepEqual(a, b, `${p.id} ${a.name}`);
    });
  });
  return found;
}

for (const build of [...NOTIFY_HONEST_BUILDS, ...NOTIFY_LEAKY_BUILDS]) {
  test(`${build}: "record" changes no verdict; "admission" changes only by admissions (${NOTIFY_LEAKY_BUILDS.includes(build) ? 'exactly one' : 'none'})`, async t => {
    const run = async use => {
      const app = await createNotifyApp({ build, egressPort: (await freePorts(1))[0] }); t.after(() => app.close());
      const profile = notifyProfile(app);
      if (use) profile.appLogs = [{ ...structuredClone(NOTIFY_APP_LOG), use, log: { file: { path: app.actionLogPath } } }];
      const result = await runHttpAssessment(profile, { env: app.env });
      validateHttpRunEvidence(result);
      return result;
    };
    const plain = await run(null), recorded = await run('record'), admitting = await run('admission');
    assert.deepEqual(decisions(recorded), decisions(plain));
    const found = onlyAdmissions(plain, admitting);
    // Each run read the app's lines: the status check's window holds the digest job's line (and the build's own lines).
    const status = admitting.results.find(r => r.id === 'STATUS');
    assert.ok(status.trace[1].data.appLogWindows[0].events.some(e => e.name === 'mail.example' && e.resource === 'POST /v1/batch'), 'the digest ran in the status window');
    if (NOTIFY_HONEST_BUILDS.includes(build)) { assert.deepEqual(found, [], 'an honest build is never admitted'); return; }
    assert.deepEqual(found.map(f => [f.row, f.name]), [['STATUS', 'Observed effect 1 (effect.none)']]);
    assert.notEqual(found[0].before, 'fail');
    assert.equal(status.status, 'fail');
    assert.match(status.assertions.find(admitted).actual, /app log actions/);
  });
}

for (const build of [...SAME_PATH_HONEST_BUILDS, ...SAME_PATH_LEAKY_BUILDS]) {
  test(`${build}: allowBackground reads as its shape-only allow at the custody tier; "admission" changes only by admissions (${SAME_PATH_LEAKY_BUILDS.includes(build) ? 'both status clauses' : 'none'})`, async t => {
    const run = async (use, { explicit = false } = {}) => {
      const app = await createNotifyApp({ build, egressPort: (await freePorts(1))[0] }); t.after(() => app.close());
      const profile = notifySamePathProfile(app, { explicit });
      if (use) profile.appLogs = [{ ...structuredClone(NOTIFY_SAME_PATH_APP_LOG), use, log: { file: { path: app.actionLogPath } } }];
      const result = await runHttpAssessment(profile, { env: app.env });
      validateHttpRunEvidence(result);
      return result;
    };
    const plain = await run(null), byHand = await run(null, { explicit: true }), recorded = await run('record'), admitting = await run('admission');
    assert.deepEqual(decisions(byHand), decisions(plain), 'allowBackground is the shape-only allow at the custody tier');
    assert.deepEqual(decisions(recorded), decisions(plain));
    const found = onlyAdmissions(plain, admitting);
    // The lines each build is about were read, as the build says.
    const lines = id => { const row = admitting.results.find(r => r.id === id); return { token: correlationToken(row.trace[0].data.requestId), events: row.trace[1].data.appLogWindows[0].events }; };
    const status = lines('STATUS'), update = lines('UPDATE-TICKET');
    const jobLine = ({ events }) => events.find(e => e.captured?.values?.['/template']?.value === 'refund_confirmation' && (e.actor === 'svc-digest' || !events.some(x => x !== e && x.actor === 'agent-1' && x.correlation.settlementToken === e.correlation.settlementToken && e.correlation.settlementToken !== undefined)));
    const job = jobLine(status);
    ({
      'sp-digest-system': () => assert.equal(job.actor, 'svc-digest'),
      'sp-digest-user': () => assert.deepEqual([job.actor, job.correlation.settlementToken], ['agent-1', undefined]),
      'sp-digest-user-traced': () => { assert.equal(job.actor, 'agent-1'); assert.ok(job.correlation.settlementToken && job.correlation.settlementToken !== status.token); },
      'sp-digest-user-inherited': () => assert.ok(status.events.some(e => e.actor === 'agent-1' && e.correlation.settlementToken === status.token && e.captured?.values?.['/template']?.value === 'refund_confirmation'), 'the job line carries the request\'s own token'),
      'sp-digest-mixed': () => { assert.ok(update.events.some(e => e.actor === 'svc-digest')); assert.ok(status.events.some(e => e.actor === 'agent-1' && e.correlation.settlementToken && e.correlation.settlementToken !== status.token)); },
      'sp-digest-twice': () => { assert.ok(status.events.some(e => e.actor === 'svc-digest')); assert.ok(status.events.some(e => e.actor === 'agent-1' && e.correlation.settlementToken && e.correlation.settlementToken !== status.token && e.captured?.values?.['/template']?.value === 'refund_confirmation')); },
      'sp-digest-mixed-inherited': () => { assert.ok(update.events.some(e => e.actor === 'svc-digest')); assert.ok(status.events.filter(e => e.actor === 'agent-1' && e.correlation.settlementToken === status.token).length >= 1); assert.ok(!status.events.some(e => e.actor === 'svc-digest')); },
      'sp-keyed-retry': () => { const sent = update.events.filter(e => e.actor === 'agent-1' && e.outcome === 'committed' && e.captured?.values?.['/template']?.value === 'ticket_update');
        assert.equal(sent.length, 2); assert.equal(sent[0].correlation.requestId, sent[1].correlation.requestId); assert.ok(sent.every(e => e.correlation.settlementToken === update.token)); },
    })[build]?.();
    if (SAME_PATH_HONEST_BUILDS.includes(build)) { assert.deepEqual(found, [], 'an honest build is never admitted'); return; }
    assert.deepEqual(found.map(f => [f.row, f.name]), [['STATUS', 'Observed effect 1 (effect.none)'], ['STATUS', 'Observed effect 2 (effect.only)']]);
    assert.ok(found.every(f => f.before !== 'fail'));
  });
}
