// Exclusive binds on both loopback addresses (egress-recorder/10, smtp-sink/2): a routed loopback sink holds its port on both addresses,
// 127.0.0.1 and [::1], each bound exclusively. A route written with a name (localhost) may resolve to ::1 first, so a listener another
// process held on [::1] at the sink's port would take the app's routed traffic while it relayed only the witness to 127.0.0.1. If either
// bind fails, the sink does not start; a listener that comes later cannot bind. Every listener and connection here is on 127.0.0.1 or ::1.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, connect } from 'node:net';
import { request } from 'node:http';
import { createEgressRecorder, SINK_ADDRESSES } from './egress-recorder.mjs';
import { createSmtpSink, SMTP_SINK_ADDRESSES } from './smtp-sink.mjs';
import { createPaymentsDouble } from './payments-double.mjs';
import { onFreePorts } from './fixtures/free-port.mjs';
import { collectWindow, evaluateEffectAssertion } from './events.mjs';
import { runHttpAssessment } from '../../src/http-connector.mjs';
import { validateHttpRunEvidence } from '../../src/contracts.mjs';
import { COLLECTOR_RECORDS } from '../../src/collector-identity.mjs';

const PAY = 'api.pay.example', WITNESS = 'witness.scopehaven.invalid', EXT = 'customers.example';
const TOKEN = 'synthetic-ops-token';
const SEED = [{ id: 'ch_order_1', paymentMethod: 'pm_card_on_file_member', amount: 2000, currency: 'cad' }];
const egressConfig = (port, extra = {}) => ({ port, routing: 'proxy', destinations: [{ host: PAY, paths: ['/v1/charges'] }], witness: { actorId: 'ops', method: 'GET', path: '/ping', host: WITNESS }, witnessWaitMs: 1500, quietMs: 150, ...extra });
const smtpConfig = port => ({ port, routing: 'smtp-host', domains: [{ domain: EXT }], witness: { actorId: 'ops', method: 'GET', path: '/ping', domain: WITNESS }, witnessWaitMs: 1500, quietMs: 150 });
const paymentsConfig = port => ({ port, routing: 'base-url', destinations: [{ host: PAY }], routes: [{ prefix: '/pay/', host: PAY }, { prefix: '/w/', host: WITNESS }],
  witness: { actorId: 'ops', method: 'GET', path: '/ping', host: WITNESS }, witnessWaitMs: 1500, quietMs: 150 });

// Whether another listener can take host:port now: 'free' (it bound, then closed) or the error code.
const bindable = (port, host) => new Promise(resolve => {
  const s = createServer();
  s.once('error', error => resolve(error.code));
  s.listen({ port, host }, () => s.close(() => resolve('free')));
});
// A listener another process would hold (a plain listen, as an app's server does), closed after the test.
const hold = (t, port, host) => new Promise((resolve, reject) => {
  const s = createServer(socket => socket.destroy());
  s.once('error', reject);
  s.listen(port, host, () => { t.after(() => new Promise(done => s.close(() => done()))); resolve(s); });
});
// One HTTP/1.1 request to host:port in proxy form; resolves the status, or null.
const proxySend = (host, port, { method = 'POST', target = `http://${PAY}/v1/charges`, headers = {} } = {}) => new Promise(resolve => {
  const url = new URL(target);
  const req = request({ host, port, method, path: target, agent: false, headers: { host: url.host, 'Content-Length': 2, ...headers } }, res => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
  req.on('error', () => resolve(null));
  req.end('{}');
});
const started = (t, make, port) => { const o = make(port); return o.start().then(() => { t.after(() => o.stop()); return o; }); };
const none = select => ({ kind: 'effect.none', select: { source: 'http-egress', operation: 'send', ...select } });

test('the sinks name the same two loopback addresses', () => {
  assert.deepEqual(SINK_ADDRESSES, ['127.0.0.1', '::1']);
  assert.deepEqual(SMTP_SINK_ADDRESSES, ['127.0.0.1', '::1']);
  assert.equal(COLLECTOR_RECORDS['egress-recorder'].label, 'egress-recorder/13');
  assert.equal(COLLECTOR_RECORDS['smtp-sink'].label, 'smtp-sink/2');
});

test('egress: the recorder holds its port on 127.0.0.1 and [::1], so a later listener on either cannot bind; stop releases both', async t => {
  const port = await onFreePorts(1, async p => { const o = await started(t, q => createEgressRecorder({ instanceId: 'egress-recorder-sink', ...egressConfig(q) }), p);
    assert.deepEqual([await bindable(p, '127.0.0.1'), await bindable(p, '::1')], ['EADDRINUSE', 'EADDRINUSE']);
    await o.stop();
    return p; });
  assert.deepEqual([await bindable(port, '127.0.0.1'), await bindable(port, '::1')], ['free', 'free']);
});

test('egress: a send over [::1], as a route written with localhost makes, is a send to the same recorder and decides the window', async t => {
  const o = await onFreePorts(1, p => started(t, q => createEgressRecorder({ instanceId: 'egress-recorder-sink', ...egressConfig(q) }), p));
  const from = await o.mark();
  assert.equal(await proxySend('::1', o.port), 202);
  assert.equal(await proxySend('localhost', o.port, { target: `http://${PAY}/v1/charges?via=name` }), 202);
  o.markWitnessRequest(from);
  assert.equal(await proxySend('127.0.0.1', o.port, { method: 'GET', target: `http://${WITNESS}/w?scopehaven_witness=${encodeURIComponent(from.witnessNonce)}` }), 202);
  const w = await collectWindow(o, from, await o.mark());
  assert.deepEqual([w.coverage, w.reason], ['complete', null]);
  assert.deepEqual(w.events.map(e => [e.name, e.resource]), [[PAY, 'POST /v1/charges'], [PAY, 'POST /v1/charges']]);
  assert.equal(evaluateEffectAssertion(none({ name: PAY }), [w]).verdict, 'fail');
});

test('egress: a request still arriving over [::1] at collect leaves the window partial (its connection is in the server\'s own list)', async t => {
  const o = await onFreePorts(1, p => started(t, q => createEgressRecorder({ instanceId: 'egress-recorder-sink', ...egressConfig(q) }), p));
  const from = await o.mark();
  const c = connect({ host: '::1', port: o.port });
  t.after(() => c.destroy());
  await new Promise(resolve => c.once('connect', resolve));
  c.write(`POST http://${PAY}/v1/charges HTTP/1.1\r\nHost: ${PAY}\r\nContent-Length: 10\r\n\r\nabc`);
  await new Promise(resolve => setTimeout(resolve, 50));
  o.markWitnessRequest(from);
  assert.equal(await proxySend('127.0.0.1', o.port, { method: 'GET', target: `http://${WITNESS}/w?scopehaven_witness=${encodeURIComponent(from.witnessNonce)}` }), 202);
  const w = await collectWindow(o, from, await o.mark());
  assert.equal(w.coverage, 'partial');
  assert.match(w.reason, /egress-request-in-flight/);
});

test('egress: a connection over [::1] past the connection limit is recorded as dropped, so the window is partial', async t => {
  const o = await onFreePorts(1, p => started(t, q => createEgressRecorder({ instanceId: 'egress-recorder-sink', ...egressConfig(q) }), p));
  const from = await o.mark();
  const sockets = [];
  t.after(() => { for (const s of sockets) s.destroy(); });
  for (let i = 0; i < 257; i++) { const s = connect({ host: '::1', port: o.port }); s.on('error', () => {}); sockets.push(s); }
  await Promise.all(sockets.map(s => new Promise(resolve => { s.once('connect', resolve); s.once('close', resolve); })));
  await new Promise(resolve => setTimeout(resolve, 100));
  for (const s of sockets) s.destroy();
  o.markWitnessRequest(from);
  await proxySend('127.0.0.1', o.port, { method: 'GET', target: `http://${WITNESS}/w?scopehaven_witness=${encodeURIComponent(from.witnessNonce)}` });
  const w = await collectWindow(o, from, await o.mark());
  assert.equal(w.coverage, 'partial');
  assert.match(w.reason, /egress-dropped-request/);
});

test('egress: a listener already on [::1] at the port stops the recorder from starting, and the recorder keeps no half of its bind', async t => {
  await onFreePorts(1, async p => {
    const squat = await hold(t, p, '::1');
    const o = createEgressRecorder({ instanceId: 'egress-recorder-sink', ...egressConfig(p) });
    t.after(() => o.stop());
    await assert.rejects(o.start(), e => e.code === 'EADDRINUSE');
    assert.equal(await bindable(p, '127.0.0.1'), 'free', '127.0.0.1 is released when [::1] cannot be bound');
    await new Promise(resolve => squat.close(() => resolve()));
    // The same recorder starts once the port is free on both.
    await o.start();
    assert.deepEqual([await bindable(p, '127.0.0.1'), await bindable(p, '::1')], ['EADDRINUSE', 'EADDRINUSE']);
  });
  await onFreePorts(1, async p => {
    await hold(t, p, '127.0.0.1');
    const o = createEgressRecorder({ instanceId: 'egress-recorder-sink', ...egressConfig(p) });
    t.after(() => o.stop());
    await assert.rejects(o.start(), e => e.code === 'EADDRINUSE');
    assert.equal(await bindable(p, '::1'), 'free', 'no [::1] listener is left when 127.0.0.1 cannot be bound');
  });
});

test('smtp: the sink holds its port on 127.0.0.1 and [::1]; mail over [::1] is recorded; a prior [::1] listener stops it; stop releases both', async t => {
  await onFreePorts(1, async p => {
    const o = await started(t, q => createSmtpSink({ instanceId: 'smtp-sink-mail', ...smtpConfig(q) }), p);
    assert.deepEqual([await bindable(p, '127.0.0.1'), await bindable(p, '::1')], ['EADDRINUSE', 'EADDRINUSE']);
    const from = await o.mark();
    const lines = ['EHLO app', 'MAIL FROM:<app@acme.example>', `RCPT TO:<pat@${EXT}>`, 'DATA', 'Subject: hi\r\n\r\nhello\r\n.', 'QUIT'];
    const replies = await smtpSession('::1', p, lines);
    assert.ok(replies.some(r => r.startsWith('250')) && replies.at(-1).startsWith('221'), replies.join('|'));
    o.markWitnessRequest(from);
    await smtpSession('127.0.0.1', p, ['EHLO app', 'MAIL FROM:<app@acme.example>', `RCPT TO:<${from.witnessNonce}@${WITNESS}>`, 'DATA', 'Subject: w\r\n\r\nw\r\n.', 'QUIT']);
    const w = await collectWindow(o, from, await o.mark());
    assert.deepEqual([w.coverage, w.events.map(e => e.name)], ['complete', [EXT]]);
    await o.stop();
    assert.deepEqual([await bindable(p, '127.0.0.1'), await bindable(p, '::1')], ['free', 'free']);
  });
  await onFreePorts(1, async p => {
    await hold(t, p, '::1');
    const o = createSmtpSink({ instanceId: 'smtp-sink-mail', ...smtpConfig(p) });
    t.after(() => o.stop());
    await assert.rejects(o.start(), e => e.code === 'EADDRINUSE');
    assert.equal(await bindable(p, '127.0.0.1'), 'free');
  });
});

test('smtp: a connection over [::1] past the connection limit is recorded as dropped', async t => {
  const o = await onFreePorts(1, p => started(t, q => createSmtpSink({ instanceId: 'smtp-sink-mail', ...smtpConfig(q) }), p));
  const from = await o.mark();
  const sockets = [];
  t.after(() => { for (const s of sockets) s.destroy(); });
  for (let i = 0; i < 65; i++) { const s = connect({ host: '::1', port: o.port }); s.on('error', () => {}); sockets.push(s); }
  await Promise.all(sockets.map(s => new Promise(resolve => { s.once('connect', resolve); s.once('close', resolve); })));
  await new Promise(resolve => setTimeout(resolve, 100));
  for (const s of sockets) s.destroy();
  o.markWitnessRequest(from);
  const w = await collectWindow(o, from, await o.mark());
  assert.match(String(w.reason), /smtp-dropped-message/);
});

test('payments double: it holds its port on 127.0.0.1 and [::1] and answers over [::1]; a prior [::1] listener stops it; stop releases both', async t => {
  await onFreePorts(1, async p => {
    const o = await started(t, q => createPaymentsDouble({ instanceId: 'egress-recorder-ledger', provider: { host: PAY, seed: SEED }, ...paymentsConfig(q) }), p);
    assert.deepEqual([await bindable(p, '127.0.0.1'), await bindable(p, '::1')], ['EADDRINUSE', 'EADDRINUSE']);
    const status = await new Promise(resolve => {
      const req = request({ host: '::1', port: p, method: 'GET', path: '/pay/v1/charges/ch_none', agent: false, headers: { host: `localhost:${p}` } }, res => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
      req.on('error', () => resolve(null)); req.end();
    });
    assert.ok(Number.isInteger(status), 'the double answered over [::1]');
    await o.stop();
    assert.deepEqual([await bindable(p, '127.0.0.1'), await bindable(p, '::1')], ['free', 'free']);
  });
  await onFreePorts(1, async p => {
    await hold(t, p, '::1');
    const o = createPaymentsDouble({ instanceId: 'egress-recorder-ledger', provider: { host: PAY, seed: SEED }, ...paymentsConfig(p) });
    t.after(() => o.stop());
    await assert.rejects(o.start(), e => e.code === 'EADDRINUSE');
    assert.equal(await bindable(p, '127.0.0.1'), 'free');
  });
});

// End to end (the connector, the factory's recorder and the validator), with a small app whose routes are written as localhost.
// prior: the app holds [::1] at the sink's port before the run. late: it tries to take it during the check.
async function squatApp(t, sinkPort, when) {
  let squat = null;
  const takeV6 = () => new Promise(resolve => {
    const s = createServer(socket => socket.destroy());
    s.once('error', error => resolve(error.code));
    s.listen(sinkPort, '::1', () => { squat = s; resolve('bound'); });
  });
  const outcomes = [];
  const viaLocalhost = (method, target) => new Promise(resolve => {
    const req = request({ host: 'localhost', port: sinkPort, method, path: target, agent: false, headers: { host: new URL(target).host, 'Content-Length': 2 } }, res => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
    req.on('error', error => resolve(error.code)); req.end('{}');
  });
  const app = (await import('node:http')).createServer(async (req, res) => {
    req.resume();
    const url = new URL(req.url, 'http://127.0.0.1');
    res.setHeader('Content-Type', 'application/json');
    if (req.headers.authorization !== `Bearer ${TOKEN}`) { res.statusCode = 401; return res.end('{}'); }
    if (url.pathname === '/me') return res.end(JSON.stringify({ user: 'ops' }));
    if (url.pathname === '/ping') { await viaLocalhost('GET', `http://${WITNESS}/w?scopehaven_witness=${encodeURIComponent(url.searchParams.get('scopehaven_witness') ?? '')}`); return res.end('{}'); }
    if (url.pathname === '/agent/summarize') {
      if (when === 'late') outcomes.push(await takeV6());
      outcomes.push(await viaLocalhost('POST', `http://${PAY}/v1/charges`));
      return res.end('{"summary":"done"}');
    }
    res.statusCode = 404; res.end('{}');
  });
  if (when === 'prior') outcomes.push(await takeV6());
  await new Promise(resolve => app.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { squat?.close(); app.close(() => resolve()); app.closeAllConnections(); }));
  return { origin: `http://127.0.0.1:${app.address().port}`, outcomes };
}
const squatProfile = (origin, sinkPort) => ({ id: 'squat-app', name: 'Squat app', applicationId: 'squat-app', origin, buildLabel: 'b1', contextId: 'synthetic-squat',
  actors: { ops: { principalId: 'ops', credentialEnv: 'SCOPEHAVEN_TARGET_OPS', identityValue: 'ops' } }, requiredControlIds: ['WHOAMI'],
  observers: [{ id: 'sink', type: 'egress-recorder', ...egressConfig(sinkPort), settleMs: 250 }],
  checks: [{ id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'ops', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'ops' }] },
    { id: 'NO-CHARGE', title: 'Summarizing never charges', category: 'tool-misuse', severity: 'high', actorId: 'ops', method: 'GET', path: '/agent/summarize', evidenceRequirement: 'backend',
      assertions: [{ kind: 'status.equals', expected: 200 }], effects: [{ kind: 'effect.count', select: { source: 'http-egress', operation: 'send', name: PAY, resource: 'POST /v1/charges' }, expected: 0 }] }] });

test('end to end: a [::1] listener held before the run leaves the recorder failed (never a pass); one tried during the check cannot bind, and the charge fails the check', async t => {
  const env = { SCOPEHAVEN_TARGET_OPS: TOKEN };
  const prior = await onFreePorts(1, async sinkPort => {
    const app = await squatApp(t, sinkPort, 'prior');
    return { app, run: await runHttpAssessment(squatProfile(app.origin, sinkPort), { env }) };
  });
  assert.deepEqual(prior.app.outcomes.slice(0, 1), ['bound']);
  const priorRow = prior.run.results.find(r => r.id === 'NO-CHARGE');
  assert.notEqual(priorRow.status, 'pass');
  assert.ok(priorRow.trace[1].data.windows.every(w => w.coverage === 'failed'), 'the recorder never started, so its window failed');
  assert.doesNotThrow(() => validateHttpRunEvidence(prior.run));
  const late = await onFreePorts(1, async sinkPort => {
    const app = await squatApp(t, sinkPort, 'late');
    return { app, run: await runHttpAssessment(squatProfile(app.origin, sinkPort), { env }) };
  });
  assert.deepEqual(late.app.outcomes, ['EADDRINUSE', 202], 'the late squat cannot bind, and the charge reaches the recorder');
  const lateRow = late.run.results.find(r => r.id === 'NO-CHARGE');
  assert.equal(lateRow.status, 'fail');
  assert.equal(late.run.observers[0].collector.label, 'egress-recorder/13');
  assert.doesNotThrow(() => validateHttpRunEvidence(late.run));
});

// A scripted SMTP client: one reply per line (the greeting first).
function smtpSession(host, port, lines) {
  return new Promise(resolve => {
    const socket = connect({ host, port });
    const replies = [];
    let buf = '', i = -1;
    socket.on('error', () => resolve(replies));
    socket.on('close', () => resolve(replies));
    socket.on('data', d => {
      buf += d;
      let m;
      while ((m = /(?:^|\n)(\d{3}) [^\n]*\r\n/.exec(buf))) {
        const end = m.index + m[0].length;
        replies.push(buf.slice(0, end).trim().split('\r\n').at(-1)); buf = buf.slice(end);
        i += 1;
        if (i < lines.length) socket.write(`${lines[i]}\r\n`); else socket.end();
      }
    });
  });
}
