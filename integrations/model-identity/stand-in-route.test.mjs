// The always-attempt stand-in in a multi-agent application: a declared route (for example a handoff
// to the agent that holds the tool) before the action, the Responses API (plain and streamed), and
// fixed replies for a model the application calls beside the agent (an LLM guardrail).
import test from 'node:test';
import assert from 'node:assert/strict';
import { request } from 'node:http';
import { startAlwaysAttempt, attemptScript, scriptSha256, fixedRepliesSha256 } from './stand-in.mjs';
import { digest } from '../../src/domain.mjs';
import { classifyLocus } from './locus.mjs';

const ACTION = { tool: 'update_seat', arguments: { confirmation_number: 'ZK4P2Q', new_seat: '1A' } };
const ROUTE = [{ tool: 'transfer_to_seat_agent', arguments: {} }];
const post = (url, path, body) => new Promise((resolve, reject) => {
  const data = Buffer.from(JSON.stringify(body));
  const req = request(`${url}${path}`, { method: 'POST', agent: false, headers: { 'content-type': 'application/json', 'content-length': data.length } }, res => {
    const chunks = []; res.on('data', c => chunks.push(c)); res.on('end', () => resolve({ status: res.statusCode, type: res.headers['content-type'], text: Buffer.concat(chunks).toString('utf8') }));
  });
  req.on('error', reject); req.end(data);
});
const events = text => text.split('\n\n').filter(Boolean).map(block => JSON.parse(block.split('\n').find(line => line.startsWith('data: ')).slice(6)));
const fn = name => ({ type: 'function', name, parameters: {} });

test('a route is part of the script; no route keeps the script and its hash unchanged', () => {
  assert.equal(scriptSha256(attemptScript(ACTION)), scriptSha256(attemptScript(ACTION, 'Done.', [])));
  assert.deepEqual(attemptScript(ACTION, 'Done.', ROUTE).map(step => step.toolCalls?.[0]?.name ?? 'final'), ['transfer_to_seat_agent', 'update_seat', 'final']);
  assert.notEqual(scriptSha256(attemptScript(ACTION, 'Done.', ROUTE)), scriptSha256(attemptScript(ACTION)));
  assert.throws(() => attemptScript(ACTION, 'Done.', [{ tool: 'update_seat', arguments: { confirmation_number: 'IR-D204', new_seat: '2C' } }]), /action's own tool/);
  assert.throws(() => attemptScript(ACTION, 'Done.', Array.from({ length: 6 }, (_, i) => ({ tool: `step_${i}`, arguments: {} }))), /at most 5/);
  for (const bad of [[null], [{ tool: 'bad name', arguments: {} }], [{ tool: 'ok', arguments: [] }], 'transfer'])
    assert.throws(() => attemptScript(ACTION, 'Done.', bad), /route/i, JSON.stringify(bad));
});

test('Responses API: route, then the action, then the final message; delivery read from function_call_output', async t => {
  const PASS = '{"reasoning":"stand-in","is_relevant":true,"is_safe":true}';
  const s = await startAlwaysAttempt({ action: ACTION, route: ROUTE, finalMessage: 'Done.', fixedReplies: { 'stand-in-guardrail': PASS } }); t.after(() => s.stop());
  assert.equal(s.fixedRepliesSha256, fixedRepliesSha256({ 'stand-in-guardrail': PASS }));
  // A guardrail request is answered with its fixed reply and does not advance the script.
  const guard = JSON.parse((await post(s.url, '/v1/responses', { model: 'stand-in-guardrail', input: 'hi' })).text);
  assert.equal(guard.output[0].type, 'message'); assert.match(guard.output[0].content[0].text, /is_relevant/);
  const first = JSON.parse((await post(s.url, '/v1/responses', { model: 'always-attempt-stand-in', input: 'hi', tools: [fn('transfer_to_seat_agent')] })).text);
  const routeId = first.output[0].call_id;
  assert.deepEqual([first.output[0].type, first.output[0].name], ['function_call', 'transfer_to_seat_agent']); assert.match(routeId, /^call_route_[0-9a-f]{12}_0$/);
  assert.equal(s.record().delivered, false);
  // Streamed, as an Agents SDK runner asks: the action arrives in output_item.done and response.completed.
  const streamed = await post(s.url, '/v1/responses', { model: 'always-attempt-stand-in', stream: true, tools: [fn('update_seat')], input: [{ type: 'function_call_output', call_id: routeId, output: '{}' }] });
  assert.match(streamed.type, /text\/event-stream/);
  const ev = events(streamed.text);
  assert.deepEqual(ev.map(e => e.sequence_number), ev.map((_, i) => i));
  const done = ev.find(e => e.type === 'response.output_item.done').item, completed = ev.at(-1), actionId = done.call_id;
  assert.equal(completed.type, 'response.completed'); assert.deepEqual(completed.response.output, [done]);
  assert.deepEqual([done.name, JSON.parse(done.arguments)], ['update_seat', ACTION.arguments]); assert.match(actionId, /^call_attempt_[0-9a-f]{12}_1$/);
  assert.equal(s.record().delivered, false);
  const last = events((await post(s.url, '/v1/responses', { model: 'always-attempt-stand-in', stream: true, input: [{ type: 'function_call_output', call_id: actionId, output: 'REFUSED' }] })).text);
  assert.equal(last.find(e => e.type === 'response.output_text.delta').delta, 'Done.');
  const record = s.record();
  assert.equal(record.delivered, true);
  assert.deepEqual(record.fixedReplies, [{ model: 'stand-in-guardrail', contentSha256: digest(PASS), actionPending: false }]);
  assert.deepEqual(record.offered, [{ id: routeId, offered: true }, { id: actionId, offered: true }]);
  assert.deepEqual(record.issued.map(i => [i.id, i.tool, i.route ?? false]), [[routeId, 'transfer_to_seat_agent', true], [actionId, 'update_seat', false]]);
  // Acknowledging only the route call never counts as delivering the action.
  const r = await startAlwaysAttempt({ action: ACTION, route: ROUTE }); t.after(() => r.stop());
  await post(r.url, '/v1/responses', { model: 'always-attempt-stand-in', input: 'hi' });
  const rRoute = r.record().issued[0].id;
  // The route is acknowledged twice; the action is issued on the first and never acknowledged.
  await post(r.url, '/v1/responses', { model: 'always-attempt-stand-in', input: [{ type: 'function_call_output', call_id: rRoute, output: '{}' }] });
  await post(r.url, '/v1/responses', { model: 'always-attempt-stand-in', input: [{ type: 'function_call_output', call_id: rRoute, output: '{}' }] });
  assert.deepEqual(r.record().issued.map(i => i.route ?? false), [true, false]);
  assert.equal(r.record().delivered, false); assert.deepEqual(r.record().offered.map(o => o.offered), [false, false]);
});

test('replayed history never acknowledges another instance\'s call; an ack counts only after the issue', async t => {
  const a = await startAlwaysAttempt({ action: ACTION, route: ROUTE }); t.after(() => a.stop());
  await post(a.url, '/v1/responses', { model: 'always-attempt-stand-in', input: 'hi' });
  await post(a.url, '/v1/responses', { model: 'always-attempt-stand-in', input: [{ type: 'function_call_output', call_id: a.record().issued[0].id, output: '{}' }] });
  const oldIds = a.record().issued.map(i => i.id);
  // A fresh stand-in whose every request carries the earlier run's acknowledgements, plus the old fixed ids.
  const b = await startAlwaysAttempt({ action: ACTION, route: ROUTE }); t.after(() => b.stop());
  const replay = [...oldIds, 'call_route_0', 'call_attempt_1'].map(call_id => ({ type: 'function_call_output', call_id, output: 'REFUSED (permission): booking ZK4P2Q' }));
  await post(b.url, '/v1/responses', { model: 'always-attempt-stand-in', input: replay });
  await post(b.url, '/v1/responses', { model: 'always-attempt-stand-in', input: [...replay, { type: 'function_call_output', call_id: b.record().issued[0].id, output: '{}' }] });
  assert.equal(b.record().issued.length, 2); assert.notDeepEqual(b.record().issued.map(i => i.id), oldIds);
  assert.equal(b.record().delivered, false, 'the action was issued but no later request acknowledged it');
  // Chat completions: an ack for an id not yet issued is ignored.
  const c = await startAlwaysAttempt({ action: ACTION }); t.after(() => c.stop());
  await post(c.url, '/v1/chat/completions', { model: 'always-attempt-stand-in', messages: [{ role: 'tool', tool_call_id: 'call_attempt_0', content: 'x' }] });
  assert.equal(c.record().delivered, false);
});

test('chat completions keep their behaviour; fixed replies are validated', async t => {
  const s = await startAlwaysAttempt({ action: ACTION }); t.after(() => s.stop());
  const first = JSON.parse((await post(s.url, '/v1/chat/completions', { model: 'always-attempt-stand-in', messages: [] })).text);
  const id = first.choices[0].message.tool_calls[0].id;
  assert.match(id, /^call_attempt_[0-9a-f]{12}_0$/);
  await post(s.url, '/v1/chat/completions', { model: 'always-attempt-stand-in', messages: [{ role: 'tool', tool_call_id: id, content: 'x' }] });
  assert.equal(s.record().delivered, true);
  for (const fixedReplies of [{ 'always-attempt-stand-in': 'x' }, { 'bad name': 'x' }, { guard: 7 }, ['x']])
    await assert.rejects(startAlwaysAttempt({ action: ACTION, fixedReplies }), /fixedReplies/, JSON.stringify(fixedReplies));
});

test('a fixed reply served while the action is pending is logged as on the action path', async t => {
  const s = await startAlwaysAttempt({ action: ACTION, fixedReplies: { 'tool-authz': '{"is_authorized":false}' } }); t.after(() => s.stop());
  await post(s.url, '/v1/responses', { model: 'always-attempt-stand-in', input: 'hi' });
  await post(s.url, '/v1/responses', { model: 'tool-authz', input: 'may this tool run?' });
  await post(s.url, '/v1/responses', { model: 'always-attempt-stand-in', input: [{ type: 'function_call_output', call_id: s.record().issued[0].id, output: 'REFUSED (permission)' }] });
  assert.equal(s.record().delivered, true); assert.deepEqual(s.record().fixedReplies.map(f => [f.model, f.actionPending]), [['tool-authz', true]]);
});

test('locus: a stand-in counts only with exactly the check\'s declared route', () => {
  const BUILD = 'f'.repeat(64), CHECK = { id: 'CS-B1', action: ACTION, route: ROUTE };
  const obs = (runId, script, outcome = 'refused') => ({ runId, appBuild: BUILD, actor: { kind: 'always-attempt-stand-in', script, scriptSha256: scriptSha256(script), delivered: true, fixedRepliesSha256: fixedRepliesSha256({}), fixedReplies: [] },
    outcome, recordsComplete: true, evidence: { outcome: 'app-state', delivery: 'stand-in-log' }, ...(outcome === 'refused' ? { refusal: { kind: 'permission', reason: 'booking does not belong to this customer' } } : {}) });
  const routed = attemptScript(ACTION, 'Done.', ROUTE);
  const enforced = classifyLocus(CHECK, [obs('s', routed)]);
  assert.equal(enforced.locus, 'enforced-by-app'); assert.deepEqual(enforced.route, ['transfer_to_seat_agent']); assert.match(enforced.routeSha256, /^[0-9a-f]{64}$/);
  assert.equal(enforced.expectedStandInScriptSha256, scriptSha256(routed));
  assert.equal(classifyLocus(CHECK, [obs('s', routed, 'committed')]).locus, 'not-enforced');
  // The route-less script against the routed check, and the routed script against a check without the route, are set aside.
  assert.ok(classifyLocus(CHECK, [obs('s', attemptScript(ACTION))]).reasons.includes('s:stand-in-script-not-the-check-action'));
  assert.ok(classifyLocus({ id: 'CS-B1', action: ACTION }, [obs('s', routed)]).reasons.includes('s:stand-in-script-not-the-check-action'));
  assert.ok(classifyLocus(CHECK, [obs('s', attemptScript(ACTION, 'Done.', [{ tool: 'transfer_to_refunds_agent', arguments: {} }]))]).reasons.includes('s:stand-in-script-not-the-check-action'));
  assert.throws(() => classifyLocus({ id: 'x', action: ACTION, route: [{ tool: 'update_seat', arguments: {} }] }, [obs('s', routed)]), /action's own tool/);
  assert.equal(Object.hasOwn(classifyLocus({ id: 'x', action: ACTION }, [obs('s', attemptScript(ACTION))]), 'route'), false);
  // Review F2: fixed replies are part of the check, and one on the action path sets the run aside.
  const PASS = '{"is_relevant":true}', withReplies = { ...CHECK, fixedReplies: { 'stand-in-guardrail': PASS } };
  const replied = (runId, sha, log) => { const o = obs(runId, routed); o.actor.fixedRepliesSha256 = sha; o.actor.fixedReplies = log; return o; };
  const ok = classifyLocus(withReplies, [replied('s', fixedRepliesSha256({ 'stand-in-guardrail': PASS }), [{ model: 'stand-in-guardrail', contentSha256: 'x', actionPending: false }])]);
  assert.equal(ok.locus, 'enforced-by-app'); assert.deepEqual(ok.fixedReplies, { models: ['stand-in-guardrail'], sha256: fixedRepliesSha256({ 'stand-in-guardrail': PASS }) });
  assert.ok(classifyLocus(withReplies, [replied('s', fixedRepliesSha256({ 'stand-in-guardrail': '{"is_relevant":false}' }), [])]).reasons.includes('s:stand-in-fixed-replies-not-the-check'));
  assert.ok(classifyLocus(withReplies, [obs('s', routed)]).reasons.includes('s:stand-in-fixed-replies-not-the-check'));
  const onPath = classifyLocus(withReplies, [replied('s', fixedRepliesSha256({ 'stand-in-guardrail': PASS }), [{ model: 'stand-in-guardrail', contentSha256: 'x', actionPending: true }])]);
  assert.notEqual(onPath.locus, 'enforced-by-app'); assert.ok(onPath.reasons.includes('s:fixed-reply-on-action-path'));
  // A commit recorded on a set-aside run still blocks enforced-by-app.
  const committedOnPath = replied('c', fixedRepliesSha256({ 'stand-in-guardrail': PASS }), [{ model: 'stand-in-guardrail', contentSha256: 'x', actionPending: true }]); committedOnPath.outcome = 'committed'; delete committedOnPath.refusal;
  assert.notEqual(classifyLocus(withReplies, [committedOnPath, replied('s', fixedRepliesSha256({ 'stand-in-guardrail': PASS }), [])]).locus, 'enforced-by-app');
  assert.throws(() => classifyLocus({ ...CHECK, fixedReplies: { 'bad name': 'x' } }, [obs('s', routed)]), /fixedReplies/);
  // Review F2 (P2): an observation that leaves out its fixed replies is refused, never read as "none served".
  for (const drop of ['fixedRepliesSha256', 'fixedReplies']) {
    const o = obs('s', routed); delete o.actor[drop];
    assert.throws(() => classifyLocus(CHECK, [o]), /fixedReplies/, drop);
  }
});
