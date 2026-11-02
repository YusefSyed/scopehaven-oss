import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createSqliteAuditObserver } from '../observers/sqlite.mjs';
import { createHoldGate } from '../sequences/gate.mjs';
import { validateSequenceRun } from '../sequences/run-validator.mjs';
import { compileScenario, runScenario, captureTransport, replayDigest, MULTITURN_SCHEMA } from './multiturn.mjs';
import { startTicketDesk, DESK_ACTIONS, DESK_DENIED } from './desk.mjs';

const TOKENS = { 'user-a': 'synthetic-multiturn-a', 'user-b': 'synthetic-multiturn-b' };
const ENV = { SCOPEHAVEN_TARGET_MT_A: TOKENS['user-a'], SCOPEHAVEN_TARGET_MT_B: TOKENS['user-b'] };
const ACTORS = { a: { principalId: 'user-a', credentialEnv: 'SCOPEHAVEN_TARGET_MT_A' }, b: { principalId: 'user-b', credentialEnv: 'SCOPEHAVEN_TARGET_MT_B' } };
const by = (actor, name, more = {}) => ({ source: 'sql-audit-table', actor, name, ...more });
// A creates a ticket and notes it; B does the same on its own; B then tries A's ticket (captured id); A closes its ticket.
const SCENARIO = {
  schema: MULTITURN_SCHEMA, id: 'two-identities-ticket-ownership', actors: ACTORS,
  turns: [
    { actor: 'a', method: 'POST', path: '/tickets', body: {}, capture: { ticketA: '/id' }, expect: [201] },
    { actor: 'a', method: 'POST', path: '/tickets/{{ticketA}}/notes', body: { text: 'Customer called.' }, expect: [201] },
    { actor: 'b', method: 'POST', path: '/tickets', body: {}, capture: { ticketB: '/id' }, expect: [201] },
    { actor: 'b', method: 'POST', path: '/tickets/{{ticketB}}/notes', body: { text: 'Own ticket.' }, expect: [201] },
    { actor: 'b', method: 'POST', path: '/tickets/{{ticketA}}/notes', body: { text: 'Not mine.' }, expect: [201, 403] },
    { actor: 'b', method: 'POST', path: '/tickets/{{ticketA}}/close', body: {}, expect: [200, 403] },
    { actor: 'a', method: 'POST', path: '/tickets/{{ticketA}}/close', body: {}, expect: [200] },
  ],
  assertions: [
    { id: 'MT-01', title: 'No note by B on A\'s ticket', severity: 'high', window: 'turn-5..turn-6', effect: { kind: 'effect.none', select: by('user-b', 'ticket.note') }, control: 'MT-C2' },
    { id: 'MT-02', title: 'B cannot close A\'s ticket', severity: 'high', window: 'turn-5..turn-6', effect: { kind: 'effect.none', select: by('user-b', 'ticket.close') }, control: 'MT-C3' },
    { id: 'MT-C1', title: 'A notes its own ticket', severity: 'control', window: 'turn-1..turn-2', effect: { kind: 'effect.exists', select: by('user-a', 'ticket.note') } },
    { id: 'MT-C2', title: 'B notes its own ticket', severity: 'control', window: 'turn-3..turn-4', effect: { kind: 'effect.exists', select: by('user-b', 'ticket.note') } },
    { id: 'MT-C3', title: 'A closes its own ticket after B\'s attempts', severity: 'control', window: 'turn-7..turn-7', effect: { kind: 'effect.exists', select: by('user-a', 'ticket.close') } },
  ],
};

// gated: the desk calls a downstream tool service for each committed note and close, through a hold gate
// that holds nothing and records every call: a request-path observer the desk cannot write.
async function runOn(t, build, scenario = SCENARIO, { gated = false } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven multiturn '));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  let gate = null;
  if (gated) {
    const tool = createServer((req, res) => { req.resume(); req.on('end', () => { res.writeHead(200, { 'Content-Type': 'application/json', Connection: 'close' }); res.end('{}'); }); });
    await new Promise(resolve => tool.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => { tool.close(resolve); tool.closeAllConnections?.(); }));
    gate = createHoldGate({ upstream: `http://127.0.0.1:${tool.address().port}`, instanceId: 'gate-desk-tools',
      rules: [{ id: 'ticket-note', method: 'POST', pathPrefix: '/tool/ticket-note', holds: 0 }, { id: 'ticket-close', method: 'POST', pathPrefix: '/tool/ticket-close', holds: 0 }] });
    await gate.start(); t.after(() => gate.stop());
  }
  const desk = await startTicketDesk({ dbPath: join(dir, 'desk.db'), tokens: TOKENS, build, ...(gate ? { downstream: gate.url } : {}) });
  t.after(() => desk.stop());
  const observer = createSqliteAuditObserver({ instanceId: 'sqlite-audit-desk', path: join(dir, 'desk.db'), principals: ['user-a', 'user-b'],
    audit: { table: 'audit', idColumn: 'id', actorColumn: 'actor', actionColumn: 'action', resourceColumn: 'resource', actions: DESK_ACTIONS, deniedActions: DESK_DENIED } });
  // The gate has no settle of its own: the gated harness declares one, so each end mark waits for late downstream calls.
  if (gate) observer.postResponseSettleMs = 250;
  return runScenario(scenario, { origin: desk.origin, observers: gate ? [observer, gate.observer()] : [observer], env: ENV });
}
// The same scenario judged on the request path: the desk's calls to its tool service, recorded by the hold gate. The
// gate names no actor, so these selectors name none; in turns 5 and 6 only B acts, so any note or close there is B's.
const call = name => ({ source: 'hold-proxy', operation: 'tool-call', name });
// Its last controls are exact counts, and a final turn notes A's ticket again: a forbidden call that lands late adds a
// second call to one of them and fails it.
const GATED = { ...SCENARIO, id: 'two-identities-ticket-ownership-request-path',
  turns: [...SCENARIO.turns, { actor: 'a', method: 'POST', path: '/tickets/{{ticketA}}/notes', body: { text: 'Closed out.' }, expect: [201] }],
  assertions: [
    { id: 'MT-01', title: 'No note on A\'s ticket while only B acts', severity: 'high', window: 'turn-5..turn-6', effect: { kind: 'effect.none', select: call('ticket-note') }, control: 'MT-C2' },
    { id: 'MT-02', title: 'No close of A\'s ticket while only B acts', severity: 'high', window: 'turn-5..turn-6', effect: { kind: 'effect.none', select: call('ticket-close') }, control: 'MT-C3' },
    { id: 'MT-C1', title: 'A notes its own ticket', severity: 'control', window: 'turn-1..turn-2', effect: { kind: 'effect.exists', select: call('ticket-note') } },
    { id: 'MT-C2', title: 'B notes its own ticket', severity: 'control', window: 'turn-3..turn-4', effect: { kind: 'effect.exists', select: call('ticket-note') } },
    { id: 'MT-C3', title: 'A closes its own ticket after B\'s attempts: exactly one close', severity: 'control', window: 'turn-7..turn-7', effect: { kind: 'effect.count', select: call('ticket-close'), expected: 1 } },
    { id: 'MT-C4', title: 'A notes its own ticket last: exactly one note', severity: 'control', window: 'turn-8..turn-8', effect: { kind: 'effect.count', select: call('ticket-note'), expected: 1 } },
  ] };
const statuses = r => Object.fromEntries(r.run.results.map(x => [x.id, x.status]));
const custodyOf = (r, id) => { const x = r.run.results.find(y => y.id === id); return [x.status, x.custody, x.custodyReason]; };
const HELD = ['inconclusive', 'subject-writable', 'subject-writable-custody'];

test('the checked desk reads inconclusive under custody; the unchecked desk fails the forbidden turns; the paired controls pass on both', async t => {
  const checked = await runOn(t, 'checked');
  assert.equal(checked.run.aborted, null);
  // Custody: only the desk's own audit table decides MT-01 and MT-02 (no request-path observer attributes an actor), so the checked desk's absences read inconclusive.
  assert.deepEqual(statuses(checked), { 'MT-01': 'inconclusive', 'MT-02': 'inconclusive', 'MT-C1': 'pass', 'MT-C2': 'pass', 'MT-C3': 'pass' });
  for (const id of ['MT-01', 'MT-02']) assert.deepEqual(custodyOf(checked, id), HELD, id);
  // The run is an ordinary sequence-run/2 the shared validator recomputes.
  assert.deepEqual(validateSequenceRun(checked.run).results.map(r => r.status), checked.run.results.map(r => r.status));
  const unchecked = await runOn(t, 'unchecked');
  assert.deepEqual(statuses(unchecked), { 'MT-01': 'fail', 'MT-02': 'fail', 'MT-C1': 'pass', 'MT-C2': 'pass', 'MT-C3': 'pass' });
  for (const id of ['MT-01', 'MT-02']) assert.equal(custodyOf(unchecked, id)[2], undefined, id);
});

test('later turns use state earlier turns created: B\'s attempts named A\'s captured ticket, judged from the audit records', async t => {
  const unchecked = await runOn(t, 'unchecked');
  const offending = unchecked.run.windows[Object.keys(unchecked.run.windows).find(k => k === 'after-4>after-6')];
  const resources = offending.flatMap(w => w.events.filter(e => e.actor === 'user-b').map(e => `${e.name} ${e.resource}`));
  assert.deepEqual(resources, ['ticket.note tickets/1', 'ticket.close tickets/1']);
  const checked = await runOn(t, 'checked');
  const denied = checked.run.windows['after-4>after-6'].flatMap(w => w.events.filter(e => e.actor === 'user-b').map(e => `${e.name} ${e.outcome} ${e.resource}`));
  assert.deepEqual(denied, ['ticket.note.denied denied tickets/1', 'ticket.close.denied denied tickets/1']);
});

test('replay is deterministic: two runs on fresh desks give the same verdicts and records (replay digest)', async t => {
  const [first, second] = [await runOn(t, 'checked'), await runOn(t, 'checked')];
  assert.equal(first.replayDigest, second.replayDigest);
  assert.notEqual(first.run.runDigest, second.run.runDigest, 'the sealed digest also covers observation times');
  assert.notEqual((await runOn(t, 'unchecked')).replayDigest, first.replayDigest);
});

test('a capture that is missing stops the run: the forbidden checks read missing, never pass', async t => {
  const broken = { ...SCENARIO, turns: SCENARIO.turns.map((turn, i) => (i === 0 ? { ...turn, capture: { ticketA: '/no-such-field' } } : turn)) };
  const r = await runOn(t, 'unchecked', broken);
  assert.match(r.run.aborted, /^(precondition|transport)-failed:turn-2/);
  assert.ok(r.run.results.filter(x => x.severity !== 'control').every(x => x.status !== 'pass'));
  assert.deepEqual(r.captureLog[0], { turn: 1, uncaptured: 'ticketA' });
  // The turn that needed the value was never sent: the transport refused it.
  assert.deepEqual(r.captureLog[1], { turn: 2, missing: ['ticketA'] });
  assert.equal(r.run.timeline.find(e => e.step === 'response' && e.request === 'turn-2').transport, 'capture-missing');
});

test('captured values are plain identifiers, so a response cannot add a path segment or a placeholder', async () => {
  const scenario = { turns: [{ capture: { x: '/v' } }, { capture: {} }] };
  for (const [value, kept] of [['42', true], ['abc-1', true], ['../admin', false], ['1?x=2', false], ['{{x}}', false], ['a'.repeat(201), false]]) {
    const { transport, captured } = captureTransport(scenario, { base: async () => ({ jsonParsed: true, json: { v: value }, status: 200 }) });
    await transport('http://127.0.0.1:1', { method: 'POST', path: '/x' }, {});
    assert.equal(captured.has('x'), kept, value);
  }
});

test('the scenario format is checked: captures before use, 3 turns per judged identity, a paired control, windows within the turns', () => {
  assert.equal(compileScenario(SCENARIO).steps.filter(s => s.request).length, 7);
  const variants = {
    'uses {{ticketB}} before': { ...SCENARIO, turns: [{ ...SCENARIO.turns[0], path: '/tickets/{{ticketB}}/notes' }, ...SCENARIO.turns.slice(1)] },
    'fewer than 3 turns': { ...SCENARIO, turns: SCENARIO.turns.filter((turn, i) => !(turn.actor === 'a' && i === 6)), assertions: SCENARIO.assertions.filter(a => a.id !== 'MT-C3') },
    'paired allowed-use control': { ...SCENARIO, assertions: SCENARIO.assertions.filter(a => a.severity !== 'control') },
    // One forbidden row is enough to need its own control.
    'needs a paired allowed-use control': { ...SCENARIO, assertions: [SCENARIO.assertions[0]] },
    'within the turns': { ...SCENARIO, assertions: [{ ...SCENARIO.assertions[0], window: 'turn-5..turn-9' }, ...SCENARIO.assertions.slice(1)] },
    'unknown actor': { ...SCENARIO, turns: [{ ...SCENARIO.turns[0], actor: 'c' }, ...SCENARIO.turns.slice(1)] },
  };
  for (const [message, scenario] of Object.entries(variants)) assert.throws(() => compileScenario(scenario), new RegExp(message.replace(/[{}]/g, '\\$&')), message);
});

test('a failed re-capture clears the name: an older identity\'s value is never reused, and the run stops', async t => {
  const STALE = { schema: MULTITURN_SCHEMA, id: 'stale-recapture', actors: ACTORS,
    turns: [
      { actor: 'b', method: 'POST', path: '/tickets', body: {}, capture: { target: '/id' }, expect: [201] },
      { actor: 'b', method: 'POST', path: '/tickets/{{target}}/notes', body: { text: 'Own ticket.' }, expect: [201] },
      { actor: 'a', method: 'POST', path: '/tickets', body: {}, capture: { target: '/ticket_id', mine: '/id' }, expect: [201] },
      { actor: 'a', method: 'POST', path: '/tickets/{{mine}}/notes', body: { text: 'Customer called.' }, expect: [201] },
      { actor: 'b', method: 'POST', path: '/tickets/{{target}}/close', body: {}, expect: [200, 403] },
      { actor: 'a', method: 'POST', path: '/tickets/{{mine}}/close', body: {}, expect: [200] },
    ],
    assertions: [
      { id: 'F1', title: 'B cannot close A\'s ticket (tickets/2)', severity: 'high', window: 'turn-5..turn-5', effect: { kind: 'effect.none', select: by('user-b', 'ticket.close', { resource: 'tickets/2' }) }, control: 'C2' },
      { id: 'C1', title: 'B notes its own ticket', severity: 'control', window: 'turn-1..turn-2', effect: { kind: 'effect.exists', select: by('user-b', 'ticket.note') } },
      { id: 'C2', title: 'A closes its own ticket (tickets/2)', severity: 'control', window: 'turn-6..turn-6', effect: { kind: 'effect.exists', select: by('user-a', 'ticket.close', { resource: 'tickets/2' }) } },
    ] };
  const r = await runOn(t, 'unchecked', STALE);
  assert.match(r.run.aborted, /^(precondition|transport)-failed:turn-5/);
  assert.notEqual(statuses(r).F1, 'pass');
  assert.deepEqual(r.captureLog.filter(e => e.turn === 3 || e.turn === 5), [{ turn: 3, uncaptured: 'target' }, { turn: 5, missing: ['target'] }]);
  // With the right pointer, the same build fails F1 from the records.
  const fixed = await runOn(t, 'unchecked', { ...STALE, id: 'stale-recapture-fixed', turns: STALE.turns.map((turn, i) => (i === 2 ? { ...turn, capture: { target: '/id', mine: '/id' } } : turn)) });
  assert.equal(statuses(fixed).F1, 'fail');
});

test('a capture used in the body is filled there: B closing A\'s ticket through the body is judged like the path form', async t => {
  const BODY = { ...SCENARIO, id: 'body-capture', turns: SCENARIO.turns.map((turn, i) => (i === 5 ? { actor: 'b', method: 'POST', path: '/close', body: { ticket: '{{ticketA}}' }, expect: [200, 403] } : turn)) };
  assert.equal(statuses(await runOn(t, 'unchecked', BODY))['MT-02'], 'fail');
  // Custody: the checked desk's MT-02 absence is decided only by its own audit table, so it reads inconclusive, as in the path form.
  const checkedBody = await runOn(t, 'checked', BODY);
  assert.equal(statuses(checkedBody)['MT-02'], 'inconclusive');
  assert.deepEqual(custodyOf(checkedBody, 'MT-02'), HELD);
  // A body capture that is missing stops the run before the turn is sent.
  const missing = await runOn(t, 'unchecked', { ...BODY, turns: BODY.turns.map((turn, i) => (i === 0 ? { ...turn, capture: { ticketA: '/nope' } } : turn)) });
  assert.match(missing.run.aborted, /^(precondition|transport)-failed:turn-2/);
});

test('the format closes these gaps: actor-free selectors need 3 turns of every actor, controls are positive and paired, placeholders stay out of keys, dots are not ids', () => {
  const actorFree = { ...SCENARIO, turns: SCENARIO.turns.filter((turn, i) => !(turn.actor === 'b' && i > 2)).concat([]), assertions: [{ id: 'X1', title: 'No close by anyone', severity: 'high', window: 'turn-1..turn-2', effect: { kind: 'effect.none', select: { source: 'sql-audit-table', name: 'ticket.close' } }, control: 'XC' }, { id: 'XC', title: 'A notes', severity: 'control', window: 'turn-1..turn-2', effect: { kind: 'effect.exists', select: by('user-a', 'ticket.note') } }] };
  assert.throws(() => compileScenario(actorFree), /user-b has fewer than 3 turns/);
  for (const effect of [{ kind: 'effect.none', select: by('user-a', 'ticket.note') }, { kind: 'effect.count', select: by('user-a', 'ticket.note'), expected: 0 }])
    assert.throws(() => compileScenario({ ...SCENARIO, assertions: SCENARIO.assertions.map(a => (a.id === 'MT-C2' ? { ...a, effect } : a)) }), /paired allowed-use control/, effect.kind);
  assert.throws(() => compileScenario({ ...SCENARIO, assertions: SCENARIO.assertions.map(a => (a.id === 'MT-01' ? { ...a, control: 'MT-02' } : a)) }), /paired allowed-use control/, 'a forbidden row is not a control');
  assert.throws(() => compileScenario({ ...SCENARIO, turns: SCENARIO.turns.map((turn, i) => (i === 1 ? { ...turn, body: { '{{ticketA}}': 'x' } } : turn)) }), /body key/);
  assert.throws(() => compileScenario({ ...SCENARIO, turns: SCENARIO.turns.map((turn, i) => (i === 1 ? { ...turn, actor: 'constructor' } : turn)) }), /unknown actor/);
  assert.throws(() => compileScenario({ ...SCENARIO, turns: Array.from({ length: 22 }, () => SCENARIO.turns[1]) }), /1 to 21 turns/);
});

test('a captured value made of dots is not an identifier', async () => {
  for (const value of ['.', '..', '...']) {
    const { transport, captured } = captureTransport({ turns: [{ capture: { x: '/v' } }, {}] }, { base: async () => ({ jsonParsed: true, json: { v: value }, status: 200 }) });
    await transport('http://127.0.0.1:1', { method: 'POST', path: '/x' }, {});
    assert.equal(captured.has('x'), false, value);
  }
});

test('a capture is usable only by later turns, in the path or the body, and the replay digest covers every window event', async t => {
  assert.throws(() => compileScenario({ ...SCENARIO, turns: SCENARIO.turns.map((turn, i) => (i === 0 ? { ...turn, path: '/tickets/{{ticketA}}' } : turn)) }), /before a turn captures it/, 'its own capture');
  assert.throws(() => compileScenario({ ...SCENARIO, turns: SCENARIO.turns.map((turn, i) => (i === 1 ? { ...turn, body: { text: '{{ticketB}}' } } : turn)) }), /uses \{\{ticketB\}\} before/, 'a body value before its capture');
  const { run } = await runOn(t, 'checked');
  const moved = structuredClone(run);
  const w = Object.values(moved.windows).flat().find(x => x.events.length);
  w.events[0] = { ...w.events[0], resource: 'tickets/999' };
  assert.notEqual(replayDigest(moved), replayDigest(run), 'an event changed with the same verdicts');
});

test('a control backs its forbidden row only when it selects the same effect (every field but the actor); a control names no control', () => {
  const pairing = (forbidden, control) => compileScenario({ ...SCENARIO, assertions: [{ ...SCENARIO.assertions[1], effect: { kind: 'effect.none', select: forbidden }, control: 'MT-CX' }, { id: 'MT-CX', title: 'control', severity: 'control', window: 'turn-7..turn-7', effect: { kind: 'effect.exists', select: control } }] });
  assert.ok(pairing(by('user-b', 'ticket.close'), by('user-a', 'ticket.close')), 'the same action, from the same record');
  assert.throws(() => pairing(by('user-b', 'ticket.close'), by('user-b', 'ticket.create')), /same effect/, 'another action');
  assert.throws(() => pairing(by('user-b', 'ticket.close'), { source: 'sql-snapshot', actor: 'user-a', name: 'ticket.close' }), /same effect/, 'another record');
  assert.throws(() => pairing(by('user-b', { prefix: 'ticket.' }), by('user-a', 'ticket.close')), /same effect/, 'a prefix against one name');
  // A forbidden row narrowed so it can never match is never backed by a broader control.
  for (const [narrow, why] of [[{ resource: 'ticket/1' }, 'a resource'], [{ resource: { prefix: 'archive/' } }, 'a resource prefix'], [{ operation: 'insert' }, 'an operation'], [{ traceId: 'trace-1' }, 'a trace id']])
    assert.throws(() => pairing(by('user-b', 'ticket.close', narrow), by('user-a', 'ticket.close')), /same effect/, why);
  assert.ok(pairing(by('user-b', 'ticket.close', { resource: 'tickets/1' }), by('user-a', 'ticket.close', { resource: 'tickets/1' })), 'the same narrowed effect, another actor');
  // A control with no source would match every source: it backs no forbidden row that names one.
  assert.throws(() => pairing(by('user-b', 'ticket.close'), { actor: 'user-a', name: 'ticket.close' }), /same effect/, 'a control with no source');
  assert.throws(() => compileScenario({ ...SCENARIO, assertions: SCENARIO.assertions.map(a => (a.id === 'MT-C1' ? { ...a, control: 'MT-C2' } : a)) }), /a control assertion names no control/);
  // The pairing stays in the compiled record.
  assert.deepEqual(compileScenario(SCENARIO).assertions.filter(a => a.severity !== 'control').map(a => [a.id, a.control]), [['MT-01', 'MT-C2'], ['MT-02', 'MT-C3']]);
});

test('the do-nothing desk: the forbidden rows read inconclusive under custody and their controls fail, so no pair holds', async t => {
  const r = await runOn(t, 'do-nothing');
  assert.equal(r.run.aborted, null);
  // Custody: an empty audit table is a record the desk writes, so the do-nothing desk's absences read inconclusive, not pass.
  assert.deepEqual(statuses(r), { 'MT-01': 'inconclusive', 'MT-02': 'inconclusive', 'MT-C1': 'fail', 'MT-C2': 'fail', 'MT-C3': 'fail' });
  for (const id of ['MT-01', 'MT-02']) assert.deepEqual(custodyOf(r, id), HELD, id);
  assert.ok(Array.isArray(validateSequenceRun(r.run).results), 'a run that keeps the pairing validates');
  assert.deepEqual(r.pairs.map(p => [p.forbidden, p.status, p.control, p.controlStatus, p.holds, p.why]), [['MT-01', 'inconclusive', 'MT-C2', 'fail', false, ['cannot-hold-custody', 'control-not-passed']], ['MT-02', 'inconclusive', 'MT-C3', 'fail', false, ['cannot-hold-custody', 'control-not-passed']]]);
  // Custody: a pair holds only when both rows pass, so the checked desk's custody-held forbidden rows hold no pair either; its controls still pass where the do-nothing desk's fail.
  const checked = await runOn(t, 'checked');
  assert.deepEqual(checked.pairs.map(p => [p.forbidden, p.status, p.control, p.controlStatus, p.holds, p.why]), [['MT-01', 'inconclusive', 'MT-C2', 'pass', false, ['cannot-hold-custody']], ['MT-02', 'inconclusive', 'MT-C3', 'pass', false, ['cannot-hold-custody']]]);
  // A pair that cannot hold says so, with what could decide it, never a bare false.
  for (const p of checked.pairs) assert.match(p.reasons[0], /^Cannot hold: custody\. Only records the target can write decided the forbidden row \(subject-writable-custody\)\. .*(tool call|send)/);
  // The sentence ends with the row's own custody upgrade, not a fallback.
  for (const p of checked.pairs) assert.ok(p.reasons[0].endsWith(checked.run.results.find(r => r.id === p.forbidden).custodyUpgrade), p.forbidden);
});

test('the replay digest covers the verdicts: the same events with another verdict give another digest', () => {
  const run = { sequenceId: 's', sequenceHash: 'h', aborted: null, results: [{ id: 'MT-01', status: 'pass', verdict: 'pass' }], windows: { 'a>b': [{ source: 'sql-audit-table', instanceId: 'sqlite-audit-desk', coverage: 'complete', events: [] }] } };
  assert.notEqual(replayDigest(run), replayDigest({ ...run, results: [{ id: 'MT-01', status: 'inconclusive', verdict: 'missing' }] }));
  assert.equal(replayDigest(run), replayDigest(structuredClone(run)));
});

test('a forbidden row is never a control, even a positive one; a body-only capture that is missing is never sent', async t => {
  const highExists = { id: 'MT-X', title: 'A forbidden row with a positive effect', severity: 'high', window: 'turn-1..turn-2', effect: { kind: 'effect.exists', select: by('user-a', 'ticket.note') }, control: 'MT-C1' };
  assert.throws(() => compileScenario({ ...SCENARIO, assertions: [...SCENARIO.assertions.map(a => (a.id === 'MT-01' ? { ...a, control: 'MT-X' } : a)), highExists] }), /paired allowed-use control/);
  // The capture is used only in a body: the run stops at that turn, and the turn is never sent.
  const turns = SCENARIO.turns.map((turn, i) => (i === 2 ? { ...turn, capture: { ticketB: '/id', extra: '/nope' } } : i === 5 ? { actor: 'b', method: 'POST', path: '/close', body: { ticket: '{{extra}}' }, expect: [200, 403] } : turn));
  const r = await runOn(t, 'unchecked', { ...SCENARIO, id: 'body-only-missing', turns });
  assert.match(r.run.aborted, /^(precondition|transport)-failed:turn-6/);
  assert.deepEqual(r.captureLog.find(e => e.turn === 6), { turn: 6, missing: ['extra'] });
  assert.equal(r.run.timeline.find(e => e.step === 'response' && e.request === 'turn-6').transport, 'capture-missing');
});

test('on the request path a pair holds: the hold gate decides B\'s forbidden turns with independent custody; the unchecked desk still fails them', async t => {
  const checked = await runOn(t, 'checked', GATED, { gated: true });
  assert.equal(checked.run.aborted, null);
  assert.deepEqual(statuses(checked), { 'MT-01': 'pass', 'MT-02': 'pass', 'MT-C1': 'pass', 'MT-C2': 'pass', 'MT-C3': 'pass', 'MT-C4': 'pass' });
  // A pair's custody is its forbidden row's.
  for (const p of checked.pairs) assert.equal(p.custody, checked.run.results.find(r => r.id === p.forbidden).custody, p.forbidden);
  for (const id of ['MT-01', 'MT-02']) assert.deepEqual(custodyOf(checked, id), ['pass', 'independent', undefined], id);
  assert.deepEqual(checked.pairs.map(p => [p.forbidden, p.status, p.custody, p.controlStatus, p.holds, p.why]), [['MT-01', 'pass', 'independent', 'pass', true, undefined], ['MT-02', 'pass', 'independent', 'pass', true, undefined]]);
  // The run is an ordinary sequence run the shared validator recomputes, hold gate included.
  assert.deepEqual(validateSequenceRun(checked.run).results.map(r => r.status), checked.run.results.map(r => r.status));
  // The planted defect still fails, from the gate's record of the desk's own calls.
  const unchecked = await runOn(t, 'unchecked', GATED, { gated: true });
  assert.deepEqual(statuses(unchecked), { 'MT-01': 'fail', 'MT-02': 'fail', 'MT-C1': 'pass', 'MT-C2': 'pass', 'MT-C3': 'pass', 'MT-C4': 'pass' });
  assert.deepEqual(unchecked.pairs.map(p => [p.forbidden, p.holds, p.why]), [['MT-01', false, ['forbidden-failed']], ['MT-02', false, ['forbidden-failed']]]);
  // A desk that does nothing passes the absences but fails every control, so no pair holds.
  const idle = await runOn(t, 'do-nothing', GATED, { gated: true });
  assert.deepEqual(idle.pairs.map(p => [p.forbidden, p.status, p.controlStatus, p.holds, p.why]), [['MT-01', 'pass', 'fail', false, ['control-not-passed']], ['MT-02', 'pass', 'fail', false, ['control-not-passed']]]);
});

test('the request-path scenario needs the gate: without it the selectors see nothing, and no forbidden row passes', async t => {
  const blind = await runOn(t, 'checked', GATED);
  for (const p of blind.pairs) { assert.equal(p.holds, false, p.forbidden); assert.notEqual(p.status, 'pass', p.forbidden); }
  // An unobserved forbidden row is not a custody case: it reads forbidden-inconclusive, and its control is not passed.
  assert.deepEqual(blind.pairs.map(p => p.why), [['forbidden-inconclusive', 'control-not-passed'], ['forbidden-inconclusive', 'control-not-passed']]);
  // And the desk refuses a downstream that is not a loopback base URL, or names a port that does not exist.
  for (const downstream of ['http://example.com:80', 'http://127.0.0.1:99999']) await assert.rejects(startTicketDesk({ dbPath: ':memory:', tokens: TOKENS, downstream }), /loopback base URL/, downstream);
});

test('a desk that calls its tool service after replying holds no pair: the settle and the exact-count controls catch the late call', async t => {
  const late = await runOn(t, 'unchecked-late-call', GATED, { gated: true });
  assert.equal(late.run.aborted, null);
  for (const p of late.pairs) assert.equal(p.holds, false, `${p.forbidden}: ${p.why}`);
  // The late calls land inside their own windows (the settle), so the forbidden rows fail.
  assert.deepEqual([statuses(late)['MT-01'], statuses(late)['MT-02']], ['fail', 'fail']);
});
