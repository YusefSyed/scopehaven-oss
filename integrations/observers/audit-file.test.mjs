import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, appendFileSync, renameSync, truncateSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createAuditFileObserver } from './audit-file.mjs';
import { collectWindow, evaluateEffectAssertion } from './events.mjs';
import { digest } from '../../src/domain.mjs';

// Lines shaped like Open WebUI's audit.log (AUDIT_LOG_LEVEL=METADATA), with a status.
const ORIGIN = 'http://127.0.0.1:4420';
const KB = '985a317d-e23c-49bc-86b5-f60cd58472be';
const entry = (verb, uri, status, userId = 'u-support', extra = {}) => ({ id: Math.random().toString(16).slice(2), timestamp: Date.now(), user: { id: userId, email: `${userId}@synthetic.test` }, audit_level: 'METADATA', verb, request_uri: `${ORIGIN}${uri}`, response_status_code: status, ...extra });
const line = (...args) => `${JSON.stringify(entry(...args))}\n`;
const witnessLine = from => line('POST', `/api/v1/chats/new?scopehaven_witness=${from.witnessNonce}`, 200);
const rules = [
  { name: 'knowledge.update', method: 'POST', path: '/api/v1/knowledge/{id}/update', refusedStatuses: [400, 401, 403] },
  { name: 'chat.create', method: 'POST', path: '/api/v1/chats/new', operation: 'insert' },
];
const ignore = [{ method: 'POST', path: '/api/v1/auths/signin' }];
const none = { kind: 'effect.none', select: { source: 'file-audit-log', actor: 'support1', name: 'knowledge.update' } };
function setup(t, extra = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-audit-file-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, 'audit.log');
  writeFileSync(path, line('POST', '/api/v1/auths/signin', 200, 'u-admin'));
  return { path, o: createAuditFileObserver({ path, origin: ORIGIN, rules, ignore, actors: { support1: 'u-support' }, witness: 'chat.create', settleMs: 300, ...extra }) };
}

test('a committed forbidden write fails; a declared refusal with this window\'s witness proves absence', async t => {
  const { path, o } = setup(t);
  await o.start();
  let from = await o.mark();
  appendFileSync(path, line('POST', `/api/v1/knowledge/${KB}/update`, 200) + witnessLine(from));
  let w = await collectWindow(o, from, await o.mark());
  assert.equal(w.coverage, 'complete', w.reason);
  assert.equal(evaluateEffectAssertion(none, [w]).verdict, 'fail');
  from = await o.mark();
  appendFileSync(path, line('POST', `/api/v1/knowledge/${KB}/update`, 400) + line('POST', '/api/v1/auths/signin', 200, 'u-admin') + witnessLine(from));
  w = await collectWindow(o, from, await o.mark());
  assert.equal(w.coverage, 'complete', w.reason);
  // The witness is the test's own request: never an event.
  assert.deepEqual(w.events.map(e => [e.name, e.outcome, e.actor]), [['knowledge.update', 'denied', 'support1']]);
  assert.equal(evaluateEffectAssertion(none, [w]).verdict, 'pass');
});

test('real Open WebUI METADATA lines have a null status: unknown, so absence is never claimed', async t => {
  const { path, o } = setup(t);
  const from = await o.mark();
  appendFileSync(path, line('POST', `/api/v1/knowledge/${KB}/update`, null) + witnessLine(from));
  const w = await collectWindow(o, from, await o.mark());
  assert.equal(w.coverage, 'partial');
  assert.equal(evaluateEffectAssertion(none, [w]).verdict, 'missing');
});

test('a request_uri built from a crafted Host header is unreadable, never skipped', async t => {
  for (const host of ['127.0.0.1:4420/x', '127.0.0.1:4420?', '127.0.0.1:4420#', 'a b', 'evil.example:4420', '127.0.0.1:4421']) {
    const { path, o } = setup(t);
    const from = await o.mark();
    const crafted = { ...entry('POST', '', 200), request_uri: `http://${host}/api/v1/knowledge/${KB}/update` };
    appendFileSync(path, `${JSON.stringify(crafted)}\n` + witnessLine(from));
    const w = await collectWindow(o, from, await o.mark());
    assert.equal(w.coverage, 'partial', `host ${host}: ${w.reason}`);
    assert.notEqual(evaluateEffectAssertion(none, [w]).verdict, 'pass', host);
  }
});

test('a late witness from an earlier window never completes the next window', async t => {
  const { path, o } = setup(t);
  const w1from = await o.mark(), w1to = await o.mark();
  const w2from = await o.mark();
  appendFileSync(path, witnessLine(w1from)); // window 1's witness arrives late, inside window 2
  const w2 = await collectWindow(o, w2from, await o.mark());
  assert.match(w2.reason, /audit-witness-not-logged/);
  // Window 1 is collected late (after window 2): it never reads past its own end mark,
  // so its witness, written after that mark, cannot complete it.
  const w1 = await collectWindow(o, w1from, w1to);
  assert.equal(w1.coverage, 'partial'); assert.match(w1.reason, /audit-collect-late/);
});

test('a rule line after the witness, or an end mark inside a line, is not covered', async t => {
  let { path, o } = setup(t);
  let from = await o.mark();
  appendFileSync(path, witnessLine(from) + line('POST', `/api/v1/knowledge/${KB}/update`, 200));
  let w = await collectWindow(o, from, await o.mark());
  assert.match(w.reason, /rule-line-after-witness/);
  ({ path, o } = setup(t));
  from = await o.mark();
  const half = line('POST', `/api/v1/knowledge/${KB}/update`, 200);
  appendFileSync(path, witnessLine(from) + half.slice(0, 30));
  w = await collectWindow(o, from, await o.mark());
  assert.match(w.reason, /end-mark-inside-a-line/);
  assert.notEqual(evaluateEffectAssertion(none, [w]).verdict, 'pass');
});

test('rotation, truncation in place and copytruncate with regrowth fail the window', async t => {
  let { path, o } = setup(t);
  let from = await o.mark();
  appendFileSync(path, witnessLine(from));
  let to = await o.mark();
  writeFileSync(`${path}.new`, witnessLine(from));
  renameSync(`${path}.new`, path); // rotated: new inode
  assert.equal((await collectWindow(o, from, to)).coverage, 'failed');
  ({ path, o } = setup(t));
  from = await o.mark();
  appendFileSync(path, line('POST', `/api/v1/knowledge/${KB}/update`, 200) + witnessLine(from));
  to = await o.mark();
  truncateSync(path, 0); // copytruncate: same inode, emptied ...
  appendFileSync(path, line('POST', '/api/v1/auths/signin', 200, 'u-admin').repeat(20)); // ... and regrown past the old end
  assert.equal((await collectWindow(o, from, to)).coverage, 'failed');
});

test('ambiguous, unreadable, unknown-route, path-variant and coerced-status lines are gaps', async t => {
  const overlapping = [...rules, { name: 'knowledge.any', method: 'POST', path: '/api/v1/knowledge/{id}/{action}' }];
  const cases = [
    { name: 'overlapping rules', rules: overlapping, line: () => line('POST', `/api/v1/knowledge/${KB}/update`, 200) },
    { name: 'unreadable', line: () => 'not json\n' },
    { name: 'missing uri', line: () => `${JSON.stringify({ verb: 'POST', response_status_code: 200 })}\n` },
    { name: 'unknown route', line: () => line('POST', '/api/v1/knowledge/create', 200) },
    { name: 'matrix params', line: () => line('POST', `/api/v1/knowledge/${KB};x=1/update`, 200) },
    { name: 'double slash', line: () => line('POST', `/api/v1//knowledge/${KB}/update`, 200) },
    { name: 'dot segment', line: () => line('POST', `/api/v1/x/%2e%2e/knowledge/${KB}/update`, 200) },
    { name: 'status "2e2"', line: () => line('POST', `/api/v1/knowledge/${KB}/update`, '2e2') },
    { name: 'status " 403 "', line: () => line('POST', `/api/v1/knowledge/${KB}/update`, ' 403 ') },
  ];
  for (const c of cases) {
    const { path, o } = setup(t, c.rules ? { rules: c.rules } : {});
    const from = await o.mark();
    appendFileSync(path, c.line() + witnessLine(from));
    const w = await collectWindow(o, from, await o.mark());
    assert.equal(w.coverage, 'partial', `${c.name}: ${w.reason}`);
    assert.notEqual(evaluateEffectAssertion(none, [w]).verdict, 'pass', c.name);
  }
});

test('late flush: a witness written after the end mark extends the window and is recorded', async t => {
  const { path, o } = setup(t, { settleMs: 2000 });
  const from = await o.mark(), to = await o.mark();
  setTimeout(() => appendFileSync(path, line('POST', `/api/v1/knowledge/${KB}/update`, 403) + witnessLine(from)), 300);
  const w = await collectWindow(o, from, to);
  assert.equal(w.coverage, 'complete', w.reason);
  assert.ok(o.lastFreshness.waitedMs >= 200 && o.lastFreshness.extendedPastMarkBytes > 0);
  assert.equal(evaluateEffectAssertion(none, [w]).verdict, 'pass');
});

test('configuration: origin, witness and refused statuses are validated; unknown users are unlisted', async t => {
  const { path, o } = setup(t);
  const from = await o.mark();
  appendFileSync(path, line('POST', `/api/v1/knowledge/${KB}/update`, 200, 'u-mallory') + witnessLine(from));
  const w = await collectWindow(o, from, await o.mark());
  assert.match(w.events[0].actor, /^unlisted:/);
  assert.equal(evaluateEffectAssertion(none, [w]).verdict, 'missing');
  assert.throws(() => createAuditFileObserver({ path, origin: `${ORIGIN}/x`, rules, witness: 'chat.create' }), /origin/);
  assert.throws(() => createAuditFileObserver({ path, rules, witness: 'chat.create' }), /origin/);
  assert.throws(() => createAuditFileObserver({ path, origin: ORIGIN, rules }), /witness/);
  assert.throws(() => createAuditFileObserver({ path, origin: ORIGIN, rules: [{ name: 'x', method: 'POST', path: '/a', refusedStatuses: [500] }], witness: 'x' }), /4xx/);
});

// Truncation, lines after the witness, logged paths and statuses.
const emptyLog = (t, extra = {}) => {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-audit-file-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, 'audit.log'); writeFileSync(path, '');
  return { path, o: createAuditFileObserver({ path, origin: ORIGIN, rules, ignore, actors: { support1: 'u-support' }, witness: 'chat.create', settleMs: 1000, quietMs: 200, ...extra }) };
};
const later = (ms, fn) => new Promise(resolve => setTimeout(() => { fn(); resolve(); }, ms));

test('truncation during the settle fails the window, even when it started on an empty log', async t => {
  // Target line, end mark, truncate to 0 at 150 ms, witness at 300 ms.
  let { path, o } = emptyLog(t);
  let from = await o.mark();
  appendFileSync(path, line('POST', `/api/v1/knowledge/${KB}/update`, 200));
  let to = await o.mark();
  let pending = Promise.all([later(150, () => truncateSync(path, 0)), later(300, () => appendFileSync(path, witnessLine(from)))]);
  let w = await collectWindow(o, from, to); await pending;
  assert.deepEqual([w.coverage, w.reason], ['failed', 'audit-file-truncated-or-rotated']);
  // from = to = 0, a late target, then truncate, then the witness.
  ({ path, o } = emptyLog(t));
  from = await o.mark(); to = await o.mark();
  pending = Promise.all([later(100, () => appendFileSync(path, line('POST', `/api/v1/knowledge/${KB}/update`, 200))), later(250, () => truncateSync(path, 0)), later(400, () => appendFileSync(path, witnessLine(from)))]);
  w = await collectWindow(o, from, to); await pending;
  assert.notEqual(evaluateEffectAssertion(none, [w]).verdict, 'pass', `${w.coverage} ${w.reason}`);
  // Truncated below the end mark during the settle, then regrown with the witness.
  ({ path, o } = emptyLog(t));
  from = await o.mark();
  appendFileSync(path, line('POST', `/api/v1/knowledge/${KB}/update`, 200).repeat(3));
  to = await o.mark();
  pending = Promise.all([later(150, () => truncateSync(path, 10)), later(300, () => appendFileSync(path, witnessLine(from)))]);
  w = await collectWindow(o, from, to); await pending;
  assert.equal(w.coverage, 'failed');
});

// A line after the witness cannot be attributed to the check (it may be the witness route's own
// doing or a later action): the window is partial, absence never passes, and the line is never
// an event, so it cannot satisfy effect.exists either.
const exists = { kind: 'effect.exists', select: { source: 'file-audit-log', actor: 'support1', name: 'knowledge.update' } };
const unattributed = (w, label) => {
  assert.notEqual(evaluateEffectAssertion(none, [w]).verdict, 'pass', `${label}: ${w.coverage} ${w.reason}`);
  assert.notEqual(evaluateEffectAssertion(exists, [w]).verdict, 'pass', label);
  assert.equal(w.coverage, 'partial'); assert.match(w.reason, /rule-line-after-witness/); assert.equal(w.events.length, 0, label);
};
test('a forbidden line logged after the witness and the end mark is read, and never passes absence', async t => {
  // Witness, end mark, then the committed forbidden line.
  let { path, o } = emptyLog(t);
  let from = await o.mark();
  appendFileSync(path, witnessLine(from));
  let to = await o.mark();
  appendFileSync(path, line('POST', `/api/v1/knowledge/${KB}/update`, 200));
  let w = await collectWindow(o, from, to);
  unattributed(w, 'after the end mark');
  // The forbidden line 50 ms after the end mark.
  ({ path, o } = emptyLog(t));
  from = await o.mark(); appendFileSync(path, witnessLine(from)); to = await o.mark();
  let pending = later(50, () => appendFileSync(path, line('POST', `/api/v1/knowledge/${KB}/update`, 200)));
  w = await collectWindow(o, from, to); await pending;
  unattributed(w, '50 ms after the end mark');
  // End mark first, witness flushed at 150 ms, forbidden line at 260 ms.
  ({ path, o } = emptyLog(t, { settleMs: 2000 }));
  from = await o.mark(); to = await o.mark();
  pending = Promise.all([later(150, () => appendFileSync(path, witnessLine(from))), later(260, () => appendFileSync(path, line('POST', `/api/v1/knowledge/${KB}/update`, 200)))]);
  w = await collectWindow(o, from, to); await pending;
  unattributed(w, 'witness flushed late');
});

test('the witness line is the test\'s own request, never an effect of its rule', async t => {
  const { path, o } = emptyLog(t);
  const from = await o.mark();
  appendFileSync(path, witnessLine(from));
  const w = await collectWindow(o, from, await o.mark());
  assert.equal(w.coverage, 'complete', w.reason); assert.equal(w.events.length, 0);
  const chat = { source: 'file-audit-log', name: 'chat.create' };
  assert.equal(evaluateEffectAssertion({ kind: 'effect.exists', select: chat }, [w]).verdict, 'fail');
  assert.equal(evaluateEffectAssertion({ kind: 'effect.count', select: chat, expected: 1 }, [w]).verdict, 'fail');
  assert.equal(evaluateEffectAssertion({ kind: 'effect.none', select: chat }, [w]).verdict, 'pass');
  // A witness line from another window is neither an effect nor this window's witness.
  const next = await o.mark();
  appendFileSync(path, witnessLine(from) + witnessLine(next));
  const w2 = await collectWindow(o, next, await o.mark());
  assert.equal(w2.coverage, 'partial'); assert.match(w2.reason, /foreign-audit-witness/); assert.equal(w2.events.length, 0);
});

test('logged paths are not decoded again; a "?" that could be part of the path is ambiguous', async t => {
  const promptRules = [...rules, { name: 'prompt.update', method: 'POST', path: '/api/v1/prompts/command/{command}/update' }];
  const prompt = { kind: 'effect.none', select: { source: 'file-audit-log', name: 'prompt.update' } };
  // The decoded path /command/sum?x/update would be read as /command/sum by a "?" split.
  let { path, o } = emptyLog(t, { rules: promptRules, ignore: [...ignore, { path: '/api/v1/prompts/command/{command}' }] });
  let from = await o.mark();
  appendFileSync(path, line('POST', '/api/v1/prompts/command/sum?x/update', 200) + witnessLine(from));
  let w = await collectWindow(o, from, await o.mark());
  assert.notEqual(evaluateEffectAssertion(prompt, [w]).verdict, 'pass', `${w.coverage} ${w.reason}`);
  assert.match(w.reason, /ambiguous-audit-line/);
  // A literal %2F in an already-decoded path is one segment, not a "/".
  ({ path, o } = emptyLog(t, { rules: promptRules, ignore: [...ignore, { path: '/api/v1/prompts/command/{a}/{b}/update' }] }));
  from = await o.mark();
  appendFileSync(path, line('POST', '/api/v1/prompts/command/a%2Fb/update', 200) + witnessLine(from));
  w = await collectWindow(o, from, await o.mark());
  assert.equal(evaluateEffectAssertion(prompt, [w]).verdict, 'fail', `${w.coverage} ${w.reason}`);
});

test('a missing status has its own reason, and a control character makes only its line unreadable', async t => {
  let { path, o } = emptyLog(t);
  let from = await o.mark();
  appendFileSync(path, line('POST', `/api/v1/knowledge/${KB}/update`, null) + witnessLine(from));
  const raw = await o.collect(from, await o.mark());
  assert.equal(raw.coverage, 'partial'); assert.match(raw.reason, /audit-status-missing/);
  ({ path, o } = emptyLog(t));
  from = await o.mark();
  appendFileSync(path, line('POST', `/api/v1/knowledge/KB\t/update`, 200) + line('POST', `/api/v1/knowledge/${KB}/update`, 200) + witnessLine(from));
  const w = await collectWindow(o, from, await o.mark());
  assert.equal(w.coverage, 'partial'); assert.match(w.reason, /unreadable-audit-line/);
  assert.equal(evaluateEffectAssertion(none, [w]).verdict, 'fail', 'the other lines are still read');
});

// Lines still being written, late collects and rotation.
test('a line still being written is activity, and an incomplete line at return is never covered', async t => {
  // Witness, clean end mark; half of a forbidden line 150 ms later, the rest 600 ms after that.
  let { path, o } = emptyLog(t, { settleMs: 1000, quietMs: 300 });
  let from = await o.mark(); appendFileSync(path, witnessLine(from)); let to = await o.mark();
  let target = line('POST', `/api/v1/knowledge/${KB}/update`, 200);
  let pending = Promise.all([later(150, () => appendFileSync(path, target.slice(0, 60))), later(750, () => appendFileSync(path, target.slice(60)))]);
  let w = await collectWindow(o, from, to); await pending;
  assert.notEqual(evaluateEffectAssertion(none, [w]).verdict, 'pass', `half a line: ${w.coverage} ${w.reason}`);
  // One long forbidden line streamed in 64-byte chunks every 50 ms; the log never pauses.
  ({ path, o } = emptyLog(t, { settleMs: 1000, quietMs: 300 }));
  from = await o.mark(); appendFileSync(path, witnessLine(from)); to = await o.mark();
  target = line('POST', `/api/v1/knowledge/${KB}/update`, 200, 'u-support', { request_object: 'x'.repeat(2000) });
  const chunks = []; for (let i = 0; i < target.length; i += 64) chunks.push(target.slice(i, i + 64));
  let k = 0; const stream = setInterval(() => { if (k < chunks.length) appendFileSync(path, chunks[k++]); else clearInterval(stream); }, 50);
  t.after(() => clearInterval(stream));
  w = await collectWindow(o, from, to);
  assert.notEqual(evaluateEffectAssertion(none, [w]).verdict, 'pass', `streamed line: ${w.coverage} ${w.reason}`);
  assert.equal(w.coverage, 'partial');
  await new Promise(resolve => setTimeout(resolve, (chunks.length - k) * 50 + 100));
  // The partial line already exists when collect starts and completes at 900 ms.
  ({ path, o } = emptyLog(t, { settleMs: 1000, quietMs: 300 }));
  from = await o.mark(); appendFileSync(path, witnessLine(from)); to = await o.mark();
  target = line('POST', `/api/v1/knowledge/${KB}/update`, 200); appendFileSync(path, target.slice(0, 60));
  pending = later(900, () => appendFileSync(path, target.slice(60)));
  w = await collectWindow(o, from, to); await pending;
  assert.notEqual(evaluateEffectAssertion(none, [w]).verdict, 'pass', `partial line at collect: ${w.coverage} ${w.reason}`);
});

test('a late collect never reads past its end mark, so a later line cannot satisfy effect.exists', async t => {
  const exists = { kind: 'effect.exists', select: { source: 'file-audit-log', name: 'knowledge.update' } };
  for (const withWitness of [false, true]) {
    const { path, o } = emptyLog(t);
    const from = await o.mark();
    if (withWitness) appendFileSync(path, witnessLine(from));
    const to = await o.mark();
    appendFileSync(path, line('POST', `/api/v1/knowledge/${KB}/update`, 200)); // after the end mark
    await new Promise(resolve => setTimeout(resolve, 400)); // the caller collects later (as a sequence does)
    const w = await collectWindow(o, from, to);
    assert.equal(w.events.length, 0, `witness ${withWitness}`);
    assert.notEqual(evaluateEffectAssertion(exists, [w]).verdict, 'pass');
    assert.equal(w.coverage, 'partial'); assert.match(w.reason, /audit-collect-late/);
  }
  // A late collect with nothing written after the end mark is still complete.
  const { path, o } = emptyLog(t);
  const from = await o.mark(); appendFileSync(path, witnessLine(from)); const to = await o.mark();
  await new Promise(resolve => setTimeout(resolve, 400));
  assert.equal((await collectWindow(o, from, to)).coverage, 'complete');
});

test('a log rotated after start() and before the window starts fails the window', async t => {
  const { path, o } = emptyLog(t);
  await o.start();
  renameSync(path, `${path}.1`); writeFileSync(path, ''); // logrotate (create mode); the writer still holds the old file
  const from = await o.mark();
  appendFileSync(`${path}.1`, line('POST', `/api/v1/knowledge/${KB}/update`, 200));
  appendFileSync(path, witnessLine(from));
  const w = await collectWindow(o, from, await o.mark());
  assert.deepEqual([w.coverage, w.reason], ['failed', 'audit-file-rotated-before-window']);
  // The next window, after the writer has reopened the new file, is judged normally.
  const next = await o.mark(); appendFileSync(path, witnessLine(next));
  assert.equal((await collectWindow(o, next, await o.mark())).coverage, 'complete');
});

// A settlement gap window (collect with { gap: true }) is an exact
// range with no witness of its own. Its own window's witness line and any other window's witness line are the test's own
// requests, never effects; the rule line between them is one.
test('a settlement gap window skips every witness line, its own and another window\'s, and keeps the rule lines', async t => {
  const { path, o } = setup(t);
  await o.start();
  const from = await o.mark(), other = await o.mark();
  appendFileSync(path, witnessLine(from) + line('POST', `/api/v1/knowledge/${KB}/update`, 200) + witnessLine(other) + line('POST', '/api/v1/auths/signin', 200, 'u-admin'));
  const gap = await o.collect(from, await o.mark(), { gap: true });
  assert.equal(gap.coverage, 'complete', gap.reason);
  assert.deepEqual(gap.events.map(e => [e.name, e.operation, e.outcome, e.actor]), [['knowledge.update', 'update', 'committed', 'support1']]);
  assert.equal(evaluateEffectAssertion({ kind: 'effect.none', select: { source: 'file-audit-log', name: 'chat.create' } }, [{ source: 'file-audit-log', instanceId: o.instanceId, scope: o.scope, ...gap }]).verdict, 'pass', 'no witness line counts as chat.create');
});

// An unlisted user and the line it came from are digests keyed per observer instance.
test('an unlisted user and its line are kept as digests keyed per observer instance; a declared user stays', async t => {
  const { path, o } = setup(t);
  const other = createAuditFileObserver({ path, origin: ORIGIN, rules, ignore, actors: { support1: 'u-support' }, witness: 'chat.create', settleMs: 300 });
  const [from, otherFrom] = [await o.mark(), await other.mark()];
  const mallory = line('POST', `/api/v1/knowledge/${KB}/update`, 200, 'u-mallory');
  appendFileSync(path, mallory + mallory + line('POST', `/api/v1/knowledge/${KB}/update`, 200) + witnessLine(from));
  const w = await collectWindow(o, from, await o.mark());
  assert.match(w.events[0].actor, /^unlisted:[0-9a-f]{16}$/);
  assert.notEqual(w.events[0].actor, `unlisted:${digest('u-mallory').slice(0, 16)}`, 'not the plain SHA-256 of the user id');
  assert.equal(w.events[1].actor, w.events[0].actor);
  assert.equal(w.events[2].actor, 'support1');
  assert.notEqual(w.events[0].contentDigest, digest(digest(mallory.trimEnd())), 'the line digest cannot confirm a guessed user');
  const ow = await collectWindow(other, otherFrom, await other.mark());
  const otherActor = ow.events.find(e => e.actor !== 'support1')?.actor;
  assert.match(otherActor, /^unlisted:[0-9a-f]{16}$/);
  assert.notEqual(otherActor, w.events[0].actor, 'another observer instance keys it differently');
  // A settlement gap window keys the same way.
  const gapFrom = await o.mark();
  appendFileSync(path, mallory);
  const gap = await o.collect(gapFrom, await o.mark(), { gap: true });
  assert.equal(gap.events[0].actor, w.events[0].actor);
  assert.notEqual(gap.events[0].contentDigest, digest(digest(mallory.trimEnd())), 'the line digest cannot confirm a guessed user');
});
