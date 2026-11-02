// A late scoped egress entry that is exactly one completed after-witness request carries that request's ledger seq
// and captured record (egress-recorder/4). An effect.only clause reads such an entry as covered toward a pass when the record
// definitely matches an allowed selector that pins nothing beyond source, operation, name, resource and fields. Each newly decided
// case sits beside the refused case next to it: pure decisions over synthetic admitted windows, the recorder over real loopback
// HTTP (destination hosts are names only and are never resolved or contacted), and one connector run validated end to end.
import test from 'node:test';
import assert from 'node:assert/strict';
import { request, createServer } from 'node:http';
import { makeEffect, admitScoped, markUnfollowed, evaluateEffectAssertion, validateWindow, onlyCoverageFor, consistentScopedCaptures, collectWindow } from '../src/effect-events.mjs';
import { decideEffects } from '../src/http-effects.mjs';
import { validateIdempotencyDeclaration } from '../src/idempotency.mjs';
import { judgeOnly, onlyScopedComplete } from '../integrations/collateral/only.mjs';
import { createEgressRecorder } from '../integrations/observers/egress-recorder.mjs';
import { onFreePorts, watchingBinds } from '../integrations/observers/fixtures/free-port.mjs';
import { buildObservers } from '../integrations/observers/factory.mjs';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateHttpRunEvidence, validateTargetFile } from '../src/contracts.mjs';
import { createRegistry } from '../src/registry.mjs';
import { digest } from '../src/domain.mjs';

const DESK = 'desk.example.test', BILL = 'billing.example.test', INST = 'egress-recorder-sink';
const NOTE = 'POST /v1/tickets', OTHER_NOTE = 'POST /v1/zz', CHARGE = 'POST /v1/charges', REFUND = 'POST /v1/refunds';
const AFTER = 'egress-request-after-witness-request', IN_FLIGHT = 'egress-request-in-flight', AMBIGUOUS = 'egress-path-ambiguous';
const REMINDERS = ['Reminder: we are on it.', 'Reminder: awaiting your reply.', 'Reminder: closing soon.'];
const SCOPE = Object.freeze({ operations: ['send'], names: [BILL, DESK], actorAttribution: 'none', evidence: 'authoritative', capture: { [DESK]: ['/text'] } });
const FORM = Object.freeze({ ...SCOPE, captureForm: [DESK] });
const KEYED = Object.freeze({ ...SCOPE, idempotency: { [DESK]: validateIdempotencyDeclaration({ header: 'idempotency-key' }) } });
let seq = 0;
const ev = (name, resource, extra = {}) => makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId: INST }, seq: ++seq, observedAt: '2026-10-12T00:00:00.000Z',
  operation: 'send', name, resource, outcome: 'committed', ...extra });
// A captured record of the note text: a string, or a stored value as given ({ type, ... }).
const text = value => ({ status: 'captured', values: { '/text': typeof value === 'object' ? value : { type: typeof value === 'number' ? 'number' : 'string', value } } });
// A late entry as the recorder writes it; with a record it gets a seq after every event made so far.
const late = (captured, { name = DESK, resource = NOTE, codes = [AFTER], seq: s } = {}) => ({ name, resource, codes, ...(captured === undefined ? {} : { seq: s ?? 1000 + ++seq, captured }) });
const scoped = (events, entries, { followed = true, scope = SCOPE } = {}) => {
  const w = admitScoped({ source: 'http-egress', instanceId: INST, scope, coverage: 'partial', reason: [...new Set(entries.flatMap(e => e.codes))].sort().join(','), events, scoped: entries });
  return followed ? w : markUnfollowed(w);
};
const sel = (name, resource) => ({ source: 'http-egress', operation: 'send', name, ...(resource ? { resource } : {}) });
const noteAllow = (extra = {}) => ({ ...sel(DESK, NOTE), fields: [{ pointer: '/text', in: REMINDERS }], ...extra });
const only = ({ expect = [sel(BILL, CHARGE)], allow = [noteAllow()], countBy } = {}) => ({ kind: 'effect.only', expect: expect.map(select => ({ select, count: 1 })), allow, sources: ['http-egress'], ...(countBy ? { countBy } : {}) });
const decided = (clause, windows) => decideEffects([clause], windows)[0];
const verdictOf = (clause, windows) => decided(clause, windows).verdict;
const charge = () => [ev(BILL, CHARGE)];

// ---------------------------------------------------------------------------
test('1. lift: a late note whose own captured text is an allowed reminder lifts an effect.only pass; another text does not', () => {
  const lifted = decided(only(), [scoped(charge(), [late(text(REMINDERS[1]))])]);
  assert.equal(lifted.verdict, 'pass', lifted.basis);
  assert.match(lifted.basis, /did not attribute fits an allowed selector and no expected one/);
  assert.equal(verdictOf(only(), [scoped(charge(), [late(text('Your refund was sent.'))])]), 'missing', 'a text outside the allowed set');
  assert.equal(verdictOf(only(), [scoped(charge(), [late(undefined)])]), 'missing', 'as before: the entry without its record (the late-entry lift refuses a fields pin)');
  // equals and a form reading on a host declared that way lift too; the same form reading on a JSON-only host is refused (test 7).
  assert.equal(verdictOf(only({ allow: [{ ...sel(DESK, NOTE), fields: [{ pointer: '/text', equals: REMINDERS[0] }] }] }), [scoped(charge(), [late(text(REMINDERS[0]))])]), 'pass');
  assert.equal(verdictOf(only(), [scoped(charge(), [late(text({ type: 'text', value: REMINDERS[2] }))], { scope: FORM })]), 'pass', 'a form text value');
  // The late-entry lift itself is unchanged: an allow on name and resource alone lifts the entry with or without its record.
  for (const captured of [undefined, text('anything at all')]) assert.equal(verdictOf(only({ allow: [sel(DESK, NOTE)] }), [scoped(charge(), [late(captured)])]), 'pass');
});

test('2. unknown never lifts: a capped, undeclared, unreadable, absent, redacted or mistyped field reads missing', () => {
  for (const [captured, why] of [
    [{ status: 'over-cap', values: {} }, 'a body over capture.maxBytes'],
    [{ status: 'path-undeclared', values: {} }, 'a path the destination does not declare'],
    [{ status: 'not-json', values: {} }, 'a body that is not JSON'],
    [{ status: 'json-duplicate-key', values: {} }, 'a repeated key'],
    [text({ type: 'unusable', reason: 'value-over-cap' }), 'a string over the capture cap'],
    [text({ type: 'unusable', reason: 'redacted' }), 'a secret-shaped value'],
    [text({ type: 'absent' }), 'an absent field'],
    [text({ type: 'null', value: null }), 'null'],
    [text(5), 'a number where the allow lists strings'],
    [text({ type: 'text', value: ` ${REMINDERS[0]}` }), 'form text with edge whitespace (may differ)'],
  ]) {
    const scope = captured.values['/text']?.type === 'text' ? FORM : SCOPE;
    assert.equal(verdictOf(only(), [scoped(charge(), [late(captured)], { scope })]), 'missing', why);
  }
});

test('3. allow keys: an actor, upstream, outcome or traceId pin never lifts; only source, operation, name, resource and fields', () => {
  for (const [allow, why] of [[noteAllow({ actor: 'svc-notes' }), 'an actor pin'], [noteAllow({ traceId: 'trace-1' }), 'a traceId pin']]) assert.equal(verdictOf(only({ allow: [allow] }), [scoped(charge(), [late(text(REMINDERS[0]))])]), 'missing', why);
  // upstream and outcome are refused in effect.only at load; onlyCoverageFor never lifts on them either.
  const w = scoped(charge(), [late(text(REMINDERS[0]))]), expects = [sel(BILL, CHARGE)];
  for (const extra of [{ upstream: 'applied' }, { outcome: 'committed' }, { actor: 'svc' }, { traceId: 'trace-1' }]) assert.equal(onlyCoverageFor(w, { expects, allows: [noteAllow(extra)] }), 'partial', JSON.stringify(extra));
  assert.equal(onlyCoverageFor(w, { expects, allows: [noteAllow()] }), 'complete');
  assert.equal(onlyCoverageFor(w, { expects, allows: [{ ...noteAllow(), source: 'smtp-capture' }] }), 'partial', 'another source');
  // A name-free allow never lifts (effect.only refuses it at load; the late-entry lift needs a name too).
  const { name: _name, ...nameless } = noteAllow();
  assert.equal(onlyCoverageFor(w, { expects, allows: [nameless] }), 'partial', 'no name');
});

test('4. expected slots: an expected selector the late note could fit blocks, whatever its fields say', () => {
  const w = () => scoped(charge(), [late(text(REMINDERS[0]))]);
  const closing = { ...sel(DESK, NOTE), fields: [{ pointer: '/text', equals: 'Your ticket is closed.' }] };
  assert.equal(verdictOf(only({ expect: [sel(BILL, CHARGE), closing] }), [w()]), 'missing', 'an expect on the same path with another text');
  assert.equal(verdictOf(only({ expect: [sel(BILL, CHARGE), sel(DESK)] }), [w()]), 'missing', 'an expect on the whole host');
  assert.equal(verdictOf(only({ expect: [sel(BILL, CHARGE), sel(DESK, 'POST /v1/close')] }), [w()]), 'pass', 'adjacent: an expect on another path of the host');
});

test('5. keyed host: under countBy a late note on a host that records keys blocks; unkeyed, or without countBy, it lifts', () => {
  const w = scope => scoped(charge(), [late(text(REMINDERS[0]))], { scope });
  assert.equal(verdictOf(only({ countBy: 'idempotency-key' }), [w(KEYED)]), 'missing', 'keyed host under countBy');
  assert.equal(verdictOf(only({ countBy: 'idempotency-key' }), [w(SCOPE)]), 'pass', 'the same host unkeyed');
  assert.equal(verdictOf(only(), [w(KEYED)]), 'pass', 'keyed host, no countBy');
});

test('6. the window: unfollowed reads missing, and every entry must lift', () => {
  assert.equal(verdictOf(only(), [scoped(charge(), [late(text(REMINDERS[0]))], { followed: false })]), 'missing', 'unfollowed');
  assert.equal(verdictOf(only(), [scoped(charge(), [late(text(REMINDERS[0])), late(text('unlisted'), { resource: OTHER_NOTE })])]), 'missing', 'a second entry that does not lift');
  assert.equal(verdictOf(only({ allow: [noteAllow(), sel(DESK, OTHER_NOTE)] }), [scoped(charge(), [late(text(REMINDERS[0])), late(undefined, { resource: OTHER_NOTE })])]), 'pass', 'adjacent: both lift');
  // An unknown-outcome event that no entry covers still holds it.
  assert.equal(verdictOf(only(), [scoped([...charge(), ev(BILL, REFUND, { outcome: 'unknown' })], [late(text(REMINDERS[0]))])]), 'missing');
});

test('7. binding: a record only on an after-witness entry with a resource and the declared pointers, each seq once (the seq after the sealed window\'s events: test 11)', () => {
  const win = (entries, { events = charge(), scope = SCOPE } = {}) => ({ source: 'http-egress', instanceId: INST, scope, coverage: 'partial', reason: [...new Set(entries.flatMap(e => e.codes))].sort().join(','), events, scoped: entries });
  validateWindow(win([late(text(REMINDERS[0]))]));
  validateWindow(win([late(text({ type: 'text', value: 'x' }))], { scope: FORM }));
  validateWindow(win([late({ status: 'path-undeclared', values: {} }, { resource: 'POST *' })]));
  validateWindow(win([late(undefined, { resource: null, codes: [AMBIGUOUS, AFTER] })]));
  for (const [entries, why, opts = {}] of [
    [[late(text(REMINDERS[0]), { codes: [IN_FLIGHT] })], 'an in-flight entry'],
    [[late(text(REMINDERS[0]), { codes: [AFTER, IN_FLIGHT] })], 'an entry that is also in flight'],
    [[late(text(REMINDERS[0]), { resource: null, codes: [AMBIGUOUS, AFTER] })], 'a path-ambiguous entry'],
    [[late({ status: 'captured', values: { '/note': { type: 'string', value: 'x' } } })], 'a pointer not declared for the host'],
    [[late(text('x'), { name: BILL, resource: CHARGE })], 'a host that declares no capture'],
    [[late(text({ type: 'text', value: 'x' }))], 'a form reading on a JSON-only host'],
    [[{ name: DESK, resource: NOTE, codes: [AFTER], captured: text('x') }], 'a record without its seq'],
    [[{ name: DESK, resource: NOTE, codes: [AFTER], seq: 5000 }], 'a seq without its record'],
    [[late(text('x'), { seq: 5001 }), late(text('y'), { resource: OTHER_NOTE, seq: 5001 })], 'one seq on two entries'],
    [[late({ status: 'over-cap', values: { '/text': { type: 'string', value: 'x' } } })], 'values on a record that was not captured'],
  ]) assert.throws(() => validateWindow(win(entries, opts)), /scoped/, why);
});

test('8. the cross-check: every sealed event of the instance and seq agrees with the entry; an absent one is no disagreement', () => {
  const entry = late(text(REMINDERS[0])), own = scoped(charge(), [entry]);
  const gap = events => ({ source: 'http-egress', instanceId: INST, scope: SCOPE, coverage: 'complete', reason: null, events });
  const sent = (extra = {}) => makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId: INST }, seq: entry.seq, observedAt: '2026-10-12T00:00:00.000Z', operation: 'send', name: DESK, resource: NOTE, outcome: 'committed', captured: entry.captured, ...extra });
  consistentScopedCaptures([own, gap([sent()])]);
  consistentScopedCaptures([own, gap([])]);
  consistentScopedCaptures([own, { ...gap([sent({ captured: text(REMINDERS[1]) })]), instanceId: 'egress-recorder-other' }]);
  for (const [extra, why] of [[{ captured: text(REMINDERS[1]) }, 'another text'], [{ captured: undefined }, 'no record'], [{ resource: OTHER_NOTE }, 'another resource']]) {
    const e = sent(extra);
    if (extra.captured === undefined && Object.hasOwn(extra, 'captured')) delete e.captured;
    assert.throws(() => consistentScopedCaptures([own, gap([e])]), /scoped-captured/, why);
  }
  const twin = scoped([], [{ ...entry, captured: text(REMINDERS[2]) }]);
  assert.throws(() => consistentScopedCaptures([own, twin]), /scoped-captured/, 'two entries naming one seq disagree');
});

// ---------------------------------------------------------------------------
// Condition 5: the lift is toward a pass only. Over a grid of clauses and shared windows, each window W is judged against its
// earlier-shaped twin S (the same entries without seq and captured, as egress-recorder/3 writes them): a result that is not pass is
// deep-equal to S's, a pass on S is the same pass on W, every core clause reads alike, and a lifted pass also passes with the late
// request seen in the window. (A scratch run against a frozen copy of an earlier src/effect-events.mjs checks S against that build itself.)
test('9. differential: every result but a lifted pass is deep-equal to the earlier-shaped window\'s, and a lift is never more lenient than the send seen', () => {
  const clauses = [only(), only({ allow: [noteAllow({ actor: 'svc' })] }), only({ allow: [sel(DESK, NOTE)] }), only({ allow: [noteAllow(), sel(BILL, REFUND)] }),
    only({ expect: [sel(BILL, CHARGE), sel(DESK)] }), only({ expect: [] }), only({ countBy: 'idempotency-key' }), only({ allow: [{ ...sel(DESK, NOTE), fields: [{ pointer: '/text', equals: REMINDERS[0] }] }] })];
  const eventSets = [() => charge(), () => [...charge(), ...charge()], () => [ev(BILL, REFUND)], () => [], () => [...charge(), ev(DESK, NOTE, { captured: text(REMINDERS[0]) })],
    () => [...charge(), ev(DESK, NOTE, { captured: text('not a reminder') })], () => [...charge(), ev(BILL, CHARGE, { outcome: 'unknown' })]];
  const entrySets = [() => [late(text(REMINDERS[0]))], () => [late(text('other'))], () => [late({ status: 'over-cap', values: {} })], () => [late(text(REMINDERS[1])), late(text(REMINDERS[2]), { resource: OTHER_NOTE })],
    () => [late(text(REMINDERS[0])), late(undefined, { resource: OTHER_NOTE })], () => [late(undefined, { name: BILL, resource: CHARGE }), late(text(REMINDERS[0]))], () => [late(undefined, { name: BILL, resource: REFUND, codes: [IN_FLIGHT] }), late(text(REMINDERS[0]))]];
  const core = [{ kind: 'effect.none', select: sel(DESK, NOTE) }, { kind: 'effect.none', select: noteAllow() }, { kind: 'effect.exists', select: sel(BILL, CHARGE) }, { kind: 'effect.count', select: sel(BILL, CHARGE), expected: 1 },
    { kind: 'effect.none', select: sel(BILL, REFUND) }, { kind: 'effect.exists', select: noteAllow() }];
  const opts = { fields: true, countBy: true };
  const judged = (clause, windows) => judgeOnly(clause, windows, { ...opts, scopedComplete: onlyScopedComplete(clause, windows) });
  let compared = 0, lifts = 0;
  for (const scope of [SCOPE, KEYED]) for (const followed of [true, false]) for (const events of eventSets) for (const entries of entrySets) {
    const list = entries(), own = events();
    const W = scoped(own, list, { followed, scope }), S = scoped(own, list.map(({ seq: _s, captured: _c, ...e }) => e), { followed, scope });
    for (const clause of clauses) {
      const w = judged(clause, [W]), s = judged(clause, [S]);
      compared++;
      if (w.verdict !== 'pass' || s.verdict === 'pass') { assert.deepEqual(w, s, `${JSON.stringify(clause)} over ${JSON.stringify(W.scoped)}`); continue; }
      lifts++;
      // Never more lenient than seen: each captured entry's request placed in the window as the recorder would record it.
      const seenEvents = [...own, ...list.filter(e => e.captured).map(e => ev(e.name, e.resource, { seq: e.seq, captured: e.captured }))].sort((a, b) => a.seq - b.seq);
      const rest = list.filter(e => !e.captured);
      const seen = rest.length ? scoped(seenEvents, rest, { followed, scope }) : { source: 'http-egress', instanceId: INST, scope, coverage: 'complete', reason: null, events: seenEvents };
      assert.equal(judged(clause, [seen]).verdict, 'pass', `seen: ${JSON.stringify(clause)} over ${JSON.stringify(W.scoped)}`);
    }
    for (const clause of core) assert.deepEqual(evaluateEffectAssertion(clause, [W], { countBy: true, scoped: true }), evaluateEffectAssertion(clause, [S], { countBy: true, scoped: true }));
  }
  assert.ok(compared > 1500 && lifts > 20, `compared ${compared}, lifted ${lifts}`);
});

// ---------------------------------------------------------------------------
// The recorder over real loopback HTTP.
const WITNESS = 'witness.scopehaven.invalid';
const NOTE_DEST = Object.freeze({ host: DESK, paths: ['/v1/tickets'], capture: { pointers: ['/text'], maxBytes: 1024 } });
const sink = (t, destinations = [NOTE_DEST, { host: BILL, paths: ['/v1'] }]) => onFreePorts(1, async port => {
  const o = createEgressRecorder({ instanceId: INST, port, routing: 'proxy', destinations, witness: { actorId: 'ops', method: 'GET', path: '/ping', host: WITNESS }, witnessWaitMs: 1500, quietMs: 150 });
  await o.start(); t.after(() => o.stop()); return o;
});
const post = (port, host, path, body) => new Promise(resolve => {
  const req = request({ host: '127.0.0.1', port, method: 'POST', path: `http://${host}${path}`, headers: { host, 'content-type': 'application/json' } }, res => { res.resume(); res.on('end', resolve); });
  req.on('error', resolve); req.end(body);
});
const note = (o, value, path = '/v1/tickets/t-1/notes') => post(o.port, DESK, path, JSON.stringify({ text: value }));
// One check window, then the gap after it (as settlement collects it): `late` runs after the witness request.
async function checkAndGap(o, { during = async () => {}, late: after = async () => {} } = {}) {
  const from = await o.mark(); await during(); o.markWitnessRequest(from);
  await after();
  await new Promise(resolve => { const req = request({ host: '127.0.0.1', port: o.port, method: 'GET', path: `http://${WITNESS}/w?scopehaven_witness=${encodeURIComponent(from.witnessNonce)}`, headers: { host: WITNESS } }, res => { res.resume(); res.on('end', resolve); }); req.on('error', resolve); req.end(); });
  const to = await o.mark(), w = await collectWindow(o, from, to, { scoped: true });
  const next = await o.mark(), g = await o.collect(to, next, { gap: true });
  return { w, gap: { source: 'http-egress', instanceId: o.instanceId, scope: o.scope, coverage: g.coverage, reason: g.reason ?? null, events: g.events } };
}

test('10. recorder: one late note carries its seq and captured record, the same record its gap event carries; two notes, or an unreadable one, lift nothing', async t => {
  const o = await sink(t);
  const one = await checkAndGap(o, { during: () => post(o.port, BILL, '/v1/charges', '{}'), late: () => note(o, REMINDERS[0]) });
  const [entry] = one.w.scoped;
  assert.deepEqual([entry.name, entry.resource, entry.codes, entry.captured], [DESK, NOTE, [AFTER], text(REMINDERS[0])]);
  assert.ok(one.w.events.every(e => e.seq < entry.seq));
  const gapEvent = one.gap.events.find(e => e.seq === entry.seq);
  assert.deepEqual([gapEvent.name, gapEvent.resource, gapEvent.captured], [DESK, NOTE, entry.captured], 'the gap after the check holds the same record');
  consistentScopedCaptures([one.w, one.gap]);
  assert.equal(verdictOf(only({ expect: [sel(BILL, 'POST /v1')] }), [one.w]), 'pass');
  // Two late notes to the same path: one entry, no record.
  const two = await checkAndGap(o, { late: async () => { await note(o, REMINDERS[0]); await note(o, REMINDERS[1], '/v1/tickets/t-2/notes'); } });
  assert.deepEqual(two.w.scoped, [{ name: DESK, resource: NOTE, codes: [AFTER] }]);
  assert.equal(verdictOf(only({ expect: [] }), [two.w]), 'missing');
  // An undeclared path and a body over capture.maxBytes: the entry carries the record, which reads unknown.
  const undeclared = await checkAndGap(o, { late: () => note(o, REMINDERS[0], '/v2/notes') });
  assert.deepEqual([undeclared.w.scoped[0].resource, undeclared.w.scoped[0].captured], ['POST *', { status: 'path-undeclared', values: {} }]);
  assert.equal(verdictOf(only({ expect: [], allow: [{ ...noteAllow(), resource: 'POST *' }] }), [undeclared.w]), 'missing');
  const capped = await checkAndGap(o, { late: () => note(o, `${REMINDERS[0]}${' '.repeat(1100)}`) });
  assert.deepEqual(capped.w.scoped[0].captured, { status: 'over-cap', values: {} });
  assert.equal(verdictOf(only({ expect: [] }), [capped.w]), 'missing');
});

test('10b. recorder: a note still in flight (a pending forward) carries no record', async t => {
  let hold;
  const held = new Promise(resolve => { hold = resolve; });
  const upstream = createServer(async (req, res) => { req.resume(); await held; res.writeHead(200, { 'Content-Length': '0' }); res.end(); });
  await new Promise(r => upstream.listen(0, '127.0.0.1', r));
  t.after(() => new Promise(r => { hold(); upstream.close(r); upstream.closeAllConnections(); }));
  const o = await sink(t, [{ ...NOTE_DEST, forward: { upstream: `http://127.0.0.1:${upstream.address().port}` } }]);
  let sending;
  const { w } = await checkAndGap(o, { during: () => { sending = note(o, REMINDERS[0]); return new Promise(r => setTimeout(r, 150)); } });
  assert.deepEqual(w.scoped, [{ name: DESK, resource: NOTE, codes: [IN_FLIGHT] }], JSON.stringify(w));
  hold(); await sending;
});

test('10c. recorder: a late note beside one still in flight on the same path, or a late path-ambiguous note, carries no record', async t => {
  // An upstream that holds only the note whose text is "hold" and answers every other at once.
  const held = [];
  const upstream = createServer((req, res) => { const chunks = []; req.on('data', c => chunks.push(c)); req.on('end', () => {
    const answer = () => { if (!res.writableEnded) { res.writeHead(200, { 'Content-Length': '0' }); res.end(); } };
    if (Buffer.concat(chunks).toString().includes('"hold"')) held.push(answer); else answer();
  }); });
  await new Promise(r => upstream.listen(0, '127.0.0.1', r));
  t.after(() => new Promise(r => { held.forEach(f => f()); upstream.close(r); upstream.closeAllConnections(); }));
  const o = await sink(t, [{ ...NOTE_DEST, forward: { upstream: `http://127.0.0.1:${upstream.address().port}` } }]);
  let sending;
  const mixed = await checkAndGap(o, { during: () => { sending = note(o, 'hold'); return new Promise(r => setTimeout(r, 150)); }, late: () => note(o, REMINDERS[0]) });
  assert.deepEqual(mixed.w.scoped, [{ name: DESK, resource: NOTE, codes: [AFTER, IN_FLIGHT] }], JSON.stringify(mixed.w));
  held.forEach(f => f()); await sending;
  // A late note whose path decodes to a declared path only after percent-decoding: path-ambiguous, resource null, no record.
  const plain = await sink(t);
  const ambiguous = await checkAndGap(plain, { late: () => note(plain, REMINDERS[0], '/v1/%74ickets/t-1/notes') });
  assert.deepEqual(ambiguous.w.scoped, [{ name: DESK, resource: null, codes: [AMBIGUOUS, AFTER] }], JSON.stringify(ambiguous.w));
});

// ---------------------------------------------------------------------------
// End to end: a check whose app sends a reminder note after the witness request, followed by a later check, under the judge.
async function noteApp(t, sinkPort) {
  let pending = [];
  const outbound = (target, body) => new Promise(resolve => { const url = new URL(target); const req = request({ host: '127.0.0.1', port: sinkPort, method: body === undefined ? 'GET' : 'POST', path: target, headers: { host: url.host, ...(body === undefined ? {} : { 'content-type': 'application/json' }) } }, res => { res.resume(); res.on('end', resolve); }); req.on('error', resolve); req.end(body); });
  const server = createServer(async (req, res) => {
    const reply = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
    req.resume();
    if (req.headers.authorization !== 'Bearer synthetic-ops-token') return reply(401, {});
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname === '/me') return reply(200, { user: 'ops' });
    if (url.pathname === '/ping') { for (const text of pending) await outbound(`http://${DESK}/v1/tickets/t-1/notes`, JSON.stringify({ text })); pending = []; await outbound(`http://${WITNESS}/w?scopehaven_witness=${encodeURIComponent(url.searchParams.get('scopehaven_witness') ?? '')}`); return reply(200, { ok: true }); }
    if (url.pathname === '/remind') { await outbound(`http://${BILL}/v1/charges`, '{}'); pending = [REMINDERS[0]]; return reply(403, {}); }
    if (url.pathname === '/remind/twice') { await outbound(`http://${BILL}/v1/charges`, '{}'); pending = [REMINDERS[0], REMINDERS[1]]; return reply(403, {}); }
    if (url.pathname === '/quiet') return reply(403, {});
    reply(404, {});
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(() => new Promise(r => { server.close(r); server.closeAllConnections(); }));
  return `http://127.0.0.1:${server.address().port}`;
}
const env = { SCOPEHAVEN_TARGET_OPS: 'synthetic-ops-token' };
const check = (id, path, extra = {}) => ({ id, title: id, category: 'support', severity: 'high', actorId: 'ops', method: 'POST', path, body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 403 }], ...extra });
const run = (t, checks) => onFreePorts(1, async port => {
  const p = { id: 'notes', name: 'Notes', applicationId: 'notes', origin: await noteApp(t, port), buildLabel: 'b1', contextId: 'synthetic-notes',
    actors: { ops: { principalId: 'ops', credentialEnv: 'SCOPEHAVEN_TARGET_OPS', identityValue: 'ops' } }, requiredControlIds: ['WHOAMI'], settlement: { mode: 'run', outsideWindow: 'judge' },
    observers: [{ id: 'sink', type: 'egress-recorder', port, routing: 'proxy', destinations: [NOTE_DEST, { host: BILL, paths: ['/v1'] }], witness: { actorId: 'ops', method: 'GET', path: '/ping', host: WITNESS }, settleMs: 250, quietMs: 150 }],
    checks: [{ id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'ops', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'ops' }] }, ...checks] };
  validateTargetFile({ schemaVersion: 1, targets: [p] });
  const watch = watchingBinds(buildObservers);
  return { p, run: await runHttpAssessment(p, { env, observerFactory: watch.factory }), lostBind: watch.state.lostBind };
}, r => r.lostBind);

test('11. end to end: a late reminder note lets an effect.only pass stand under the judge; the validator binds its record to its gap event', async t => {
  const clause = { effects: [{ kind: 'effect.only', expect: [{ select: sel(BILL, 'POST /v1'), count: 1 }], allow: [noteAllow()], sources: ['http-egress'] }] };
  const statusOf = row => row.assertions.find(a => a.name === 'Observed effect 1 (effect.only)').status;
  const validated = r => validateHttpRunEvidence(r.run, { expectedSuite: createRegistry({ profiles: [r.p], env }).exportSuite(r.p.id) });
  // FIRST's witness unit comes before LATE's charge: a seq no sealed event carries (used by the binding forgery below).
  const r = await run(t, [check('FIRST', '/quiet', { effects: [{ kind: 'effect.none', select: sel(DESK) }] }), check('LATE', '/remind', clause), check('NEXT', '/quiet', { effects: [{ kind: 'effect.none', select: sel(BILL) }] })]);
  const row = r.run.results.find(x => x.id === 'LATE');
  assert.equal(r.run.observers[0].collector.label, 'egress-recorder/13', 'late fields came in /4; verified signature headers moved it to /5, object-route target flags to /6, in-doubt transport records to /7, the request feed to /8, read-back to /9, the two exclusive loopback binds to /10, declared aliases and sibling hosts to /11, the drain\'s quiet recheck to /12, another recorder\'s destinations to /13');
  const entry = row.trace[1].data.windows[0].scoped?.[0];
  assert.deepEqual([entry?.codes, entry?.captured], [[AFTER], text(REMINDERS[0])], JSON.stringify(row.trace[1].data.windows[0]));
  assert.equal(statusOf(row), 'pass', JSON.stringify(row.assertions));
  assert.equal(row.trace[1].data.effects[0].settlementNote, 'effect-outside-window-judged');
  validated(r);
  const reseal = (run, mutate) => { const forged = structuredClone(run), fx = forged.results.find(x => x.id === 'LATE'); mutate(forged, fx); fx.evidenceDigest = digest({ evidence: fx.trace[0].data, effects: fx.trace[1].data, assertions: fx.assertions }); return forged; };
  const gapEventOf = forged => forged.settlement.gaps.flatMap(g => g.windows).flatMap(w => w.events).find(e => e.seq === entry.seq);
  assert.ok(gapEventOf(r.run), 'the late note is an event of the gap after its check');
  // The entry's text changed to another allowed reminder: the verdict would not move, but its gap event disagrees.
  const disagree = reseal(r.run, (_f, fx) => { fx.trace[1].data.windows[0].scoped[0].captured = text(REMINDERS[1]); });
  assert.throws(() => validateHttpRunEvidence(disagree), e => e.code === 'invalid-run-evidence' && e.detail === 'effect-trace', 'disagreement');
  // A seq that is not after the window's own events, and a collector label older than /4, are refused at binding.
  // The seq moved before the window's own event, to one no sealed event of the run carries (a witness unit's), so only the binding
  // can refuse it.
  const own = row.trace[1].data.windows[0].events;
  assert.equal(own.length, 1, 'the charge is the window\'s own event');
  const sealedSeqs = new Set([...r.run.results.flatMap(x => x.trace?.[1]?.data?.windows ?? []), ...r.run.settlement.gaps.flatMap(g => g.windows)].flatMap(w => w.events.map(e => e.seq)));
  const unused = [...Array(own[0].seq).keys()].reverse().find(n => n >= 1 && !sealedSeqs.has(n));
  assert.ok(unused !== undefined, 'a seq before the charge that no event carries');
  const early = reseal(r.run, (_f, fx) => { fx.trace[1].data.windows[0].scoped[0].seq = unused; });
  assert.throws(() => validateHttpRunEvidence(early), e => e.code === 'invalid-run-evidence' && e.detail === 'effect-trace', 'a seq not after the window\'s own events');
  const relabelled = structuredClone(r.run); relabelled.observers[0].collector.label = 'egress-recorder/3';
  assert.throws(() => validateHttpRunEvidence(relabelled), e => e.code === 'invalid-run-evidence' && e.detail === 'effect-trace', 'egress-recorder/3 never writes a record');
  // Adjacent: two late notes to the same path leave one entry with no record, and the pass is not reached.
  const twice = await run(t, [check('LATE', '/remind/twice', clause), check('NEXT', '/quiet', { effects: [{ kind: 'effect.none', select: sel(BILL) }] })]);
  const twiceRow = twice.run.results.find(x => x.id === 'LATE');
  assert.deepEqual(twiceRow.trace[1].data.windows[0].scoped, [{ name: DESK, resource: NOTE, codes: [AFTER] }]);
  assert.equal(statusOf(twiceRow), 'inconclusive', JSON.stringify(twiceRow.assertions));
  validated(twice);
});
