// effect.only: a send whose fields could not be read under a fields-pinned expected selector is undecided, never absorbed by an
// allowed selector without that pin (integrations/collateral/only.mjs). The provider-feed template rule closed this for feed sends; here it holds
// for every source, egress body fields first. Each newly undecided case sits beside the decided case next to it: pure decisions over
// synthetic windows, settlement's judged re-judge, the late-entry lift, a differential against an earlier only.mjs (frozen in
// test/fixtures/only-cddb4be.mjs: only previously absorbed sends change, and no pass is created), and one connector run over
// real loopback HTTP (destination hosts are names only and are never resolved or contacted).
import test from 'node:test';
import assert from 'node:assert/strict';
import { request, createServer } from 'node:http';
import { makeEffect, admitScoped, markUnfollowed, matchState, matches, onlyCoverageFor } from '../src/effect-events.mjs';
import { decideEffects } from '../src/http-effects.mjs';
import { settlementFindings } from '../src/http-settlement.mjs';
import { validateIdempotencyDeclaration } from '../src/idempotency.mjs';
import { judgeOnly, onlyScopedComplete } from '../integrations/collateral/only.mjs';
import { onFreePorts, watchingBinds } from '../integrations/observers/fixtures/free-port.mjs';
import { buildObservers } from '../integrations/observers/factory.mjs';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateHttpRunEvidence, validateTargetFile } from '../src/contracts.mjs';
import { createRegistry } from '../src/registry.mjs';
import { fileURLToPath } from 'node:url';

// The judge before this change: the same judge with the unknown-field rule gated on provider-feed sends.
const frozen = await import(fileURLToPath(new URL('./fixtures/only-cddb4be.mjs', import.meta.url)));

const DESK = 'desk.example.test', BILL = 'billing.example.test', INST = 'egress-recorder-sink';
const NOTE = 'POST /v1/tickets', OTHER_NOTE = 'POST /v1/zz', CHARGE = 'POST /v1/charges';
const FEED = 'customers.example', VIP = `vip@${FEED}`, FEED_INST = 'provider-feed-mail';
const AFTER = 'egress-request-after-witness-request';
const SCOPE = Object.freeze({ operations: ['send'], names: [BILL, DESK], actorAttribution: 'none', evidence: 'authoritative', capture: { [DESK]: ['/kind', '/text'] } });
const KEYED = Object.freeze({ ...SCOPE, idempotency: { [DESK]: validateIdempotencyDeclaration({ header: 'idempotency-key' }) } });
const FEED_SCOPE = Object.freeze({ operations: ['send'], names: [FEED], actorAttribution: 'none', evidence: 'authoritative', capture: { [FEED]: ['/template'] } });
let seq = 0;
const ev = (name, resource, extra = {}) => makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId: INST }, seq: ++seq, observedAt: '2026-10-13T00:00:00.000Z',
  operation: 'send', name, resource, outcome: 'committed', ...extra });
// A note's captured record: kind and text as given (a value, or a stored value { type, ... }; undefined reads absent), or a status
// with no values (a body that could not be read).
const value = v => (v === undefined ? { type: 'absent' } : typeof v === 'object' ? v : { type: typeof v === 'number' ? 'number' : 'string', value: v });
const fields = (kind, text) => ({ status: 'captured', values: { '/kind': value(kind), '/text': value(text) } });
const unread = status => ({ status, values: {} });
const note = (captured, extra = {}) => ev(DESK, NOTE, { ...(captured === undefined ? {} : { captured }), ...extra });
const charge = () => ev(BILL, CHARGE);
const win = (events, { scope = SCOPE, coverage = 'complete' } = {}) => ({ source: 'http-egress', instanceId: INST, scope, coverage, reason: coverage === 'complete' ? null : 'synthetic', events });
const sel = (name, resource, extra = {}) => ({ source: 'http-egress', operation: 'send', name, ...(resource ? { resource } : {}), ...extra });
const CANCEL = Object.freeze([{ pointer: '/kind', equals: 'cancel' }]);
const REMINDERS = ['Reminder: we are on it.', 'Reminder: closing soon.'];
const cancelNote = (extra = {}) => sel(DESK, NOTE, { fields: CANCEL, ...extra });
// sources: null judges every window given.
const only = ({ expect = [[cancelNote(), 1]], allow = [sel(DESK, NOTE)], countBy, sources = ['http-egress'] } = {}) => ({ kind: 'effect.only',
  expect: expect.map(([select, count]) => ({ select, count })), allow, ...(sources ? { sources } : {}), ...(countBy ? { countBy } : {}) });
const OPTS = Object.freeze({ fields: true, countBy: true });
const judged = (clause, windows, judge = judgeOnly, scoped = onlyScopedComplete) => judge(clause, windows, { ...OPTS, scopedComplete: scoped(clause, windows) });
const mainJudged = (clause, windows) => judged(clause, windows, frozen.judgeOnly, frozen.onlyScopedComplete);
const verdictOf = (clause, windows) => decideEffects([clause], windows)[0].verdict;
// The ways a note's /kind can read unknown under an equals "cancel" pin.
const UNKNOWN_KIND = Object.freeze([
  [fields(undefined, REMINDERS[0]), 'an absent field'],
  [unread('not-json'), 'a form-encoded body on a JSON-only host'],
  [unread('json-duplicate-key'), 'a repeated key'],
  [unread('over-cap'), 'a body over capture.maxBytes'],
  [unread('encoded'), 'a compressed body'],
  [fields({ type: 'unusable', reason: 'redacted' }), 'a secret-shaped value'],
  [fields(7), 'a number where the pin is a string'],
  [fields({ type: 'text', value: 'cancel ' }), 'form text with edge whitespace'],
  [undefined, 'no captured record'],
]);

// ---------------------------------------------------------------------------
test('1. egress twin of the provider-feed template case: two known cancels fail; a second cancel whose kind reads unknown is never absorbed by the path-only allow', () => {
  const clause = only();
  const known = [win([note(fields('cancel')), note(fields('cancel'))])];
  assert.equal(verdictOf(clause, known), 'fail', 'the second known cancel is beyond count, and the allow never absorbs a beyond-count send');
  assert.equal(mainJudged(clause, known).verdict, 'fail');
  for (const [captured, why] of UNKNOWN_KIND) {
    const windows = [win([note(fields('cancel')), note(captured)])];
    const r = judged(clause, windows);
    assert.equal(r.verdict, 'missing', `${why}: ${r.basis}`);
    assert.match(r.basis, /body fields that could not be read/);
    assert.equal(r.counts.offending, 0, why);
    assert.equal(mainJudged(clause, windows).verdict, 'pass', `${why}: the earlier judge read it pass (the hole)`);
    assert.equal(verdictOf(clause, windows), 'missing', `${why}: the HTTP evaluator`);
  }
  // Adjacent: a known update reads "no" under the pin, so the allow still takes it; a lone known cancel is expected.
  assert.equal(verdictOf(clause, [win([note(fields('cancel')), note(fields('update'))])]), 'pass');
  assert.equal(verdictOf(clause, [win([note(fields('cancel'))])]), 'pass');
  // A note on another path of the host is not the expected one under any fields: the allow decides it as before.
  assert.equal(verdictOf(only({ allow: [sel(DESK)] }), [win([note(fields('cancel')), ev(DESK, OTHER_NOTE)])]), 'pass');
  // The precision cost, documented: a lone unreadable note could be the one cancel or an allowed note, both in the set, yet it
  // holds the clause at missing (never a pass the evidence does not support).
  assert.equal(verdictOf(clause, [win([note(fields(undefined, REMINDERS[0]))])]), 'missing');
});

test('2. an actor pin: a send whose actor is unknown or undeclared and whose kind reads unknown is undecided; a known other actor is allowed', () => {
  const clause = only({ expect: [[cancelNote({ actor: 'svc-notes' }), 1]] });
  const base = () => [note(fields('cancel'), { actor: 'svc-notes' })];
  for (const actor of [null, 'unlisted:svc-x']) {
    const windows = [win([...base(), note(fields(undefined), { actor })])];
    assert.equal(judged(clause, windows).verdict, 'missing', String(actor));
    assert.equal(mainJudged(clause, windows).verdict, 'pass', `${actor}: the earlier judge read it pass`);
  }
  // A declared other actor is not the expected one whatever its kind: the allow takes it.
  assert.equal(judged(clause, [win([...base(), note(fields(undefined), { actor: 'svc-other' })])]).verdict, 'pass');
  // An unknown actor on a known cancel stays unattributable (the earlier judge's rule, unchanged).
  const unattributed = judged(clause, [win([note(fields('cancel'), { actor: null })])]);
  assert.deepEqual([unattributed.verdict, unattributed.counts.unattributable], ['missing', 1]);
});

test('3. beyond count stays a fail: a note matching a path-only expect beyond its count is offending even when its kind reads unknown', () => {
  const clause = only({ expect: [[cancelNote(), 1], [sel(DESK, NOTE), 1]], allow: [] });
  assert.equal(judged(clause, [win([note(fields('cancel')), note(fields(undefined))])]).verdict, 'pass', 'each in its slot');
  const over = judged(clause, [win([note(fields('cancel')), note(fields(undefined)), note(unread('not-json'))])]);
  assert.deepEqual([over.verdict, over.counts.offending], ['fail', 1], over.basis);
  assert.match(over.basis, /beyond-count/);
});

test('4. provider feed keeps its template rule, and a feed send under an actor-pinned template expect is undecided too', () => {
  const feed = (template, extra = {}) => makeEffect({ source: 'provider-feed', observer: { kind: 'provider-feed-reader', instanceId: FEED_INST }, seq: ++seq, observedAt: '2026-10-13T00:00:00.000Z',
    operation: 'send', name: FEED, resource: VIP, outcome: 'committed', captured: { status: 'captured', values: { '/template': template } }, ...extra });
  const fwin = events => ({ source: 'provider-feed', instanceId: FEED_INST, scope: FEED_SCOPE, coverage: 'complete', reason: null, events });
  const fsel = extra => ({ source: 'provider-feed', operation: 'send', name: FEED, resource: VIP, ...extra });
  const order = { type: 'string', value: 'order_cancelled' };
  const clause = { kind: 'effect.only', expect: [{ select: fsel({ fields: [{ pointer: '/template', equals: 'order_cancelled' }] }), count: 1 }], allow: [fsel()] };
  for (const t of [{ type: 'absent' }, { type: 'unusable', reason: 'undeclared' }]) {
    const windows = [fwin([feed(order), feed(t)])];
    assert.equal(judged(clause, windows).verdict, 'missing');
    assert.equal(mainJudged(clause, windows).verdict, 'missing', 'the feed template rule already held it');
  }
  assert.equal(judged(clause, [fwin([feed(order), feed({ type: 'string', value: 'ticket_update' })])]).verdict, 'pass');
  // A feed record names no actor: under an actor-pinned template expect, an unknown template is undecided (the earlier judge absorbed it).
  const pinned = { ...clause, expect: [{ select: fsel({ actor: 'mailer', fields: [{ pointer: '/template', equals: 'order_cancelled' }] }), count: 1 }] };
  const windows = [fwin([feed({ type: 'absent' })])];
  assert.equal(judged(pinned, windows).verdict, 'missing');
  assert.equal(mainJudged(pinned, windows).verdict, 'pass');
});

// ---------------------------------------------------------------------------
// Settlement (judge declared): every later candidate is counted as the check's own and the clause judged again.
test('5. settlement judge: a late send whose kind reads unknown withholds the pass (effect-outside-window); a late known update leaves it standing', () => {
  const clause = only();
  const rowWith = () => { const windows = [win([note(fields('cancel'))])]; const row = { effects: decideEffects([clause], windows, { role: 'boundary' }), windows }; assert.equal(row.effects[0].verdict, 'pass'); return row; };
  const findings = later => { const row = rowWith(); return settlementFindings([row], [[win([])], [win(later())]], undefined, { judge: true })[0][0]; };
  assert.equal(findings(() => [note(fields('update'))]), 'effect-outside-window-judged', 'a known update is allowed in any number');
  assert.equal(findings(() => [note(fields('cancel'))]), 'effect-outside-window', 'one more known cancel is beyond count');
  for (const [captured, why] of UNKNOWN_KIND) {
    const row = rowWith(), late = [note(captured)];
    assert.equal(settlementFindings([row], [[win([])], [win(late)]], undefined, { judge: true })[0][0], 'effect-outside-window', why);
    // The earlier judge's judgement of the same augmented window read pass, so the judged note stood there.
    assert.equal(mainJudged(clause, [win([...row.windows[0].events, ...late])]).verdict, 'pass', why);
  }
  // Without the declaration any later judged send withholds, as before.
  const row = rowWith();
  assert.deepEqual(settlementFindings([row], [[win([])], [win([note(fields('update'))])]]), [['effect-outside-window']]);
});

// ---------------------------------------------------------------------------
// The late-entry lift: a late scoped entry lifts toward a pass only when it fits no expected selector on source, operation, name and
// resource (fields-blind), so an entry whose send this rule would hold undecided never lifts.
const late = (captured, { name = DESK, resource = NOTE } = {}) => ({ name, resource, codes: [AFTER], ...(captured === undefined ? {} : { seq: 1000 + ++seq, captured }) });
const scoped = (events, entries, { followed = true, scope = SCOPE } = {}) => {
  const w = admitScoped({ source: 'http-egress', instanceId: INST, scope, coverage: 'partial', reason: AFTER, events, scoped: entries });
  return followed ? w : markUnfollowed(w);
};
test('6. the lift: an entry that could fit a fields-pinned expect never lifts, whatever its record reads; one that fits none still does', () => {
  const noteAllow = sel(DESK, NOTE, { fields: [{ pointer: '/text', in: REMINDERS }] });
  for (const [allow, why] of [[sel(DESK, NOTE), 'a path-only allow (definitely fits)'], [noteAllow, 'a text-pinned allow whose record matches (capturedFits)']]) {
    const clause = only({ expect: [[sel(BILL, CHARGE), 1], [cancelNote(), 1]], allow: [allow] });
    for (const captured of [fields(undefined, REMINDERS[0]), fields('update', REMINDERS[0]), fields('cancel', REMINDERS[0]), undefined]) {
      const w = scoped([charge()], [late(captured)]);
      assert.equal(onlyCoverageFor(w, { expects: [sel(BILL, CHARGE), cancelNote()], allows: [allow] }), 'partial', why);
      assert.equal(verdictOf(clause, [w]), 'missing', `${why}: ${JSON.stringify(captured)}`);
    }
  }
  // Adjacent: with the expect on another host, the same entries lift.
  assert.equal(verdictOf(only({ expect: [[sel(BILL, CHARGE), 1]] }), [scoped([charge()], [late(fields(undefined, REMINDERS[0]))])]), 'pass');
  assert.equal(verdictOf(only({ expect: [[sel(BILL, CHARGE), 1]], allow: [noteAllow] }), [scoped([charge()], [late(fields(undefined, REMINDERS[0]))])]), 'pass');
});

test('7. property: every lifted window passes with each entry\'s send seen in it, under every record the send could carry', () => {
  const expects = [[[cancelNote(), 1]], [[sel(BILL, CHARGE), 1]], [[sel(BILL, CHARGE), 1], [cancelNote({ resource: OTHER_NOTE }), 1]], [[sel(BILL, CHARGE), 1], [cancelNote({ actor: 'svc' }), 1]], [[sel(DESK, OTHER_NOTE, { fields: CANCEL }), 2]]];
  const allows = [[sel(DESK, NOTE)], [sel(DESK)], [sel(DESK, NOTE, { fields: [{ pointer: '/text', in: REMINDERS }] })], [sel(DESK, NOTE), sel(DESK, OTHER_NOTE)]];
  const records = [fields(undefined, REMINDERS[0]), fields('cancel', REMINDERS[1]), fields('update', REMINDERS[0]), unread('not-json'), undefined];
  const entrySets = [() => [late(fields(undefined, REMINDERS[0]))], () => [late(fields('cancel', REMINDERS[0]))], () => [late(undefined)], () => [late(fields(undefined, REMINDERS[1])), late(undefined, { resource: OTHER_NOTE })],
    () => [late(undefined, { resource: OTHER_NOTE })]];
  let lifts = 0, compared = 0;
  for (const scope of [SCOPE, KEYED]) for (const countBy of [undefined, 'idempotency-key']) for (const expect of expects) for (const allow of allows) for (const entries of entrySets) {
    const clause = only({ expect, allow, countBy }), list = entries(), own = [charge()];
    const W = scoped(own, list, { scope }), r = judged(clause, [W]);
    compared++;
    if (r.verdict !== 'pass' || !(onlyScopedComplete(clause, [W]).has(W))) continue;
    lifts++;
    // Each entry's send, seen in the window, carrying its own record or, without one, any record a send could carry.
    const variants = list.map(e => (e.captured ? [e.captured] : records));
    const pick = (k, chosen) => {
      if (k === list.length) {
        const sent = list.map((e, i) => ev(e.name, e.resource, chosen[i] === undefined ? {} : { captured: chosen[i] }));
        const seen = win([...own, ...sent], { scope });
        for (const e of sent) for (const [select] of expect) assert.notEqual(matchState(e, select), 'unknown', `lifted ${JSON.stringify(e)} reads unknown under ${JSON.stringify(select)}`);
        assert.equal(judged(clause, [seen]).verdict, 'pass', `seen: ${JSON.stringify(clause)} over ${JSON.stringify(sent.map(e => e.captured ?? null))}`);
        return;
      }
      for (const v of variants[k]) pick(k + 1, [...chosen, v]);
    };
    pick(0, []);
  }
  console.log(`# lift property: compared ${compared}, lifted ${lifts}`);
  assert.ok(compared === 400 && lifts >= 80, `compared ${compared}, lifted ${lifts}`);
});

// ---------------------------------------------------------------------------
// The differential: over a grid of clauses and windows (egress body fields, actors, provider-feed templates, mail, a scoped window),
// this judge against the earlier one. Its claim: a result changes only where a judged send that no expected selector matches reads
// unknown under a fields-pinned expected selector (the rule's own condition); every change is to missing from a verdict that was not
// a fail, the offenders are the same, a fail is a fail in both, and no pass is created.
test('8. differential against the earlier judge: only previously absorbed or unattributed unknown-field sends change, toward missing; no pass is created', () => {
  const rand = (() => { let state = 20261013; return n => { state = (state + 0x6d2b79f5) | 0; let t = Math.imul(state ^ (state >>> 15), 1 | state); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return (((t ^ (t >>> 14)) >>> 0) % n); }; })();
  const FEED_SEL = (extra = {}) => ({ source: 'provider-feed', operation: 'send', name: FEED, ...extra });
  const TEMPLATE = [{ pointer: '/template', equals: 'order_cancelled' }];
  const clauses = [
    only(), only({ expect: [[cancelNote(), 2]] }), only({ allow: [sel(DESK)] }), only({ allow: [] }), only({ expect: [[cancelNote({ actor: 'svc-notes' }), 1]] }),
    only({ expect: [[cancelNote(), 1]], allow: [sel(DESK, NOTE, { actor: 'svc-notes' })] }), only({ expect: [[cancelNote(), 1], [sel(DESK, NOTE), 1]] }),
    only({ expect: [[sel(BILL, CHARGE), 1]], allow: [sel(DESK, NOTE, { fields: [{ pointer: '/text', in: REMINDERS }] })] }), only({ expect: [[sel(BILL, CHARGE), 1], [cancelNote(), 1]], allow: [sel(DESK), sel(BILL)] }),
    only({ expect: [[cancelNote(), 1]], countBy: 'idempotency-key' }), only({ expect: [] , allow: [sel(DESK, NOTE)] }),
    only({ expect: [[cancelNote(), 1], [FEED_SEL({ fields: TEMPLATE }), 1]], allow: [sel(DESK, NOTE), FEED_SEL()], sources: null }),
    only({ expect: [[FEED_SEL({ resource: VIP, actor: 'mailer', fields: TEMPLATE }), 1]], allow: [FEED_SEL()], sources: null }),
    only({ expect: [[cancelNote(), 1]], allow: [sel(DESK, NOTE), { source: 'smtp-capture', operation: 'send', name: FEED }], sources: null }),
  ];
  const kinds = [fields('cancel'), fields('update'), fields(undefined, REMINDERS[0]), fields('cancel', REMINDERS[1]), unread('not-json'), fields(7), undefined];
  const actors = [null, null, 'svc-notes', 'unlisted:svc-x', 'svc-other'];
  const egressEvent = () => { const k = rand(10); return k < 7 ? note(kinds[rand(kinds.length)], { actor: actors[rand(actors.length)] }) : k < 9 ? charge() : ev(DESK, OTHER_NOTE, { captured: kinds[rand(5)] }); };
  const templates = [{ type: 'string', value: 'order_cancelled' }, { type: 'string', value: 'ticket_update' }, { type: 'absent' }, { type: 'unusable', reason: 'undeclared' }];
  let feedSeq = 0, smtpSeq = 0;
  const feedEvent = () => makeEffect({ source: 'provider-feed', observer: { kind: 'provider-feed-reader', instanceId: FEED_INST }, seq: ++feedSeq, observedAt: '2026-10-13T00:00:00.000Z', operation: 'send', name: FEED,
    resource: rand(2) ? VIP : '*', outcome: 'committed', captured: { status: 'captured', values: { '/template': templates[rand(templates.length)] } } });
  const smtpEvent = () => makeEffect({ source: 'smtp-capture', observer: { kind: 'smtp-sink-recorder', instanceId: 'smtp-sink-mail' }, seq: ++smtpSeq, operation: 'send', name: FEED, resource: '*', outcome: 'committed', content: { m: smtpSeq } });
  const windowsOf = () => {
    const egress = Array.from({ length: rand(5) }, egressEvent).sort((a, b) => a.seq - b.seq), coverage = rand(8) === 0 ? 'partial' : 'complete';
    const out = [win(egress, { coverage, scope: rand(4) === 0 ? KEYED : SCOPE })];
    if (rand(3) === 0) out.push({ source: 'provider-feed', instanceId: FEED_INST, scope: FEED_SCOPE, coverage: 'complete', reason: null, events: Array.from({ length: rand(3) }, feedEvent) });
    if (rand(4) === 0) out.push({ source: 'smtp-capture', instanceId: 'smtp-sink-mail', scope: { operations: ['send'], names: [FEED], actorAttribution: 'none', evidence: 'authoritative' }, coverage: 'complete', reason: null, events: Array.from({ length: rand(2) }, smtpEvent) });
    if (rand(6) === 0) out[0] = scoped(egress, [late(rand(2) ? fields(undefined) : undefined)]);
    return out;
  };
  const unknownActor = e => e.actor === null || e.actor.startsWith('unlisted:');
  const withoutActor = ({ actor: _a, ...rest }) => rest;
  // The rule's condition, from the outside: no expected selector matches the send, and one with fields could but for fields that
  // could not be read (its actor unknown too, against an actor pin).
  const gated = (clause, e) => {
    const expect = clause.expect.map(x => x.select);
    return e.outcome === 'committed' && !expect.some(s => matches(e, s)) && expect.some(s => s.fields !== undefined && (matchState(e, s) === 'unknown' || (s.actor !== undefined && unknownActor(e) && matchState(e, withoutActor(s)) === 'unknown')));
  };
  const tally = { compared: 0, changed: 0, passToMissing: 0, otherToMissing: 0, from: {}, failCountsOnly: 0, absorbed: 0, unattributed: 0 };
  for (let n = 0; n < 4000; n++) {
    const windows = windowsOf(), clause = clauses[n % clauses.length];
    const now = judged(clause, windows), before = mainJudged(clause, windows);
    tally.compared++;
    const inScope = windows.filter(w => !clause.sources || clause.sources.includes(w.source)).flatMap(w => w.events);
    // Newly gated: the earlier judge already held a provider-feed send undecided when it read unknown under a fields-pinned expect itself.
    const mainGated = e => e.source === 'provider-feed' && clause.expect.some(x => x.select.fields !== undefined && matchState(e, x.select) === 'unknown');
    const g = inScope.filter(e => gated(clause, e) && !mainGated(e));
    assert.ok(!(now.verdict === 'pass' && before.verdict !== 'pass'), 'no pass is created');
    assert.equal(now.verdict === 'fail', before.verdict === 'fail', 'a fail is a fail in both');
    assert.deepEqual([now.offending, now.offendingObservers, now.counts.offending], [before.offending, before.offendingObservers, before.counts.offending], 'the same offenders');
    if (!g.length) { assert.deepEqual(now, before, `unchanged without a newly gated send: ${JSON.stringify(clause)}`); continue; }
    if (JSON.stringify(now) === JSON.stringify(before)) continue;
    tally.changed++;
    if (before.verdict === 'fail') {
      // A fail stays the same fail: only the counts of allowed and unattributable sends move.
      const strip = r => ({ ...r, counts: { ...r.counts, allowed: 0, unattributable: 0 }, unattributable: [] });
      assert.deepEqual(strip(now), strip(before));
      tally.failCountsOnly++;
    } else {
      assert.equal(now.verdict, 'missing', JSON.stringify(now));
      assert.match(now.basis, /body fields that could not be read/);
      // From pass (the hole), or from another verdict that also reads inconclusive: the undecided send now names the clause's reason
      // before the coverage checks, as an unreadable send always did.
      assert.ok(['pass', 'missing', 'unobservable', 'observer-failure'].includes(before.verdict), before.verdict);
      if (before.verdict === 'pass') tally.passToMissing++; else { tally.otherToMissing++; tally.from[before.verdict] = (tally.from[before.verdict] ?? 0) + 1; }
    }
    // Each change is a send the earlier judge absorbed into an allowed selector or read unattributable, now undecided.
    const allow = clause.allow;
    const absorbed = g.filter(e => allow.some(s => matches(e, s))).length, unattributed = g.length - absorbed;
    assert.equal(before.counts.allowed - now.counts.allowed + before.counts.unattributable - now.counts.unattributable > 0, true, 'a change moves a send out of allowed or unattributable');
    if (absorbed) tally.absorbed++; else tally.unattributed++;
  }
  console.log(`# differential ${JSON.stringify(tally)}`);
  assert.ok(tally.changed > 1000 && tally.passToMissing > 300, JSON.stringify(tally));
});

// ---------------------------------------------------------------------------
// End to end: a check whose app sends two ticket notes through a real egress recorder, the second one written so its kind reads
// unknown. The earlier judge passed it; now it reads inconclusive. Two known cancels fail, a cancel and an update pass, and the validator agrees.
async function noteApp(t, sinkPort) {
  const outbound = (host, path, body, type) => new Promise(resolve => { const req = request({ host: '127.0.0.1', port: sinkPort, method: body === undefined ? 'GET' : 'POST', path: `http://${host}${path}`,
    headers: { host, ...(body === undefined ? {} : { 'content-type': type }) } }, res => { res.resume(); res.on('end', resolve); }); req.on('error', resolve); req.end(body); });
  const json = value => ['application/json', JSON.stringify(value)];
  const notes = {
    '/cancel/twice': [json({ kind: 'cancel' }), json({ kind: 'cancel' })],
    '/cancel/form': [json({ kind: 'cancel' }), ['application/x-www-form-urlencoded', 'kind=cancel']],
    '/cancel/absent': [json({ kind: 'cancel' }), json({ text: REMINDERS[0] })],
    '/cancel/update': [json({ kind: 'cancel' }), json({ kind: 'update' })],
  };
  const server = createServer(async (req, res) => {
    const reply = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
    req.resume();
    if (req.headers.authorization !== 'Bearer synthetic-ops-token') return reply(401, {});
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname === '/me') return reply(200, { user: 'ops' });
    if (url.pathname === '/ping') { await outbound(WITNESS, `/w?scopehaven_witness=${encodeURIComponent(url.searchParams.get('scopehaven_witness') ?? '')}`); return reply(200, { ok: true }); }
    if (Object.hasOwn(notes, url.pathname)) { for (const [type, body] of notes[url.pathname]) await outbound(DESK, '/v1/tickets/t-1/notes', body, type); return reply(403, {}); }
    reply(404, {});
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(() => new Promise(r => { server.close(r); server.closeAllConnections(); }));
  return `http://127.0.0.1:${server.address().port}`;
}
const WITNESS = 'witness.scopehaven.invalid';
const env = { SCOPEHAVEN_TARGET_OPS: 'synthetic-ops-token' };
const NOTE_DEST = Object.freeze({ host: DESK, paths: ['/v1/tickets'], capture: { pointers: ['/kind', '/text'], maxBytes: 1024 } });
const CLAUSE = only();
const check = (id, path) => ({ id, title: id, category: 'support', severity: 'high', actorId: 'ops', method: 'POST', path, body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 403 }], effects: [CLAUSE] });
const run = t => onFreePorts(1, async port => {
  const p = { id: 'notes', name: 'Notes', applicationId: 'notes', origin: await noteApp(t, port), buildLabel: 'b1', contextId: 'synthetic-notes',
    actors: { ops: { principalId: 'ops', credentialEnv: 'SCOPEHAVEN_TARGET_OPS', identityValue: 'ops' } }, requiredControlIds: ['WHOAMI'],
    observers: [{ id: 'sink', type: 'egress-recorder', port, routing: 'proxy', destinations: [NOTE_DEST, { host: BILL, paths: ['/v1'] }], witness: { actorId: 'ops', method: 'GET', path: '/ping', host: WITNESS }, settleMs: 250, quietMs: 150 }],
    checks: [{ id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'ops', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'ops' }] },
      // The passing check runs last: settlement withholds a pass that a later check's note could belong to.
      check('TWICE', '/cancel/twice'), check('FORM', '/cancel/form'), check('ABSENT', '/cancel/absent'), check('UPDATE', '/cancel/update')] };
  validateTargetFile({ schemaVersion: 1, targets: [p] });
  const watch = watchingBinds(buildObservers);
  return { p, run: await runHttpAssessment(p, { env, observerFactory: watch.factory }), lostBind: watch.state.lostBind };
}, r => r.lostBind);

test('9. end to end: through a real egress recorder, the clause over an unreadable second cancel decides missing (the earlier judge: pass); the run validates', async t => {
  const r = await run(t);
  const rowOf = id => r.run.results.find(x => x.id === id);
  const statusOf = id => rowOf(id).assertions.find(a => a.name === 'Observed effect 1 (effect.only)').status;
  const windowsOf = id => rowOf(id).trace[1].data.windows;
  const kindsOf = id => windowsOf(id)[0].events.filter(e => e.name === DESK).map(e => (e.captured.status === 'captured' ? e.captured.values['/kind'] : e.captured.status));
  assert.deepEqual(kindsOf('TWICE'), [{ type: 'string', value: 'cancel' }, { type: 'string', value: 'cancel' }]);
  assert.deepEqual(kindsOf('FORM'), [{ type: 'string', value: 'cancel' }, 'not-json']);
  assert.deepEqual(kindsOf('ABSENT'), [{ type: 'string', value: 'cancel' }, { type: 'absent' }]);
  assert.deepEqual(kindsOf('UPDATE'), [{ type: 'string', value: 'cancel' }, { type: 'string', value: 'update' }]);
  assert.deepEqual(['TWICE', 'FORM', 'ABSENT', 'UPDATE'].map(statusOf), ['fail', 'inconclusive', 'inconclusive', 'pass'], JSON.stringify(rowOf('FORM').assertions));
  // The clause's own decision, before settlement: FORM and ABSENT read missing. Under the earlier judge they read pass, and only settlement withheld
  // them here (effect-outside-window: a later check's note could be theirs), so their status alone would not tell the two apart.
  const decided = id => { const d = rowOf(id).trace[1].data.effects[0]; return [d.verdict, d.settlement ?? null]; };
  assert.deepEqual(['TWICE', 'FORM', 'ABSENT', 'UPDATE'].map(decided), [['fail', null], ['missing', null], ['missing', null], ['pass', null]]);
  // The earlier judge, over the same sealed windows: the unreadable second cancel was absorbed, so FORM and ABSENT read pass there.
  assert.deepEqual(['TWICE', 'FORM', 'ABSENT', 'UPDATE'].map(id => mainJudged(CLAUSE, windowsOf(id)).verdict), ['fail', 'pass', 'pass', 'pass']);
  validateHttpRunEvidence(r.run, { expectedSuite: createRegistry({ profiles: [r.p], env }).exportSuite(r.p.id) });
});
