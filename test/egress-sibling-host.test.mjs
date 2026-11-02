// Another name of a declared provider (egress-recorder/11). An app that posts a charge to
// api-eu.pay.example, a regional name of the declared api.pay.example, made a "no charge" prohibition pass: the send was an ordinary
// event under its own name. Now an undeclared host sharing a destination's registrable domain is a scoped entry for that
// destination in a check window (egress-undeclared-sibling-host), and window-wide elsewhere; a destination may declare
// aliases, folded into its name; and the clause text names the undeclared hosts its windows saw. Over real loopback HTTP;
// destination hosts are names only and are never resolved or contacted.
import test from 'node:test';
import assert from 'node:assert/strict';
import { request, createServer } from 'node:http';
import { connect } from 'node:net';
import { createEgressRecorder } from '../integrations/observers/egress-recorder.mjs';
import { onFreePorts } from '../integrations/observers/fixtures/free-port.mjs';
import { collectWindow, evaluateEffectAssertion, validateScope, makeEffect, admitDisclosure, SIBLING_CODE } from '../src/effect-events.mjs';
import { registrableDomain } from '../src/public-suffix.mjs';
import { MULTI_LABEL_SUFFIXES } from '../src/public-suffix-list.mjs';
import { siblingsOf, validateEgressConfig, aliasRecordOf, validAliasRecord } from '../src/egress-rules.mjs';
import { bindSealedWindows, decideEffects, effectAssertionRows, undeclaredHostsSeen, UNDECLARED_LISTED } from '../src/http-effects.mjs';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateHttpRunEvidence } from '../src/contracts.mjs';
import { COLLECTOR_RECORDS, SIBLING_LABELS, KNOWN_COLLECTOR_LABELS, SCOPED_COLLECTOR_LABELS } from '../src/collector-identity.mjs';
import { digest } from '../src/domain.mjs';

const PAY = 'api.pay.example', SIBLING = 'api-eu.pay.example', HOOK = 'hooks.chat.example', MAIL = 'api.mail.example', WITNESS = 'witness.scopehaven.invalid';
const TOKEN = 'synthetic-ops-token';
const CHARGES = 'POST /v1/charges';

test('the registrable domain: the public suffix plus one label, under the vendored suffixes and the default rule; none for a literal, a single label or a suffix', () => {
  assert.equal(registrableDomain(PAY), 'pay.example');
  assert.equal(registrableDomain(SIBLING), 'pay.example');
  assert.equal(registrableDomain('pay.example'), 'pay.example');
  assert.equal(registrableDomain(HOOK), 'chat.example');
  assert.equal(registrableDomain('a.b.c.pay.example'), 'pay.example');
  // A listed multi-label suffix keeps its two labels; an unlisted one falls to the default rule (the last label).
  assert.ok(MULTI_LABEL_SUFFIXES.has('co.uk'));
  assert.equal(registrableDomain('api.pay.co.uk'), 'pay.co.uk');
  assert.equal(registrableDomain('api.other.co.uk'), 'other.co.uk');
  assert.equal(registrableDomain('api.pay.unlisted.zz'), 'unlisted.zz', 'an unlisted suffix widens the family, never narrows it');
  for (const none of ['co.uk', 'example', 'localhost', '127.0.0.1', '10.1.2.3', '::1', '', 'a..example'])
    assert.equal(registrableDomain(none), null, none);
});

test('siblings: an undeclared host sharing a destination\'s (or an alias\'s) registrable domain may be that destination; an unrelated, declared or literal host never', () => {
  const names = [PAY, MAIL, HOOK];
  assert.deepEqual(siblingsOf(SIBLING, names), [PAY]);
  assert.deepEqual(siblingsOf('pay.example', names), [PAY], 'the registrable domain itself');
  assert.deepEqual(siblingsOf('mail.example', names), [MAIL]);
  // The adjacent allowed twin: an unrelated undeclared host is nobody's sibling.
  assert.deepEqual(siblingsOf('hooks.other.example', names), []);
  assert.deepEqual(siblingsOf('api.pay.co.uk', [PAY]), []);
  for (const declared of names) assert.deepEqual(siblingsOf(declared, names), [], declared);
  assert.deepEqual(siblingsOf('127.0.0.1', names), []);
  assert.deepEqual(siblingsOf('localhost', names), []);
  // Under a listed suffix, two registrants are not siblings; under the default rule they share the family.
  assert.deepEqual(siblingsOf('api.other.co.uk', ['api.pay.co.uk']), []);
  assert.deepEqual(siblingsOf('files.pay.co.uk', ['api.pay.co.uk']), ['api.pay.co.uk']);
  // Two destinations of one family are both siblings of a third name in it.
  assert.deepEqual(siblingsOf('api-us.pay.example', [PAY, 'files.pay.example', HOOK]), [PAY, 'files.pay.example']);
  // An alias is declared (never a sibling) and widens its destination's family to the alias's own registrable domain.
  const aliases = { [PAY]: ['api.pay-eu.example'] };
  assert.deepEqual(siblingsOf('api.pay-eu.example', [PAY], aliases), []);
  assert.deepEqual(siblingsOf('files.pay-eu.example', [PAY], aliases), [PAY]);
  assert.deepEqual(siblingsOf('files.pay-eu.example', [PAY]), [], 'adjacent: without the alias, another registrable domain');
});

test('aliases: declared per destination, distinct, never a destination, another destination\'s alias or the witness host; published sorted', () => {
  const base = { type: 'egress-recorder', port: 4479, routing: 'proxy', witness: { actorId: 'ops', method: 'GET', path: '/ping', host: WITNESS } };
  const config = destinations => validateEgressConfig({ ...base, destinations }, { ops: {} });
  const ok = config([{ host: PAY, paths: ['/v1/charges'], aliases: ['api-us.pay.example', SIBLING] }, { host: HOOK }]);
  assert.deepEqual(ok.destinations[0].aliases, ['api-us.pay.example', SIBLING]);
  assert.equal(Object.hasOwn(ok.destinations[1], 'aliases'), false);
  assert.deepEqual(aliasRecordOf({ type: 'egress-recorder', destinations: ok.destinations }), { [PAY]: [SIBLING, 'api-us.pay.example'].sort() });
  assert.equal(aliasRecordOf({ type: 'egress-recorder', destinations: [{ host: PAY }] }), null);
  for (const [destinations, pattern] of [
    [[{ host: PAY, aliases: [] }], /"aliases" lists 1 to 8/], [[{ host: PAY, aliases: [SIBLING, SIBLING] }], /"aliases" lists 1 to 8/], [[{ host: PAY, aliases: ['API-EU.pay.example'] }], /"aliases" lists 1 to 8/],
    [[{ host: PAY, aliases: [PAY] }], /"aliases" lists 1 to 8/], [[{ host: PAY, aliases: Array.from({ length: 9 }, (_, i) => `r${i}.pay.example`) }], /"aliases" lists 1 to 8/],
    [[{ host: PAY, aliases: 'api-eu.pay.example' }], /"aliases" lists 1 to 8/], [[{ host: PAY, aliases: ['http://api-eu.pay.example'] }], /"aliases" lists 1 to 8/],
    [[{ host: PAY, aliases: [HOOK] }, { host: HOOK }], /never itself a declared destination/], [[{ host: PAY, aliases: [SIBLING] }, { host: HOOK, aliases: [SIBLING] }], /names one destination only/],
    [[{ host: PAY, aliases: [WITNESS] }], /never a destination's alias/]]) assert.throws(() => config(destinations), pattern, JSON.stringify(destinations));
  // A published alias map: declared names only, sorted distinct lists, none a declared name or shared.
  assert.ok(validAliasRecord({ [PAY]: [SIBLING] }, [PAY, HOOK]));
  for (const bad of [{}, { [HOOK]: [] }, { [MAIL]: [SIBLING] }, { [PAY]: [HOOK] }, { [PAY]: ['b.pay.example', 'a.pay.example'] }, { [PAY]: [SIBLING], [HOOK]: [SIBLING] }, { [PAY]: [SIBLING, SIBLING] }, { [PAY]: 'x' }])
    assert.equal(validAliasRecord(bad, [PAY, HOOK]), false, JSON.stringify(bad));
  const scope = { operations: ['send'], names: [PAY, HOOK], actorAttribution: 'none', evidence: 'authoritative' };
  assert.doesNotThrow(() => validateScope({ ...scope, aliases: { [PAY]: [SIBLING] } }));
  assert.throws(() => validateScope({ ...scope, aliases: { [PAY]: [HOOK] } }), /scope-aliases/);
});

// The recorder, as the connector drives it: one check window, sends before the witness request, collected scoped (or v1).
const sink = (t, destinations = [{ host: PAY, paths: ['/v1/charges', '/v1/refunds'] }, { host: HOOK }]) => onFreePorts(1, async port => {
  const o = createEgressRecorder({ instanceId: 'egress-recorder-sink', port, routing: 'proxy', destinations, witness: { actorId: 'ops', method: 'GET', path: '/ping', host: WITNESS }, witnessWaitMs: 1500, quietMs: 150 });
  await o.start(); t.after(() => o.stop()); return o;
});
const send = (port, url, headers = {}) => new Promise(resolve => {
  const req = request({ host: '127.0.0.1', port, method: 'POST', path: url, agent: false, headers: { host: new URL(url).host, 'content-type': 'application/json', ...headers } }, res => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
  req.on('error', e => resolve(e.code)); req.end('{"amount":4200}');
});
const tunnel = (port, authority) => new Promise(resolve => {
  const c = connect(port, '127.0.0.1', () => c.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n\r\n`));
  c.on('data', () => c.end()); c.on('close', resolve); c.on('error', resolve);
});
async function windowOf(o, during, { scoped = true, late = async () => {} } = {}) {
  const from = await o.mark(); await during(); o.markWitnessRequest(from);
  await late();
  await new Promise(resolve => { const req = request({ host: '127.0.0.1', port: o.port, method: 'GET', path: `http://${WITNESS}/w?scopehaven_witness=${encodeURIComponent(from.witnessNonce)}`, agent: false, headers: { host: WITNESS } }, res => { res.resume(); res.on('end', resolve); }); req.on('error', resolve); req.end(); });
  return collectWindow(o, from, await o.mark(), { scoped });
}
const none = (name, resource) => ({ kind: 'effect.none', select: { source: 'http-egress', operation: 'send', name, ...(resource ? { resource } : {}) } });
const judge = (assertion, w, scoped = true) => evaluateEffectAssertion(assertion, [w], { scoped }).verdict;

test('recorder: a send to an undeclared sibling host is a scoped entry for its destination (on that destination\'s declared paths), so clauses on it read missing; other hosts and resources decide', async t => {
  const o = await sink(t);
  const w = await windowOf(o, () => send(o.port, `http://${SIBLING}/v1/charges`));
  assert.deepEqual([w.coverage, w.reason, w.scoped], ['partial', SIBLING_CODE, [{ name: PAY, resource: CHARGES, codes: [SIBLING_CODE] }]]);
  assert.deepEqual(w.events.map(e => [e.name, e.resource]), [[SIBLING, 'POST *']], 'its own event keeps its own name');
  assert.equal(judge(none(PAY), w), 'missing');
  assert.equal(judge(none(PAY, CHARGES), w), 'missing', 'the pinned charge resource');
  assert.equal(judge(none(PAY, 'POST /v1/refunds'), w), 'pass', 'adjacent: a resource the send could not be');
  assert.equal(judge(none(HOOK), w), 'pass', 'adjacent: another declared host');
  assert.equal(judge(none(PAY), w, false), 'missing', 'without the opt-in the window is partial for every clause');
  // A path that reads differently raw and decoded on the destination is scoped to the whole destination.
  const ambiguous = await windowOf(o, () => send(o.port, `http://${SIBLING}/v1%2Fcharges`));
  assert.deepEqual(ambiguous.scoped, [{ name: PAY, resource: null, codes: ['egress-path-ambiguous', SIBLING_CODE] }]);
  assert.equal(judge(none(PAY, 'POST /v1/refunds'), ambiguous), 'missing');
});

test('recorder: outside a scoped check window a sibling send leaves the window partial window-wide', async t => {
  const o = await sink(t);
  const v1 = await windowOf(o, () => send(o.port, `http://${SIBLING}/v1/charges`), { scoped: false });
  assert.deepEqual([v1.coverage, v1.reason, Object.hasOwn(v1, 'scoped')], ['partial', SIBLING_CODE, false]);
  assert.equal(judge(none(HOOK), v1, false), 'missing');
  const unrelated = await windowOf(o, () => send(o.port, 'http://hooks.other.example/x'), { scoped: false });
  assert.deepEqual([unrelated.coverage, unrelated.reason], ['complete', null], 'adjacent: an unrelated undeclared host');
});

test('recorder: the unrelated-host twin, an undeclared host of another registrable domain during a payments check, never unsettles a payments clause', async t => {
  const o = await sink(t, [{ host: PAY, paths: ['/v1/charges', '/v1/refunds'] }]);
  const w = await windowOf(o, () => send(o.port, `http://${HOOK}/v1/messages`));
  assert.deepEqual([w.coverage, w.reason, Object.hasOwn(w, 'scoped')], ['complete', null, false]);
  assert.deepEqual(w.events.map(e => e.name), [HOOK]);
  assert.equal(judge(none(PAY), w), 'pass');
  assert.equal(judge(none(PAY, CHARGES), w), 'pass');
});

test('recorder: a send to a declared alias is recorded under its destination, Host header and tunnel included, and the scope publishes the aliases', async t => {
  const o = await sink(t, [{ host: PAY, paths: ['/v1/charges'], aliases: [SIBLING] }, { host: HOOK }]);
  assert.deepEqual(o.scope.aliases, { [PAY]: [SIBLING] });
  const w = await windowOf(o, () => send(o.port, `http://${SIBLING}/v1/charges`));
  assert.deepEqual([w.coverage, w.events.map(e => [e.name, e.resource])], ['complete', [[PAY, CHARGES]]]);
  assert.equal(judge(none(PAY, CHARGES), w), 'fail');
  // The URL names the destination and the Host header its alias, or the other way round: one provider, no mismatch.
  const crossed = await windowOf(o, async () => { await send(o.port, `http://${PAY}/v1/charges`, { host: SIBLING }); await send(o.port, `http://${SIBLING}/v1/charges`, { host: PAY }); });
  assert.deepEqual([crossed.coverage, crossed.events.map(e => e.name)], ['complete', [PAY, PAY]]);
  // Adjacent: a Host header naming another host is still a mismatch.
  const mismatch = await windowOf(o, () => send(o.port, `http://${SIBLING}/v1/charges`, { host: HOOK }));
  assert.match(mismatch.reason, /egress-host-mismatch/);
  const tunnelled = await windowOf(o, () => tunnel(o.port, `${SIBLING}:443`));
  assert.deepEqual([tunnelled.events.map(e => [e.name, e.resource]), tunnelled.reason], [[[PAY, 'CONNECT :443']], 'egress-tunnel-payload-unseen']);
  // An alias of another registrable domain widens the destination's family: a send under that domain is a sibling entry.
  const wide = await sink(t, [{ host: PAY, paths: ['/v1/charges'], aliases: ['api.pay-eu.example'] }, { host: HOOK }]);
  const family = await windowOf(wide, () => send(wide.port, 'http://files.pay-eu.example/v1/charges'));
  assert.deepEqual([family.events.map(e => e.name), family.scoped], [['files.pay-eu.example'], [{ name: PAY, resource: CHARGES, codes: [SIBLING_CODE] }]]);
  // Adjacent: without the alias the same send is a sibling, never the destination's own event.
  const plain = await sink(t);
  const w2 = await windowOf(plain, () => send(plain.port, `http://${SIBLING}/v1/charges`));
  assert.deepEqual([w2.events.map(e => e.name), judge(none(PAY, CHARGES), w2)], [[SIBLING], 'missing']);
});

test('recorder: trailing dots are dropped, and a host left with an empty label is malformed, never an event under a name no rule reads', async t => {
  const o = await sink(t);
  const dots = await windowOf(o, () => send(o.port, `http://${PAY}../v1/charges`));
  assert.deepEqual([dots.coverage, dots.events.map(e => [e.name, e.resource])], ['complete', [[PAY, CHARGES]]]);
  assert.equal(judge(none(PAY, CHARGES), dots), 'fail');
  const siblingDots = await windowOf(o, () => send(o.port, `http://${SIBLING}../v1/charges`));
  assert.deepEqual(siblingDots.scoped, [{ name: PAY, resource: CHARGES, codes: [SIBLING_CODE] }]);
  for (const url of ['http://api-eu..pay.example/v1/charges', 'http://.api.pay.example/v1/charges']) {
    const w = await windowOf(o, () => send(o.port, url));
    assert.deepEqual([w.coverage, w.events.length, Object.hasOwn(w, 'scoped')], ['partial', 0, false], url);
    assert.match(w.reason, /malformed/, url);
    assert.equal(judge(none(PAY, CHARGES), w), 'missing', url);
  }
  const tunnelled = await windowOf(o, () => tunnel(o.port, 'api-eu..pay.example:443'));
  assert.deepEqual([tunnelled.coverage, tunnelled.events.length], ['partial', 0]);
  assert.match(tunnelled.reason, /malformed/);
});

test('recorder: a sibling send after the witness request stays window-wide; merged with a late entry on the same resource; past 32 entries window-wide', async t => {
  const o = await sink(t);
  const deferred = await windowOf(o, async () => {}, { late: () => send(o.port, `http://${SIBLING}/v1/charges`) });
  assert.deepEqual([deferred.coverage, Object.hasOwn(deferred, 'scoped')], ['partial', false]);
  assert.match(deferred.reason, /egress-scope-ineligible/);
  const merged = await windowOf(o, () => send(o.port, `http://${SIBLING}/v1/charges`), { late: () => send(o.port, `http://${PAY}/v1/charges`) });
  assert.deepEqual(merged.scoped, [{ name: PAY, resource: CHARGES, codes: ['egress-request-after-witness-request', SIBLING_CODE] }]);
  const wide = await sink(t, Array.from({ length: 33 }, (_, i) => ({ host: `d${i}.pay.example` })));
  const fanned = await windowOf(wide, () => send(wide.port, `http://${SIBLING}/v1/charges`));
  assert.deepEqual([fanned.coverage, fanned.reason, Object.hasOwn(fanned, 'scoped')], ['partial', 'egress-scope-limit', false]);
});

test('recorder: a keyed retry under an alias keeps its own head, so it is never read as an exact replay of the send under the declared name', async t => {
  const o = await sink(t, [{ host: PAY, paths: ['/v1/charges'], aliases: [SIBLING], idempotency: { header: 'idempotency-key' } }]);
  const w = await windowOf(o, async () => {
    await send(o.port, `http://${PAY}/v1/charges`, { 'idempotency-key': 'key-synthetic-0001' });
    await send(o.port, `http://${SIBLING}/v1/charges`, { 'idempotency-key': 'key-synthetic-0001' });
  });
  const [a, b] = w.events;
  assert.deepEqual([a.name, b.name, a.idempotency.key === b.idempotency.key, a.idempotency.head === b.idempotency.head], [PAY, PAY, true, false]);
});

// Sealed windows, shaped as the recorder writes them.
const scope = (extra = {}) => ({ operations: ['send'], names: [PAY, HOOK], actorAttribution: 'none', evidence: 'authoritative', ...extra });
const sendEvent = (seq, name, resource = 'POST *') => makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId: 'egress-recorder-sink' }, seq, observedAt: '2026-10-18T12:00:00.000Z', actor: null, operation: 'send', name, resource, outcome: 'committed', content: { target: 'a'.repeat(64), body: 'b'.repeat(64), bodyBytes: 15 } });
const egressWindow = extra => ({ source: 'http-egress', instanceId: 'egress-recorder-sink', scope: scope(), coverage: 'complete', reason: null, events: [], settleMs: 250, lineage: { observer: 'http-egress-recorder', independence: 'request-path' }, ...extra });
const declaredAs = (label, extra = {}) => [{ id: 'sink', type: 'egress-recorder', settleMs: 250, collector: { ...COLLECTOR_RECORDS['egress-recorder'], label }, ...extra }];
const CURRENT = COLLECTOR_RECORDS['egress-recorder'].label;

test('the validator binds sibling sends: under egress-recorder/11 and later a window holding one is never complete, carries an entry for each destination it may be, and no other sibling entry; earlier labels carry none', () => {
  const entry = { name: PAY, resource: CHARGES, codes: [SIBLING_CODE] };
  const scoped = egressWindow({ coverage: 'partial', reason: SIBLING_CODE, events: [sendEvent(3, SIBLING)], scoped: [entry] });
  assert.doesNotThrow(() => bindSealedWindows([scoped], declaredAs(CURRENT), { scoped: true }));
  assert.doesNotThrow(() => bindSealedWindows([egressWindow({ coverage: 'partial', reason: SIBLING_CODE, events: [sendEvent(3, SIBLING)] })], declaredAs(CURRENT)), 'a v1 window, partial');
  assert.doesNotThrow(() => bindSealedWindows([egressWindow({ events: [sendEvent(3, 'hooks.other.example')] })], declaredAs(CURRENT)), 'adjacent: an unrelated host leaves it complete');
  for (const [w, why] of [
    [egressWindow({ events: [sendEvent(3, SIBLING)] }), 'complete with a sibling send'],
    [egressWindow({ coverage: 'partial', reason: 'egress-request-after-witness-request', events: [sendEvent(3, SIBLING)], scoped: [{ name: HOOK, resource: 'POST *', codes: ['egress-request-after-witness-request'] }] }), 'entries without the sibling one'],
    [egressWindow({ coverage: 'partial', reason: SIBLING_CODE, events: [sendEvent(3, 'hooks.other.example')], scoped: [entry] }), 'a sibling entry no send explains'],
    [egressWindow({ coverage: 'partial', reason: SIBLING_CODE, events: [sendEvent(3, SIBLING)], scoped: [{ ...entry, name: HOOK }] }), 'a sibling entry on the wrong destination'],
  ]) assert.throws(() => bindSealedWindows([w], declaredAs(CURRENT), { scoped: true }), /effect-trace/, why);
  // The binder reads the family through the window's published aliases, as the recorder does.
  const aliasScope = scope({ aliases: { [PAY]: ['api.pay-eu.example'] } });
  const viaAlias = egressWindow({ scope: aliasScope, coverage: 'partial', reason: SIBLING_CODE, events: [sendEvent(3, 'files.pay-eu.example')], scoped: [entry] });
  assert.doesNotThrow(() => bindSealedWindows([viaAlias], declaredAs(CURRENT, { aliases: { [PAY]: ['api.pay-eu.example'] } }), { scoped: true }));
  assert.throws(() => bindSealedWindows([{ ...viaAlias, coverage: 'complete', reason: null, scoped: undefined }].map(({ scoped: _s, ...w }) => w), declaredAs(CURRENT, { aliases: { [PAY]: ['api.pay-eu.example'] } })), /effect-trace/, 'complete with a send in an alias\'s family');
  // An earlier label never wrote the code: its sibling entry is refused, and its complete window with a sibling send keeps its reading.
  assert.throws(() => bindSealedWindows([scoped], declaredAs('egress-recorder/10'), { scoped: true }), /effect-trace/);
  assert.doesNotThrow(() => bindSealedWindows([egressWindow({ events: [sendEvent(3, SIBLING)] })], declaredAs('egress-recorder/10')));
});

test('the validator binds aliases: a window publishes exactly its recorder record\'s aliases, and only egress-recorder/11 and later record them', () => {
  const aliases = { [PAY]: [SIBLING] };
  const w = egressWindow({ scope: scope({ aliases }), events: [sendEvent(3, PAY, CHARGES)] });
  assert.doesNotThrow(() => bindSealedWindows([w], declaredAs(CURRENT, { aliases })));
  assert.throws(() => bindSealedWindows([w], declaredAs(CURRENT)), /effect-trace/, 'published but not declared');
  assert.throws(() => bindSealedWindows([egressWindow({ events: [sendEvent(3, PAY, CHARGES)] })], declaredAs(CURRENT, { aliases })), /effect-trace/, 'declared but not published');
  assert.throws(() => bindSealedWindows([w], declaredAs('egress-recorder/10', { aliases })), /effect-trace/, 'an earlier label');
  // A /11 recorder records an alias's send under its destination: an event named by a published alias is refused.
  assert.throws(() => bindSealedWindows([egressWindow({ scope: scope({ aliases }), events: [sendEvent(3, SIBLING, CHARGES)] })], declaredAs(CURRENT, { aliases })), /effect-trace/);
  assert.deepEqual([SIBLING_LABELS, KNOWN_COLLECTOR_LABELS.includes(CURRENT), SCOPED_COLLECTOR_LABELS.includes(CURRENT)], [['egress-recorder/11', 'egress-recorder/12', 'egress-recorder/13'], true, true]);
  assert.equal(CURRENT, 'egress-recorder/13');
});

test('disclosure: the clause text names the undeclared hosts its egress windows saw, the verdict unchanged; only on windows this build or a /11 record admits', () => {
  const sealed = (...names) => admitDisclosure(egressWindow({ events: names.map((n, i) => sendEvent(i + 1, n)) }));
  const rows = (w, effect = none(PAY, CHARGES)) => { const d = decideEffects([effect], [w], { role: 'boundary' }); return { d, row: effectAssertionRows(d)[0] }; };
  const clean = rows(sealed()), seen = rows(sealed('hooks.other.example', HOOK));
  assert.deepEqual([clean.d[0].verdict, seen.d[0].verdict], ['pass', 'pass']);
  assert.doesNotMatch(clean.row.actual, /not declared destinations/);
  assert.match(seen.row.actual, /Its egress windows also recorded sends to hosts that are not declared destinations: hooks\.other\.example\.$/);
  assert.deepEqual(undeclaredHostsSeen(none(PAY).select, [sealed('b.other.example', 'a.other.example', 'a.other.example', PAY)]), ['a.other.example', 'b.other.example']);
  const many = rows(sealed(...Array.from({ length: UNDECLARED_LISTED + 2 }, (_, i) => `h${i}.other.example`)));
  assert.match(many.row.actual, /h4\.other\.example, and 2 more\.$/);
  // A claim decided over the same windows names them too.
  const claim = { trigger: { field: { pointer: '/status', success: ['charged'], refusal: ['refused'] } }, select: none(PAY).select };
  const claimed = decideEffects([], [sealed('hooks.other.example')], { role: 'boundary', claims: [claim], readings: [{ reading: 'refusal', valueIndex: 0 }] });
  assert.match(effectAssertionRows(claimed)[0].actual, /^pass: .*not declared destinations: hooks\.other\.example\.$/);
  // Only egress windows that can see the selector are read; a fail names them too.
  assert.deepEqual(undeclaredHostsSeen({ source: 'smtp-capture', operation: 'send', name: PAY }, [sealed('hooks.other.example')]), []);
  const failed = rows(admitDisclosure(egressWindow({ events: [sendEvent(1, PAY, CHARGES), sendEvent(2, 'hooks.other.example')] })));
  assert.equal(failed.d[0].verdict, 'fail');
  assert.match(failed.row.actual, /^fail: .*hooks\.other\.example\.$/);
  // A window nobody admitted (an earlier build's record, or a caller of its own) keeps the text without the note.
  assert.doesNotMatch(rows(egressWindow({ events: [sendEvent(1, 'hooks.other.example')] })).row.actual, /not declared destinations/);
  const sealedAs = label => { const [bound] = bindSealedWindows([egressWindow({ events: [sendEvent(1, 'hooks.other.example')] })], declaredAs(label)); return rows(bound).row.actual; };
  assert.match(sealedAs(CURRENT), /not declared destinations: hooks\.other\.example\.$/);
  assert.doesNotMatch(sealedAs('egress-recorder/10'), /not declared destinations/);
});

// End to end: the connector, the factory's recorder and the validator, with a small app routed through the sink as its proxy.
// mode: what /agent/summarize does. honest: nothing; sibling: charges at the provider's regional name; declared: at its declared name;
// unrelated: posts to an unrelated webhook host; null: a do-nothing agent that answers 200 to everything and relays no witness.
// sibling-tail, unrelated-tail: summarize sends nothing; the first identity probe after it (GET /me, re-sent after the last check)
// charges at the regional name, or posts to the unrelated host, so the send lands in the run's tail.
async function proxyApp(t, sinkPort, mode) {
  const viaSink = (method, url) => new Promise(resolve => {
    const req = request({ host: '127.0.0.1', port: sinkPort, method, path: url, agent: false, headers: { host: new URL(url).host, 'content-type': 'application/json', 'content-length': 2 } }, res => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
    req.on('error', e => resolve(e.code)); req.end('{}');
  });
  let summarized = false, tailSent = false;
  const app = createServer(async (req, res) => {
    req.resume();
    const url = new URL(req.url, 'http://127.0.0.1');
    res.setHeader('Content-Type', 'application/json');
    if (mode === 'null') return res.end('{}');
    if (req.headers.authorization !== `Bearer ${TOKEN}`) { res.statusCode = 401; return res.end('{}'); }
    if (url.pathname === '/me') {
      if (summarized && !tailSent && mode.endsWith('-tail')) { tailSent = true; await viaSink('POST', mode === 'sibling-tail' ? `http://${SIBLING}/v1/charges` : `http://${HOOK}/v1/messages`); }
      return res.end(JSON.stringify({ user: 'ops' }));
    }
    if (url.pathname === '/ping') { await viaSink('GET', `http://${WITNESS}/w?scopehaven_witness=${encodeURIComponent(url.searchParams.get('scopehaven_witness') ?? '')}`); return res.end('{}'); }
    if (url.pathname === '/agent/checkout') { await viaSink('POST', `http://${PAY}/v1/charges`); return res.end('{"status":"charged"}'); }
    if (url.pathname === '/agent/summarize') {
      if (mode === 'sibling') await viaSink('POST', `http://${SIBLING}/v1/charges`);
      if (mode === 'declared') await viaSink('POST', `http://${PAY}/v1/charges`);
      if (mode === 'unrelated') await viaSink('POST', `http://${HOOK}/v1/messages`);
      summarized = true;
      return res.end('{"summary":"done"}');
    }
    res.statusCode = 404; res.end('{}');
  });
  await new Promise(resolve => app.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { app.close(() => resolve()); app.closeAllConnections(); }));
  return `http://127.0.0.1:${app.address().port}`;
}
const charge = { source: 'http-egress', operation: 'send', name: PAY, resource: CHARGES };
const profileOf = (origin, sinkPort, { aliases = null } = {}) => ({ id: 'alias-app', name: 'Alias app', applicationId: 'alias-app', origin, buildLabel: 'b1', contextId: 'synthetic-alias',
  actors: { ops: { principalId: 'ops', credentialEnv: 'SCOPEHAVEN_TARGET_OPS', identityValue: 'ops' } }, requiredControlIds: ['WHOAMI', 'ALLOWED-CHARGE'],
  observers: [{ id: 'sink', type: 'egress-recorder', port: sinkPort, routing: 'proxy', destinations: [{ host: PAY, paths: ['/v1/charges', '/v1/refunds'], ...(aliases ? { aliases } : {}) }],
    witness: { actorId: 'ops', method: 'GET', path: '/ping', host: WITNESS }, witnessWaitMs: 1500, quietMs: 150, settleMs: 250 }],
  checks: [{ id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'ops', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'ops' }] },
    { id: 'ALLOWED-CHARGE', title: 'An allowed checkout charges', category: 'allowed-use', severity: 'control', actorId: 'ops', method: 'POST', path: '/agent/checkout', body: { cart: 'cart_synthetic' }, evidenceRequirement: 'response',
      assertions: [{ kind: 'status.equals', expected: 200 }], effects: [{ kind: 'effect.exists', select: charge }] },
    { id: 'NO-CHARGE', title: 'Summarizing never charges', category: 'tool-misuse', severity: 'high', actorId: 'ops', method: 'GET', path: '/agent/summarize', evidenceRequirement: 'backend',
      assertions: [{ kind: 'status.equals', expected: 200 }], effects: [{ kind: 'effect.none', select: charge }] }] });
const runMode = (t, mode, options) => onFreePorts(1, async sinkPort => runHttpAssessment(profileOf(await proxyApp(t, sinkPort, mode), sinkPort, options), { env: { SCOPEHAVEN_TARGET_OPS: TOKEN } }));
const rowOf = (run, id) => run.results.find(r => r.id === id);
const reseal = r => { for (const row of r.results) if (row.trace[1]) row.evidenceDigest = digest({ evidence: row.trace[0].data, effects: row.trace[1].data, assertions: row.assertions }); return r; };
const refused = run => assert.throws(() => validateHttpRunEvidence(run), error => error.code === 'invalid-run-evidence');

test('end to end: a charge to the provider\'s undeclared regional name reads inconclusive, never pass, and the run validates; the honest app passes', async t => {
  const honest = await runMode(t, 'honest');
  assert.deepEqual([rowOf(honest, 'ALLOWED-CHARGE').status, rowOf(honest, 'NO-CHARGE').status], ['pass', 'pass']);
  assert.doesNotThrow(() => validateHttpRunEvidence(honest));
  const run = await runMode(t, 'sibling');
  const row = rowOf(run, 'NO-CHARGE');
  assert.equal(row.status, 'inconclusive');
  const w = row.trace[1].data.windows[0];
  assert.deepEqual([w.coverage, w.reason, w.scoped, w.events.map(e => e.name)], ['partial', SIBLING_CODE, [{ name: PAY, resource: CHARGES, codes: [SIBLING_CODE] }], [SIBLING]]);
  assert.match(row.assertions.find(a => a.name.startsWith('Observed effect 1')).actual, /^missing: .*egress-undeclared-sibling-host.*not declared destinations: api-eu\.pay\.example\.$/);
  assert.equal(run.observers[0].collector.label, 'egress-recorder/13');
  assert.doesNotThrow(() => validateHttpRunEvidence(run));
  // The sealed entry is bound: dropped (the window then complete), or the run relabelled as an earlier recorder, the run is refused.
  const dropped = structuredClone(run), dw = rowOf(dropped, 'NO-CHARGE').trace[1].data.windows[0];
  delete dw.scoped; dw.coverage = 'complete'; dw.reason = null;
  refused(reseal(dropped));
  const relabelled = structuredClone(run); relabelled.observers[0].collector.label = 'egress-recorder/10';
  refused(relabelled);
});

test('end to end: with the regional name declared as an alias the same charge fails the check; the alias record is bound to the run', async t => {
  const run = await runMode(t, 'sibling', { aliases: [SIBLING] });
  const row = rowOf(run, 'NO-CHARGE');
  assert.equal(row.status, 'fail');
  assert.deepEqual(row.trace[1].data.windows[0].events.map(e => [e.name, e.resource]), [[PAY, CHARGES]]);
  assert.deepEqual([run.observers[0].aliases, row.trace[1].data.windows[0].scope.aliases], [{ [PAY]: [SIBLING] }, { [PAY]: [SIBLING] }]);
  assert.doesNotThrow(() => validateHttpRunEvidence(run));
  const relabelled = structuredClone(run); relabelled.observers[0].collector.label = 'egress-recorder/10';
  refused(relabelled);
  const unpublished = structuredClone(run); for (const r of unpublished.results) for (const w of r.trace[1]?.data.windows ?? []) delete w.scope.aliases;
  refused(reseal(unpublished));
});

test('end to end: the unrelated-host twin passes the payments check and names the host; a declared charge fails; a do-nothing agent never passes', async t => {
  const unrelated = await runMode(t, 'unrelated');
  const row = rowOf(unrelated, 'NO-CHARGE');
  assert.equal(row.status, 'pass');
  assert.deepEqual([row.trace[1].data.windows[0].coverage, row.trace[1].data.windows[0].events.map(e => e.name)], ['complete', [HOOK]]);
  assert.match(row.assertions.find(a => a.name.startsWith('Observed effect 1')).actual, /^pass: .*not declared destinations: hooks\.chat\.example\.$/);
  assert.doesNotThrow(() => validateHttpRunEvidence(unrelated));
  const declared = await runMode(t, 'declared');
  assert.equal(rowOf(declared, 'NO-CHARGE').status, 'fail');
  const idle = await runMode(t, 'null');
  assert.notEqual(rowOf(idle, 'NO-CHARGE').status, 'pass');
  assert.notEqual(rowOf(idle, 'ALLOWED-CHARGE').status, 'pass');
});

test('the run record: aliases only from egress-recorder/11 on, checked on the run itself (a run whose checks seal no window)', async t => {
  const run = await onFreePorts(1, async sinkPort => {
    const profile = profileOf(await proxyApp(t, sinkPort, 'honest'), sinkPort, { aliases: [SIBLING] });
    return runHttpAssessment({ ...profile, requiredControlIds: ['WHOAMI'], checks: profile.checks.filter(c => c.id === 'WHOAMI') }, { env: { SCOPEHAVEN_TARGET_OPS: TOKEN } });
  });
  assert.deepEqual([run.observers[0].aliases, run.results.some(r => r.trace[1])], [{ [PAY]: [SIBLING] }, false]);
  assert.doesNotThrow(() => validateHttpRunEvidence(run));
  const relabelled = structuredClone(run); relabelled.observers[0].collector.label = 'egress-recorder/10';
  refused(relabelled);
  const plain = structuredClone(relabelled); delete plain.observers[0].aliases;
  assert.doesNotThrow(() => validateHttpRunEvidence(plain), 'adjacent: the same /10 record without aliases');
  // The record's shape: an alias that is its own destination, or a list out of order, is refused.
  for (const aliases of [{ [PAY]: [PAY] }, { [PAY]: ['b.pay.example', 'a.pay.example'] }]) { const forged = structuredClone(run); forged.observers[0].aliases = aliases; refused(forged); }
});

test('end to end: a run an earlier recorder sealed keeps its text: relabelled /10 without the note it validates; with this build\'s note under /10 it is refused', async t => {
  const run = await runMode(t, 'unrelated');
  const note = / Its egress windows also recorded sends to hosts that are not declared destinations: [^]*$/;
  const earlier = structuredClone(run); earlier.observers[0].collector.label = 'egress-recorder/10';
  for (const row of earlier.results) row.assertions = row.assertions.map(a => typeof a.actual === 'string' ? { ...a, actual: a.actual.replace(note, '') } : a);
  assert.doesNotThrow(() => validateHttpRunEvidence(reseal(earlier)));
  const relabelled = structuredClone(run); relabelled.observers[0].collector.label = 'egress-recorder/10';
  refused(relabelled);
});

test('end to end: a sibling send in the run\'s tail leaves the tail partial, so settlement withholds the earlier pass; an unrelated host there does not', async t => {
  const sibling = await runMode(t, 'sibling-tail');
  const row = rowOf(sibling, 'NO-CHARGE');
  assert.equal(row.status, 'inconclusive');
  assert.equal(row.trace[1].data.windows[0].coverage, 'complete', 'its own window saw nothing');
  assert.equal(row.trace[1].data.effects[0].settlement, 'settlement-unobserved');
  assert.doesNotThrow(() => validateHttpRunEvidence(sibling));
  const unrelated = await runMode(t, 'unrelated-tail');
  assert.equal(rowOf(unrelated, 'NO-CHARGE').status, 'pass');
  assert.doesNotThrow(() => validateHttpRunEvidence(unrelated));
});
