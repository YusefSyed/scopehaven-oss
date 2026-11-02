// Resource pins on egress background sources: an egress background source may pin the resource the egress recorder names a send by ("<METHOD> <declared
// path>" or "<METHOD> *"), with operation send and an exact host, and only a resource that host's declared destinations can
// produce. Classification stays inclusive: a send with no resource fits the pin, and a send the pin excludes is not background,
// so a clause about that host stays decisive for it. Pure unit tests plus profile validation (no I/O).
import test from 'node:test';
import assert from 'node:assert/strict';
import { makeEffect } from '../src/effect-events.mjs';
import { decideEffects } from '../src/http-effects.mjs';
import { attributionFindings, backgroundProblem, backgroundClassifier, backgroundUnseen } from '../src/http-attribution.mjs';
import { validateTargetFile } from '../src/contracts.mjs';

const HOST = 'hooks.example';
const OBS = { source: 'http-egress', kind: 'http-egress-recorder', instanceId: 'egress-recorder-hooks', scope: { operations: ['send'], names: [HOST], actorAttribution: 'none', evidence: 'authoritative' } };
let seq = 0;
const send = resource => makeEffect({ source: OBS.source, observer: { kind: OBS.kind, instanceId: OBS.instanceId }, seq: ++seq, operation: 'send', name: HOST, resource, outcome: 'committed' });
const win = (events = []) => ({ source: OBS.source, instanceId: OBS.instanceId, scope: OBS.scope, coverage: 'complete', reason: null, events });
const SYNC = { id: 'sync', select: { operation: 'send', name: HOST, resource: 'POST /sync/' } };
const HOST_WIDE = { id: 'sync', select: { operation: 'send', name: HOST } };
const NONE_HOST = { kind: 'effect.none', select: { source: 'http-egress', operation: 'send', name: HOST } };
const FILLER = { kind: 'effect.none', select: { source: 'http-egress', operation: 'send', name: HOST, resource: 'POST /other' } };
// A two-check run whose first row's own window holds the given sends.
const run = sends => ({ rows: [{ effects: decideEffects([NONE_HOST], [win(sends)], { role: 'boundary' }), windows: [win(sends)] }, { effects: decideEffects([FILLER], [win()], { role: 'boundary' }), windows: [win()] }], gaps: [[win()], [win()], [win()]] });
const finding = (r, background) => attributionFindings(r.rows, r.gaps, undefined, { background })[0][0];

test('resource pin declaration: a resource pin needs operation send, an exact host and an exact egress resource', () => {
  for (const resource of ['POST /sync/', 'POST *', 'DELETE /v1/charges']) assert.equal(backgroundProblem([{ id: 's', select: { operation: 'send', name: HOST, resource } }]), null, resource);
  const refused = select => assert.match(backgroundProblem([{ id: 's', select }]) ?? '', /resource" pin needs operation "send", an exact host/, JSON.stringify(select));
  refused({ name: HOST, resource: 'POST /sync/' });
  refused({ operation: 'update', name: 'orders', resource: 'POST /sync/' });
  refused({ operation: 'send', name: { prefix: 'hooks.' }, resource: 'POST /sync/' });
  for (const resource of [{ prefix: 'POST /' }, 'post /sync/', 'CONNECT :443', 'POST sync', 'POST  /sync', 'POST /sync /x', 'POST'])
    refused({ operation: 'send', name: HOST, resource });
  // The other refused pins are unchanged.
  for (const key of ['source', 'outcome', 'traceId']) assert.match(backgroundProblem([{ id: 's', select: { operation: 'send', name: HOST, [key]: 'x' } }]) ?? '', /"select" pins only/, key);
});

test('resource pin profile: the pinned resource must be one the host\'s egress-recorder destinations produce', () => {
  const profile = (resource, destinations = [{ host: HOST, paths: ['/sync/', '/notify'] }]) => ({ id: 't', name: 'T', applicationId: 'a', origin: 'http://127.0.0.1:4000', buildLabel: 'b', contextId: 'c',
    actors: { u: { principalId: 'u' } }, requiredControlIds: ['C'],
    observers: [{ id: 'hooks', type: 'egress-recorder', port: 40998, routing: 'proxy', destinations, witness: { actorId: 'u', method: 'GET', path: '/ping', host: 'witness.scopehaven.invalid' }, settleMs: 250, quietMs: 150 }],
    attribution: { background: [{ id: 'sync', select: { operation: 'send', name: HOST, resource } }] },
    checks: [{ id: 'C', title: 'c', category: 'x', severity: 'control', actorId: 'u', method: 'POST', path: '/notify', body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }],
      effects: [{ kind: 'effect.exists', select: { source: 'http-egress', operation: 'send', name: HOST, resource: 'POST /notify' } }] }] });
  const valid = (...args) => validateTargetFile({ schemaVersion: 1, targets: [profile(...args)] });
  for (const resource of ['POST /sync/', 'PUT /notify', 'POST *']) assert.doesNotThrow(() => valid(resource), resource);
  assert.throws(() => valid('POST /other'), /attribution-resource-unproducible/);
  assert.throws(() => valid('POST /sync/', [{ host: HOST }]), /attribution-resource-unproducible/, 'a destination without paths names every send "<METHOD> *"');
  assert.doesNotThrow(() => valid('POST *', [{ host: HOST }]));
  assert.throws(() => valid('POST /sync/', [{ host: 'other.example', paths: ['/sync/'] }]), /attribution-resource-unproducible/, 'no destination for the host');
});

test('resource pin classification stays inclusive: a pinned source takes its resource and sends with none; other resources stay decisive', () => {
  const isBackground = backgroundClassifier([SYNC]);
  assert.equal(isBackground(send('POST /sync/')), true);
  assert.equal(isBackground(send('POST /notify')), false);
  assert.equal(isBackground(send(null)), true, 'a send with no resource fits any resource pin');
  assert.deepEqual(backgroundUnseen([SYNC], [OBS]), [], 'the pin does not hide the source from the observer that records the host');
  // A host-wide absence: a forbidden send the pin excludes keeps the fail standing; a host-wide source would make it unattributed.
  const forbidden = run([send('POST /notify')]);
  assert.equal(forbidden.rows[0].effects[0].verdict, 'fail');
  assert.equal(finding(forbidden, [SYNC]), null, 'the narrowed source leaves the clause decisive');
  assert.equal(finding(forbidden, [HOST_WIDE]), 'background-unattributed', 'a host-wide source cannot let it fail');
  // The source's own resource, or a send with none, is background as before.
  assert.equal(finding(run([send('POST /sync/')]), [SYNC]), 'background-unattributed');
  assert.equal(finding(run([send(null)]), [SYNC]), 'background-unattributed');
});

// A send whose path the recorder flagged as ambiguous may be another declared path, so it fits
// every resource pin. Otherwise a pin could classify it "not background" on an uncertain resource and let a pass it decided stand.
test('resource pins: a send in a window that flags its path as ambiguous fits every resource pin (v1 reason and v2 scoped entry)', () => {
  const PIN_B = [{ id: 'worker', select: { operation: 'send', name: HOST, resource: 'POST /v1/b' } }];
  const EXISTS_A = { kind: 'effect.exists', select: { source: 'http-egress', operation: 'send', name: HOST, resource: 'POST /v1/a' } };
  const findingFor = own => {
    const rows = [{ effects: decideEffects([EXISTS_A], [own], { role: 'boundary' }), windows: [own] }, { effects: decideEffects([FILLER], [win()], { role: 'boundary' }), windows: [win()] }];
    assert.equal(rows[0].effects[0].verdict, 'pass');
    return attributionFindings(rows, [[win()], [win()], [win()]], undefined, { background: PIN_B })[0][0];
  };
  // A certain resource: the pin excludes the send, so the pass rests on a non-background send and stands.
  assert.equal(findingFor(win([send('POST /v1/a')])), null);
  // v1: the window names the ambiguity but not the send; every send in it may be POST /v1/b.
  assert.equal(findingFor({ ...win([send('POST /v1/a')]), coverage: 'partial', reason: 'egress-path-ambiguous' }), 'background-unattributed');
  // v2: a scoped entry for the host with no resource.
  const scoped = { ...win([send('POST /v1/a')]), coverage: 'partial', reason: 'egress-path-ambiguous', scoped: [{ name: HOST, resource: null, codes: ['egress-path-ambiguous'] }] };
  assert.equal(findingFor(scoped), 'background-unattributed');
  // A scoped entry for another host leaves this host's sends certain.
  assert.equal(findingFor({ ...scoped, scoped: [{ name: 'other.example', resource: null, codes: ['egress-path-ambiguous'] }] }), null);
});
