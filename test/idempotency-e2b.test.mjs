// Rejected retries: countApplications on a forwarded host reads only a proven outcome, and a rejection only with a status in the window's own
// declared rejected list. Checked on windows built directly, so the rule holds even where the forward's outcome binding is not in the path.
import test from 'node:test';
import assert from 'node:assert/strict';
import { countApplications } from '../src/idempotency.mjs';

const HOST = 'payments.example.test', hex = c => c.repeat(64);
const send = (seq, { key = '1', content = 'c', upstream } = {}) => ({ seq, name: HOST, operation: 'send', outcome: 'committed', contentDigest: hex(content), correlation: {},
  idempotency: { status: 'keyed', key: hex(key), fold: hex(key), head: hex('a'), firstSeq: 1 }, ...(upstream ? { upstream } : {}) });
const forwarded = (events, rejected = [402]) => ({ events, scope: { forward: { [HOST]: { upstreamPort: 47100, applied: [200, 201], rejected, proof: true } } } });
const applied = { outcome: 'applied', status: 201, proven: true }, declined = { outcome: 'rejected', status: 402, proven: true };
const count = w => { const r = countApplications(w, HOST, w.events); return [r.low, r.high]; };

test('a rejection drops out only when proven and listed in the window\'s own declared rejected list', () => {
  assert.deepEqual(count(forwarded([send(1, { upstream: declined }), send(2, { content: 'd', upstream: applied })])), [1, 1]);
  assert.deepEqual(count(forwarded([send(1, { upstream: declined }), send(2, { content: 'd', upstream: applied })], [])), [1, 2], 'an empty list: the 402 may have applied');
  assert.deepEqual(count(forwarded([send(1, { upstream: { ...declined, status: 409 } }), send(2, { content: 'd', upstream: applied })])), [1, 2], 'a status outside the list');
  assert.deepEqual(count(forwarded([send(1, { upstream: { ...declined, proven: false } }), send(2, { content: 'd', upstream: applied })])), [1, 2], 'an unproven rejection');
  assert.deepEqual(count(forwarded([send(1, { upstream: { ...applied, proven: false } })])), [0, 1], 'an unproven application');
  assert.deepEqual(count(forwarded([send(1)])), [0, 1], 'no outcome on a forwarded host');
  assert.deepEqual(count({ events: [send(1, { upstream: declined })], scope: {} }), [1, 1], 'a host the window does not forward ignores the outcome');
});
