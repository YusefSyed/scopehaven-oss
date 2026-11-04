import test from 'node:test';
import assert from 'node:assert/strict';
import { assessSummary } from '../src/assess-summary.mjs';

const failed = (id, actual) => ({ id, title: `${id} title`, status: 'fail', assertions: [{ status: 'pass', actual: 'fine' }, { status: 'fail', actual }] });
const run = (evidenceOrigin, results, counts) => ({ id: 'run-1', targetId: 'demo', evidenceOrigin, results, counts, checksTotal: results.length });

test('lists each check that did not pass and each distinct observed value once, for the synthetic fixture', () => {
  const text = assessSummary(run('synthetic-local-http', [failed('A-1', 'same'), failed('A-2', 'same'), failed('A-3', 'other'), { id: 'OK-1', title: 'allowed', status: 'pass' }],
    { pass: 1, fail: 3, inconclusive: 0, error: 0 }), { directory: '/data/', defaultData: '/data/' });
  assert.match(text, /^\n1 of 4 checks passed on demo: 3 failed, 0 inconclusive, 0 error\.$/m);
  for (const id of ['A-1', 'A-2', 'A-3']) assert.match(text, new RegExp(`^  FAIL ${id} ${id} title$`, 'm'));
  assert.equal(text.match(/^ {7}same$/gm).length, 1);
  assert.match(text, /^ {7}other$/m);
  assert.doesNotMatch(text, /OK-1/);
  assert.match(text, /\.\/scopehaven start/);
});

test('never prints observed values from a target that is not the synthetic fixture', () => {
  const text = assessSummary(run('http', [failed('A-1', 'customer@example.test')], { pass: 0, fail: 1 }), { directory: '/out', defaultData: '/data/' });
  assert.match(text, /FAIL A-1/);
  assert.doesNotMatch(text, /customer@example\.test/);
});

test('strips control characters that a target could use to rewrite the terminal, and caps the length', () => {
  const text = assessSummary(run('synthetic-local-http', [failed('A\u001b[2J-1', `x\u001b]0;owned\u0007\n${'y'.repeat(400)}`)], { pass: 0, fail: 1 }), { directory: '/data/', defaultData: '/data/' });
  assert.doesNotMatch(text, /[\u0000-\u0009\u000b-\u001f\u007f-\u009f]/);
  assert.ok(text.split('\n').every(line => line.length < 200));
});

test('a run outside the default data directory names an export command that quotes the folder', () => {
  const text = assessSummary(run('http', [failed('A-1', 'v')], { pass: 0, fail: 1 }), { directory: "/my evidence/it's", defaultData: '/data/' });
  assert.match(text, /export --run run-1 --format html --out \/absolute\/new\/report\.html --data '\/my evidence\/it'\\''s'/);
});

test('a clean run says so and points nowhere', () => {
  const text = assessSummary(run('synthetic-local-http', [{ id: 'OK-1', title: 't', status: 'pass' }], { pass: 1 }), { directory: '/data/', defaultData: '/data/' });
  assert.equal(text, '\n1 of 1 checks passed on demo: 0 failed, 0 inconclusive, 0 error.\n');
});
