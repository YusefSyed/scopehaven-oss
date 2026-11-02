// Size limits: an effect.only clause lists up to 128 selectors (expect plus allow), at most 32 of
// them expected, and an egress destination lists up to 128 path prefixes. Past either cap the profile is refused at load.
import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluateOnly, validateOnlyAssertion, ONLY_LIMITS } from '../integrations/collateral/only.mjs';
import { makeEffect } from '../integrations/observers/events.mjs';
import { validateEgressConfig, EGRESS_BOUNDS } from '../src/egress-rules.mjs';

const ev = (seq, over) => makeEffect({ source: 'sql-audit-table', observer: { kind: 'test', instanceId: 'audit' }, seq, actor: null, outcome: 'committed', operation: 'insert', ...over });
const win = (events, names) => ({ source: 'sql-audit-table', instanceId: 'audit', coverage: 'complete', reason: null, events, scope: { operations: ['insert', 'update', 'delete'], names, actorAttribution: 'principal', evidence: 'authoritative' } });
const sel = i => ({ name: `t${i}`, operation: 'insert' });
const only = (expected, allowed) => ({ kind: 'effect.only', expect: Array.from({ length: expected }, (_, i) => ({ select: sel(i), count: 1 })), allow: Array.from({ length: allowed }, (_, i) => sel(expected + i)) });

test('effect.only selector caps: 128 in all, 32 of them expected; refused one past either', () => {
  assert.deepEqual([ONLY_LIMITS.selectors, ONLY_LIMITS.expect], [128, 32]);
  for (const [expected, allowed] of [[0, 128], [32, 96], [4, 19], [1, 127], [32, 0]]) assert.doesNotThrow(() => validateOnlyAssertion(only(expected, allowed)), `${expected}+${allowed}`);
  for (const [expected, allowed] of [[0, 129], [32, 97], [33, 0], [33, 10]]) assert.throws(() => validateOnlyAssertion(only(expected, allowed)), error => error.code === 'selectors', `${expected}+${allowed}`);
});

test('an allowed selector past the old 20th position decides like any other; anything outside the set still fails', () => {
  const names = Array.from({ length: 128 }, (_, i) => `t${i}`);
  const spec = only(4, 100);
  const inSet = [ev(1, { name: 't0' }), ev(2, { name: 't3' }), ev(3, { name: 't1' }), ev(4, { name: 't2' }), ev(5, { name: 't99' }), ev(6, { name: 't103' })];
  assert.equal(evaluateOnly(spec, [win(inSet, names)]).verdict, 'pass');
  assert.equal(evaluateOnly(spec, [win([...inSet, ev(7, { name: 't104' })], names)]).verdict, 'fail', 'one past the declared allow list');
  assert.equal(evaluateOnly(spec, [win([...inSet, ev(7, { name: 't0' })], names)]).verdict, 'fail', 'beyond an expected count');
});

test('matching cost at the new caps: 10 windows of 5,000 events against 32 expected selectors at count 1000 and 96 allowed', () => {
  const names = Array.from({ length: 128 }, (_, i) => `t${i}`);
  const spec = { kind: 'effect.only', expect: Array.from({ length: 32 }, (_, i) => ({ select: sel(i), count: 1000 })), allow: Array.from({ length: 96 }, (_, i) => sel(32 + i)) };
  const windows = Array.from({ length: 10 }, (_, w) => win(Array.from({ length: 5000 }, (_, k) => ev(w * 5000 + k + 1, { name: `t${(w * 5000 + k) % 128}`, resource: `r/${w * 5000 + k}` })), names));
  const started = performance.now();
  const r = evaluateOnly(spec, windows);
  const ms = performance.now() - started;
  // 50,000 events over 128 names: about 390 per name, so every expected name stays within its count and the rest are allowed.
  assert.equal(r.verdict, 'pass');
  assert.equal(r.counts.expected + r.counts.allowed, 50000);
  assert.ok(ms < 10000, `${Math.round(ms)} ms`);
});

test('egress paths: up to 128 distinct literal prefixes per destination, refused at 129', () => {
  assert.equal(EGRESS_BOUNDS.paths, 128);
  const config = n => ({ port: 47001, destinations: [{ host: 'payments.example.test', paths: Array.from({ length: n }, (_, i) => `/v1/p${i}`) }] });
  assert.equal(validateEgressConfig(config(128)).destinations[0].paths.length, 128);
  assert.throws(() => validateEgressConfig(config(129)), /up to 128 distinct literal path prefixes/);
});

test('matching cost with overlapping prefix selectors (many distinct option groups) stays bounded at 32 expected', () => {
  // Half the expected selectors are nested name prefixes, half nested resource prefixes: an event matches a different subset of
  // each chain, so the flow runs over many groups. Measured about 0.7 s on the build machine, against about 0.2 s at 20.
  const expect = [];
  for (let i = 0; i < 16; i++) expect.push({ select: { name: { prefix: 'n' + 'x'.repeat(i) } }, count: 1000 });
  for (let i = 0; i < 16; i++) expect.push({ select: { name: { prefix: 'n' }, resource: { prefix: 'r' + 'y'.repeat(i) } }, count: 1000 });
  const windows = Array.from({ length: 10 }, (_, w) => win(Array.from({ length: 5000 }, (_, k) => { const n = w * 5000 + k; return ev(n + 1, { name: 'n' + 'x'.repeat(n % 16), resource: 'r' + 'y'.repeat(Math.floor(n / 16) % 16) }); }), null));
  const started = performance.now();
  const r = evaluateOnly({ kind: 'effect.only', expect, allow: [] }, windows);
  const ms = performance.now() - started;
  assert.equal(r.verdict, 'fail', '50,000 events against 32,000 slots: the rest offend');
  assert.equal(r.counts.expected, 32000);
  assert.ok(ms < 10000, `${Math.round(ms)} ms`);
});

test('more than 512 distinct combinations of overlapping expected selectors read missing, never decided; under the bound they decide', () => {
  // Three overlapping families of expected selectors (10 nested name prefixes, 11 nested resource prefixes, 11 actors): an event
  // matches a different subset for each (name, resource, actor), 10 x 11 x 11 = 1210 combinations in all.
  const expect = [
    ...Array.from({ length: 10 }, (_, i) => ({ select: { name: { prefix: 'n' + 'x'.repeat(i) } }, count: 1000 })),
    ...Array.from({ length: 11 }, (_, i) => ({ select: { name: { prefix: 'n' }, resource: { prefix: 'r' + 'y'.repeat(i) } }, count: 1000 })),
    ...Array.from({ length: 11 }, (_, i) => ({ select: { name: { prefix: 'n' }, actor: `a${i}` }, count: 1000 })),
  ];
  const events = (actors) => { const out = []; let seq = 0; for (let i = 0; i < 10; i++) for (let j = 0; j < 11; j++) for (let a = 0; a < actors; a++) out.push(ev(++seq, { name: 'n' + 'x'.repeat(i), resource: 'r' + 'y'.repeat(j), actor: `a${a}` })); return out; };
  const names = Array.from({ length: 10 }, (_, i) => 'n' + 'x'.repeat(i));
  const over = evaluateOnly({ kind: 'effect.only', expect, allow: [] }, [win(events(11), names)]);
  assert.equal(over.verdict, 'missing');
  assert.match(over.basis, /more than 512 distinct combinations/);
  // 10 x 11 x 4 = 440 combinations: allocated and decided.
  assert.equal(evaluateOnly({ kind: 'effect.only', expect, allow: [] }, [win(events(4), names)]).verdict, 'pass');
});
