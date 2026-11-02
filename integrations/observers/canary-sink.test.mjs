// Outbound canary sink (integrations/observers/canary-sink.mjs): seeded canaries from SCOPEHAVEN_TARGET_ variables, found in
// what the app sent out (here: synthetic texts, and real lookups to the loopback DNS stub),
// judged per destination. Every value is synthetic; nothing leaves loopback.
import test from 'node:test';
import assert from 'node:assert/strict';
import { Resolver } from 'node:dns/promises';
import { createCanaryScanner, validateSinkCanaries, judgeCanaries, destinationAllowed, decodedForms, decodeAll, fromDnsWindow, sharedMatch, CANARY_VIAS, CANARY_SINK_RECORD, CANARY_SINK_FILES, CANARY_SINK_LIMITS, CANARY_SINK_REASONS } from './canary-sink.mjs';
import { collectorDigest } from '../../src/collector-identity.mjs';
import { matchValue, foldForMatch, skeletonFold, SKELETON_KIND, drawCanaryValue, canaryVerdict, CANARY_REASONS, CANARY_ENCODINGS } from '../../src/canary.mjs';
import { gzipSync } from 'node:zlib';
import { createHash } from 'node:crypto';
import { createDnsStub } from './dns-stub.mjs';
import { encodeQuery } from './dns-wire.mjs';
import { onFreePorts } from './fixtures/free-port.mjs';
import { createSocket } from 'node:dgram';

// Marker-shaped and random, as a planted canary must be (src/canary.mjs CANARY_VALUE_RULE: printable ASCII, at least 16
// characters, 10 distinct once case is folded, no run of 4). The pinned cases below depend on these two, so each goes through
// drawCanaryValue with one attempt: the file stops at load if either breaks the rule. The tests at the end draw theirs.
const A = drawCanaryValue(() => 'cnry7Kq2ZpW9a41x', { attempts: 1 }), B = drawCanaryValue(() => 'tnB-58vQ-r2Lm-0kdz', { attempts: 1 });
const env = { SCOPEHAVEN_TARGET_CANARY_A: A, SCOPEHAVEN_TARGET_CANARY_B: B, SCOPEHAVEN_TARGET_CANARY_WORD: 'password', SCOPEHAVEN_TARGET_UNUSED: 'x' };
const declared = [
  { id: 'tenant-a', valueEnv: 'SCOPEHAVEN_TARGET_CANARY_A', owner: { tenant: 'acme' }, allow: ['api.pay.example', '*.crm.example'] },
  { id: 'tenant-b', valueEnv: 'SCOPEHAVEN_TARGET_CANARY_B', owner: { tenant: 'globex' } },
];
const scanner = (list = declared) => createCanaryScanner({ canaries: list, env });
const hitsIn = (text, s = scanner()) => s.scan({ where: 'http-body', text }).hits;
const SCANNED = ['tenant-a', 'tenant-b', 'word', 'unset'];
const win = (units, extra = {}) => ({ collector: 'egress-recorder', coverage: 'complete', authoritative: true, drained: true, scannedCanaries: SCANNED, units, ...extra });
const unit = (destination, ...canaries) => ({ destination, canaries, scanned: true });

test('canary-sink declarations: the shared { id, valueEnv } plus owner and allow; a value never sits in a profile', () => {
  const [a, b] = validateSinkCanaries(declared);
  assert.deepEqual([a.owner, a.allow, b.owner, b.allow], [{ kind: 'tenant', name: 'acme' }, ['api.pay.example', '*.crm.example'], { kind: 'tenant', name: 'globex' }, []]);
  const refused = [
    [{ id: 'x', valueEnv: 'SCOPEHAVEN_TARGET_X', value: A }, 'unknown-key'], [{ id: 'x', valueEnv: 'HOME' }, 'value-env'],
    [{ id: 'x', valueEnv: 'SCOPEHAVEN_TARGET_X', owner: { team: 'a' } }, 'owner'], [{ id: 'x', valueEnv: 'SCOPEHAVEN_TARGET_X', owner: { tenant: 'a', role: 'b' } }, 'owner'],
    [{ id: 'x', valueEnv: 'SCOPEHAVEN_TARGET_X', allow: ['API.pay.example'] }, 'allow'], [{ id: 'x', valueEnv: 'SCOPEHAVEN_TARGET_X', allow: ['*'] }, 'allow'],
    [{ id: 'x', valueEnv: 'SCOPEHAVEN_TARGET_X', allow: ['https://api.pay.example'] }, 'allow'], [{ id: 'x', valueEnv: 'SCOPEHAVEN_TARGET_X', allow: ['a.example', 'a.example'] }, 'allow'],
    // The owner's name must be a string: an array or a number that prints like a name is refused.
    [{ id: 'x', valueEnv: 'SCOPEHAVEN_TARGET_X', owner: { tenant: ['acme'] } }, 'owner'], [{ id: 'x', valueEnv: 'SCOPEHAVEN_TARGET_X', owner: { role: 42 } }, 'owner'],
  ];
  // Failure messages name the case by position, never the declaration (one carries a value).
  for (const [i, [c, code]] of refused.entries()) assert.throws(() => validateSinkCanaries([c]), e => e.code === code, `refused case ${i + 1}`);
  assert.throws(() => validateSinkCanaries([declared[0], { ...declared[1], valueEnv: declared[0].valueEnv }]), e => e.code === 'duplicate-value-env');
});

test('canary-sink destinations: exact names, or "*.suffix" for names under it (never the suffix itself); unknown is never allowed', () => {
  const allow = ['api.pay.example', '*.crm.example'];
  assert.deepEqual(['api.pay.example', 'eu.crm.example', 'a.b.crm.example', 'crm.example', 'api.pay.example.evil', 'xapi.pay.example', null, ''].map(d => destinationAllowed(d, allow)), [true, true, true, false, false, false, false, false]);
  // A unit that went to a name strictly under the destination (exact: false) is allowed only by a wildcard naming the destination
  // or an ancestor of it, never by an exact entry.
  assert.deepEqual(['api.pay.example', 'crm.example', 'eu.crm.example', 'pay.example', 'evilcrm.example', null].map(d => destinationAllowed(d, allow, { exact: false })), [false, true, true, false, false, false]);
});

test('canary-sink judgement: a unit under a declared name (exact: false) passes only under a wildcard, and reads unknown when an entry lies under it (twins)', () => {
  const s = scanner(), hit = { canary: 'tenant-a', channel: 'verbatim' };
  const judged = (destination, exact) => judgeCanaries({ scanner: s, windows: [win([{ ...unit(destination, hit), exact }])], required: ['egress-recorder'] }).canaries[0];
  const read = (destination, exact) => { const c = judged(destination, exact); return [c.outcome, c.reason ?? null, c.findings.map(f => f.subdomain ?? false)]; };
  assert.deepEqual(read('api.pay.example', true), ['pass', null, []], 'the exact allowed name itself');
  assert.deepEqual(read('api.pay.example', undefined), ['pass', null, []], 'a unit that does not say exact: false names the very name');
  assert.deepEqual(read('api.pay.example', false), ['fail', null, [true]], 'a name under an exact entry is not that entry');
  assert.deepEqual(read('crm.example', false), ['pass', null, []], 'a name under crm.example is under *.crm.example');
  assert.deepEqual(read('crm.example', true), ['fail', null, [false]], 'the suffix itself is not under its wildcard');
  assert.deepEqual(read('eu.crm.example', false), ['pass', null, []], 'a wildcard naming an ancestor');
  assert.deepEqual(read('pay.example', false), ['inconclusive', 'destination-unknown', [true]], 'api.pay.example lies under pay.example: the name may be it');
  assert.deepEqual(read('example', false), ['inconclusive', 'destination-unknown', [true]], 'both entries lie under example');
  assert.deepEqual(read('other.example', false), ['fail', null, [true]], 'nothing allowed lies under other.example');
  assert.deepEqual(judged('api.pay.example', false).findings, [{ canary: 'tenant-a', owner: { kind: 'tenant', name: 'acme' }, collector: 'egress-recorder', destination: 'api.pay.example', subdomain: true, channel: 'verbatim' }]);
  // fromDnsWindow carries each lookup's exact flag; a lookup that does not say exact: true reads as under its declared name.
  const units = fromDnsWindow({ coverage: 'complete', lookups: [{ name: 'api.pay.example', exact: true, scanned: true }, { name: 'api.pay.example', exact: false, scanned: true }, { name: 'api.pay.example', scanned: true }, { name: '*', exact: false, scanned: true }] }, null).units;
  assert.deepEqual(units.map(u => [u.destination, u.exact]), [['api.pay.example', true], ['api.pay.example', false], ['api.pay.example', false], [null, false]]);
});

test('canary-sink scanner: the shared channels on the unit\'s own text, and decoded forms named by via', () => {
  const s = scanner();
  const b64 = s2 => Buffer.from(s2).toString('base64'), b32 = s2 => { const a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits = '', out = ''; for (const byte of Buffer.from(s2)) bits += byte.toString(2).padStart(8, '0'); for (let i = 0; i < bits.length; i += 5) out += a[parseInt(bits.slice(i, i + 5).padEnd(5, '0'), 2)]; return out; };
  const cases = [
    ['verbatim', `{"note":"${A}"}`, { channel: 'verbatim' }],
    ['case-folded', `{"note":"${A.toUpperCase()}"}`, { channel: 'folded' }],
    ['entities', `<p>${[...A].map(c => `&#${c.charCodeAt(0)};`).join('')}</p>`, { channel: 'folded' }],
    ['skeleton (spaced out)', `id: ${[...A].join(' ')} end`, { channel: 'skeleton' }],
    ['percent', `q=${[...A].map(c => `%${c.charCodeAt(0).toString(16)}`).join('')}`, { channel: 'verbatim', via: 'percent' }],
    ['hex', `data=ff${Buffer.from(`x:${A}`).toString('hex')}`, { channel: 'verbatim', via: 'hex' }],
    ['base64', `blob=${b64(`${A}!`)}`, { channel: 'verbatim', via: 'base64' }],
    ['base64url', `t=${b64(`zz${A}`).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')}`, { channel: 'verbatim', via: 'base64' }],
    ['base32', `k=${b32(`q${A}`)}`, { channel: 'verbatim', via: 'base32' }],
    ['quoted-printable', `Content-Transfer-Encoding: quoted-printable\r\n\r\nref ${A.slice(0, 6)}=\r\n${[...A.slice(6)].map(c => `=${c.charCodeAt(0).toString(16).toUpperCase()}`).join('')} end`, { channel: 'verbatim', via: 'quoted-printable' }],
    // The reference starts at byte 33 (encoded characters 44 to 66): a wrap at 52 splits it across two lines.
    ['MIME base64 wrapped mid-value', (() => { const enc = b64(`Dear customer, your reference is ${A}. Thanks.`); return `Content-Transfer-Encoding: base64\r\n\r\n${enc.slice(0, 52)}\r\n${enc.slice(52)}\r\n`; })(), { channel: 'verbatim', via: 'base64' }],
    ['unicode escapes', `{"n":"${[...A].map(c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`).join('')}"}`, { channel: 'verbatim', via: 'unicode-escape' }],
  ];
  for (const [label, text, expect] of cases) assert.deepEqual(hitsIn(text, s), [{ canary: 'tenant-a', ...expect }], label);
  for (const n of [0, 1, 2, 3]) assert.deepEqual(hitsIn(`x${'y'.repeat(n)}${b64(`${'q'.repeat(n)}${B}`)}`, s).map(h => h.canary), ['tenant-b'], `base64 misaligned by ${n}`);
  assert.deepEqual(hitsIn(`${A} and ${B}`, s).map(h => h.canary), ['tenant-a', 'tenant-b']);
  assert.deepEqual(hitsIn(`{"note":"${A.slice(0, -1)}"}`, s), [], 'a prefix of a canary is not the canary');
  assert.deepEqual(hitsIn('An ordinary reply about refunds, invoices and account 7K-Q2.', s), []);
  assert.deepEqual(CANARY_VIAS, ['labels', 'percent', 'quoted-printable', 'unicode-escape', 'tags', 'selectors', 'zero-width', 'whitespace-bits', 'hex', 'base32', 'base64', 'rot13', 'reversed']);
});

test('canary-sink scanner over a DNS name: labels as sent, joined across labels, and decoded per label', () => {
  const s = scanner();
  const view = labels => s.scan({ where: 'dns-qname', labels, name: labels.join('.').toLowerCase() }).hits;
  assert.deepEqual(view([A, 'drop', 'example']), [{ canary: 'tenant-a', channel: 'verbatim' }]);
  assert.deepEqual(view([A.slice(0, 7), A.slice(7), 'drop', 'example']), [{ canary: 'tenant-a', channel: 'verbatim', via: 'labels' }], 'split across labels');
  assert.deepEqual(view([Buffer.from(B).toString('hex'), 'x', 'example']), [{ canary: 'tenant-b', channel: 'verbatim', via: 'hex' }]);
  const hex = Buffer.from(`id=${B};`).toString('hex');
  assert.deepEqual(view([hex.slice(0, 20), hex.slice(20), 'example']), [{ canary: 'tenant-b', channel: 'verbatim', via: 'hex' }], 'hex split across labels, read joined');
  assert.deepEqual(view(['www', 'example']), []);
  // Base64url of base64url, split over two labels with its case as sent: only the labels joined hold the whole run, and only the
  // shared layers read two deep.
  const twice = Buffer.from(Buffer.from(`id ${B};`).toString('base64url')).toString('base64url');
  assert.deepEqual(view([twice.slice(0, 30), twice.slice(30), 'example']), [{ canary: 'tenant-b', channel: 'encoded', via: 'base64', layers: ['base64', 'base64'] }], 'two layers split across labels');
});

test('canary-sink scanner: a value that cannot be judged is never matched, and is listed with the shared reason', () => {
  const s = scanner([...declared, { id: 'word', valueEnv: 'SCOPEHAVEN_TARGET_CANARY_WORD' }, { id: 'unset', valueEnv: 'SCOPEHAVEN_TARGET_CANARY_UNSET' }]);
  assert.deepEqual(s.unavailable, [{ canary: 'word', reason: 'value-not-marker-shaped' }, { canary: 'unset', reason: 'value-unavailable' }]);
  assert.deepEqual(hitsIn('your password was reset', s), []);
  const r = judgeCanaries({ scanner: s, windows: [win([])], required: ['egress-recorder'] });
  assert.deepEqual(r.canaries.map(c => [c.canary, c.outcome, c.reason ?? null]), [['tenant-a', 'pass', null], ['tenant-b', 'pass', null], ['word', 'inconclusive', 'value-not-marker-shaped'], ['unset', 'inconclusive', 'value-unavailable']]);
  assert.equal(r.outcome, 'inconclusive');
});

test('canary-sink judgement: a canary to an allowed destination passes; the same canary anywhere else fails (twins)', () => {
  const s = scanner(), hit = { canary: 'tenant-a', channel: 'verbatim' };
  const allowed = judgeCanaries({ scanner: s, windows: [win([unit('api.pay.example', hit), unit('eu.crm.example', { ...hit, via: 'base64' })])], required: ['egress-recorder'] });
  assert.deepEqual([allowed.outcome, allowed.canaries.map(c => c.outcome)], ['pass', ['pass', 'pass']]);
  const leaked = judgeCanaries({ scanner: s, windows: [win([unit('api.pay.example', hit), unit('hooks.partner.example', { ...hit, via: 'hex' })])], required: ['egress-recorder'] });
  assert.equal(leaked.outcome, 'fail');
  assert.deepEqual(leaked.canaries[0].findings, [{ canary: 'tenant-a', owner: { kind: 'tenant', name: 'acme' }, collector: 'egress-recorder', destination: 'hooks.partner.example', channel: 'verbatim', via: 'hex' }]);
  assert.ok(!JSON.stringify(leaked).includes(A), 'a finding never carries the value');
  // tenant-b may go nowhere: even an allowed destination of tenant-a fails it.
  assert.equal(judgeCanaries({ scanner: s, windows: [win([unit('api.pay.example', { canary: 'tenant-b', channel: 'folded' })])], required: ['egress-recorder'] }).canaries[1].outcome, 'fail');
});

test('canary-sink judgement: an unknown destination fails a canary that may go nowhere, and is inconclusive for one with an allow list', () => {
  const s = scanner();
  const r = judgeCanaries({ scanner: s, windows: [win([unit(null, { canary: 'tenant-a', channel: 'verbatim' }, { canary: 'tenant-b', channel: 'verbatim' })])], required: ['egress-recorder'] });
  assert.deepEqual(r.canaries.map(c => [c.outcome, c.reason ?? null, c.findings.map(f => f.destination)]), [['inconclusive', 'destination-unknown', ['*']], ['fail', null, ['*']]]);
  // A destination that is not a host name is unknown, never under a wildcard.
  for (const odd of ['.crm.example', 'a..crm.example', 'evil.example/.crm.example', 'EU.crm.example', 'eu.crm.example.']) {
    const j = judgeCanaries({ scanner: s, windows: [win([unit(odd, { canary: 'tenant-a', channel: 'verbatim' })])], required: ['egress-recorder'] });
    assert.deepEqual([j.canaries[0].outcome, j.canaries[0].reason, j.canaries[0].findings[0].destination], ['inconclusive', 'destination-unknown', '*'], odd);
  }
});

test('canary-sink scanner: a view it could not read in full says so (complete: false, a named reason), with or without hits', () => {
  const s = scanner();
  // Each decoding has its own budget inside the total, counted in characters of distinct forms: 8,400 lines of opaque base64 (read
  // line by line and again unwrapped, each at four alignments: more than base64's share) are held to that share, and a hex canary
  // after them, read later, is still found, with the view marked scan-capped (the sink's reasons come after any shared one).
  const flood = Array.from({ length: 8400 }, (_, i) => seededBytes(`flood-${i}`, 57).toString('base64')).join('\n');
  const text = `${flood}\n${Buffer.from(`id=${A};`).toString('hex')}`;
  const used = decodeAll(text), chars = via => used.forms.filter(f => f.via === via).reduce((n, f) => n + f.text.length, 0);
  assert.ok(used.capped && chars('base64') <= CANARY_SINK_LIMITS.perDecodingChars && chars('base64') > 2 * 1024 * 1024, 'base64 is held to its share');
  assert.ok(used.forms.some(f => f.via === 'hex' && f.text.includes(A)), 'the hex run read after the flood still has its form');
  const starved = s.scan({ where: 'http-body', text });
  assert.deepEqual([starved.hits, starved.complete, starved.reasons.at(-1)], [[{ canary: 'tenant-a', channel: 'verbatim', via: 'hex' }], false, 'scan-capped']);
  assert.equal(judgeCanaries({ scanner: s, windows: [win([{ ...unit('api.pay.example'), scanned: false, reason: 'scan-capped' }])], required: ['egress-recorder'] }).canaries[0].reason, 'scan-capped:egress-recorder');
  // A view over the bound, with the canary after it, reports no hit and complete: false.
  const long = s.scan({ where: 'http-body', text: `${'x'.repeat(CANARY_SINK_LIMITS.viewChars)} ${A}` });
  assert.deepEqual([long.hits, long.complete, long.reasons.includes('scan-too-large')], [[], false, true]);
  // Over the bound with nothing else left unread (short words: no run to decode, nothing the shared module cannot examine): the
  // bound alone marks it, by name, and the verdict names it.
  const bounded = s.scan({ where: 'http-body', text: `${'the cat sat. '.repeat(Math.ceil(CANARY_SINK_LIMITS.viewChars / 13))} ${A}` });
  assert.deepEqual([bounded.hits, bounded.complete, bounded.reasons], [[], false, ['scan-too-large']]);
  assert.equal(judgeCanaries({ scanner: s, windows: [win([{ ...unit('api.pay.example'), scanned: false, reason: bounded.reasons[0] }])], required: ['egress-recorder'] }).canaries[0].reason, 'scan-too-large:egress-recorder');
  assert.deepEqual(s.scan({ where: 'http-body', text: `short ${A}` }).complete, true);
});

// A per-decoding budget of 48 forms was used up by ordinary words and ids, so a 1 KiB webhook body never
// read as fully scanned. Budgets now count characters, and a repeated word or id is read once.
test('canary-sink scanner: ordinary webhook bodies read as fully scanned, and the same body with a canary in it fails (twins)', () => {
  const s = scanner();
  const id = (seed, n) => createHash('sha256').update(seed).digest('hex').slice(0, n);
  const uuid = seed => { const h = id(seed, 32); return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-a${h.slice(17, 20)}-${h.slice(20)}`; };
  const events = (n, extra = {}) => JSON.stringify({ object: 'list', data: Array.from({ length: n }, (_, i) => ({ id: `evt_${uuid(`e${i}`)}`, type: i % 2 ? 'invoice.payment_succeeded' : 'customer.subscription.updated',
    created: 1760000000 + i, description: `Monthly subscription renewal for workspace number ${i}, processed automatically`, customer: `cus_${id(`c${i}`, 14)}`, amount: 1200 + i, ...(i === n - 1 ? extra : {}) })) });
  for (const n of [5, 10, 20, 40]) {
    const clean = s.scan({ where: 'http-body', text: events(n) });
    assert.deepEqual([clean.hits, clean.complete, clean.reasons], [[], true, []], `${n} events`);
    const leaked = s.scan({ where: 'http-body', text: events(n, { metadata: { ref: Buffer.from(`ref ${A}`).toString('base64') } }) });
    assert.deepEqual([leaked.hits, leaked.complete], [[{ canary: 'tenant-a', channel: 'verbatim', via: 'base64' }], true], `${n} events with a canary`);
    const j = d => judgeCanaries({ scanner: s, windows: [win([{ destination: 'hooks.partner.example', canaries: d.hits, scanned: d.complete }])], required: ['egress-recorder'] }).canaries[0].outcome;
    assert.deepEqual([j(clean), j(leaked)], ['pass', 'fail'], `${n} events judged`);
  }
  assert.ok(events(5).length >= 1000 && events(40).length >= 7900);
  // A form the same decoding already gave is kept once.
  const forms = decodedForms(Array.from({ length: 200 }, () => 'description customer_id subscription').join(' '));
  assert.equal(new Set(forms.map(f => `${f.via}\n${f.text}`)).size, forms.length, 'no form twice');
});

test('canary-sink judgement: missing evidence never passes (no window, partial, failed, not drained, not authoritative); a hit in a partial window still fails', () => {
  const s = scanner();
  const gaps = [
    [[], 'collector-missing:egress-recorder'],
    [[win([], { coverage: 'partial' })], 'window-partial:egress-recorder'],
    [[win([], { coverage: 'failed' })], 'window-failed:egress-recorder'],
    [[win([], { drained: false })], 'not-drained:egress-recorder'],
    [[win([], { authoritative: false })], 'not-authoritative:egress-recorder'],
    [[win([]), win([], { coverage: 'partial' })], 'window-partial:egress-recorder'],
    [[win([unit('api.pay.example'), { ...unit('api.pay.example'), scanned: false }])], 'scan-incomplete:egress-recorder'],
  ];
  for (const [windows, reason] of gaps) {
    const r = judgeCanaries({ scanner: s, windows, required: ['egress-recorder'] });
    assert.deepEqual([r.outcome, r.canaries[0].reason], ['inconclusive', reason], reason);
  }
  // Every flag must be present and true: a window that does not say it drained, a unit that does not say it was scanned.
  const { drained, ...undrained } = win([]);
  assert.equal(judgeCanaries({ scanner: s, windows: [undrained], required: ['egress-recorder'] }).canaries[0].reason, 'not-drained:egress-recorder');
  assert.equal(judgeCanaries({ scanner: s, windows: [win([{ destination: 'api.pay.example', canaries: [] }])], required: ['egress-recorder'] }).canaries[0].reason, 'scan-incomplete:egress-recorder');
  // A window whose scanner did not hold the canary never stands for it.
  const onlyA = judgeCanaries({ scanner: s, windows: [win([], { scannedCanaries: ['tenant-a'] })], required: ['egress-recorder'] });
  assert.deepEqual(onlyA.canaries.slice(0, 2).map(c => [c.outcome, c.reason ?? null]), [['pass', null], ['inconclusive', 'not-scanned:egress-recorder']]);
  assert.equal(judgeCanaries({ scanner: s, windows: [win([], { scannedCanaries: undefined })], required: ['egress-recorder'] }).canaries[0].reason, 'not-scanned:egress-recorder');
  // Two required collectors: a complete egress window does not stand for a DNS stub that was not running.
  assert.equal(judgeCanaries({ scanner: s, windows: [win([])], required: ['egress-recorder', 'dns-stub'] }).canaries[0].reason, 'collector-missing:dns-stub');
  // A presence-only or app-written window can only fail.
  const partialLeak = judgeCanaries({ scanner: s, windows: [win([unit('hooks.partner.example', { canary: 'tenant-a', channel: 'skeleton' })], { coverage: 'partial', authoritative: false })], required: ['egress-recorder'] });
  assert.deepEqual([partialLeak.outcome, partialLeak.canaries[0].outcome], ['fail', 'fail']);
  assert.throws(() => judgeCanaries({ scanner: s, windows: [win([])], required: [] }), e => e.code === 'judge');
});

test('canary-sink with the DNS stub: a canary looked up under an undeclared name fails; under a declared name, only a wildcard allows it; no witness, no pass', async t => {
  const s = scanner();
  await onFreePorts(1, async port => {
    const stub = createDnsStub({ instanceId: 'dns-stub-canary', scanner: s, port, routing: 'resolver', names: [{ name: 'api.pay.example', subdomains: true }, { name: 'crm.example', subdomains: true }],
      witness: { actorId: 'ops', method: 'GET', path: '/ping', domain: 'witness.scopehaven.invalid' }, witnessWaitMs: 1500, quietMs: 150 });
    await stub.start(); t.after(() => stub.stop());
    const r = new Resolver({ timeout: 1000, tries: 1 }); r.setServers([`127.0.0.1:${port}`]);
    const quiet = p => p.catch(() => null);
    const window = async (between, { witness = true } = {}) => {
      const from = await stub.mark(); await between(); stub.markWitnessRequest(from);
      if (witness) await quiet(r.resolve4(`${from.witnessNonce}.witness.scopehaven.invalid`));
      return fromDnsWindow(await stub.collect(from, await stub.mark()), stub);
    };
    // tenant-a may go to api.pay.example (exact) and under crm.example (*.crm.example). The stub records a lookup under a declared
    // name that declares subdomains by that name, exact: false: under crm.example the wildcard allows it.
    const allowed = await window(() => quiet(r.resolve4(`${A}.eu.crm.example`)));
    assert.deepEqual([allowed.units.map(u => [u.destination, u.exact]), judgeCanaries({ scanner: s, windows: [allowed], required: ['dns-stub'] }).outcome], [[['crm.example', false]], 'pass']);
    // Its twin under api.pay.example: the exact entry names api.pay.example itself, not a name under it, so the lookup fails. (The
    // resolver may change the case of the name it sends, so the channel is verbatim or folded.)
    const under = await window(() => quiet(r.resolve4(`${A}.api.pay.example`)));
    const underJudged = judgeCanaries({ scanner: s, windows: [under], required: ['dns-stub'] });
    assert.deepEqual([under.units.map(u => [u.destination, u.exact]), underJudged.outcome, underJudged.canaries[0].findings.map(({ channel, ...f }) => [f, ['verbatim', 'folded'].includes(channel)])],
      [[['api.pay.example', false]], 'fail', [[{ canary: 'tenant-a', owner: { kind: 'tenant', name: 'acme' }, collector: 'dns-stub', destination: 'api.pay.example', subdomain: true }, true]]]);
    // tenant-b, hex-encoded and split over two labels of an undeclared name (sent raw, so the case is as written).
    const hex = Buffer.from(B).toString('hex');
    const leak = await window(async () => { await new Promise(resolve => { const u = createSocket('udp4'); u.on('message', () => { u.close(); resolve(); }); u.send(encodeQuery({ id: 3, labels: [hex.slice(0, 18), hex.slice(18), 'drop', 'example'] }), port, '127.0.0.1'); }); });
    const judged = judgeCanaries({ scanner: s, windows: [leak], required: ['dns-stub'] });
    assert.deepEqual([judged.outcome, judged.canaries[1].findings], ['fail', [{ canary: 'tenant-b', owner: { kind: 'tenant', name: 'globex' }, collector: 'dns-stub', destination: '*', channel: 'verbatim', via: 'hex' }]]);
    assert.ok(!JSON.stringify(leak).includes(hex.slice(0, 18)), 'the window never holds the name');
    // tenant-b as the hex of its hex, split over two labels: one decoding deep misses it, the shared module's layers find it, and
    // the stub keeps the encoded channel and its outer encoding.
    const twice = Buffer.from(hex).toString('hex');
    const deep = await window(async () => { await new Promise(resolve => { const u = createSocket('udp4'); u.on('message', () => { u.close(); resolve(); }); u.send(encodeQuery({ id: 4, labels: [twice.slice(0, 36), twice.slice(36), 'drop', 'example'] }), port, '127.0.0.1'); }); });
    const deepJudged = judgeCanaries({ scanner: s, windows: [deep], required: ['dns-stub'] });
    assert.deepEqual([deepJudged.outcome, deepJudged.canaries[1].findings], ['fail', [{ canary: 'tenant-b', owner: { kind: 'tenant', name: 'globex' }, collector: 'dns-stub', destination: '*', channel: 'encoded', via: 'hex' }]]);
    const silent = await window(async () => {}, { witness: false });
    assert.deepEqual(judgeCanaries({ scanner: s, windows: [silent], required: ['dns-stub'] }).canaries[0].reason, 'window-partial:dns-stub');
  });
});

test('canary-sink with the DNS stub: a stub that scanned for tenant-a only never stands for tenant-b', async t => {
  await onFreePorts(1, async port => {
    const onlyA = scanner([declared[0]]);
    const stub = createDnsStub({ port, scanner: onlyA, names: [], routing: 'resolver', witness: { actorId: 'ops', method: 'GET', path: '/ping', domain: 'witness.scopehaven.invalid' }, witnessWaitMs: 1500, quietMs: 150 });
    await stub.start(); t.after(() => stub.stop());
    const r = new Resolver({ timeout: 1000, tries: 1 }); r.setServers([`127.0.0.1:${port}`]);
    const from = await stub.mark();
    await r.resolve4(`${B.replace(/-/g, '')}.drop.example`).catch(() => null);
    stub.markWitnessRequest(from); await r.resolve4(`${from.witnessNonce}.witness.scopehaven.invalid`).catch(() => null);
    const w = fromDnsWindow(await stub.collect(from, await stub.mark()), stub);
    const judged = judgeCanaries({ scanner: scanner(), windows: [w], required: ['dns-stub'] });
    assert.deepEqual(judged.canaries.map(c => [c.canary, c.outcome, c.reason ?? null]), [['tenant-a', 'pass', null], ['tenant-b', 'inconclusive', 'not-scanned:dns-stub']]);
  });
});

test('canary-sink: a DNS stub without a scanner, or presence-only, cannot make a canary pass', async t => {
  await onFreePorts(1, async port => {
    const bare = createDnsStub({ port, names: [] });
    await bare.start(); t.after(() => bare.stop());
    const from = await bare.mark();
    const w = fromDnsWindow(await bare.collect(from, await bare.mark()), bare);
    assert.deepEqual([w.coverage, w.authoritative], ['complete', false]);
    assert.equal(judgeCanaries({ scanner: scanner(), windows: [w], required: ['dns-stub'] }).canaries[0].reason, 'not-authoritative:dns-stub');
  });
  // Routed and witnessed, but nothing scanned its names: complete, never authoritative for a canary.
  await onFreePorts(1, async port => {
    const unscanned = createDnsStub({ port, names: [], routing: 'resolver', witness: { actorId: 'ops', method: 'GET', path: '/ping', domain: 'witness.scopehaven.invalid' }, witnessWaitMs: 1500, quietMs: 150 });
    await unscanned.start(); t.after(() => unscanned.stop());
    const r = new Resolver({ timeout: 1000, tries: 1 }); r.setServers([`127.0.0.1:${port}`]);
    const from = await unscanned.mark(); unscanned.markWitnessRequest(from);
    await r.resolve4(`${from.witnessNonce}.witness.scopehaven.invalid`).catch(() => null);
    const w = fromDnsWindow(await unscanned.collect(from, await unscanned.mark()), unscanned);
    assert.deepEqual([w.coverage, unscanned.scope.evidence, w.authoritative], ['complete', 'authoritative', false]);
    assert.equal(judgeCanaries({ scanner: scanner(), windows: [w], required: ['dns-stub'] }).canaries[0].reason, 'not-authoritative:dns-stub');
  });
});

// The scanner folds each text once (sharedMatch); it must read exactly as the shared matcher does, channel included.
test('canary-sink sharedMatch equals the shared matchValue (hit and channel) on a corpus of encodings, near misses and prose', () => {
  const values = [A, B, 'Ab12cd34', '7KQ2-zp-W9a4'];
  const texts = [];
  for (const v of values) {
    texts.push(v, v.toUpperCase(), `%${v}`, `%4${v}`, `&amp;${v}`, `${v.slice(0, -1)}`, `x${v}y`, `${v.slice(0, 5)} ${v.slice(5)}`, `[${[...v].join('.')}]`, `${v}${v}`, encodeURIComponent(`${v}/`), v.normalize('NFKD'));
  }
  texts.push('', 'An ordinary reply about refunds and order 4471.', 'Total: $12.90 for ORDER-1290', 'refund issued', '&#x41;&#66;');
  let compared = 0;
  for (const [v, value] of values.entries()) for (let i = 0; i < texts.length; i++) {
    const group = [texts[i], texts[(i * 7 + 3) % texts.length]];
    const prepared = [[null, group.map(text => ({ text, folded: foldForMatch(text), skeleton: skeletonFold(text) }))]];
    const fast = sharedMatch(prepared, { value, folded: foldForMatch(value), skeleton: skeletonFold(value) });
    const shared = matchValue(group, value, SKELETON_KIND);
    // The message names positions only: the texts and the values are canaries.
    assert.deepEqual(fast ? fast.channel : null, shared.hit ? shared.channel : null, `text ${i} with value ${v}`);
    compared++;
  }
  assert.ok(compared > 200); // the carrier-fixture encodings are not in the open edition, so the corpus is smaller
});

test('canary-sink identity: every judgement carries canary-sink/1, a digest of this module and the shared canary module', async () => {
  assert.deepEqual(CANARY_SINK_FILES, ['integrations/observers/canary-sink.mjs', 'src/canary.mjs']);
  assert.deepEqual(CANARY_SINK_RECORD, { label: 'canary-sink/1', digest: await collectorDigest(CANARY_SINK_FILES, new URL('../../', import.meta.url)), node: process.versions.node });
  assert.equal(judgeCanaries({ scanner: scanner(), windows: [win([])], required: ['egress-recorder'] }).judge, CANARY_SINK_RECORD);
});

test('canary-sink decodings are bounded: short runs are not decoded, and forms are held to the character budgets', () => {
  assert.deepEqual(decodedForms('abc123').filter(f => ['hex', 'base32', 'base64'].includes(f.via)), []);
  // A view as long as the bound: lines of base32 letters (the heaviest decoding, read again unwrapped), after one percent, one
  // quoted-printable, one JavaScript escape and one tag character, so six decodings each give a form as long as the view. Each
  // decoding is held to its share and all of them to the total, which binds here.
  const prefix = `%41=41\\x41${String.fromCodePoint(0xe0041)}\n`;
  const heavy = decodeAll(prefix + Array.from({ length: CANARY_SINK_LIMITS.viewChars / 64 - 1 }, (_, i) => createHash('sha256').update(`l${i}`).digest('base64').replace(/[^a-z]/gi, 'q').slice(0, 63)).join('\n'));
  const per = new Map();
  for (const f of heavy.forms) per.set(f.via, (per.get(f.via) ?? 0) + f.text.length);
  assert.deepEqual(['percent', 'quoted-printable', 'unicode-escape', 'tags', 'rot13', 'reversed'].filter(via => per.has(via)).length, 6);
  assert.ok(heavy.capped && [...per.values()].every(n => n <= CANARY_SINK_LIMITS.perDecodingChars) && [...per.values()].reduce((a, b) => a + b, 0) <= CANARY_SINK_LIMITS.decodedChars);
  assert.deepEqual(CANARY_SINK_REASONS, ['scan-too-large', 'scan-capped']);
});

// The shared module's value rule: a value a person would type, or one with a character outside printable
// ASCII, is refused with the shared reason and judges inconclusive, never pass.
test('canary-sink scanner: the shared value rule refuses typed and non-ASCII values, which judge inconclusive', () => {
  const env2 = { ...env, SCOPEHAVEN_TARGET_TYPED: 'ORDER-1290', SCOPEHAVEN_TARGET_STEPS: 'abcd1234wxyz5678', SCOPEHAVEN_TARGET_CR: `${A}\r`, SCOPEHAVEN_TARGET_ACCENT: `${A.slice(0, -1)}é` };
  const s = createCanaryScanner({ env: env2, canaries: [declared[0], ...['TYPED', 'STEPS', 'CR', 'ACCENT'].map(k => ({ id: k.toLowerCase(), valueEnv: `SCOPEHAVEN_TARGET_${k}` }))] });
  assert.deepEqual(s.unavailable, [{ canary: 'typed', reason: 'value-low-entropy' }, { canary: 'steps', reason: 'value-low-entropy' }, { canary: 'cr', reason: 'value-not-marker-shaped' }, { canary: 'accent', reason: 'value-not-marker-shaped' }]);
  assert.deepEqual(hitsIn('Order ORDER-1290 shipped; ref abcd1234wxyz5678.', s), []);
  const r = judgeCanaries({ scanner: s, windows: [win([], { scannedCanaries: ['tenant-a'] })], required: ['egress-recorder'] });
  assert.deepEqual(r.canaries.map(c => [c.canary, c.outcome, c.reason ?? null]), [['tenant-a', 'pass', null], ['typed', 'inconclusive', 'value-low-entropy'], ['steps', 'inconclusive', 'value-low-entropy'], ['cr', 'inconclusive', 'value-not-marker-shaped'], ['accent', 'inconclusive', 'value-not-marker-shaped']]);
  assert.equal(r.outcome, 'inconclusive');
});

// Deterministic bytes and drawn values for the coverage tests: a seeded generator through drawCanaryValue, as the shared module's
// own tests draw (20 letters and digits, 32 hex, a UUID, 24 base64 characters).
const seededBytes = (seed, n) => { const out = []; for (let i = 0; out.length < n; i++) out.push(...createHash('sha256').update(`${seed}:${i}`).digest()); return Buffer.from(out.slice(0, n)); };
const drawn = seed => {
  let i = 0;
  const chars = (alphabet, n) => [...seededBytes(`${seed}:${i++}`, n)].map(b => alphabet[b % alphabet.length]).join('');
  const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  return [() => chars(ALNUM, 20), () => chars('0123456789abcdef', 32),
    () => { const h = chars('0123456789abcdef', 32); return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-a${h.slice(17, 20)}-${h.slice(20)}`; },
    () => chars(`${ALNUM}+/`, 24)].map(draw => drawCanaryValue(draw));
};
const b64 = text => Buffer.from(text).toString('base64');
const PROSE = 'Your order is ready and waiting at the desk, and the invoice follows by mail today. Thanks again for ordering with us.';

// The shared coverage rule: a pass needs every entry and every decoded layer examined. A part the shared module could not examine
// makes the unit not fully scanned, with the shared reason, and the judgement names it; a hit there still fails.
test('canary-sink coverage: a unit the shared module could not examine in full never passes, and its reason reaches the verdict', () => {
  const s = scanner();
  const gzipped = text => gzipSync(Buffer.from(text)).toString('latin1');
  const scanOf = text => s.scan({ where: 'http-body', text });
  const unitOf = (destination, r) => ({ destination, canaries: r.hits, scanned: r.complete, ...(r.reasons.length ? { reason: r.reasons[0] } : {}) });
  const judged = units => judgeCanaries({ scanner: s, windows: [win(units)], required: ['egress-recorder'] });
  // A compressed body and a body holding an opaque blob, neither with a canary in it: inconclusive with the shared reason, never pass.
  for (const [text, reason] of [[gzipped(PROSE), 'corpus-compressed'], [`{"img":"${seededBytes('blob', 1000).toString('base64')}"}`, 'corpus-binary-layer']]) {
    const r = scanOf(text);
    assert.deepEqual([r.hits, r.complete, r.reasons], [[], false, [reason]], reason);
    const j = judged([unitOf('api.pay.example', r)]);
    assert.deepEqual([j.outcome, j.canaries[0].outcome, j.canaries[0].reason], ['inconclusive', 'inconclusive', `${reason}:egress-recorder`], reason);
  }
  // The same compressed body holding a canary: found in the inflated layer, and it fails though the unit is not fully scanned.
  const zipped = scanOf(gzipped(`ref ${A} end`));
  assert.deepEqual([zipped.hits, zipped.complete], [[{ canary: 'tenant-a', channel: 'encoded', via: 'gzip', layers: ['gzip'] }], false]);
  assert.deepEqual(judged([unitOf('hooks.partner.example', zipped)]).canaries[0].findings, [{ canary: 'tenant-a', owner: { kind: 'tenant', name: 'acme' }, collector: 'egress-recorder', destination: 'hooks.partner.example', channel: 'encoded', via: 'gzip', layers: ['gzip'] }]);
  // Two encodings deep (base64 of base64): the sink's own readings, one decoding deep, miss it; the shared layers find it.
  const twice = scanOf(`blob=${b64(b64(`note: ${B}.`))}`);
  assert.deepEqual([twice.hits, twice.complete, twice.reasons], [[{ canary: 'tenant-b', channel: 'encoded', via: 'base64', layers: ['base64', 'base64'] }], true, []]);
  assert.equal(judged([unitOf('api.pay.example', twice)]).canaries[1].outcome, 'fail');
  // A byte list (how Node writes a Buffer in JSON): only the shared encoded channel on the unit's own text reads it.
  assert.deepEqual(scanOf(`{"data":{"type":"Buffer","data":[${[...Buffer.from(A)].join(',')}]}}`).hits, [{ canary: 'tenant-a', channel: 'encoded', via: 'byte-list' }]);
  // Three deep: the shared needles show it under the last layer, which is past the depth the shared module decodes, so the unit is
  // not fully scanned (corpus-too-deep) and the hit still fails.
  const thrice = scanOf(`blob=${b64(b64(b64(`note: ${B}.`)))}`);
  assert.deepEqual([thrice.hits, thrice.complete, thrice.reasons], [[{ canary: 'tenant-b', channel: 'encoded', via: 'base64', layers: ['base64', 'base64', 'base64'] }], false, ['corpus-too-deep']]);
  assert.deepEqual(judged([unitOf('api.pay.example', thrice)]).canaries.map(c => [c.outcome, c.reason ?? null]), [['inconclusive', 'corpus-too-deep:egress-recorder'], ['fail', null]]);
  // A unit that claims scanned: true but gives a reason is not fully scanned; a reason that is not a shared corpus reason or one of
  // the sink's own (CANARY_SINK_REASONS) is never copied into the verdict.
  for (const [i, [u, reason]] of [[{ ...unit('api.pay.example'), reason: 'corpus-too-deep' }, 'corpus-too-deep'], [{ ...unit('api.pay.example'), scanned: false, reason: `leaked ${A}` }, 'scan-incomplete'],
    [{ ...unit('api.pay.example'), scanned: false, reason: 'value-low-entropy' }, 'scan-incomplete'], [{ ...unit('api.pay.example'), reason: null }, null]].entries()) {
    const j = judged([u]);
    // The message names the case by position: one reason carries a value.
    assert.deepEqual(j.canaries[0].reason ?? null, reason === null ? null : `${reason}:egress-recorder`, `reason case ${i + 1}`);
    assert.ok(!JSON.stringify(j).includes(A));
  }
  // A layers list is copied only when every name is a shared encoding name.
  assert.deepEqual(judged([unit('hooks.partner.example', { canary: 'tenant-a', channel: 'encoded', via: 'base64', layers: ['base64', A] })]).canaries[0].findings[0].layers, undefined);
  for (const r of [zipped, twice]) assert.ok(r.reasons.every(x => CANARY_REASONS.includes(x)) && r.hits.every(h => (h.layers ?? []).every(l => CANARY_ENCODINGS.includes(l))));
});

// Bytes the sink decodes out of invisible characters (variation selectors, zero-width binary, whitespace
// bits) were only matched as text, so compressed bytes there read as a clean full scan. They now go to the shared reading too:
// compressed or binary bytes give the shared reason, and a value under a shared encoding in them is found (for example,
// base64 hidden in tag characters or zero-width binary).
const hide = {
  selectors: bytes => [...bytes].map(b => String.fromCodePoint(b < 16 ? 0xfe00 + b : 0xe0100 + b - 16)).join(''),
  'zero-width': bytes => [...bytes].map(b => b.toString(2).padStart(8, '0').replace(/0/g, '\u200b').replace(/1/g, '\u200c')).join(''),
  'whitespace-bits': bytes => [...bytes].map((b, i) => `\nline ${i}${b.toString(2).padStart(8, '0').replace(/0/g, ' ').replace(/1/g, '\t')}`).join(''),
};
test('canary-sink coverage: bytes hidden in invisible characters get the shared reading and its coverage rule (twins)', () => {
  const s = scanner();
  const scanOf = text => s.scan({ where: 'http-body', text });
  const judged = (r, destination = 'hooks.partner.example') => judgeCanaries({ scanner: s, windows: [win([{ destination, canaries: r.hits, scanned: r.complete, ...(r.reasons.length ? { reason: r.reasons[0] } : {}) }])], required: ['egress-recorder'] }).canaries[0];
  for (const [via, encode] of Object.entries(hide)) {
    // Compressed prose: nothing to find, and never a pass (it read pass before).
    const prose = scanOf(`Great job \u{1f44d}${encode(gzipSync(Buffer.from(PROSE)))}\nThanks`);
    assert.deepEqual([prose.hits, prose.complete, prose.reasons[0]], [[], false, 'corpus-compressed'], via);
    assert.deepEqual([judged(prose).outcome, judged(prose).reason], ['inconclusive', 'corpus-compressed:egress-recorder'], via);
    // Its twin holding a canary: found under the hidden bytes' gzip layer, and it fails.
    const leak = scanOf(`Great job \u{1f44d}${encode(gzipSync(Buffer.from(`ref ${A} end`)))}\nThanks`);
    assert.deepEqual([leak.hits, leak.complete], [[{ canary: 'tenant-a', channel: 'encoded', via, layers: ['gzip'] }], false], via);
    assert.deepEqual([judged(leak).outcome, judged(leak).findings[0].via, judged(leak).findings[0].layers], ['fail', via, ['gzip']], via);
    // Plain text hidden the same way is read in full: no reason, so a clean unit still passes.
    const plainText = scanOf(`Great job${encode(Buffer.from('see you at the standup on monday'))}\nThanks`);
    assert.deepEqual([plainText.hits, plainText.complete, plainText.reasons, judged(plainText).outcome], [[], true, [], 'pass'], via);
  }
  // Base64 of a canary written in tag characters or in zero-width binary: the shared encoded channel on the decoded text finds it.
  const tagged = scanOf(`ok${[...b64(`ref ${A}`)].map(ch => String.fromCodePoint(0xe0000 + ch.charCodeAt(0))).join('')}`);
  assert.deepEqual([tagged.hits, tagged.complete], [[{ canary: 'tenant-a', channel: 'encoded', via: 'tags', layers: ['base64'] }], true]);
  const zw = scanOf(`ok${hide['zero-width'](Buffer.from(b64(`ref ${A}`)))}`);
  assert.deepEqual([zw.hits, zw.complete], [[{ canary: 'tenant-a', channel: 'encoded', via: 'zero-width', layers: ['base64'] }], true]);
  // Errs safe (CANARY-SINK.md): both zero-width bit assignments are read, and the wrong one of a plain text over 512 bytes is opaque.
  const long = scanOf(`ok${hide['zero-width'](Buffer.from(PROSE.repeat(6)))}`);
  assert.deepEqual([long.hits, long.complete, long.reasons], [[], false, ['corpus-binary-layer']]);
});

// Known limits (CANARY-SINK.md, Limits): a transform outside the decodings listed there, or two of the sink's own one-deep decodings
// combined, is not found; when nothing else is left unread the unit reads as a clean full scan, so the judgement passes. Pinned so
// that a change in either direction updates the documentation.
test('canary-sink known limits: rot13 or reversal combined with an encoding is not found and reads as fully scanned', () => {
  const s = scanner();
  const rot13 = t => t.replace(/[a-z]/gi, ch => String.fromCharCode((ch <= 'Z' ? 65 : 97) + (ch.toLowerCase().charCodeAt(0) - 84) % 26));
  const reversed = t => [...t].reverse().join('');
  const hex = t => Buffer.from(t).toString('hex');
  for (const [label, text] of [['rot13 of hex', rot13(hex(B))], ['hex of the reversed value', hex(reversed(B))], ['base64 of the reversed value', b64(`ref ${reversed(A)}`)], ['rot13 of base64', rot13(b64(`ref ${A}`))], ['a reversed base64 run', reversed(b64(`ref ${A}`))]]) {
    const r = s.scan({ where: 'http-body', text: `id=${text}` });
    assert.deepEqual([r.hits, r.complete], [[], true], label);
  }
  // A DNS case: rot13 of the hex of tenant-b as one label of an undeclared name.
  assert.deepEqual(s.scan({ where: 'dns-qname', labels: [rot13(hex(B)), 'drop', 'example'], name: `${rot13(hex(B))}.drop.example` }), { hits: [], complete: true, reasons: [] });
});

// The sink is never weaker than the shared verdict on a unit: whatever canaryVerdict fails, the scanner finds; whatever it reads
// inconclusive, the scanner reports as not fully scanned (or finds). So no inconclusive is ever turned into a pass.
test('canary-sink coverage: never weaker than canaryVerdict on a unit, for drawn values over plain, encoded, compressed and opaque bodies', () => {
  let compared = 0;
  const outcomes = new Set();
  for (const [k, value] of [...drawn('e1-rebuild'), ...drawn('e1-rebuild-2')].entries()) {
    const s = createCanaryScanner({ canaries: [{ id: 'drawn', valueEnv: 'SCOPEHAVEN_TARGET_DRAWN' }], env: { SCOPEHAVEN_TARGET_DRAWN: value } });
    const other = drawn(`other-${k}`)[k % 4];
    const texts = [`id=${value}`, PROSE, `id=${other}`, b64(b64(`note: ${value}.`)), b64(b64(`note: ${other}.`)), gzipSync(Buffer.from(`ref ${value}`)).toString('latin1'),
      gzipSync(Buffer.from(PROSE)).toString('latin1'), `img=${seededBytes(`blob-${k}`, 900).toString('base64')}`, encodeURIComponent(JSON.stringify({ q: Buffer.from(value).toString('hex') })),
      `=?utf-8?B?${b64(value)}?=`, `Authorization: Basic ${b64(`user:${value}`)}`, `${PROSE} ${b64(gzipSync(Buffer.from(`ref ${value}`)))}`, Buffer.from(value).toString('base64url').split('').join('.'), b64(b64(b64(`note: ${value}.`))), JSON.stringify(Buffer.from(`ref ${value}`))];
    for (const text of texts) {
      const verdict = canaryVerdict([text], value, { complete: true }), r = s.scan({ where: 'http-body', text });
      outcomes.add(verdict.outcome);
      const found = r.hits.some(h => h.canary === 'drawn');
      if (verdict.outcome === 'fail') assert.ok(found, `${JSON.stringify(verdict)} at ${k}`);
      if (verdict.outcome === 'inconclusive') assert.ok(found || (r.complete === false && r.reasons.includes(verdict.reason)), `${JSON.stringify(verdict)} at ${k}`);
      if (!found && r.complete) assert.equal(verdict.outcome, 'pass', `a clean full scan is the shared pass at ${k}`);
      compared++;
    }
  }
  assert.deepEqual([...outcomes].sort(), ['fail', 'inconclusive', 'pass']);
  assert.ok(compared >= 100);
});
