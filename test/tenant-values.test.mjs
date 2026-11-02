// Forbidden-value leak detection, the pure module (src/tenant-values.mjs), after the allowlist redesign: fail only on a literal
// whole-token foreign identifier; pass only when every leaf is in the plain
// form and no other tenant's value occurs in any reading; everything else inconclusive. Every block pairs a forbidden
// case with its adjacent allowed case. Synthetic values only; non-ASCII characters are written as escapes.
import test from 'node:test';
import assert from 'node:assert/strict';
import { validateTenantValues, compileTenantValues, matcherFor, scanForeignValues, foreignValuesPredicate, foreignValuesActual, validForeignValuesPredicate,
  TENANT_VALUE_LIMITS, FOREIGN_VALUES_KIND, COUNT_KEYS, SCAN_STATES, numberSourceReviver } from '../src/tenant-values.mjs';
import { evaluateHttpCheck } from '../src/contracts.mjs';

const DECL = { tenants: {
  acme: { identifiers: ['ORD-1001', 'Ada Lovelace', 'ada@acme.example'], attributes: ['42.50'] },
  globex: { identifiers: ['ORD-2002', 'Grace Hopper', 'bob@globex.example', "Pat O'Brien", 'Lovelace'], attributes: ['Blue Widget', '19.99'] },
  initech: { identifiers: ['ORD-3003', 'SHARED-77'], attributes: ['Gold Plan'] },
  umbrella: { identifiers: ['SHARED-77', 'ORD-4004'], attributes: ['Gold Plan'] },
} };
const compiled = (decl = DECL) => { validateTenantValues(decl); return compileTenantValues(decl); };
const scan = (value, { tenant = 'acme', request = { path: '/chat' }, decl = DECL } = {}) => scanForeignValues(matcherFor(compiled(decl), tenant, request), { value }, 0);
const outcome = (value, options) => scan(value, options).outcome;
const zero = Object.fromEntries(COUNT_KEYS.map(key => [key, 0]));
const counts = patch => ({ ...zero, ...patch });

test('pass: a reply in the plain form with no other tenant value passes, own values included', () => {
  for (const text of ['Your order ORD-1001 has shipped.', 'Hello! How can I help you today?', 'Ada, your order is on its way (2 items).', 'Contact: ada@acme.example',
    'Line one\nLine two  with two spaces', 'Hopper Grace', 'Grace', 'Price: $12 - see #4 / page 2; ok: "yes" \'no\''])
    assert.deepEqual(scan(text), { scan: 'complete', outcome: 'pass', counts: zero, refs: [] }, text);
  assert.equal(outcome({ ok: true, none: null, n: 3, list: ['plain words', 'more words'] }), 'pass');
});

test('fail: a foreign identifier written literally as a whole token fails, at edges, beside spaces and closed punctuation', () => {
  for (const text of ['ORD-2002', 'ORD-2002.', '(ORD-2002)', '"ORD-2002"', 'id: ORD-2002', 'total ORD-2002!', 'see #ORD-2002', 'ORD-2002, ORD-3003', "Pat O'Brien", 'mail: bob@globex.example.', 'x\nGrace Hopper\ny'])
    assert.equal(outcome(text), 'fail', text);
  const r = scan('ORD-2002, ORD-3003');
  assert.deepEqual([r.counts.identifiers, r.refs], [2, [{ tenant: 2, class: 'identifier', value: 1 }, { tenant: 3, class: 'identifier', value: 1 }]]);
  // Keys and nested leaves are scanned; pointer "" scans the whole body.
  assert.equal(outcome({ orders: [{ id: 'x' }, { note: ['deep', ['ORD-2002']] }] }), 'fail');
  assert.equal(outcome({ 'ORD-2002': 'key leak' }), 'fail');
  const check = { assertions: [{ kind: 'status.equals', expected: 200 }, { kind: FOREIGN_VALUES_KIND, pointer: '' }] };
  const matcher = matcherFor(compiled(), 'acme', { path: '/chat' });
  const observe = json => ({ status: 200, complete: true, jsonParsed: true, json, jsonSource: JSON.parse(JSON.stringify(json), numberSourceReviver), bytes: 10, repeatedKeys: 0 });
  assert.equal(evaluateHttpCheck(check, observe({ meta: { leak: 'ORD-2002' } }), { foreignValues: matcher }).status, 'fail');
  assert.equal(evaluateHttpCheck(check, observe({ meta: { mine: 'ORD-1001' } }), { foreignValues: matcher }).status, 'pass');
});

test('edges: no edge closes; letter glue of any case, digit glue and punctuation glue read inconclusive', () => {
  // No closed edge: a longer word that holds a value is glue, never another word (accepted recall loss).
  const ann = { tenants: { acme: { identifiers: ['OWN-1'] }, globex: { identifiers: ['Ann Lee', 'ann'] } } };
  for (const [text, decl] of [['Lovelaces', DECL], ['our annual plan', ann], ['Joanna planned it', ann]]) assert.deepEqual(scan(text, { decl }), { scan: 'complete', outcome: 'inconclusive', counts: counts({ partial: 1 }), refs: [] }, text);
  // Glue of any other kind: a case change, a digit, an uppercase letter, or a punctuation run that meets a letter or digit.
  for (const text of ['orderORD-2002', 'ORD-2002x', 'XORD-2002', 'ORD-20021', '1ORD-2002', 'theLovelace', 'LovelaceS', 'GraceHopperOrders', 'ORD-2002-B', 'ref-ORD-2002', 'ORD-2002.5',
    '/orders/ORD-2002', 'ORD-2002,ORD-3003x', 'id:ORD-2002', 'ORD-2002_v2'])
    assert.deepEqual([outcome(text), scan(text).counts.identifiers, scan(text).counts.partial > 0], ['inconclusive', 0, true], text);
  // The adjacent allowed and forbidden cases: the same values as whole tokens fail.
  for (const text of ['order ORD-2002', 'ORD-2002 x', 'the Lovelace', '(ORD-2002) B', 'ref: ORD-2002']) assert.equal(outcome(text), 'fail', text);
  assert.equal(outcome('ANNUAL report', { decl: ann }), 'inconclusive', 'uppercase continuation is glue, not another word');
  // A value with a space or punctuation continued by a lowercase letter reads inconclusive too.
  const words = { tenants: { acme: { identifiers: ['OWN-1'] }, globex: { identifiers: ['van Dijk', 'XKCD'] } } };
  for (const text of ['sivan Dijk', 'XKCDs', 'theXKCD']) assert.deepEqual([outcome(text, { decl: words }), scan(text, { decl: words }).counts.partial], ['inconclusive', 1], text);
  for (const text of ['Mr van Dijk', 'see XKCD.']) assert.equal(outcome(text, { decl: words }), 'fail', text);
  for (const [text, decl] of [['Grace Hoppers', DECL], ['Ann Leeway', ann], ['the Ann Lee family', ann]]) assert.equal(outcome(text, { decl }), text === 'the Ann Lee family' ? 'fail' : 'inconclusive', text);
});

test('loose reading: other case, spacing, punctuation or line breaks inside a value read inconclusive, never fail or pass', () => {
  for (const text of ['GRACE HOPPER', 'grace hopper', 'Grace  Hopper', 'Grace\nHopper', 'Grace-Hopper', 'Grace.Hopper', 'G r a c e Hopper', 'GraceHopper', 'ord-2002', 'ORD 2002', 'ORD2002',
    'ORD - 2002', 'Pat OBrien', 'BOB@GLOBEX.EXAMPLE'])
    assert.deepEqual(scan(text), { scan: 'complete', outcome: 'inconclusive', counts: counts({ partial: 1 }), refs: [] }, text);
  // A value split across two leaves is seen in the joined reading: inconclusive, never pass.
  assert.deepEqual(scan({ first: 'Grace', last: 'Hopper' }).counts, counts({ partial: 1 }));
  assert.equal(outcome({ first: 'Grace', last: 'Lee' }), 'pass');
});

// Each encoding below read pass in an earlier build; each is now outside the plain form, or a loose occurrence: inconclusive.
const FINDINGS = {
  'NUL and controls': ['Grace\u0000Hopper', 'ORD\u00002002', 'ORD-20\u000702', 'Grace\tHopper', 'Grace\r\nHopper'],
  'entities, decoded or not, with or without a semicolon': ['ORD&#452002', 'ORD&#x2d2002', 'ORD&hyphen;2002', 'Grace&nbspHopper', 'Grace&#32Hopper', '&Ograve;RD-2002', 'ORD&period;2002', 'R&amp;D ORD-2', 'ORD-2&amp;'],
  'bidi controls': ['ORD-\u200e2002', '\u2066ORD-2002x\u2069', '\u202d2002-DRO\u202c', '\u202e2002-DRO\u202c', 'ORD-\u061c2002', 'x \u200fORD-200'],
  'format and default-ignorable characters at separators': ['Grace\u200bHopper', 'Grace\u2060Hopper', 'Grace\u00adHopper', 'Grace\u180eHopper', 'Grace\u3164Hopper', 'Grace\u{E0020}Hopper', 'ORD-\ufe0f2002', 'ORD-\u034f2002', 'Grace\u115fHopper'],
  'JSON and JS backslash escapes': ['ORD\\u002D2002', '\\u004FRD-2002', '\\x4FRD-2002', 'Grace\\u0020Hopper', 'Grace\\nHopper', 'ORD\\-2002'],
  'percent escapes, alone or beside plain values': ['ORD%2D2002', '%4FRD-2002', 'Grace%20Hopper', 'ORD-200%32', 'Grace+Hopper', 'ORD=2D2002'],
  'markup that renders as nothing': ['ORD<span></span>-2002', 'Grace<!---->Hopper', 'OR~~D~~-2002', '[ORD](x)-2002', 'Gr_ace_ Hopper', 'OR``D-2002', 'OR*D*-2002', 'Grace<br>Hopper', '{ORD}-2002'],
  'compatibility forms and look-alike letters': ['\uff2f\uff32\uff24-2002', 'ORD-\uff12\uff10\uff10\uff12', '\u041eRD-2002', 'ORD-200\u00b2', 'Gr\u0430ce Hopper', 'Grace Ho\ua78cpper', 'O\u0301RD-2002'],
};
test('each encoding is outside the plain form or a loose occurrence: inconclusive, never pass', () => {
  for (const [name, texts] of Object.entries(FINDINGS)) for (const text of texts) {
    const r = scan(text);
    assert.deepEqual([r.outcome, r.counts.identifiers], ['inconclusive', 0], `${name}: ${JSON.stringify(text)}`);
    assert.ok(r.counts.unplain + r.counts.partial > 0, `${name}: ${JSON.stringify(text)}`);
  }
  // Outside the form a reply reads inconclusive even with no value in it (accepted recall loss).
  for (const text of ['\ufb01ne print', 'I can\u2019t help with that.', 'Hello\u00a0there', '**Done**', 'Total: 5 \u20ac', 'a\tb', 'R&D']) assert.deepEqual(scan(text), { scan: 'complete', outcome: 'inconclusive', counts: counts({ unplain: 1 }), refs: [] }, text);
  // The adjacent forbidden case: a foreign identifier written literally as a whole token fails even in a leaf outside the
  // form (a positive violation), and the adjacent allowed case: the same leaf in the plain form passes.
  for (const text of ['ORD-2002 \u200b', '\u202e x ORD-2002 y', 'see &amp; ORD-2002', '**Order** ORD-2002 shipped', '\\n ORD-2002']) assert.equal(outcome(text), 'fail', JSON.stringify(text));
  for (const text of ["I can't help with that.", 'Hello there', 'Done', 'Total: 5 EUR', 'a b', 'R and D']) assert.equal(outcome(text), 'pass', text);
  // A character outside the form beside a letter or digit of the value makes that edge partial.
  for (const text of ['x\u200bORD-2002 y', 'y ORD-2002\u200bx', 'x\u00a0ORD-2002\u00a0y']) assert.deepEqual([outcome(text), scan(text).counts.partial], ['inconclusive', 1], JSON.stringify(text));
  // A value that begins with punctuation is open beside anything but a character outside the classes of the form.
  const net = { tenants: { acme: { identifiers: ['OWN-1'] }, globex: { identifiers: ['@example.net', 'Acme Inc.'] } } };
  assert.equal(outcome('bob@example.net', { decl: net }), 'fail');
  assert.deepEqual([outcome('bob\u200b@example.net', { decl: net }), scan('bob\u200b@example.net', { decl: net }).counts.partial], ['inconclusive', 1]);
  assert.equal(outcome('Acme Inc. x', { decl: net }), 'fail');
  assert.deepEqual([outcome('Acme Inc.\u200bx', { decl: net }), scan('Acme Inc.\u200bx', { decl: net }).counts.partial], ['inconclusive', 1]);
  // unplain counts leaves.
  assert.deepEqual(scan(['a\u200bb', 'fine', 'c\u200bd']).counts, counts({ unplain: 2 }));
});

test('declared characters: only the letters and digits declared values use join the form; one script per leaf, one direction', () => {
  // The allowlist is ASCII plus the declared characters, not whole scripts.
  const cyr = { tenants: { acme: { identifiers: ['OWN-1'] }, globex: { identifiers: ['ORD-2002', '\u0418\u0432\u0430\u043d \u041f\u0435\u0442\u0440\u043e\u0432'] } } };
  const petr = '\u041f\u0435\u0442\u0440', privet = '\u041f\u0440\u0438\u0432\u0435\u0442';
  assert.equal(outcome(petr), 'inconclusive', 'no declared value of DECL uses these letters');
  // The reply's letters and every other tenant's values are of one script group, or the reply reads inconclusive.
  const cyrOnly = { tenants: { acme: { identifiers: ['OWN-1'] }, globex: { identifiers: ['\u0418\u0432\u0430\u043d \u041f\u0435\u0442\u0440\u043e\u0432'] } } };
  assert.equal(outcome(petr, { decl: cyrOnly }), 'pass', 'every letter occurs in a declared value, and other tenants hold Cyrillic values only');
  assert.deepEqual(scan(petr, { decl: cyr }).counts, counts({ unplain: 1 }), 'another tenant also holds a Latin value');
  assert.deepEqual(scan(privet, { decl: cyr }).counts, counts({ unplain: 1 }), 'lowercase \u0438 occurs in no declared value: a whole script is not admitted');
  assert.equal(outcome('\u0418\u0432\u0430\u043d \u041f\u0435\u0442\u0440\u043e\u0432', { decl: cyr }), 'fail');
  assert.deepEqual(scan('\u041eRD-2002', { decl: cyr }).counts.unplain, 1, 'Cyrillic and Latin letters in one leaf');
  assert.deepEqual(scan(`${petr} ORD-1001`, { decl: cyr }).counts, counts({ unplain: 1 }), 'two scripts in one leaf are outside the form, even separated by a space');
  assert.deepEqual(scan([petr, 'ORD-1001'], { decl: cyr }).counts, counts({ unplain: 2 }), 'the same words in two leaves (one group across leaves)');
  const rtl = { tenants: { acme: { identifiers: ['ORD-1001', '\u05e9\u05dc\u05d5\u05dd'] }, globex: { identifiers: ['ORD-2002', '\u05d3\u05e0\u05d4 \u05db\u05d4\u05df'] } } };
  const shalom = '\u05e9\u05dc\u05d5\u05dd';
  assert.equal(outcome(shalom, { decl: { tenants: { ...rtl.tenants, globex: { identifiers: ['\u05d3\u05e0\u05d4 \u05db\u05d4\u05df'] } } } }), 'pass', 'other tenants hold Hebrew values only');
  assert.deepEqual(scan(shalom, { decl: rtl }).counts, counts({ unplain: 1 }), 'another tenant also holds a Latin value');
  assert.equal(outcome('\u05d3\u05e0\u05d4 \u05db\u05d4\u05df.', { decl: rtl }), 'fail');
  for (const text of [`${shalom} ORD-1001`, `${shalom} 2002`, `ORD-${shalom} 2002`]) assert.deepEqual(scan(text, { decl: rtl }).counts.unplain, 1, `mixed direction: ${text}`);
  const cjk = { tenants: { acme: { identifiers: ['\u5c71\u7530\u82b1\u5b50', '\u69d8\u306e\u3054\u6ce8\u6587'] }, globex: { identifiers: ['ORD-2002', '\u7530\u4e2d\u592a\u90ce'] } } };
  assert.equal(outcome('\u7530\u4e2d\u592a\u90ce', { decl: cjk }), 'fail');
  assert.equal(outcome('\u7530\u4e2d\u592a\u90ce\u69d8', { decl: cjk }), 'inconclusive', 'glued to a letter of a script without spaces');
  const cjkOnly = { tenants: { ...cjk.tenants, globex: { identifiers: ['\u7530\u4e2d\u592a\u90ce'] } } };
  assert.equal(outcome('\u5c71\u7530\u82b1\u5b50\u69d8\u306e\u3054\u6ce8\u6587', { decl: cjkOnly }), 'pass', 'Han and kana are one group');
  assert.deepEqual(scan('\u5c71\u7530\u82b1\u5b50\u69d8\u306e\u3054\u6ce8\u6587', { decl: cjk }).counts, counts({ unplain: 1 }), 'another tenant also holds a Latin value');
  assert.deepEqual(scan('\u5c71\u7530\u82b1\u5b50\u69d8\u306e\u3054\u6ce8\u6587\u3067\u3059', { decl: cjk }).counts, counts({ unplain: 1 }), 'kana no declared value uses');
  assert.equal(outcome('\u6ce8\u6587ORD-2002', { decl: cjk }), 'inconclusive', 'Han and Latin letters in one leaf');
  // Decimal digits a declared value uses read as ASCII digits in the loose reading; undeclared ones are outside the form.
  const arabic = { tenants: { acme: { identifiers: ['\u0660\u0661\u0662\u0663'] }, globex: { identifiers: ['1001', '\u0633\u0627\u0631\u0629'] } } };
  assert.deepEqual(scan('\u0661\u0660\u0660\u0661', { decl: arabic }).counts, counts({ partial: 1 }));
  assert.equal(outcome('\u0661\u0660\u0660\u0662', { decl: arabic }), 'pass');
  assert.deepEqual(scan('\u0661\u0660\u0660\u0665', { decl: arabic }).counts, counts({ unplain: 1 }), '\u0665 occurs in no declared value');
  // Scripts that need combining marks never meet the form.
  const deva = { tenants: { acme: { identifiers: ['OWN-1'] }, globex: { identifiers: ['\u0928\u092e\u0938\u094d\u0924\u0947'] } } };
  assert.equal(scan('\u0928\u092e\u0938\u094d\u0924\u0947 x', { decl: deva }).outcome, 'fail');
  assert.equal(scan('\u0915\u093f\u0924\u093e\u092c', { decl: deva }).counts.unplain, 1);
});

// Look-alike characters that each read pass with every count 0 in an earlier build. Each character
// is paired with its plain counterpart: the plain counterpart fails (the foreign identifier written literally) or passes.
const R7 = { tenants: {
  acme: { identifiers: ['ORD-1001', 'Ada Lovelace'] },
  globex: { identifiers: ['ORD-2002', 'Grace Hopper', 'bob@globex.example', 'INV7781', 'A1B2-C3', 'K9P4'] },
} };
const r7with = (tenant, values) => ({ tenants: { ...R7.tenants, initech: { identifiers: values } } });
test('spacing modifier letters, the long vowel mark and the tatweel are outside the form; the plain counterpart fails', () => {
  const pairs = [['Your order ORD\u02cd2002 shipped', 'Your order ORD-2002 shipped'], ['INV\u02bc7781', 'INV7781'], ['Grace\u02c9Hopper', 'Grace Hopper'],
    ['bob\u02ca@globex.example', 'bob@globex.example'], ['ORD-200\u02bc2', 'ORD-2002'], ['ORD\u02c72002', 'ORD-2002'], ['ORD\u02cb2002', 'ORD-2002']];
  for (const [odd, plain] of pairs) {
    assert.deepEqual(scan(odd, { decl: R7 }), { scan: 'complete', outcome: 'inconclusive', counts: counts({ unplain: 1 }), refs: [] }, JSON.stringify(odd));
    assert.equal(outcome(plain, { decl: R7 }), 'fail', plain);
  }
  // Declaring a script does not bring its Common letters in: the katakana long vowel mark (drawn as a dash) and the tatweel.
  const cjk = r7with('initech', ['\u7530\u4e2d\u592a\u90ce', '\u30ab\u30fc\u30c9']), ar = r7with('initech', ['\u0633\u0627\u0640\u0631\u0629']);
  assert.deepEqual(scan('order ORD\u30fc2002', { decl: cjk }).counts, counts({ unplain: 1 }));
  assert.deepEqual(scan('\u30ab\u30fc\u30c9', { tenant: 'initech', decl: cjk }).counts, counts({ unplain: 1 }), 'even in a declared value, the long vowel mark is not in the form');
  assert.equal(outcome('\u30ab\u30fc\u30c9', { decl: cjk }), 'fail', 'a foreign identifier written literally still fails outside the form');
  assert.equal(outcome('order ORD-2002', { decl: cjk }), 'fail');
  assert.deepEqual(scan('INV\u06407781', { decl: ar }).counts, counts({ unplain: 1 }));
  // Beside digits alone (no other letter in the leaf) too: a Common letter a declared value uses never joins the form.
  const digits = { tenants: { acme: { identifiers: ['\u30ab\u30fc\u30c9', '\u0633\u0627\u0640\u0631\u0629'] }, globex: { identifiers: ['4410-77'] } } };
  for (const odd of ['4410\u30fc77', '4410\u064077']) assert.deepEqual(scan(odd, { decl: digits }).counts, counts({ unplain: 1 }), JSON.stringify(odd));
  assert.equal(outcome('4410-77', { decl: digits }), 'fail');
  assert.equal(outcome('INV 7781 INV7781', { decl: ar }), 'fail');
});

test('same-script look-alikes (small capitals, IPA and caseless letters, letters drawn like punctuation) are outside the form', () => {
  const pairs = [['Your order \u1d0f\u0280\u1d05-2002 shipped', 'Your order ORD-2002 shipped'], ['\u026a\u0274\u1d20 7781', 'INV7781'], ['bob@\u0261lobex.example', 'bob@globex.example'],
    ['Gr\u0251ce Hopper', 'Grace Hopper'], ['\u0262\u0280\u1d00\u1d04\u1d07 \u029c\u1d0f\u1d18\u1d18\u1d07\u0280', 'Grace Hopper'], ['ORD\ua7f72002', 'ORD-2002'], ['ORD\ua78f2002', 'ORD-2002']];
  for (const [odd, plain] of pairs) {
    assert.deepEqual(scan(odd, { decl: R7 }), { scan: 'complete', outcome: 'inconclusive', counts: counts({ unplain: 1 }), refs: [] }, JSON.stringify(odd));
    assert.equal(outcome(plain, { decl: R7 }), 'fail', plain);
  }
  // A non-ASCII Latin letter joins the form only when a declared value uses it, and in a cased script only with a case pair.
  const accents = r7with('initech', ['Ren\u00e9e Dubois', '\u0138aj Lund', 'Ma\u0294ii']);
  assert.equal(outcome('Ren\u00e9e Dubois', { decl: accents }), 'fail');
  assert.equal(outcome('caf\u00e9 opens', { decl: accents }), 'pass', '\u00e9 is declared, so the leaf is plain');
  assert.deepEqual(scan('caf\u00e8 opens', { decl: accents }).counts, counts({ unplain: 1 }), '\u00e8 occurs in no declared value');
  for (const text of ['\u0138 is here', 'Ma\u0294ii']) assert.equal(scan(text, { tenant: 'initech', decl: accents }).counts.unplain, 1, `a caseless Latin letter never joins: ${text}`);
  // A default-ignorable letter never joins, even when a declared value uses it (the Hangul choseong filler).
  // (The other tenants hold Hangul values only, so a Hangul reply can pass.)
  const hangul = { tenants: { acme: { identifiers: ['\ubc15\uc11c\uc900'] }, initech: { identifiers: ['\uae40\u115f\ubbfc', '\uae40\ubbfc\uc900'] } } };
  assert.equal(outcome('\uae40\ubbfc\uc900', { tenant: 'initech', decl: hangul }), 'pass');
  assert.deepEqual(scan('\uae40\ubbfc\u115f\uc900', { tenant: 'initech', decl: hangul }).counts, counts({ unplain: 1 }));
  // Declared characters that NFKC composes in sequence (Hangul jamo) still leave the leaf outside the form.
  const jamo = { tenants: { acme: { identifiers: ['\u1100\u1100\u1100', '\u1161\u1161\u1161'] }, globex: { identifiers: ['\ubc15\uc11c\uc900'] } } };
  assert.equal(outcome('\u1100\u1100\u1100', { decl: jamo }), 'pass');
  assert.deepEqual(scan('\u1100\u1161', { decl: jamo }).counts, counts({ unplain: 1 }));
});

test('a case variant glued to lowercase letters reads inconclusive', () => {
  for (const text of ['xinv7781', 'refinv7781 ok', 'theord-2002x']) assert.deepEqual(scan(text, { decl: R7 }), { scan: 'complete', outcome: 'inconclusive', counts: counts({ partial: 1 }), refs: [] }, text);
  for (const text of ['INV7781', 'ref INV7781 ok']) assert.equal(outcome(text, { decl: R7 }), 'fail', text);
  const ann = { tenants: { acme: { identifiers: ['OWN-1'] }, globex: { identifiers: ['Ann', 'Lovelace'] } } };
  assert.deepEqual(scan('our annual plan', { decl: ann }).counts, counts({ partial: 1 }));
  for (const text of ['xAnne', 'theLovelaces', '1Lovelaces']) assert.deepEqual(scan(text, { decl: ann }).counts, counts({ partial: 1 }), text);
});

// Cases that each read pass with every count 0 in an earlier build. Each is paired with its
// adjacent case: the foreign identifier written literally as a whole token fails, and a reply with no foreign value passes.
const R8 = { tenants: {
  acme: { identifiers: ['ORD-1001', 'OWN-1'] },
  globex: { identifiers: ['jdoe42', 'inv7781', 'Lovelace', 'ann', 'abc123', 'acme7', 'ORD-2002', 'Grace Hopper', '02134', '000781', '0042'], attributes: ['7.50'] },
} };
test('no closed edge; another tenant\'s identifier glued to lowercase letters reads inconclusive, never pass', () => {
  for (const text of ['ref xinv7781', 'see xinv7781', 'the Lovelaces order', 'Lovelacexyz', 'mylovelace', 'Joanna planned it', 'our annual plan', 'Anne is here', 'zabc123', 'xacme7', 'acme70'])
    assert.deepEqual(scan(text, { decl: R8 }), { scan: 'complete', outcome: 'inconclusive', counts: counts({ partial: 1 }), refs: [] }, text);
  // "42" glued after "myjdoe" is also "0042" in the number reading (imprecise).
  assert.deepEqual(scan('user myjdoe42 found', { decl: R8 }).counts, counts({ partial: 1, imprecise: 1 }));
  for (const text of ['user jdoe42 found', 'ref inv7781', 'the Lovelace order', 'ask ann', 'see abc123.', 'acme7']) assert.equal(outcome(text, { decl: R8 }), 'fail', text);
  for (const text of ['user found', 'our plan', 'Jo left it']) assert.equal(outcome(text, { decl: R8 }), 'pass', text);
});

test('a value split across leaves (array chunks, object fields, a key and its value) reads inconclusive, never pass', () => {
  const split = [['Order ORD-', '2002'], { ORD: 2002 }, [...'ORD-2002'], { prefix: 'ORD-', num: 2002 }, { prefix: 'ORD', number: 2002 }, { ORD: '-2002' }, { first: 'Grace', last: 'Hopper' }, ['Grace', 'Hopper'],
    { a: { b: ['Gra'] }, c: 'ce Hop', d: ['per'] }, ['ORD', '', -2002]];
  for (const value of split) assert.deepEqual(scan(value, { decl: R8 }), { scan: 'complete', outcome: 'inconclusive', counts: counts({ partial: 1 }), refs: [] }, JSON.stringify(value));
  // The adjacent cases: the parts beside other values pass; the whole value in one leaf fails.
  for (const value of [['Order ORD-', '2003'], { prefix: 'ORD-', num: 2003 }, { first: 'Grace', last: 'Lee' }, ['ORD-1001', '2002x']]) assert.equal(outcome(value, { decl: R8 }), 'pass', JSON.stringify(value));
  for (const value of [['Order', 'ORD-2002'], { id: 'ORD-2002' }, { 'Grace Hopper': true }]) assert.equal(outcome(value, { decl: R8 }), 'fail', JSON.stringify(value));
  // Not seen (stated): the parts in another order, or with another value between them.
  for (const value of [{ num: 2002, prefix: 'ORD-' }, ['ORD-', 'x', '2002']]) assert.equal(outcome(value, { decl: R8 }), 'pass', JSON.stringify(value));
  // Through the HTTP check at a pointer.
  const check = { assertions: [{ kind: FOREIGN_VALUES_KIND, pointer: '/reply' }] };
  const matcher = matcherFor(compiled(R8), 'acme', { path: '/chat' });
  const observe = json => ({ status: 200, complete: true, jsonParsed: true, json, jsonSource: JSON.parse(JSON.stringify(json), numberSourceReviver), bytes: 10, repeatedKeys: 0 });
  for (const reply of [['Order ORD-', '2002'], { ORD: 2002 }]) assert.equal(evaluateHttpCheck(check, observe({ reply }), { foreignValues: matcher }).status, 'inconclusive', JSON.stringify(reply));
  assert.equal(evaluateHttpCheck(check, observe({ reply: ['Order ORD-', '1001'] }), { foreignValues: matcher }).status, 'pass');
});

test('a number-like leaf equal to a declared decimal value written differently is imprecise, leading zeros included', () => {
  for (const value of [{ zip: 2134 }, { acct: 781 }, { order: 42 }, { n: 7.5 }, { zip: '2134' }, { n: '7.5' }, { n: ' 7.500 ' }, { acct: '0781' }, { order: '42.0' }])
    assert.deepEqual(scan(value, { decl: R8 }), { scan: 'complete', outcome: 'inconclusive', counts: counts({ imprecise: 1 }), refs: [] }, JSON.stringify(value));
  // The adjacent cases: another number passes; the declared text itself, as a whole token, fails (or is an attribute).
  for (const value of [{ zip: 2135 }, { acct: 782 }, { order: 43 }, { zip: '2135' }, { n: 7.51 }]) assert.equal(outcome(value, { decl: R8 }), 'pass', JSON.stringify(value));
  for (const value of [{ zip: '02134' }, { acct: 'ref 000781' }, { order: '0042' }]) assert.equal(outcome(value, { decl: R8 }), 'fail', JSON.stringify(value));
  assert.deepEqual(scan({ n: '7.50' }, { decl: R8 }).counts, counts({ attributes: 1 }));
});

// Numbers written differently inside any leaf, and letters of another script group.
const one = (value, cls = 'identifiers') => ({ tenants: { acme: { identifiers: ['OWN-1'] }, globex: { [cls]: [value] } } });

test('a number written differently inside prose (leading or trailing zeros, grouping, exponent form) reads inconclusive, never pass', () => {
  for (const [value, cls, text] of [['00731', 'identifiers', 'Order 731 has shipped'], ['7.50', 'attributes', 'Your total was 7.5'], ['02134', 'identifiers', 'Boston MA 2134'],
    ['INV-0042', 'identifiers', 'Your invoice INV-42 is ready'], ['00731', 'identifiers', 'Order 7.31e2 has shipped'], ['7310', 'identifiers', 'Order 7.31e3 has shipped'],
    ['1000.00', 'attributes', 'Your balance is 1,000 today'], ['INV-0042', 'identifiers', 'invoice INV 042'], ['7.50', 'attributes', 'paid 07.5 USD'], ['00731', 'identifiers', 'Order #731.'],
    ['INV-0042', 'identifiers', { INV: 42 }], ['INV-0042', 'identifiers', { inv: '42' }], ['7.50', 'attributes', ['Total 7', '.5']],
    // The loose reading drops spaces, so a number written beside another one is still seen (no fail-open on merged digits).
    ['00731', 'identifiers', 'Order 731 2 items shipped'], ['02134', 'identifiers', 'Boston MA 2134 1 day'], ['INV-0042', 'identifiers', 'INV-42 2 days'],
    ['7.50', 'attributes', 'Total 7.5 2 items'], ['00731', 'identifiers', 'Ref 1 0731'], ['ABC-000', 'identifiers', 'ABC-0 5 items'], ['00731', 'identifiers', ['731', '2']]])
    assert.deepEqual(scan(text, { decl: one(value, cls) }), { scan: 'complete', outcome: 'inconclusive', counts: counts({ imprecise: 1 }), refs: [] }, `${value} in ${JSON.stringify(text)}`);
  // Glue that the loose reading already sees stays partial (its count is unchanged).
  assert.deepEqual(scan('Total: $7.500', { decl: one('7.50', 'attributes') }).counts, counts({ partial: 1 }));
  // The adjacent allowed cases: another number passes, also one that holds the digits inside a longer run.
  for (const [value, cls, text] of [['00731', 'identifiers', 'Order 732 has shipped'], ['00731', 'identifiers', 'Order 17310 has shipped'], ['7.50', 'attributes', 'Your total was 7.51'],
    ['7.50', 'attributes', 'Your total was 17.5'], ['02134', 'identifiers', 'Boston MA 2135'], ['INV-0042', 'identifiers', 'Your invoice INV-43 is ready'], ['INV-0042', 'identifiers', 'see INV-142'],
    ['00731', 'identifiers', 'Order 10731'], ['00731', 'identifiers', 'Order 7315'], ['000', 'identifiers', 'Order 0 of 10']])
    assert.equal(outcome(text, { decl: one(value, cls) }), 'pass', `${value} in ${text}`);
  // The adjacent forbidden case: the declared text itself, as a whole token, fails.
  for (const [value, text] of [['00731', 'Order 00731 has shipped'], ['INV-0042', 'invoice INV-0042.'], ['02134', 'Boston MA 02134']]) assert.equal(outcome(text, { decl: one(value) }), 'fail', text);
  // Accepted recall loss (stated): zeros at either end of a run of digits are not significant in this reading, so 7310 reads
  // like 731, 1 and 10 like 100.00, and ABC like ABC-000.
  for (const [value, cls, text] of [['00731', 'identifiers', 'Order 7310 has shipped'], ['100.00', 'attributes', 'in 10 days'], ['ABC-000', 'identifiers', 'ABC Corp']])
    assert.equal(outcome(text, { decl: one(value, cls) }), 'inconclusive', `${value} in ${text}`);
  // Through the HTTP check at a pointer.
  const check = { assertions: [{ kind: FOREIGN_VALUES_KIND, pointer: '/reply' }] };
  const matcher = matcherFor(compiled(one('00731')), 'acme', { path: '/chat' });
  const observe = json => ({ status: 200, complete: true, jsonParsed: true, json, jsonSource: JSON.parse(JSON.stringify(json), numberSourceReviver), bytes: 10, repeatedKeys: 0 });
  assert.equal(evaluateHttpCheck(check, observe({ reply: 'Order 731 has shipped' }), { foreignValues: matcher }).status, 'inconclusive');
  assert.equal(evaluateHttpCheck(check, observe({ reply: 'Order 732 has shipped' }), { foreignValues: matcher }).status, 'pass');
});

test('letters of two script groups anywhere at the pointer, or of another group than another tenant\'s values, read inconclusive', () => {
  // The actor's own values bring Cyrillic letters (including the look-alikes of A, B, C, E and O) and a Devanagari digit in.
  const mixed = { tenants: { acme: { identifiers: ['OWN-1', 'АВСЕ Олег', 'REF ०१'] }, globex: { identifiers: ['ORD-2002', 'ABC-2002'] } } };
  for (const value of [['О', 'RD-2002'], { 'О': 'RD-2002' }, 'АВС-2002', ['АВС', '-2002'], '०RD-2002', ['Олег', 'hello']]) {
    const r = scan(value, { decl: mixed });
    assert.deepEqual([r.outcome, r.counts.identifiers, r.counts.unplain > 0], ['inconclusive', 0, true], JSON.stringify(value));
  }
  // Another tenant's values in Cyrillic: a Latin reply could show them with Latin look-alikes.
  const cyrillicForeign = { tenants: { acme: { identifiers: ['OWN-1'] }, globex: { identifiers: ['АВС-2002'] } } };
  assert.deepEqual(scan('ABC-2002', { decl: cyrillicForeign }), { scan: 'complete', outcome: 'inconclusive', counts: counts({ unplain: 1 }), refs: [] });
  assert.equal(outcome('АВС-2002', { decl: cyrillicForeign }), 'fail', 'the Cyrillic identifier written literally fails');
  // The adjacent allowed cases: a reply with no letters, and one script throughout (the reply and every other tenant's values).
  for (const value of ['2002-11-05', ['2002', '11']]) assert.equal(outcome(value, { decl: mixed }), 'pass', JSON.stringify(value));
  const cyrillic = { tenants: { acme: { identifiers: ['Олег'] }, globex: { identifiers: ['Борис'] } } };
  assert.equal(outcome(['Олег', '42'], { decl: cyrillic }), 'pass');
  assert.equal(outcome({ id: 'ORD-1001', name: 'Grace' }), 'pass', 'Latin throughout');
  // The adjacent forbidden case: a literal foreign identifier still fails beside another script.
  assert.equal(outcome(['Олег', 'ORD-2002'], { decl: mixed }), 'fail');
});

// Adversarial cases (each read pass in an earlier build).
test('the loose reading folds case fully, drops accents and marks, reads a few letters by their base letters, kana as hiragana and 〇 as 0', () => {
  // The sharp s: the capital and the small sharp s both read as "ss".
  for (const [decl, text] of [[one('JANA STRAUẞ'), 'Kundin: Jana Strauss'], [one('JANA STRAUẞ'), 'KUNDIN: JANA STRAUSS'], [one('Jana Strauß'), 'Kundin: JANA STRAUSS']]) {
    const r = scan(text, { decl });
    assert.deepEqual([r.outcome, r.counts.identifiers, r.counts.partial], ['inconclusive', 0, 1], text);
  }
  assert.equal(outcome('Kundin: JANA STRAUẞ', { decl: one('JANA STRAUẞ') }), 'fail', 'the declared text itself fails');
  // Accents removed, and letters written without their stroke or ligature.
  const names = { tenants: { acme: { identifiers: ['OWN-1'] }, globex: { identifiers: ['Cæcilie Sørensen', 'José García', 'Paweł Nowak'] } } };
  for (const text of ['Customer: Caecilie Sorensen', 'Customer: Jose Garcia', 'Customer: Pawel Nowak'])
    assert.deepEqual(scan(text, { decl: names }), { scan: 'complete', outcome: 'inconclusive', counts: counts({ partial: 1 }), refs: [] }, text);
  for (const text of ['Customer: Cecile Soren', 'Customer: Josefina Garcon', 'Customer: Pawn Nowa']) assert.equal(outcome(text, { decl: names }), 'pass', text);
  assert.equal(outcome('Customer: José García', { decl: names }), 'fail');
  // The same name in hiragana for a katakana value, and the ideographic zero for 0.
  const kana = { tenants: { acme: { identifiers: ['ORD-1001', 'おとうさん', 'なのはな', 'こども'] }, globex: { identifiers: ['サトウ ハナコ'] } } };
  assert.deepEqual(scan('さとう はなこ', { decl: kana }).counts, counts({ partial: 1 }));
  assert.equal(outcome('こども', { decl: kana }), 'pass');
  const zero = { tenants: { acme: { identifiers: ['订单1001'] }, globex: { identifiers: ['订单二〇〇二'] } } };
  assert.deepEqual(scan('订单二00二', { decl: zero }).counts, counts({ partial: 1 }));
  assert.equal(outcome('订单1001', { decl: zero }), 'pass');
});

test('member order JavaScript changes, numbers as written, digits of two sets and bidi across leaves read inconclusive', () => {
  // An object with an array-index member name and another member: JavaScript lists index names first, so the body's order
  // is not the walk order.
  for (const text of ['{"1":"ORD-","0":"2002"}', '{"msg":"Your order is ORD-","2002":"shipped"}', '{"1":"Grace","0":"Hopper"}', '{"10":"a","20":"b"}']) {
    const r = scan(JSON.parse(text), { decl: R8 });
    assert.deepEqual([r.outcome, r.counts.identifiers, r.counts.unplain > 0], ['inconclusive', 0, true], text);
  }
  for (const text of ['{"1":"fine"}', '{"a":"x","b":"y"}', '["x","y"]', '{"01":"a","b":"c"}', '{"4294967295":"a","b":"c"}']) assert.equal(outcome(JSON.parse(text), { decl: R8 }), 'pass', text);
  // JSON numbers read as written in the body (the connector keeps each number's source text).
  const acct = { tenants: { acme: { identifiers: ['ORD-1001'] }, globex: { identifiers: ['ORD-2002', 'ACCT-12345678901234567', '00731'] } } };
  const check = { assertions: [{ kind: FOREIGN_VALUES_KIND, pointer: '/reply' }] };
  const matcher = matcherFor(compiled(acct), 'acme', { path: '/chat' });
  const observeText = text => ({ status: 200, complete: true, jsonParsed: true, json: JSON.parse(text), jsonSource: JSON.parse(text, numberSourceReviver), bytes: text.length, repeatedKeys: 0 });
  const judged = text => evaluateHttpCheck(check, observeText(text), { foreignValues: matcher }).status;
  for (const text of ['{"reply":["ACCT-", 12345678901234567]}', '{"reply":{"order": 731e-400}}', '{"reply":{"order": 731e400}}', '{"reply":731e-400}', '{"reply":{"n": 7.310e2}}'])
    assert.equal(judged(text), 'inconclusive', text);
  for (const text of ['{"reply":["ACCT-", 12345678901234568]}', '{"reply":{"n": 7.5}}', '{"reply":{"n": 1e-400}}']) assert.equal(judged(text), 'pass', text);
  assert.equal(judged('{"reply":{"acct": "ACCT-12345678901234567"}}'), 'fail');
  assert.equal(judged('{"reply":{"order": 731}}'), 'inconclusive', 'the same number read as written');
  // Without the number source text (a stub transport), a number that may be rounded or is not finite is outside the form.
  for (const value of [['ACCT-', 12345678901234567], { order: Infinity }, { n: 1e21 }]) assert.equal(scan(value, { decl: acct }).counts.unplain > 0, true, JSON.stringify(value));
  // ASCII digits beside other decimal digits in one leaf: a reader sees the ASCII number, so the leaf is outside the form.
  const deva = { tenants: { acme: { identifiers: ['ORD-1001', '१२३४५६७'] }, globex: { identifiers: ['00731', '2002-17'], attributes: ['7.50'] } } };
  for (const value of ['731५', ['१731', '7.5५']]) assert.equal(scan(value, { decl: deva }).counts.unplain > 0, true, JSON.stringify(value));
  assert.equal(outcome('१२३', { decl: deva }), 'pass', 'Devanagari digits alone');
  assert.deepEqual(scan('७३१', { decl: deva }).counts, counts({ imprecise: 1 }), 'Devanagari 731 reads as 731');
  // Right-to-left letters anywhere with left-to-right letters or digits anywhere (ASCII digits are left-to-right).
  const rtl = { tenants: { acme: { identifiers: ['ORD-1001', 'שלום כהן'] }, globex: { identifiers: ['00731'], attributes: ['7.50'] } } };
  for (const value of [['שלום', '1 3 7'], ['שלום', '1', '73']]) assert.equal(scan(value, { decl: rtl }).counts.unplain > 0, true, JSON.stringify(value));
  assert.equal(outcome(['שלום', 'כהן'], { decl: rtl }), 'pass');
});

// More adversarial cases (each read pass in an earlier build).
test('other spellings of the same letters read as the declared value (Arabic script, Hebrew finals, strokes, iteration marks, iota subscript, umlauts)', () => {
  for (const [own, foreign, text] of [
    [['محمد علي', 'كريم'], 'علی کریمی', 'علي كريمي'],
    [['سلمى', 'طه حسين'], 'فاطمة علي', 'فاطمه على'],
    [['כהנים משה'], 'יונתן כהן', 'יונתנ כהנ'],
    [['ORD-1001'], 'Ƶofia Ɉak', 'Zofia Jak'],
    [['山田 太郎', '佐藤 一郎'], '佐々木 花子', '佐佐木 花子'],
    [['ORD-1001', 'Αλέξανδρος των'], 'τῷ Ἀλεξάνδρῳ', 'τω Αλέξανδρω'],
    [['ORD-1001'], 'Jürgen Müller', 'Kunde: Juergen Mueller'],
    [['ORD-1001'], 'Jürgen Müller', 'Kunde: Jurgen Muller'],
  ]) {
    const decl = { tenants: { acme: { identifiers: own }, globex: { identifiers: [foreign] } } };
    const r = scan(text, { decl });
    // Partial, or overlapping where the actor's own value sits inside the foreign one (the first case).
    assert.deepEqual([r.outcome, r.counts.identifiers, r.counts.partial + r.counts.overlapping], ['inconclusive', 0, 1], text);
  }
  // The adjacent allowed case: another name passes, and the declared text itself fails.
  const umlaut = { tenants: { acme: { identifiers: ['ORD-1001'] }, globex: { identifiers: ['Jürgen Müller'] } } };
  assert.equal(outcome('Kunde: Jens Mertens', { decl: umlaut }), 'pass');
  assert.equal(outcome('Kunde: Jürgen Müller', { decl: umlaut }), 'fail');
});

test('right-to-left text anywhere in the body outside the pointer puts left-to-right leaves at the pointer outside the form', () => {
  const decl = one('00731');
  const check = { assertions: [{ kind: FOREIGN_VALUES_KIND, pointer: '/messages/1' }] };
  const matcher = matcherFor(compiled(decl), 'acme', { path: '/chat' });
  const observeText = text => ({ status: 200, complete: true, jsonParsed: true, json: JSON.parse(text), jsonSource: JSON.parse(text, numberSourceReviver), bytes: text.length, repeatedKeys: 0 });
  const judged = text => evaluateHttpCheck(check, observeText(text), { foreignValues: matcher });
  for (const text of ['{"messages":["שלום","1 3 7"]}', '{"note":{"שלום":1},"messages":["x","1 3 7"]}']) {
    const row = judged(text);
    assert.deepEqual([row.status, row.observed.predicates[0].counts.unplain], ['inconclusive', 1], text);
  }
  for (const text of ['{"messages":["hello","1 3 7"]}']) assert.equal(judged(text).status, 'pass', text);
});

// More adversarial cases (each read pass in an earlier build; the first two are regressions of the cases above).
test('an iteration mark repeats only a letter; one after a digit or at a leaf start is outside the form', () => {
  const iter = { tenants: { acme: { identifiers: ['ORD-1001', '佐々木 一郎'] }, globex: { identifiers: ['00731', '2002-17'], attributes: ['7.50'] } } };
  for (const value of ['731々', '7.5々', '1 々731']) {
    const r = scan(value, { decl: iter });
    assert.deepEqual([r.outcome, r.counts.identifiers, r.counts.unplain > 0], ['inconclusive', 0, true], JSON.stringify(value));
  }
  assert.equal(scan('731ゝ', { decl: { tenants: { acme: { identifiers: ['ORD-1001', 'すゝき'] }, globex: { identifiers: ['00731'] } } } }).counts.unplain, 1);
  const names = { tenants: { acme: { identifiers: ['山田 太郎', '佐藤 一郎', '野々村'] }, globex: { identifiers: ['佐々木 花子'] } } };
  assert.equal(scan(['佐', '々木 花子'], { decl: names }).outcome, 'inconclusive');
  // The adjacent cases: a mark after a letter is plain (the actor's own name passes), and the foreign name written with it fails.
  assert.equal(outcome('野々村', { decl: names }), 'pass');
  assert.equal(outcome('佐々木 花子', { decl: names }), 'fail');
});

test('any character of a right-to-left block outside the pointer counts for the direction rule', () => {
  const check = { assertions: [{ kind: FOREIGN_VALUES_KIND, pointer: '/messages/1' }] };
  const matcher = matcherFor(compiled(one('00731')), 'acme', { path: '/chat' });
  const judged = text => evaluateHttpCheck(check, { status: 200, complete: true, jsonParsed: true, json: JSON.parse(text), jsonSource: JSON.parse(text, numberSourceReviver), bytes: text.length, repeatedKeys: 0 }, { foreignValues: matcher }).status;
  for (const ch of ['־', '׳', '؟', '۔', '܀', 'ࠀ', 'ࡀ', '𐴀', '𞤀']) assert.equal(judged(JSON.stringify({ messages: [ch, '1 3 7'] })), 'inconclusive', ch.codePointAt(0).toString(16));
  for (const ch of ['-', '·', '一']) assert.equal(judged(JSON.stringify({ messages: [ch, '1 3 7'] })), 'pass', ch.codePointAt(0).toString(16));
});

test('a declared value with ae, oe, ue or aa is also read with them written a, o, u and a', () => {
  const decl = { tenants: { acme: { identifiers: ['ORD-1001', 'Jürgen Schmidt'] }, globex: { identifiers: ['ORD-2002', 'Karl Mueller'] } } };
  assert.deepEqual(scan('Kunde: Karl Müller', { decl }).counts, counts({ partial: 1, unplain: 0 }));
  assert.equal(outcome('Kunde: Karl Miller', { decl }), 'pass');
  assert.equal(outcome('Kunde: Karl Mueller', { decl }), 'fail');
});

test('many occurrences of one value never overflow the stack, and number-like leaves count toward the work bound', () => {
  const r = scan('a'.repeat(TENANT_VALUE_LIMITS.maxScanChars), { decl: one('a-a') });
  assert.equal(r.outcome ?? r.scan, r.scan === 'complete' ? 'inconclusive' : 'work-limit');
  const n = scan(Array(63000).fill(1), { decl: one('1.00', 'attributes') });
  assert.equal(n.outcome ?? n.scan, n.scan === 'complete' ? 'inconclusive' : 'work-limit');
});

test('a declared value that NFKC changes is refused; a composed value fails on composed text', () => {
  for (const value of ['Rene\u0301e Dubois', '\uff2f\uff32\uff24-9', 'R\u2163 Plan', 'Grace\u00a0Hopper'])
    assert.throws(() => validateTenantValues({ tenants: { acme: { identifiers: ['OWN-1'] }, globex: { identifiers: [value] } } }), /tenant 2 identifier 1: a value must be written as Unicode NFKC normalization leaves it/, JSON.stringify(value));
  const composed = { tenants: { acme: { identifiers: ['OWN-1'] }, globex: { identifiers: ['Ren\u00e9e Dubois'] } } };
  assert.equal(outcome('Ren\u00e9e Dubois', { decl: composed }), 'fail');
  // Decomposed text is outside the form (a combining mark): inconclusive. The loose reading removes
  // accents on both sides, so it is also a loose occurrence.
  assert.deepEqual(scan('Rene\u0301e Dubois', { decl: composed }).counts, counts({ partial: 1, unplain: 1 }));
});

test('a leaf holds letters of one script, so a look-alike letter between digits or hyphens is outside the form', () => {
  // A third tenant brings Cyrillic letters in, including the uppercase look-alikes of A, C and P.
  const decl = r7with('initech', ['\u0411\u043e\u0440\u0438\u0441 \u0418\u0432\u0430\u043d\u043e\u0432', '\u0410\u043d\u043d\u0430 \u0421\u043e\u043a\u043e\u043b', '\u0420\u0438\u0442\u0430']);
  for (const [odd, plain] of [['ref \u04101B2-\u04213 ok', 'ref A1B2-C3 ok'], ['K9\u04204', 'K9P4'], ['\u0410 1B2-C3', 'A1B2-C3']]) {
    assert.deepEqual(scan(odd, { decl }), { scan: 'complete', outcome: 'inconclusive', counts: counts({ unplain: 1 }), refs: [] }, JSON.stringify(odd));
    assert.equal(outcome(plain, { decl }), 'fail', plain);
  }
  assert.equal(outcome('\u0410\u043d\u043d\u0430 \u0421\u043e\u043a\u043e\u043b', { decl, tenant: 'acme' }), 'fail', 'a Cyrillic-only leaf is plain');
});

test('classification is order-independent: identifier wins, and a value of two tenants or of the actor and another is shared', () => {
  const a = { tenants: { acme: { identifiers: ['OWN-1'] }, globex: { identifiers: ['Blue Widget'] }, initech: { attributes: ['Blue Widget'] } }, attributesAlone: 'ignore' };
  const b = { tenants: { acme: { identifiers: ['OWN-1'] }, initech: { attributes: ['Blue Widget'] }, globex: { identifiers: ['Blue Widget'] } }, attributesAlone: 'ignore' };
  for (const decl of [a, b]) assert.deepEqual(scan('Blue Widget', { decl }), { scan: 'complete', outcome: 'inconclusive', counts: counts({ shared: 1 }), refs: [] });
  // A shared identifier reads inconclusive; an attribute held by two other tenants counts as an attribute (the policy).
  assert.deepEqual(scan('SHARED-77 is on file'), { scan: 'complete', outcome: 'inconclusive', counts: counts({ shared: 1 }), refs: [] });
  assert.deepEqual(scan('Gold Plan'), { scan: 'complete', outcome: 'inconclusive', counts: counts({ attributes: 1 }), refs: [{ tenant: 3, class: 'attribute', value: 1 }] });
  assert.equal(outcome('Gold Plan', { decl: { ...DECL, attributesAlone: 'ignore' } }), 'pass');
  assert.equal(outcome('SHARED-77 and Gold Plan', { decl: { ...DECL, attributesAlone: 'ignore' } }), 'inconclusive');
  // A value the actor's tenant holds together with another tenant is shared: inconclusive, never pass.
  const own = { tenants: { acme: { identifiers: ['ORD-9009', 'ORD-1'] }, globex: { identifiers: ['ORD-9009', 'ORD-2'] }, initech: { identifiers: ['ord 9009', 'ORD-3'] } } };
  assert.deepEqual(scan('ORD-9009', { decl: own }), { scan: 'complete', outcome: 'inconclusive', counts: counts({ shared: 1 }), refs: [] });
  assert.equal(outcome('ORD-2', { decl: own }), 'fail');
  assert.equal(outcome('ORD-1', { decl: own }), 'pass');
  // Values with one loose reading are one value: "ord 9009" (initech) joins "ORD-9009", whatever the order.
  const swapped = { tenants: { initech: own.tenants.initech, globex: own.tenants.globex, acme: own.tenants.acme } };
  assert.deepEqual(scan('ord 9009', { decl: swapped }), scan('ord 9009', { decl: own }));
});

test('overlap: an occurrence overlapping a value of another owner set reads inconclusive; a separate one still fails', () => {
  // Own "Ada Lovelace" holds globex's "Lovelace": which value is meant is ambiguous.
  assert.deepEqual(scan('Ada Lovelace placed the order'), { scan: 'complete', outcome: 'inconclusive', counts: counts({ overlapping: 1 }), refs: [] });
  assert.equal(outcome('Lovelace placed the order'), 'fail');
  assert.equal(outcome('Ada Lovelace, and also Lovelace'), 'fail', 'one occurrence that overlaps nothing is enough');
  assert.equal(outcome('Ada Lovelace', { tenant: 'globex' }), 'inconclusive', 'the roles reversed');
  // Two other tenants' values overlapping each other.
  const cross = { tenants: { acme: { identifiers: ['OWN-1'] }, globex: { identifiers: ['Grace Hopper'] }, initech: { identifiers: ['Hopper Street'] } } };
  assert.deepEqual(scan('Grace Hopper Street', { decl: cross }).counts, counts({ overlapping: 2 }));
  assert.equal(outcome('Grace Hopper. Hopper Street', { decl: cross }), 'fail');
  // A foreign value glued inside an own value (its digits in "ORD-1001") overlaps it too.
  const inside = { tenants: { acme: { identifiers: ['ORD-1001'] }, globex: { identifiers: ['1001'] } } };
  assert.deepEqual(scan('Your order ORD-1001', { decl: inside }).counts, counts({ overlapping: 1 }));
  assert.equal(outcome('Your order ORD-1002', { decl: inside }), 'pass');
  // The own value's case variant overlapping a literal foreign match also makes it ambiguous.
  const street = { tenants: { acme: { identifiers: ['Grace Hopper Street'] }, globex: { identifiers: ['Grace Hopper'] } } };
  assert.equal(outcome('Grace Hopper STREET', { decl: street }), 'inconclusive');
  assert.equal(outcome('Grace Hopper lane', { decl: street }), 'fail');
  // A value of another set overlapping two values of one set: each of the three reads overlapping.
  const three = { tenants: { acme: { identifiers: ['OWN-1'] }, globex: { identifiers: ['Grace Hopper Street Corner', 'Hopper'] }, initech: { identifiers: ['Grace Hopper'] } } };
  assert.deepEqual(scan('Grace Hopper Street Corner', { decl: three }).counts, counts({ overlapping: 3 }));
  // Values of the same owner set never make each other ambiguous.
  const same = { tenants: { acme: { identifiers: ['OWN-1'] }, globex: { identifiers: ['Grace Hopper', 'Hopper Street'] } } };
  assert.deepEqual(scan('Grace Hopper Street', { decl: same }).counts, counts({ identifiers: 2 }));
});

test('echo: a foreign identifier the request carries reads inconclusive (never pass); another identifier still fails', () => {
  const echo = scan("I can't share ORD-2002", { request: { path: '/chat', body: { message: 'show me ORD-2002' } } });
  assert.deepEqual([echo.outcome, echo.counts.echoed, echo.counts.identifiers, echo.refs], ['inconclusive', 1, 0, []]);
  const read = scan({ id: 'ORD-2002', total: 'USD 900', note: 'confidential' }, { request: { path: '/api/orders/ORD-2002' } });
  assert.deepEqual([read.outcome, read.counts.echoed], ['inconclusive', 1]);
  const both = scan('ORD-2002 belongs to bob@globex.example', { request: { path: '/chat', body: { message: 'show me ORD-2002' } } });
  assert.deepEqual([both.outcome, both.refs], ['fail', [{ tenant: 2, class: 'identifier', value: 3 }]]);
  // The path (decoded), its query with "+" as a space, and body keys and numbers are read in the loose reading.
  assert.equal(scan('ORD-2002', { request: { path: '/orders/ORD%2D2002' } }).counts.echoed, 1);
  assert.equal(scan("Pat O'Brien", { request: { path: '/search?q=Pat+O%27Brien' } }).counts.echoed, 1);
  assert.equal(scan('ORD-2002', { request: { path: '/chat', body: { 'ord-2002': true } } }).counts.echoed, 1);
  const numbers = { tenants: { acme: { identifiers: ['OWN-1'] }, globex: { identifiers: ['1001'] } } };
  assert.equal(scan(1001, { request: { path: '/chat', body: { id: 1001 } }, decl: numbers }).counts.echoed, 1);
  // An attribute the request carries is still an attribute: the policy decides.
  const attr = scan('19.99', { request: { path: '/chat', body: { amount: 19.99 } } });
  assert.deepEqual([attr.outcome, attr.counts.attributes, attr.counts.echoed], ['inconclusive', 1, 0]);
  assert.equal(outcome('I cannot help with that order', { request: { path: '/chat', body: { message: 'show me ORD-2002' } } }), 'pass');
  assert.equal(outcome('ORD-2002', { request: { path: '/chat', body: { message: 'ORD-3003' } } }), 'fail');
});

test('attributes alone: inconclusive by default, pass under "ignore"; an attribute with an identifier fails', () => {
  assert.equal(outcome('Your Blue Widget costs 19.99'), 'inconclusive');
  const ignore = { ...DECL, attributesAlone: 'ignore' };
  assert.deepEqual(scan('Your Blue Widget costs 19.99', { decl: ignore }), { scan: 'complete', outcome: 'pass', counts: counts({ attributes: 2 }), refs: [{ tenant: 2, class: 'attribute', value: 1 }, { tenant: 2, class: 'attribute', value: 2 }] });
  assert.equal(outcome('ORD-2002: Blue Widget', { decl: ignore }), 'fail');
  // A glued or variant attribute is a partial value: inconclusive under either policy.
  for (const text of ['Blue Widget-Pro', 'BLUE WIDGET', 'BlueWidget']) assert.equal(outcome(text, { decl: ignore }), 'inconclusive', text);
});

test('number leaves: exact numbers match their shortest text; other writings and rounded numbers are imprecise', () => {
  const decl = { tenants: { acme: { identifiers: ['X-100'], attributes: ['42.50'] }, globex: { identifiers: ['1001', '9007199254740992', '000123', '12345678901234567890'], attributes: ['19.99', '42.5'] } } };
  assert.equal(outcome(1001, { decl }), 'fail');
  assert.equal(outcome({ id: 1001 }, { decl }), 'fail');
  assert.deepEqual(scan(19.99, { decl }).counts, counts({ attributes: 1 }));
  assert.deepEqual(scan(JSON.parse('19.990'), { decl }).counts, counts({ attributes: 1 }));
  // Glued digits: another number that holds the value's digits.
  for (const n of [10010, 21001, 1001.5, 119.99]) assert.deepEqual([outcome(n, { decl }), scan(n, { decl }).counts.partial], ['inconclusive', 1], String(n));
  // Above 2^53, or a long decimal: without its source text the parsed number may be the declared one rounded (imprecise),
  // and the leaf is outside the form. With the source text kept, the body's digits are read as written.
  assert.deepEqual(scan(JSON.parse('12345678901234567890'), { decl }).counts, counts({ imprecise: 1, unplain: 1 }));
  assert.deepEqual(scan(JSON.parse('9007199254740993'), { decl }).counts, counts({ imprecise: 1, unplain: 1 }), 'String(n) equals the value but n is not a safe integer');
  assert.equal(outcome(JSON.parse('12345678901234567890', numberSourceReviver), { decl }), 'fail', 'the source text is the declared value');
  assert.equal(outcome(JSON.parse('[19.990, 12345678901234567891]', numberSourceReviver), { decl }), 'inconclusive', 'the source text 19.990 and a near number');
  // The actor's "42.50" and globex's "42.5" are the same JSON number: overlapping, under either policy.
  assert.deepEqual(scan(42.5, { decl }).counts, counts({ overlapping: 1 }));
  assert.equal(outcome(42.5, { decl: { ...decl, attributesAlone: 'ignore' } }), 'inconclusive');
  // A leading-zero value gets no exception: the JSON number 123 is "000123" written differently. The
  // adjacent cases pass, and the declared text itself fails.
  assert.deepEqual(scan(123, { decl }).counts, counts({ imprecise: 1 }));
  for (const n of [124, 1002, 19.98, 0]) assert.equal(outcome(n, { decl }), 'pass', String(n));
  assert.equal(outcome('ref 000123', { decl }), 'fail');
  // A number whose shortest text is outside the form (an exponent with "+") counts as a leaf outside the form.
  assert.deepEqual(scan(1e21, { decl }).counts, counts({ unplain: 1 }));
});

test('refs: capped at 32 with exact counts, in tenant, class, value order; the scan length cap reads inconclusive', () => {
  const many = Array.from({ length: 40 }, (_, i) => `REC-${String(i + 1).padStart(3, '0')}`);
  const decl = { tenants: { acme: { identifiers: ['OWN-1'] }, globex: { identifiers: many, attributes: ['Blue Widget'] } } };
  const result = scan(`Blue Widget ${[...many].reverse().join(' ')}`, { decl });
  assert.deepEqual([result.outcome, result.counts.identifiers, result.counts.attributes, result.refs.length], ['fail', 40, 1, 32]);
  assert.deepEqual(result.refs.slice(0, 2), [{ tenant: 2, class: 'identifier', value: 1 }, { tenant: 2, class: 'identifier', value: 2 }]);
  assert.ok(result.refs.every(r => r.class === 'identifier'));
  const p = { kind: FOREIGN_VALUES_KIND, present: true, type: 'string', ...result, scan: 'complete' };
  assert.match(foreignValuesActual(p), /other-tenant identifiers 40 \(tenant 2 identifier 1, .*tenant 2 identifier 32, 8 more\); other-tenant attributes 1 \(1 more\); echoed identifiers 0; shared values 0; overlapping values 0; imprecise number values 0; partial values 0; leaves outside the plain form 0; repeated member names 0; predicate fail$/);
  assert.deepEqual(scan(`Blue Widget ${many.join(' ')}`, { decl }), result);
  assert.deepEqual(scan('x'.repeat(TENANT_VALUE_LIMITS.maxScanChars) + ' ORD-2002'), { scan: 'over-limit' });
  assert.equal(outcome(['x'.repeat(TENANT_VALUE_LIMITS.maxScanChars - 10), 'ORD-2002']), 'fail', 'just under the cap is scanned');
  // The loose reading is bounded too: a character whose NFKC form is 15 letters.
  assert.deepEqual(scan('\ufdfa'.repeat(40000)), { scan: 'over-limit' });
  assert.equal(scan('\ufdfa'.repeat(1000)).outcome, 'inconclusive');
});

test('the predicate record fails closed: no matcher, absent, null, boolean or incomplete JSON read inconclusive', () => {
  const matcher = matcherFor(compiled(), 'acme', { path: '/chat' });
  assert.equal(matcherFor(compiled(), 'nobody', { path: '/chat' }), null);
  assert.deepEqual(foreignValuesPredicate(true, { present: true, type: 'string', value: 'ORD-2002' }, null), { kind: FOREIGN_VALUES_KIND, present: true, type: 'string', outcome: 'inconclusive', scan: 'unavailable' });
  for (const found of [{ present: false, type: 'absent' }, { present: true, type: 'null', value: null }, { present: true, type: 'boolean', value: false }]) {
    const p = foreignValuesPredicate(true, found, matcher, { repeatedKeys: 0, sourced: found.value });
    assert.equal(p.outcome, 'inconclusive'); assert.equal(Object.hasOwn(p, 'scan'), false);
  }
  const unavailable = foreignValuesPredicate(false, { present: false, type: 'unavailable' }, matcher);
  assert.deepEqual(unavailable, { kind: FOREIGN_VALUES_KIND, present: null, type: 'unavailable', outcome: 'inconclusive' });
  assert.equal(foreignValuesActual(unavailable), 'Complete valid JSON unavailable');
  const fail = foreignValuesPredicate(true, { present: true, type: 'string', value: 'ORD-2002 for bob@globex.example' }, matcher, { repeatedKeys: 0, sourced: 'ORD-2002 for bob@globex.example' });
  assert.equal(fail.outcome, 'fail');
  // Without the transport's number source texts (or its repeated-name count) the body is not known as written: never a pass.
  for (const transport of [{ sourced: 'ORD-2002 for bob@globex.example' }, undefined])
    assert.deepEqual(foreignValuesPredicate(true, { present: true, type: 'string', value: 'ORD-2002 for bob@globex.example' }, matcher, transport), { kind: FOREIGN_VALUES_KIND, present: true, type: 'string', outcome: 'inconclusive', scan: 'body-unchecked' });
  // With the repeat count but no source tree (a body the second parse could not read), a literal leak still fails and
  // anything else reads body-unchecked (an unreadable sibling cannot hide a fail).
  assert.equal(foreignValuesPredicate(true, { present: true, type: 'string', value: 'ORD-2002 for bob@globex.example' }, matcher, { repeatedKeys: 0 }).outcome, 'fail');
  for (const value of ['All good.', 'ord-2002 later'])
    assert.deepEqual(foreignValuesPredicate(true, { present: true, type: 'string', value }, matcher, { repeatedKeys: 0 }), { kind: FOREIGN_VALUES_KIND, present: true, type: 'string', outcome: 'inconclusive', scan: 'body-unchecked' }, value);
  assert.doesNotMatch(JSON.stringify(fail) + foreignValuesActual(fail), /ORD|globex|bob|2002/i);
  // The saved-evidence check: the scan states, the count keys and the outcome rule.
  const declared = { attributesAlone: 'inconclusive', tenants: [{ identifiers: 3, attributes: 1 }, { identifiers: 5, attributes: 2 }, { identifiers: 2, attributes: 1 }, { identifiers: 2, attributes: 1 }], actorTenants: { alice: 1 } };
  const ok = q => validForeignValuesPredicate(q, { completeJSON: true, declared, actorId: 'alice' });
  assert.equal(ok(fail), true);
  for (const state of SCAN_STATES.filter(s => s !== 'complete')) assert.equal(ok({ kind: FOREIGN_VALUES_KIND, present: true, type: 'string', outcome: 'inconclusive', scan: state }), true, state);
  assert.equal(ok({ kind: FOREIGN_VALUES_KIND, present: true, type: 'string', outcome: 'inconclusive', scan: 'mark-limit' }), false, 'mark-limit is no longer a state');
  const plainUnplain = foreignValuesPredicate(true, { present: true, type: 'string', value: 'a\u200bb' }, matcher, { repeatedKeys: 0, sourced: 'a\u200bb' });
  assert.deepEqual([plainUnplain.outcome, ok(plainUnplain), ok({ ...plainUnplain, outcome: 'pass' })], ['inconclusive', true, false]);
  for (const key of COUNT_KEYS) {
    assert.equal(ok({ ...fail, counts: { ...fail.counts, [key]: -1 } }), false, `${key} negative`);
    const missing = { ...fail, counts: { ...fail.counts } }; delete missing.counts[key];
    assert.equal(ok(missing), false, `${key} missing`);
  }
  assert.equal(ok({ ...fail, counts: { ...fail.counts, contained: 0 } }), false, 'an extra count key');
});

test('bounded work: crafted responses finish fast; past the occurrence bound the scan stops and reads inconclusive', () => {
  const timed = (label, run, limitMs) => { const t0 = performance.now(); const result = run(); const ms = performance.now() - t0; assert.ok(ms < limitMs, `${label}: ${ms.toFixed(0)} ms`); return result; };
  const fill = unit => unit.repeat(Math.floor((TENANT_VALUE_LIMITS.maxScanChars - 16) / unit.length));
  assert.equal(timed('ordinary', () => scan(fill('Order ORD-1001 for Grace Hopper shipped; ')), 5000).outcome, 'fail');
  assert.equal(timed('own only', () => scan(fill('Order ORD-1001 for Ada shipped. ')), 5000).outcome, 'pass');
  assert.equal(timed('glued everywhere', () => scan(fill('ORD-2002x ')), 5000).outcome, 'inconclusive');
  assert.equal(timed('punctuation runs', () => scan(fill('ORD-2002...........x')), 5000).outcome, 'inconclusive');
  assert.equal(timed('loose everywhere', () => scan(fill('grace hopper ')), 5000).outcome, 'inconclusive');
  // Overlaps everywhere: own and foreign occurrences on top of each other.
  const inside = { tenants: { acme: { identifiers: ['ORD-1001'] }, globex: { identifiers: ['1001'] } } };
  assert.equal(timed('overlaps', () => scan(fill('ORD-1001 '), { decl: inside }), 5000).counts.overlapping, 1);
  // Many distinct characters (one cache entry each).
  const distinct = Array.from({ length: 20000 }, (_, k) => String.fromCodePoint(0x4e00 + k)).join('');
  assert.equal(timed('distinct characters', () => scan(distinct), 5000).outcome, 'inconclusive');
  // Overlapping occurrences of many declared values: the occurrence bound stops the scan (inconclusive, never pass).
  const runs = { tenants: { acme: { identifiers: ['OWN-1'] }, globex: { identifiers: Array.from({ length: 198 }, (_, k) => 'a'.repeat(k + 3)) } } };
  assert.deepEqual(timed('occurrence bound', () => scan(fill('a'), { decl: runs }), 5000), { scan: 'work-limit' });
  // Many number leaves against many declared values.
  const numbers = { tenants: { acme: { identifiers: ['OWN-1'] }, globex: { identifiers: Array.from({ length: 512 }, (_, k) => String(10000 + k)) } } };
  assert.equal(timed('number leaves', () => scan(Array.from({ length: 20000 }, (_, k) => k), { decl: numbers }), 5000).outcome, 'fail');
  const matcher = matcherFor(compiled(runs), 'acme', { path: '/chat' });
  const p = foreignValuesPredicate(true, { present: true, type: 'string', value: fill('a') }, matcher, { repeatedKeys: 0, sourced: fill('a') });
  assert.deepEqual(p, { kind: FOREIGN_VALUES_KIND, present: true, type: 'string', outcome: 'inconclusive', scan: 'work-limit' });
  assert.equal(foreignValuesActual(p), `Present; type string; scan stopped: more than ${TENANT_VALUE_LIMITS.maxOccurrences} matches to judge; predicate inconclusive`);
  // The length bound counts every character, invisible ones included.
  assert.deepEqual(scan('\u200b'.repeat(TENANT_VALUE_LIMITS.maxScanChars) + ' ORD-2002'), { scan: 'over-limit' });
  assert.equal(outcome('\u200b'.repeat(TENANT_VALUE_LIMITS.maxScanChars - 20) + ' ORD-2002'), 'fail');
});
