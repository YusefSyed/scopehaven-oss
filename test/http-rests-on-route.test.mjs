// Identity option B (src/http-rests-on.mjs): the route reader, the anchor conditions and the served-record allowlist, lifted
// with their tests from an earlier control-scope design. Only that design's own reach rule (control-refused, control-unbounded,
// paired-control-not-passed, routeLinked) is left out; every reading below is the same as there. Pure: no I/O.
import test from 'node:test';
import assert from 'node:assert/strict';
import { identityRulesOf } from '../src/contracts.mjs';
import { pathSegments, routeSegments, recordedRouteShape, singular, stemKeys, separated, anchored, refusalLike, MAX_ROUTE_SEGMENTS, recordPredicate, recordPredicates, recordClasses, recordText,
  requestTexts, cleanObject, sentRoute, controlScopeEvidence, controlScopeShape, recordForm, outcomeText, OUTCOME_WORDS, SHORT_OUTCOME_WORDS, SENT_HEADER_TEXTS } from '../src/http-rests-on.mjs';
import { digest } from '../src/domain.mjs';

test('route segments, the anchor and refusal-like statuses', () => {
  const lit = (exact, keys) => ({ exact, keys }), rec = (record, id = false) => ({ record, id });
  // Capture types for the placeholders below: only an integer capture can fill the last record position of an anchored route.
  const TYPES = new Map([['own', 'integer'], ['other', 'integer'], ['id', 'integer'], ['i', 'integer'], ['o', 'integer'], ['repo', 'integer'], ['a', 'integer'], ['r', 'integer'], ['r2', 'integer'], ['me', 'integer'],
    ['otherInv', 'integer'], ['file', 'integer'], ['myInv', 'integer'], ['sid', 'id'], ['name', 'string'], ['invColl', 'id'], ['usersColl', 'id'], ['mine', 'integer'], ['secret', 'integer'], ['getProfile', 'string'], ['deleteInvoice', 'string'], ['coll', 'id']]);
  // Segments: the raw text (case and encoding kept, for the exact-route anchor) and the stem keys of the decoded,
  // lower-cased text (every four-letter window of each run of letters, its first three letters and the first three of its
  // consonant outline, and the same for its singular form). A record position keeps its raw text and whether it is an
  // identifier literal or an integer capture.
  assert.deepEqual(pathSegments('/api/notes/own'), [lit('api', []), lit('notes', ['not', 'note', 'nts', 'otes']), lit('own', ['own'])]);
  assert.deepEqual(pathSegments('/API/%6Eotes/'), [lit('API', []), lit('%6Eotes', ['not', 'note', 'nts', 'otes']), lit('', [])], 'raw text kept; a trailing slash is a literal with no text');
  assert.deepEqual([pathSegments('/'), pathSegments('/notes/{{id}}/share', TYPES), pathSegments('/notes/42'), pathSegments('/notes/0b9a7e2c-1d1e-4f6a-9c3b-5e2f8a7d6c41'), pathSegments('/notes/deadbeefdeadbeef'), pathSegments('/notes/v2')].map(r => r.map(x => x.exact ?? x)),
    [[''], ['notes', rec('{{id}}', true), 'share'], ['notes', rec('42', true)], ['notes', rec('0b9a7e2c-1d1e-4f6a-9c3b-5e2f8a7d6c41', true)], ['notes', rec('deadbeefdeadbeef', true)], ['notes', 'v2']]);
  assert.deepEqual(['{{sid}}', '{{name}}', '{{undeclared}}', '{{id}}'].map(x => pathSegments(`/notes/${x}`, TYPES)[1]), [rec('{{sid}}'), rec('{{name}}'), rec('{{undeclared}}'), rec('{{id}}', true)], 'only an integer capture is an id');
  assert.deepEqual(['notes', 'invoices', 'categories', 'boxes', 'churches', 'addresses', 'status', 'analysis', 'people', 'data', 'note'].map(singular), ['note', 'invoice', 'category', 'box', 'church', 'address', 'status', 'analysis', 'person', 'datum', 'note']);
  assert.deepEqual(stemKeys('boxes'), ['box', 'boxe', 'bxs', 'oxes']);
  // Decoded until stable (at most three rounds): a double-encoded literal still gives its words, and an over-long path of
  // short readable segments is opaque by its length alone.
  assert.deepEqual(pathSegments('/api/%256Eotes')[1], lit('%256Eotes', ['not', 'note', 'nts', 'otes']));
  assert.deepEqual(pathSegments(`/${Array.from({ length: 60 }, () => '1'.repeat(40)).join('/')}`), [rec('')]);
  assert.equal(pathSegments(`/${Array.from({ length: 49 }, () => '1'.repeat(40)).join('/')}`).length, 49, 'the adjacent allowed path (2009 characters) is read');
  assert.deepEqual(stemKeys('mice'), ['mic', 'mice', 'mou', 'mous', 'ouse'], 'an irregular plural also gives its singular keys');
  assert.deepEqual(stemKeys('api_keys2v'), ['api', 'key', 'keys', 'kys', 'v'], 'runs of letters split at every other character');
  // An abbreviation shares a key with the word it shortens (the first three letters, or of the consonant outline).
  for (const [a, b, key] of [['orgs', 'organizations', 'org'], ['docs', 'documents', 'doc'], ['msgs', 'messages', 'msg'], ['invoices', 'inventory', 'inv']]) assert.ok(stemKeys(a).includes(key) && stemKeys(b).includes(key), `${a} ${b}`);
  // Case never hides a shared window (the camel-case split is gone; lower-casing comes first).
  const keys = p => pathSegments(p)[1].keys;
  assert.deepEqual(keys('/api/customerNotes'), keys('/api/customernotes'));
  assert.deepEqual(keys('/api/CUSTOMERNOTES'), keys('/api/customernotes'));
  for (const p of ['/api/userinvoicenotes', '/api/userInvoiceNotes', '/api/user_invoice_notes', '/api/USERINVOICENOTES']) assert.ok(keys(p).includes('invo') && keys(p).includes('user') && keys(p).includes('note'), p);
  assert.deepEqual(['/api', '/APIS', '/v1', '/v2.1', '/rest', '/v1beta'].map(p => pathSegments(p)[0].keys.length > 0), [false, false, false, false, true, true], 'only api, apis and versions are key-free namespaces');
  // Opaque paths (one record position at the root with no stem key): anything that cannot be read without guessing. Any
  // query or fragment is opaque, since it may select or route the resource.
  for (const p of ['/api//notes/{{id}}', '/api/./notes/{{id}}', '/api/invoices/../notes/{{id}}', '/api/%2e%2e/notes/{{id}}', '/api/Notes%2F/{{id}}', '/api/notes%5C/{{id}}', '/api/notes;v=1/{{id}}',
    '/api/n%D0%BEtes/{{id}}', '/api/nоtes/{{id}}', '/api/notes%20/{{id}}', '/api/%25252565notes/{{id}}', '/api/%E0%A4%A/{{id}}', '/api/notes-{{id}}/x', `/api/${'a'.repeat(129)}/{{id}}`,
    `/${Array.from({ length: 65 }, (_, i) => `s${i}`).join('/')}`, `/api/${'n'.repeat(2050)}`, 'api/notes/{{id}}', '', '/api/notes/{{id}}?x=1', '/api/notes?', '/api/invoices/7?as=notes', '/graphql?op=notes',
    '/api/invoices/{{id}}?_method=GET&path=/api/notes/1', '/api/notes/{{id}}#frag', `/${Array.from({ length: 12 }, () => 'abcdefghijklmnopqrstuvwxyz').join('/')}/{{id}}`])
    assert.deepEqual(pathSegments(p, TYPES), [rec('')], p);
  // Keyed: the same key gives the same digests, another key other ones; a record position keeps its id flag; the shape is checked.
  const k1 = routeSegments('/api/notes/{{id}}', 'k1', TYPES), k2 = routeSegments('/api/notes/{{id}}', 'k2', TYPES);
  assert.deepEqual([k1[0].exact === routeSegments('/api/x', 'k1')[0].exact, k1[1].exact === k2[1].exact, k1[2].id, k1[2].record === k2[2].record, /^[a-f0-9]{64}$/.test(k1[1].exact), /^[a-f0-9]{64}$/.test(k1[2].record), k1[1].keys.length, k1[0].keys, Object.keys(k1[1]), Object.keys(k1[2])],
    [true, false, true, false, true, true, 4, [], ['exact', 'keys'], ['record', 'id']]);
  assert.notEqual(routeSegments('/api/Notes', 'k1')[1].exact, routeSegments('/api/notes', 'k1')[1].exact, 'the exact digest keeps case');
  assert.notEqual(routeSegments('/api/notes/{{a}}', 'k1', TYPES)[2].record, routeSegments('/api/notes/{{b}}', 'k1', TYPES)[2].record, 'two placeholder names, two record digests');
  const hex = v => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);
  assert.equal(recordedRouteShape(routeSegments('/api/invoices/{{id}}/noteItems/', 'k'), hex), true);
  const many = { exact: k1[1].exact, keys: Array.from({ length: 257 }, (_, i) => digest({ i })).sort() };
  for (const bad of [[{ ...k1[1], keys: [...k1[1].keys].reverse() }], [{ ...k1[1], keys: [k1[1].keys[0], k1[1].keys[0]] }], [{ ...k1[1], kind: 'literal' }], ['notes'], [{ ...k1[1], exact: 'notes' }], [{ exact: k1[1].exact }], [many],
    [...Array(65).fill(k1[2])], 'x', [], [null], [k1[1], null], [{ record: k1[2].record }], [{ record: k1[2].record, id: 'yes' }], [{ record: 'r', id: true }], [{ ...k1[2], keys: [] }]])
    assert.equal(recordedRouteShape(bad, hex), false, JSON.stringify(bad).slice(0, 80));
  // separated: both routes well formed, each with a stem key, each record position right after a literal with stem keys,
  // and no stem key shared anywhere.
  const s = p => pathSegments(p, TYPES);
  const sep = (a, b, why) => { assert.equal(separated(s(a), s(b)), true, why); assert.equal(separated(s(b), s(a)), true, `${why} (swapped)`); };
  const share = (a, b, why) => { assert.equal(separated(s(a), s(b)), false, why); assert.equal(separated(s(b), s(a)), false, `${why} (swapped)`); };
  sep('/api/notes/{{id}}', '/api/invoices/{{id}}', 'no shared key');
  sep('/api/CUSTOMERNOTES/{{c}}', '/api/invoices/{{id}}', 'no shared key, whatever the case');
  sep('/api/invoices/7/', '/api/notes/{{id}}/', 'a trailing slash on both');
  share('/api/userinvoicenotes/{{c}}', '/api/invoices/{{id}}', 'invo, nvoi, voic and oice are shared without a case change');
  share('/api/note/{{id}}', '/api/notes/{{id}}', 'singular beside plural');
  share('/api/notes/{{id}}', '/api/%256Eotes/{{id}}', 'double encoding');
  share('/api/notes/{{id}}', '/api/notebooks/{{id}}', 'a shared window (compound)');
  share('/api/notes/{{id}}', '/api/usernotes/{{id}}', 'a shared window (compound, end)');
  share('/api/notes/{{id}}', '/api/invoices/{{id}}/notes', 'the same word deeper in the other route');
  share('/api/categories/{{id}}', '/api/category-groups/{{id}}', 'an -ies plural beside its singular');
  share('/api/people/{{id}}', '/api/persons/{{id}}', 'an irregular plural');
  share('/api/boxes/{{id}}', '/api/box/{{id}}', 'a short singular');
  share('/api/comments/{{id}}', '/api/payments/{{id}}', 'a short shared window over-pairs (only withholds more)');
  share('/api/notes/{{id}}', '/api/7/{{id}}', 'a route with no stem key');
  share('/api/notes/{{id}}', '/api/invoices/{{id}}?x=1', 'an opaque route');
  share('/', '/api/invoices/7', 'the root has no stem key');
  // An abbreviation pairs with the word it shortens.
  share('/api/organizations/{{id}}', '/api/orgs/{{id}}', 'orgs abbreviates organizations');
  share('/api/documents/{{id}}', '/api/docs/{{id}}', 'docs abbreviates documents');
  share('/api/messages/{{id}}', '/api/msgs/{{id}}', 'msgs abbreviates messages (consonant outline)');
  share('/api/invoices/{{id}}', '/api/inventory/{{id}}', 'a shared first three letters over-pairs (only withholds more)');
  // A route whose record position may hide the collection name (at the root, right after a
  // namespace or right after another record position) is never separated from anything, whatever its literals say.
  for (const c of ['/api/{{coll}}/{{id}}/history', '/api/12/{{id}}/history', '/{{coll}}/{{id}}/export', '/api/v2/{{coll}}/{{id}}/summary', '/api/notes/{{id}}/{{id}}/export'])
    share('/api/invoices/{{other}}', c, c);
  sep('/api/invoices/{{other}}', '/api/reports/{{id}}/history', 'the adjacent allowed route: every record position after a word');
  assert.equal(separated(undefined, s('/a/b/7')), false, 'missing segments never separate');
  assert.equal(separated([{ exact: 'notes', keys: ['note'] }, 'x'], s('/invoices/7')), false, 'malformed segments never separate');
  // The anchor: a required control of the check's actor, with its method, on its exact route; every
  // record position but the last the same; the last an identifier literal or an integer capture in both.
  // An anchor's path as sent must differ from the check's (here the template text stands in for it).
  const route = (p, method = 'GET') => ({ method, routeSegments: s(p), sentRoute: sentRoute(p, 'k') });
  const anchoredBy = (b, a, method) => anchored(route(b), [route(a, method)]);
  assert.equal(anchoredBy('/api/invoices/7', '/api/invoices/3'), true, 'two records of one template');
  assert.equal(anchoredBy('/api/invoices/{{other}}', '/api/invoices/{{own}}'), true, 'two integer placeholders');
  assert.equal(anchoredBy('/api/v1/orgs/{{o}}/invoices/{{i}}', '/api/v1/orgs/{{o}}/invoices/2'), true, 'several record positions, the parent the same');
  assert.equal(anchoredBy('/api/v1/orgs/1/invoices/{{i}}', '/api/v1/orgs/1/invoices/{{own}}'), true, 'the same parent literal');
  assert.equal(anchoredBy('/thomas/{{repo}}', '/thomas/9'), true, 'an owner slug with a record after it: the same slug');
  // Another record only. An identical route, or one whose path as sent reads the same after
  // percent-decoding, lower-casing and dropping leading zeros, never anchors.
  for (const [b, a, why] of [['/api/invoices/7', '/api/invoices/7', 'an identical route'], ['/api/invoices/{{own}}', '/api/invoices/{{own}}', 'an identical placeholder'],
    ['/api/invoices/7', '/api/invoices/007', 'a leading zero'], ['/api/invoices/deadbeefdeadbeef', '/api/invoices/DEADBEEFDEADBEEF', 'upper-case hexadecimal'], ['/api/invoices/7', '/api/invoices/%37', 'a percent-encoded digit']])
    assert.equal(anchoredBy(b, a), false, why);
  assert.equal(anchored(route('/api/invoices/7'), [{ ...route('/api/invoices/3'), sentRoute: route('/api/invoices/7').sentRoute }]), false, 'another template, the same path as sent (a literal equal to the captured value)');
  assert.equal(anchored(route('/api/invoices/7'), [{ ...route('/api/invoices/3'), sentRoute: null }]), false, 'an anchor without a sent route');
  assert.equal(anchored({ ...route('/api/invoices/7'), sentRoute: undefined }, [route('/api/invoices/3')]), false, 'a check without a sent route');
  for (const [b, a, method, why] of [['/api/invoices/7', '/api/invoices/3', 'POST', 'another method'], ['/api/invoices/7', '/api/Invoices/3', 'GET', 'case differs'],
    ['/api/invoices/7', '/api/%69nvoices/3', 'GET', 'encoding differs'], ['/api/invoices/7', '/api/invoices/3/', 'GET', 'a trailing slash differs'], ['/api/invoices/7', '/api/invoices/own', 'GET', 'a literal where the check has a record'],
    ['/api/invoices/mine', '/api/invoices/mine', 'GET', 'no record position'], ['/thomas/6', '/charles/9', 'GET', 'another owner slug'], ['/api/7/invoices', '/api/3/invoices', 'GET', 'a record right after a namespace'],
    ['/7/invoices', '/3/invoices', 'GET', 'a record at the root'], ['/api/invoices/7/8', '/api/invoices/3/4', 'GET', 'a record right after a record'], ['/2024-01/7', '/2024-01/3', 'GET', 'a record after a literal with no stem key'],
    ['/api/invoices/7?x=1', '/api/invoices/7?x=1', 'GET', 'an opaque route, even an identical one'], ['/api/notes/{{a}}', '/api/notes', 'GET', 'a shorter route'],
    // A different parent never anchors (the PocketBase, NocoDB and table shapes); a last record
    // position filled by an "id" or "string" capture never anchors (the RPC shape), in the check or in the control.
    ['/api/collections/{{invColl}}/records/{{otherInv}}', '/api/collections/{{usersColl}}/records/{{me}}', 'GET', 'another collection (PocketBase)'],
    ['/api/v2/tables/9/records/7', '/api/v2/tables/4/records/3', 'GET', 'another table (NocoDB)'], ['/api/collections/2/records/7', '/api/collections/1/records/3', 'GET', 'another collection by number'],
    ['/api/tables/{{secret}}/rows/{{r2}}', '/api/tables/{{mine}}/rows/{{r}}', 'GET', 'another table by placeholder'], ['/api/v1/orgs/{{o}}/invoices/{{i}}', '/api/v1/orgs/1/invoices/2', 'GET', 'a placeholder parent beside a literal one'],
    ['/api/rpc/{{deleteInvoice}}', '/api/rpc/{{getProfile}}', 'POST', 'string captures (an RPC function name)'], ['/api/invoices/{{sid}}', '/api/invoices/3', 'GET', 'an "id" capture in the check'],
    ['/api/invoices/7', '/api/invoices/{{sid}}', 'GET', 'an "id" capture in the control'], ['/api/invoices/{{undeclared}}', '/api/invoices/{{own}}', 'GET', 'an undeclared placeholder']])
    assert.equal(anchoredBy(b, a, method), false, why);
  assert.equal(anchored(route('/api/rpc/{{deleteInvoice}}', 'POST'), [route('/api/rpc/{{getProfile}}', 'POST')]), false, 'the RPC shape with its own method');
  assert.equal(anchored(route('/api/invoices/7'), []), false, 'no anchors');
  assert.equal(anchored({ routeSegments: s('/api/invoices/7') }, [route('/api/invoices/3')]), false, 'a check without a method');
  assert.equal(anchored(route('/api/invoices/7'), [{ method: 'GET', routeSegments: 'x' }, null]), false, 'malformed anchors');
  // Linear and bounded on adversarial input: oversized paths are opaque before any per-segment work, and the largest
  // readable routes (64 segments, 256 stem keys) compare quickly.
  const started = Date.now();
  for (const p of [`/${'%25'.repeat(200000)}`, `/${'a/'.repeat(100000)}`, `/${'aA1-'.repeat(50000)}`]) assert.deepEqual(pathSegments(p), [{ record: '', id: false }]);
  const wide = `/api/${Array.from({ length: 31 }, (_, i) => `${'abcdefgh'.slice(i % 4, i % 4 + 4)}${i}/{{p${i}}}`).join('/')}`;
  assert.ok(pathSegments(wide).length <= MAX_ROUTE_SEGMENTS && pathSegments(wide).length > 60);
  const fat = `/api/${Array.from({ length: 128 }, (_, i) => String.fromCharCode(97 + ((i * 7 + (i >> 2) * 3) % 26))).join('')}/{{id}}`;
  assert.ok(pathSegments(fat)[1].keys.length > 100);
  const wideTypes = new Map(Array.from({ length: 31 }, (_, i) => [`p${i}`, 'integer']));
  const wideOther = wide.replace(/\{\{p30\}\}$/, '{{p29}}');
  const anchors = Array.from({ length: 64 }, (_, i) => ({ method: 'GET', routeSegments: pathSegments(wideOther, wideTypes), sentRoute: sentRoute(`${wideOther}${i}`, 'k') }));
  const wideCheck = { method: 'GET', routeSegments: pathSegments(wide, wideTypes), sentRoute: sentRoute(wide, 'k') };
  assert.equal(anchored(wideCheck, anchors), true, 'the widest readable route anchors on another record');
  assert.equal(anchored(wideCheck, [{ ...wideCheck }]), false, 'never itself');
  for (let i = 0; i < 2000; i++) { separated(s(wide), s(fat)); anchored(wideCheck, anchors); }
  assert.ok(Date.now() - started < 10000, `adversarial routes took ${Date.now() - started} ms`);
  // Refusal-like: the actor's statuses, any 3xx, and any non-2xx a boundary check of the actor accepts.
  const like = refusalLike([401, 403, 302], [[403], [403, 404], [200]]);
  assert.deepEqual([401, 403, 302, 307, 399, 404, 200, 500, 409, 400].map(like), [true, true, true, true, true, true, false, false, false, false]);
  assert.deepEqual([401, 403, 404].map(refusalLike(undefined)), [true, true, false], 'an uncredentialed actor: 401 and 403');
  // recordForm: the served-record form of one control (its declared 2xx, a complete parsed clean object, a passing record predicate, its identity proven).
  const soft = { required: true, accepts: [201], httpStatus: 201, transportOutcome: 'complete', jsonParsed: true, cleanObject: true, recordDeclared: true, recordPassed: [[0, 0]], identityProven: true };
  assert.deepEqual([recordForm({ ...soft, httpStatus: 201 }), recordForm({ ...soft, recordPassed: true }), recordForm({ ...soft, recordPassed: [] })], [true, false, false], 'recordPassed lists the [field, value] ranks that passed');
  for (const more of [{ httpStatus: 200 }, { transportOutcome: 'invalid-json' }, { jsonParsed: false }, { cleanObject: false }, { recordDeclared: false }, { identityProven: false }, { accepts: [201, 202] }, { accepts: [409] }, { accepts: null }, { required: false }])
    assert.equal(recordForm({ ...soft, ...more }), false, JSON.stringify(more));
  assert.deepEqual(['actor-identity/6', 'actor-identity/5', 'actor-identity/4', 'actor-identity/3'].map(identityRulesOf), [6, 5, 4, 3]);
});

test('the served-record allowlist: record predicates, clean objects, the sent route and its record', () => {
  const eq = (pointer, expected) => ({ kind: 'json.equals', pointer, expected }), ORIGIN = 'http://127.0.0.1:9';
  const ACTORS = { member: { principalId: 'member-1', credentialEnv: 'SCOPEHAVEN_TARGET_MEMBER', credentialCookie: 'sid', identityValue: 'Alice@Example.com', signInRedirectStatus: 302, tenantId: 'acme', role: 'editor', refusesWith401: true },
    owner: { principalId: 'owner-1' } };
  // A profile whose check X (GET /api/invoices/3 by default) declares /v equal to the value under test, beside other checks.
  const target = (expected, { path = '/api/invoices/3', body, method = 'GET', actors = ACTORS, origin = ORIGIN, others = [], correlation, observers, pointer = '/v' } = {}) => ({ actors, origin, ...(correlation ? { correlation } : {}), ...(observers ? { observers } : {}),
    checks: [{ id: 'X', method, path, ...(body === undefined ? {} : { body }), assertions: [{ kind: 'status.equals', expected: 200 }, eq(pointer, expected)] }, ...others] });
  const counts = (expected, options) => { const t = target(expected, options); return recordPredicates(t.checks[0], t).length === 1; };
  // The record text form. A string that, after NFKC, holds no digit of any script and two runs of three
  // letters or more. So no number, no record id (the example rule's /id equal to the route's id), no single word (the
  // string forms of true, false and null, and a status word), no superscript or full-width digit.
  for (const v of ['March rent', 'Été dernier', 'Alpha-ledger', 'Ωμέγα λίστα', 'the big one']) assert.equal(recordText(v), true, v);
  for (const v of ['n1', 'Q3 report', 'Report ³ final', 'Report ３ final', 'Report ٣ final', 'March', 'true', 'false', 'null', 'granted', '0', '3', '', ' ', 'ab cd', 'a-b-c', 3, 7, -1, 0.5, 0, null, true, false, ['a b c'], { a: 'March rent' }])
    assert.equal(recordText(v), false, JSON.stringify(v));
  // A value that names an outcome is no record text (an in-band refusal message
  // under the record's own field), read like a key (outcomeText below).
  for (const v of ['Access denied', 'Status report', 'Request failed', 'Invalid ledger', 'Login error page', 'Forbidden zone', 'Not OK here', 'Unauthorised visit']) assert.equal(recordText(v), false, v);
  assert.equal(recordText('Okay ledger'), true, 'okay is not ok');
  for (const v of ['March rent', 'Alpha ledger']) assert.equal(counts(v), true, v);
  // Pointers and kinds: exactly one top-level token, a json.equals; never the root, an empty token, a nested pointer, or
  // another kind.
  const texts = requestTexts(target('March rent'));
  for (const a of [eq('', 'March rent'), eq('/', 'March rent'), eq('/data/title', 'March rent'), eq(7, 'March rent'), { kind: 'json.exists', pointer: '/v', expected: true }, { kind: 'json.notContains', pointer: '/v', expected: 'March rent' },
    { kind: 'status.equals', expected: 200 }, null]) assert.equal(recordPredicate(a, texts), false, JSON.stringify(a));
  assert.equal(recordPredicate(eq('/title', 'March rent'), texts), true);
  assert.equal(recordPredicate(eq('/title', 'March rent'), null), false, 'unknown request texts never count');
  assert.equal(recordPredicate(eq('/title', 'March rent'), new Set()), false, 'texts of another shape never count');
  for (const broken of [{ ...target('March rent'), actors: undefined }, { ...target('March rent'), actors: [] }, { ...target('March rent'), origin: '' }, { ...target('March rent'), origin: 7 }, { ...target('March rent'), checks: null }, null])
    assert.equal(requestTexts(broken), null, `without actors, an origin or checks no predicate counts (${JSON.stringify(broken)})`);
  // Every header name and constant value the connector sends is a text a
  // request carries, so an in-band refusal that echoes one never shows a record. So are every other request text of the
  // profile: the path's words, singulars and parts, the method, the origin, every actor
  // value, any check's body or path or query, and the declared correlation header's name.
  assert.deepEqual([...SENT_HEADER_TEXTS], ['Accept', 'application/json', 'Connection', 'close', 'Authorization', 'Bearer', 'Cookie', 'Content-Type', 'Content-Length', 'Host']);
  for (const [value, why, options] of [['application/json', 'the Accept and Content-Type value'], ['Application JSON', 'its words'], ['Bearer token', 'the Authorization scheme'], ['Close call', 'the Connection value'],
    ['Cookie jar', 'the Cookie header name'], ['Content length', 'the Content-Length name'], ['Hosted ledger', 'a word that contains Host'], ['Accepted terms', 'a word that contains Accept'],
    ['Connection lost', 'the Connection name'], ['Authorization denied', 'the Authorization name'], ['Trace ledger', 'the declared correlation header', { correlation: { header: 'x-trace-ledger' } }],
    ['api invoices', 'the path\'s words'], ['Invoice ledger', 'the singular of a segment'], ['Voice memo', 'a word of three letters or more inside a path word'], ['Rapid ledger', 'a path word (api) inside a word'],
    ['Get going', 'the method'], ['http traffic', 'the origin'], ['Alice wonder', 'part of the identity value'], ['Acme corp', 'the tenant'], ['Editor note', 'the role'], ['Member area', 'the alias'],
    ['Owner list', 'another actor\'s alias'], ['Sid vicious', 'the cookie name'], ['Scopehaven target', 'the credential reference name'],
    ['March rent', 'a body value of the check', { method: 'POST', body: { title: 'March rent' } }], ['March rent', 'a padded body value', { method: 'POST', body: { title: '  March   rent ' } }],
    ['March rent', 'a full-width body value (NFKC)', { method: 'POST', body: { title: 'Ｍａｒｃｈ ｒｅｎｔ' } }], ['MARCH RENT', 'white space read as one space', { method: 'POST', body: { title: 'March \t rent' } }],
    ['Bob jones', 'a percent-encoded body value', { method: 'POST', body: { name: 'Bob%20jones' } }], ['Rent for March', 'a value that contains a body value', { method: 'POST', body: { title: 'Rent' } }],
    ['Alpha ledger', 'a value another check of the profile writes', { others: [{ id: 'W', method: 'POST', path: '/api/notes', body: { title: 'Alpha ledger' } }] }],
    ['Folder ledger', 'the singular of another check\'s segment', { others: [{ id: 'F', method: 'GET', path: '/api/folders/7' }] }],
    ['Summer sale', 'a decoded query value of another check', { others: [{ id: 'Q', method: 'GET', path: '/api/search?q=summer%20sale' }] }],
    ['Spring sale', 'a fragment part', { others: [{ id: 'Q', method: 'GET', path: '/api/search#spring%20sale' }] }],
    ['Ping pong', 'an observer\'s witness path', { observers: [{ witness: { actorId: 'owner', method: 'GET', path: '/ping?pong=1', host: 'witness.scopehaven.invalid' } }] }],
    ['Witness stand', 'the witness tag', { observers: [{ witness: { actorId: 'owner', method: 'GET', path: '/x' } }] }],
    ['March rent', 'a placeholder in the check\'s own path', { path: '/api/invoices/{{own}}' }], ['March rent', 'a placeholder in the check\'s own body', { method: 'POST', body: { note: '{{noteId}}' } }]])
    assert.equal(counts(value, options), false, why);
  // The adjacent allowed values: not carried by any of those texts.
  assert.equal(counts('March rent', { others: [{ id: 'W', method: 'POST', path: '/api/notes', body: { title: 'April rent' } }] }), false, 'shares a word (rent) with another check\'s body');
  for (const [value, options] of [['Alpha ledger', {}], ['Alpha ledger', { others: [{ id: 'W', method: 'POST', path: '/api/notes', body: { title: 'Bravo folder' } }] }], ['Summer fair', { others: [{ id: 'Q', method: 'GET', path: '/api/search?q=winter' }] }]])
    assert.equal(counts(value, options), true, value);
  // An accent-free slug or a full case fold of a request text is that text
  // (texts are compared folded: NFKD without combining marks, upper-cased then lower-cased, and by their letters and
  // digits alone), and a check that sends a body other than an empty object or array has no record
  // predicate at all, since any key or value can carry text, so the only text that differs between two partners'
  // requests is their record identifier.
  for (const [value, why, options] of [['cafe-creme', 'a slug of another check\'s body', { others: [{ id: 'W', method: 'POST', path: '/api/notes', body: { name: 'Café crème' } }] }],
    ['STRASSE MASSE', 'a full case fold (sharp s) of another check\'s body', { others: [{ id: 'W', method: 'POST', path: '/api/notes', body: { name: 'Straße Maße' } }] }],
    ['Cafe Creme', 'accents dropped', { others: [{ id: 'W', method: 'POST', path: '/api/notes', body: { name: 'Café crème' } }] }],
    ['Alpha ledger', 'the check\'s own body carries text', { method: 'POST', body: { name: 'Bravo folder' } }], ['Alpha ledger', 'a nested number in the check\'s own body', { method: 'POST', body: { lines: [{ qty: 2 }] } }],
    ['Alpha ledger', 'an empty string in the check\'s own body', { method: 'POST', body: { note: '' } }]])
    assert.equal(counts(value, options), false, why);
  for (const body of [{}, []]) assert.equal(counts('Alpha ledger', { method: 'POST', body }), true, `an empty body: ${JSON.stringify(body)}`);
  for (const body of [{ draft: true, archived: false, parent: null }, { flags: [true, false] }, { 'Søren Øster': true }, [null], null])
    assert.equal(counts('Alpha ledger', { method: 'POST', body }), false, `any other body, keys included: ${JSON.stringify(body)}`);
  // recordClasses: [index, field, value], the index among the check's JSON predicates (status skipped), field and value the
  // ranks of the pointer and the expected value among every record predicate of the profile; two checks on one field
  // with different values get one field rank and two value ranks.
  const ranked = { actors: {}, origin: ORIGIN, checks: [{ id: 'A', method: 'GET', path: '/api/invoices/3', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.exists', pointer: '/title', expected: true }, eq('/title', 'Bravo ledger'), eq('/name', 'Alpha ledger'), eq('/n', 4)] },
    { id: 'B', method: 'GET', path: '/api/invoices/4', assertions: [{ kind: 'status.equals', expected: 200 }, eq('/title', 'Alpha ledger')] }, { id: 'C', method: 'GET', path: '/api/invoices/{{x}}', assertions: [eq('/title', 'Charlie ledger')] }] };
  assert.deepEqual([...recordClasses(ranked)], [['A', [[1, 1, 1], [2, 0, 0]]], ['B', [[0, 1, 0]]], ['C', []]]);
  assert.deepEqual([recordPredicates(ranked.checks[1], ranked), recordPredicates({ ...ranked.checks[1] }, ranked), recordPredicates(null, ranked), recordPredicates(ranked.checks[0], null)], [[[0, 1, 0]], [], [], []], 'only a check the profile holds');
  // A clean JSON object has no top-level key that names an outcome: error, errors, status, success, ok and
  // message in any letter case (the list), and any key whose text holds an outcome word
  // anywhere or ok, err, msg or fail as a word, so statusCode, error_message, isError, HTTPStatus, a padded or full-width
  // error key are envelopes too. An error or status envelope is never read as a record.
  assert.deepEqual([[...OUTCOME_WORDS], [...SHORT_OUTCOME_WORDS]], [['error', 'status', 'success', 'message', 'fault', 'failure', 'failed', 'denied', 'deny', 'forbidden', 'unauthorized', 'unauthorised', 'unauthenticated', 'refused', 'rejected', 'invalid',
    'access', 'allowed', 'permission', 'permitted', 'authorized', 'authorised', 'granted', 'insufficient', 'restricted', 'blocked', 'locked', 'redacted', 'unavailable'], ['ok', 'err', 'msg', 'fail']]);
  for (const key of ['error', 'errors', 'status', 'success', 'ok', 'message', 'Error', 'ERRORS', 'OK', 'statusCode', 'status_code', 'error_message', 'errorMessage', 'isError', 'HTTPStatus', 'ERRORCODE', 'is_ok', 'isOk', 'errMsg', 'err', 'error ', '\uff25\uff32\uff32\uff2f\uff32', 'faultString', 'authFailure', 'accessDenied', 'isForbidden', 'unauthorized', 'refusedBy', 'rejected', 'invalidToken', 'messages', 'fail',
    'access', 'allowed', 'authorized', 'isAuthorised', 'permission', 'permitted', 'granted', 'locked', 'redacted', 'restricted', 'blocked', 'unavailable', 'insufficient', 'deny'])
    assert.equal(outcomeText(key), true, key);
  for (const key of ['title', 'saved', 'state', 'okay', 'token', 'book', 'lookup', 'failover', 'name', 'owner']) assert.equal(outcomeText(key), false, key);
  const obs = json => ({ complete: true, jsonParsed: true, json });
  assert.deepEqual([obs({ title: 'March rent' }), obs({}), obs({ title: 'x', data: { error: 'nested is not read' } }), obs({ state: 'open', okay: true, token: 'x' })].map(cleanObject), [true, true, true, true]);
  for (const o of [obs({ data: null, errors: [{ message: 'forbidden' }] }), obs({ id: 'n1', error: 'x' }), obs({ Error: 'x' }), obs({ ERRORS: [] }), obs({ title: 'March rent', status: 'denied' }), obs({ title: 'March rent', Status: 403 }),
    obs({ title: 'March rent', success: false }), obs({ title: 'March rent', ok: false }), obs({ title: 'March rent', OK: true }), obs({ title: 'March rent', message: 'access denied' }), obs({ MESSAGE: '' }),
    obs({ title: 'March rent', statusCode: 403 }), obs({ title: 'March rent', error_message: 'denied' }), obs({ title: 'March rent', 'error ': 'x' }), obs({ title: 'March rent', messages: [] }),
    // A refusal stated in a top-level string value, or under an access-decision key.
    obs({ title: 'March rent', access: 'denied' }), obs({ title: 'March rent', detail: 'forbidden' }), obs({ title: 'March rent', allowed: false, reason: 'not permitted' }), obs({ title: 'March rent', authorized: false }),
    obs({ title: 'March rent', note: 'Insufficient permissions' }), obs({ title: 'Access denied' }),
    obs([{ id: 'n1' }]), obs(null), obs('n1'), obs(7), { ...obs({ id: 'n1' }), complete: false }, { ...obs({ id: 'n1' }), jsonParsed: false }, { ...obs({ id: 'n1' }), error: 'invalid-json' }, null, undefined])
    assert.equal(cleanObject(o), false, JSON.stringify(o));
  // The sent route: keyed; the same record reads the same after decoding, lower-casing and dropping leading zeros.
  const same = (a, b) => assert.equal(sentRoute(a, 'k'), sentRoute(b, 'k'), `${a} ${b}`), apart = (a, b) => assert.notEqual(sentRoute(a, 'k'), sentRoute(b, 'k'), `${a} ${b}`);
  same('/api/invoices/7', '/api/invoices/007'); same('/api/invoices/7', '/api/invoices/%37'); same('/api/invoices/7', '/api/invoices/%2537'); same('/api/invoices/ABCDEF0123456789', '/api/invoices/abcdef0123456789');
  same('/api/invoices/7', '/API/Invoices/7/'); same('/api/invoices/0', '/api/invoices/000');
  // A UUID with and without its dashes, and a long hexadecimal id with leading zeros, are one record.
  same('/api/invoices/0f8fad5b-d9cb-469f-a165-70867728950e', '/api/invoices/0f8fad5bd9cb469fa16570867728950e'); same('/api/invoices/0F8FAD5B-D9CB-469F-A165-70867728950E', '/api/invoices/f8fad5bd9cb469fa16570867728950e');
  same('/api/invoices/00deadbeefdeadbeef', '/api/invoices/deadbeefdeadbeef'); apart('/api/invoices/deadbeefdeadbeef', '/api/invoices/deadbeefdeadbee0');
  apart('/api/invoices/7', '/api/invoices/3'); apart('/api/invoices/7', '/api/invoices/70'); apart('/api/invoices/7', '/api/notes/7');
  assert.notEqual(sentRoute('/api/invoices/7', 'k1'), sentRoute('/api/invoices/7', 'k2'), 'keyed');
  assert.ok(/^[a-f0-9]{64}$/.test(sentRoute('/%E0%A4%A/7', 'k')), 'a segment that does not decode is kept as it is');
  // What a row records, and its shape (the validator): [index, field, value] entries.
  const classes = new Map([['X', [[0, 2, 5]]]]);
  const recorded = controlScopeEvidence({ id: 'X' }, obs({ title: 'March rent', saved: true }), '/api/invoices/7', 'k', classes);
  assert.deepEqual(recorded, { cleanObject: true, recordPredicates: [[0, 2, 5]], sentRoute: sentRoute('/api/invoices/7', 'k'), bodyKeys: digest({ key: 'k', bodyKeys: ['saved', 'title'] }) });
  assert.deepEqual(controlScopeEvidence({ id: 'X' }, null, null, 'k', classes), { cleanObject: false, recordPredicates: [[0, 2, 5]], sentRoute: null, bodyKeys: null }, 'a row that was not sent');
  assert.deepEqual(controlScopeEvidence({ id: 'Y' }, obs({}), '/x', 'k', classes).recordPredicates, [], 'a check without record predicates');
  // The key set is keyed, read in sorted order, and recorded only for a clean object.
  assert.equal(controlScopeEvidence({ id: 'X' }, obs({ saved: false, title: 'Other' }), '/a/1', 'k', classes).bodyKeys, recorded.bodyKeys, 'the same keys in any order and with any values');
  assert.notEqual(controlScopeEvidence({ id: 'X' }, obs({ title: 'March rent' }), '/a/1', 'k', classes).bodyKeys, recorded.bodyKeys, 'another key set');
  assert.notEqual(controlScopeEvidence({ id: 'X' }, obs({ title: 'March rent', saved: true }), '/a/1', 'k2', classes).bodyKeys, recorded.bodyKeys, 'keyed');
  assert.equal(controlScopeEvidence({ id: 'X' }, obs({ title: 'x', error: 'y' }), '/a/1', 'k', classes).bodyKeys, null, 'not clean: none');
  const hex = v => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v), preds = [{ kind: 'json.equals' }, { kind: 'json.equals' }], ok = { isDigest: hex, completeJSON: true, sent: true };
  assert.equal(controlScopeShape(recorded, preds, ok), true);
  assert.equal(controlScopeShape({ ...recorded, recordPredicates: [[0, 0, 0], [1, 0, 1]] }, preds, ok), true, 'two entries in index order');
  assert.equal(controlScopeShape({ cleanObject: false, recordPredicates: [], sentRoute: null, bodyKeys: null }, [], { isDigest: hex, sent: false }), true, 'not sent');
  for (const [value, predicates, options, why] of [[{ ...recorded, cleanObject: true }, preds, { ...ok, completeJSON: false }, 'clean on a body that is not complete JSON'],
    [{ ...recorded, sentRoute: null }, preds, ok, 'sent without a route'], [recorded, preds, { ...ok, sent: false }, 'not sent with a route'], [{ ...recorded, sentRoute: 'x' }, preds, ok, 'not a digest'],
    [{ ...recorded, recordPredicates: [[2, 0, 0]] }, preds, ok, 'an index past the predicates'], [{ ...recorded, recordPredicates: [[1, 0, 0], [0, 0, 0]] }, preds, ok, 'unsorted'], [{ ...recorded, recordPredicates: [[0, 0, 0], [0, 0, 1]] }, preds, ok, 'repeated'],
    [{ ...recorded, recordPredicates: [[0, 0, 0]] }, [{ kind: 'json.exists' }], ok, 'an index of another kind'], [{ ...recorded, recordPredicates: [[-1, 0, 0]] }, preds, ok, 'negative'], [{ ...recorded, recordPredicates: [['0', 0, 0]] }, preds, ok, 'not an integer'],
    [{ ...recorded, recordPredicates: [0] }, preds, ok, 'a bare index'], [{ ...recorded, recordPredicates: [[0, 0]] }, preds, ok, 'two numbers'], [{ ...recorded, recordPredicates: [[0, 0, 0, 0]] }, preds, ok, 'four numbers'],
    [{ ...recorded, recordPredicates: [[0, 500, 0]] }, preds, ok, 'a field rank past the limit'], [{ ...recorded, recordPredicates: [[0, 0, 1.5]] }, preds, ok, 'a value rank that is not an integer'],
    [{ ...recorded, cleanObject: 'yes' }, preds, ok, 'not a boolean'], [{ ...recorded, extra: 1 }, preds, ok, 'a fifth field'], [{ cleanObject: true, recordPredicates: [[0, 0, 0]], sentRoute: recorded.sentRoute }, preds, ok, 'a field missing'], [null, preds, ok, 'not an object'],
    [{ ...recorded, bodyKeys: null }, preds, ok, 'a clean object without its key set'], [{ ...recorded, cleanObject: false }, preds, ok, 'a key set without a clean object'], [{ ...recorded, bodyKeys: 'x' }, preds, ok, 'a key set that is not a digest'],
    [recorded, null, ok, 'no predicates']])
    assert.equal(controlScopeShape(value, predicates, options), false, why);
});
