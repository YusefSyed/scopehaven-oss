// In-doubt resolution by read-back of the system of record: the declaration and every refusal, the records, templates, the sealed
// shapes, every derivation row, the profile and value clashes, and the reader against a loopback
// system of record through a real egress recorder: each read failure (a 5xx, an unproven or non-JSON reply, a list over the cap or of another
// shape, ids missing, the complete signal false, a timeout, an abandoned pre-image) reads in doubt, the pre-image is taken before any member is
// forwarded, and no id, path value, token or proof secret is ever written. Owned synthetic data and dummy secrets in env objects only (never the
// process environment); loopback only: 127.0.0.1, no provider, no hosted write, no spend.
import test from 'node:test';
import assert from 'node:assert/strict';
import { request } from 'node:http';
import { validateEgressConfig } from '../src/egress-rules.mjs';
import { declaredObserverRecord, redecideResolved, decideEffects, effectTrace, recomputeEffectTrace } from '../src/http-effects.mjs';
import { validateTargetFile, identityControlPlan } from '../src/contracts.mjs';
import { plannedTimingTerms, validateTiming } from '../src/http-timing.mjs';
import { fateOf, attemptBasis, boundRecords, bindResolutions, lateEntriesFor } from '../src/in-doubt.mjs';
import { readBackRecord, validReadBackRecord, validReadBackSend, validReadBackRead, parseTemplate, bindTemplate, fillTemplate, readBackClash, readBackSecretValueClash, readBackReserveMs, READ_BACK_BOUNDS } from '../src/read-back-rules.mjs';
import { createEgressRecorder } from '../integrations/observers/egress-recorder.mjs';
import { freePorts } from '../integrations/observers/fixtures/free-port.mjs';
import { createReadBackStub } from './fixtures/read-back-stub.mjs';
import * as C from './fixtures/in-doubt-r2-cases.mjs';

const ACTORS = { member: { principalId: 'member-1' } };
const json = value => JSON.parse(JSON.stringify(value));
const decl = (patch = {}, route = {}) => { const d = C.declaration(); Object.assign(d.destinations[0], patch); if (Object.keys(route).length) d.destinations[0].readBack.routes = [{ ...d.destinations[0].readBack.routes[0], ...route }]; return d; };
const refuses = (d, re) => assert.throws(() => validateEgressConfig(d, ACTORS), re);
const drop = (o, k) => { const { [k]: _x, ...rest } = o; return rest; };

test('1. the declaration: a full one normalizes; every rule refuses what breaks it; the loader\'s record is the recorder\'s', () => {
  const cfg = validateEgressConfig(C.declaration(), ACTORS), d = cfg.destinations[0];
  assert.deepEqual([d.credentialHeader, d.backend, d.readBack.timeoutMs, d.readBack.scopeHeaders, Object.keys(d.readBack.identities)], ['authorization', 'crm', 1000, [], ['app', 'jobs']]);
  assert.equal(JSON.stringify(readBackRecord(cfg.destinations)), JSON.stringify(declaredObserverRecord([C.declaration()])[0].readBack), 'one record, whoever builds it');
  assert.ok(validReadBackRecord(C.RECORDS.full.readBack));
  assert.deepEqual(C.RECORDS.full.readBack.backends, { [C.CRM]: 'crm', [C.ALT]: 'other' });
  assert.equal(Object.hasOwn(C.RECORDS.plain, 'readBack'), false, 'no readBack, no record');
  // Destination keys.
  const noForward2 = C.declaration(); noForward2.destinations[0].forward = drop(drop(noForward2.destinations[0].forward, 'proofVersion'), 'ids');
  refuses(noForward2, /"readBack" needs "forward" with "proofVersion": 2/);
  refuses(decl({ credentialHeader: undefined }), /"credentialHeader" is required/);
  refuses(decl({ credentialHeader: 'cookie' }), /"credentialHeader" is required/);
  refuses(decl({ credentialHeader: 'idempotency-key' }), /"credentialHeader" is required/);
  const loose = C.declaration({ readBack: false }); loose.destinations[0].credentialHeader = 'authorization';
  refuses(loose, /"credentialHeader" is declared with "readBack"/);
  const unforwarded = C.declaration({ readBack: false }); unforwarded.destinations[1] = { host: C.ALT, backend: 'x' };
  refuses(unforwarded, /"backend" is a label/);
  // readBack keys.
  const rb = C.readBackOf();
  refuses(decl({ readBack: { ...rb, credential: { env: 'CRM_READ', header: 'authorization' } } }), /"readBack.credential"/);
  refuses(decl({ readBack: { ...rb, credential: { ...rb.credential, header: 'host' } } }), /"readBack.credential"/);
  refuses(decl({ readBack: drop(rb, 'scopeHeaders') }), /"readBack.scopeHeaders" is required/);
  refuses(decl({ readBack: { ...rb, scopeHeaders: ['authorization'] } }), /"readBack.scopeHeaders"/);
  refuses(decl({ readBack: { ...rb, identities: {} } }), /"readBack.identities"/);
  refuses(decl({ readBack: { ...rb, identities: { app: { env: rb.credential.env } } } }), /"readBack.identities"/);
  refuses(decl({ readBack: { ...rb, identities: { app: { env: 'SCOPEHAVEN_TARGET_X' }, jobs: { env: 'SCOPEHAVEN_TARGET_X' } } } }), /"readBack.identities"/);
  refuses(decl({ readBack: { ...rb, timeoutMs: 50 } }), /"readBack.timeoutMs"/);
  // Route keys.
  refuses(decl({}, { write: 'GET /tickets/{ticket}/notes' }), /"write" is a method that can change state/);
  refuses(decl({}, { write: 'POST /tickets/{t}/{t}' }), /"write"/);
  refuses(decl({}, { read: 'GET /tickets/{other}/notes' }), /"read" is "GET"/);
  refuses(decl({}, { read: 'GET /tickets/{ticket}/notes?all=1' }), /"read" is "GET"/);
  refuses(decl({}, { items: 'notes' }), /"items"/);
  refuses(decl({}, { author: { pointer: '/author' } }), /"author" is \{ pointer, serverAssigned: true \}/);
  refuses(decl({}, { settleMs: 0 }), /"settleMs" is an integer from 1 to 120000/);
  refuses(decl({}, { settleMs: 100 }), /never below its documented "guarantees.settleMs"/);
  refuses(decl({}, { guarantees: drop(C.VARIANTS.full.guarantees, 'source') }), /"guarantees" is/);
  refuses(decl({}, { guarantees: { ...C.VARIANTS.full.guarantees, consistency: 'linearizable' } }), /"guarantees" is/);
  refuses(decl({}, { complete: { pointer: '/complete' } }), /"complete" is \{ pointer, equals \}/);
  refuses(decl({}, { match: { fields: { '/text': '/note' } } }), /"match.fields"/);
  refuses(decl({}, { match: { fields: { '/text': '/body' }, key: '/key' } }), /"match" is/);
  refuses(decl({}, { lifecycle: { pointer: '/state', applied: ['posted'], notApplied: ['posted'] } }), /each state word once/);
  refuses(decl({}, { view: { covers: ['nobody'], items: 'all-items' } }), /"view"/);
  refuses(decl({}, { deferredFields: undefined }), /"deferredFields" is required/);
  refuses(decl({}, { deferredFields: ['/publish_at'] }), /"deferredFields" is required/);
  refuses(decl({}, { control: { bind: {} } }), /"control"/);
  refuses(decl({}, { control: { bind: { ticket: '..' } } }), /"control"/);
  refuses(decl({}, { touches: ['GET /tickets/{ticket}'] }), /"touches"/);
  const keyed = C.declaration(); keyed.destinations[0].readBack.routes[0] = { ...C.VARIANTS.full, match: { key: '/key', serverAssigned: true } };
  validateEgressConfig(keyed, ACTORS);
  refuses((() => { const k = structuredClone(keyed); k.destinations[0].readBack.routes[0].match = { key: '/key' }; return k; })(), /"match" is/);
  delete keyed.destinations[0].idempotency; refuses(keyed, /"match.key"/);
  const twice = C.declaration(); twice.destinations[0].readBack.routes.push(C.VARIANTS.full);
  refuses(twice, /declared once/);
  // A record whose route was edited is not valid: the record re-validates every route.
  for (const edit of [r => { r.settleMs = 1; }, r => { r.extra = true; }, r => { r.guarantees.consistency = 'eventual-ish'; }, r => { r.view.covers = ['nobody']; }, r => { r.write = 'GET /x'; }]) {
    const rec = json(C.RECORDS.full.readBack); edit(rec.hosts[C.CRM].routes[0]);
    assert.equal(validReadBackRecord(rec), false);
  }
  // Read endpoints of another shape: an object read with a change log, a declined lifecycle with non-final words, no
  // complete field (single-object completeness), eventual consistency and possible removal all declare (and can then only confirm).
  const e3 = C.declaration(); e3.destinations[0].readBack.routes[0] = { write: 'POST /tickets/{ticket}/notes', read: 'GET /tickets/{ticket}/notes', items: '/changes', id: '/id', author: { pointer: '/author', serverAssigned: true }, settleMs: 500,
    lifecycle: { pointer: '/to', applied: ['cancelled'], notApplied: ['shipped', 'delivered'], nonFinal: ['pending'] }, guarantees: { consistency: 'eventual', completeness: 'single-object', removal: 'possible', settleMs: 500, source: 'ENV-DP6 section R1' },
    view: { covers: ['app', 'jobs'], items: 'all-items' }, deferredFields: [], control: { bind: { ticket: 'o-ctrl' }, identities: ['app'] } };
  validateEgressConfig(e3, ACTORS);
});

test('2. templates: a write binds only literal-equal paths and placeholders of the charset alone, raw and decoded agreeing; the read is filled from those bindings only', () => {
  const w = parseTemplate('POST /tickets/{ticket}/notes', 'write'), r = parseTemplate('GET /tickets/{ticket}/notes', 'read');
  assert.deepEqual(bindTemplate(w, 'POST', '/tickets/T-1/notes'), { ticket: 'T-1' });
  assert.equal(fillTemplate(r, { ticket: 'T-1' }), '/tickets/T-1/notes');
  for (const [method, path] of [['PUT', '/tickets/T-1/notes'], ['POST', '/tickets/T-1/notes/x'], ['POST', '/tickets/T%2D1/notes'], ['POST', '/tickets/../notes'], ['POST', '/tickets/./notes'], ['POST', '/tickets/T-1/note'], ['POST', '/tickets/T-1/notes?x=1'], ['POST', '/tickets//notes'], ['POST', `/tickets/${'a'.repeat(129)}/notes`]]) {
    assert.equal(bindTemplate(w, method, path), null, `${method} ${path}`);
  }
  assert.equal(parseTemplate('GET /tickets/{ticket}/notes', 'write'), null);
  assert.equal(parseTemplate('POST /tickets/{ticket}/notes', 'read'), null);
  assert.equal(fillTemplate(r, {}), null);
});

test('3. the sealed shapes (m2): per send and per read, counts, flags and times only, internally consistent; anything else is refused', () => {
  const e = C.send({ seq: 1 });
  assert.ok(validReadBackSend(e.upstream.readBack, C.RECORDS.full.readBack.hosts[C.CRM].routes));
  for (const edit of [r => { r.route = 1; }, r => { r.group = 'x'; }, r => { r.preImage = 'none'; }, r => { r.extra = 1; }, r => { r.touches = []; }, r => { r.touches = ['b'.repeat(64), 'a'.repeat(64)]; }, r => { r.preImageMs = -1; },
    r => { r.credential = null; }, r => { r.route = null; }]) {
    const rec = structuredClone(e.upstream.readBack); edit(rec);
    assert.equal(validReadBackSend(rec, C.RECORDS.full.readBack.hosts[C.CRM].routes), false, String(edit));
  }
  assert.ok(validReadBackSend({ route: null, group: null, object: null, touches: null, credential: null, scopeUndeclared: false, authorInBody: false, preImage: 'none', preImageMs: null, forwardMono: null }, []));
  for (const forwardMono of [-1, 'x']) assert.equal(validReadBackSend({ ...e.upstream.readBack, forwardMono }, C.RECORDS.full.readBack.hosts[C.CRM].routes), false);
  const read = C.honest({ added: [{ id: 'n1', author: 'app', state: 'posted', text: 'hello' }] });
  assert.ok(validReadBackRead(read));
  const EDITS = [r => { delete r.laterTouching; }, r => { r.groupSends = 0; }, r => { r.s1.credNew = 5; }, r => { r.s1.credApplied = 0; }, r => { r.s2.outcome = 'status'; }, r => { r.s3.atMono = null; },
    r => { r.pre.newIds = 1; }, r => { r.control.mInRead = 1; }, r => { r.s1.credChanged = 1; }, r => { r.s1.lateNew = 1; }, r => { r.s1.total = 1001; }, r => { r.identity = 'Not A Label'; }, r => { r.s2.atMono = r.s2.doneMono + 1; },
    r => { r.s1.anonNew = 2; }, r => { r.s1.extra = 0; }];
  for (const edit of EDITS) { const r = structuredClone(read); edit(r); assert.equal(validReadBackRead(r), false, String(edit)); }
  // A read never sent has no times and no counts; one that failed has times and no counts.
  const notRun = structuredClone(read); notRun.s3 = { ...notRun.s3, outcome: 'not-run', atMono: null, doneMono: null, atWall: null, complete: false, ...Object.fromEntries(['total', 'missingPre', 'newIds', 'newInM', 'mInRead', 'credItems', 'credNew', 'credApplied', 'credNotApplied', 'credOther', 'credUnmatched', 'credChanged', 'anonNew', 'lateNew'].map(k => [k, 0])) };
  assert.ok(validReadBackRead(notRun));
});

// --- The derivation, row by row ----------------------------------------------------------------------------------------------------------
// One group on T-1 under the app's credential. members: [{ outcome, ...send fields }]; read: the group's sealed read (C.honest by default).
function decide(members, read, { variant = 'full', others = [], effects = [C.EXISTS, C.count(0), C.count(1)] } = {}) {
  let n = 0;
  const events = members.map((m, i) => C.send({ seq: C.START + i, end: 1050 + 20 * i, preImage: i === 0 ? 'first' : 'member', firstSeq: C.START, minted: `m${C.START + i}`, ...m }));
  const extra = others.map((o, i) => C.send({ seq: C.START + 50 + i, key: `K-other-${i}`, ...o }));
  const w = C.windowOf([...events, ...extra], { variant });
  const supplied = events.filter(e => e.upstream.outcome === 'unknown' && e.upstream.transport?.connected).map(e => C.supplied(e, typeof read === 'function' ? read(e, n++) : read));
  const [again] = redecideResolved([{ effects, claims: [], readings: [], role: 'boundary', windows: [w] }], supplied);
  const decisions = again ?? decideEffects(effects, [w]);
  return { fates: events.map(e => (e.upstream.outcome === 'unknown' && e.upstream.transport?.connected ? fateOf(e) : null)), r2: events.map(e => { const r = boundRecords(e).find(x => x.resolver === 'r2'); return r ? (r.status === 'failed' ? `failed:${r.reason}` : r.result) : null; }),
    verdicts: decisions.map(d => d.verdict), events, window: w, decisions };
}
const NOTE = (id, extra = {}) => ({ id, author: 'app', state: 'posted', text: 'hello', ...extra });
const r2Of = (members, read, opts) => decide(members, read, opts).r2;
// A group read from explicit lists per read (the recorder's own counting): pre, s1, s2, s3 lists of notes; times as C.honest's.
const lists = ({ pre = [], s1 = pre, s2 = s1, s3 = s2, M = [], counts = {}, lastEnd = 1100, control = true }) => {
  const ctx = { identity: 'app', text: 'hello' }, at1 = lastEnd + C.SETTLE + 1, at2 = at1 + C.SETTLE + 6, at3 = at2 + 50;
  return C.sealed({ M, counts, reads: { pre: C.okRead(C.START + 100, pre, ctx), s1: C.okRead(at1, s1, ctx), s2: C.okRead(at2, s2, ctx), s3: C.okRead(at3, s3, ctx), control: control ? C.okRead(at3, [NOTE('ctl')], ctx) : null } });
};

test('4. derivation: refutation, confirmation, the exact count and its assignment within one identity', () => {
  // Reset before apply: nothing new on S1 or S2, sighted through the control item: refuted; the agent-write exists fails, exactly zero passes (before any
  // later stage), exactly one fails.
  const rb = decide([{ outcome: 'reset' }], C.honest());
  assert.deepEqual([rb.r2, rb.verdicts, rb.fates], [['refutes'], ['fail', 'pass', 'fail'], ['refuted']]);
  assert.equal(attemptBasis(rb.events[0]).by, 'r2');
  // Reset after apply: the write's own note (G's identity, matching): confirmed; exists and exactly one pass.
  const ra = decide([{ outcome: 'reset' }], C.honest({ added: [NOTE('n1')] }));
  assert.deepEqual([ra.r2, ra.verdicts], [['confirms'], ['pass', 'fail', 'pass']]);
  // A proven retry beside a reset: its minted note is the only new item, so the reset is refuted as a further application.
  const ps1 = decide([{ outcome: 'reset' }, { outcome: 'applied' }], C.honest({ added: [NOTE(`m${C.START + 1}`)], M: [`m${C.START + 1}`], counts: { groupSends: 2 } }));
  assert.deepEqual([ps1.r2, ps1.verdicts], [['refutes', null], ['pass', 'fail', 'pass']]);
  // ... and a second note beside the minted one, under another key, is the reset's: confirmed, and exactly one fails (two applications).
  const dup = decide([{ outcome: 'reset' }, { outcome: 'applied', key: 'K2', firstSeq: C.START + 1 }], C.honest({ added: [NOTE(`m${C.START + 1}`), NOTE('n1')], M: [`m${C.START + 1}`], counts: { groupSends: 2 } }));
  assert.deepEqual([dup.r2, dup.verdicts], [['confirms', null], ['pass', 'fail', 'fail']]);
  // Two resets and one note: exactly one of them applied. Within one identity the first is confirmed and the second refuted; exactly one passes.
  const two = decide([{ outcome: 'reset' }, { outcome: 'reset' }], C.honest({ added: [NOTE('n1')], counts: { groupSends: 2 } }));
  assert.deepEqual([two.r2, two.verdicts], [['confirms', 'refutes'], ['pass', 'fail', 'pass']]);
  // Two resets under one key and one body (one identity to read-back and to the key collapse): on a backend that dedupes the key
  // (one note) the first is confirmed and the second refuted, and every keyed and plain clause reads one application. On one that does not
  // (two notes) read-back would confirm both while the collapse reads them as one, so it confirms nothing: in doubt, as without read-back.
  const KEYED = [C.KEYED_COUNT(1), C.KEYED_COUNT(2), C.count(1), C.count(2), C.EXISTS];
  const dedupes = decide([{ outcome: 'reset' }, { outcome: 'reset' }], C.honest({ added: [NOTE('n1')], counts: { groupSends: 2 } }), { effects: KEYED });
  assert.deepEqual([dedupes.r2, dedupes.verdicts], [['confirms', 'refutes'], ['pass', 'fail', 'pass', 'fail', 'pass']], 'a deduping backend');
  const twice = decide([{ outcome: 'reset' }, { outcome: 'reset' }], C.honest({ added: [NOTE('n1'), NOTE('n2')], counts: { groupSends: 2 } }), { effects: KEYED });
  const without = decide([{ outcome: 'reset' }, { outcome: 'reset' }], { ...C.honest({ added: [NOTE('n1'), NOTE('n2')], counts: { groupSends: 2 } }), identity: null }, { effects: KEYED });
  assert.deepEqual([twice.r2, twice.verdicts], [['silent', 'silent'], without.verdicts], 'a backend that applied one key twice: nothing confirmed');
  assert.ok(twice.verdicts[0] !== 'pass' && twice.verdicts[2] !== 'pass', 'neither exactly-one passes');
  // The same under two keys: the collapse counts two applications too, so both are confirmed and every clause reads two.
  const twoKeys = decide([{ outcome: 'reset' }, { outcome: 'reset', key: 'K2', firstSeq: C.START + 1 }], C.honest({ added: [NOTE('n1'), NOTE('n2')], counts: { groupSends: 2 } }), { effects: KEYED });
  assert.deepEqual([twoKeys.r2, twoKeys.verdicts], [['confirms', 'confirms'], ['fail', 'pass', 'fail', 'pass', 'pass']], 'two keys, two applications');
  // A proven retry and a reset under one key, with two notes (the backend applied the key twice): the reset is not confirmed beside the retry.
  assert.deepEqual(r2Of([{ outcome: 'reset' }, { outcome: 'applied' }], C.honest({ added: [NOTE(`m${C.START + 1}`), NOTE('n1')], M: [`m${C.START + 1}`], counts: { groupSends: 2 } })), ['silent', null]);
  // Members of two identities (one body's deferred field is null, the other's absent): the count is not assigned.
  assert.deepEqual(r2Of([{ outcome: 'reset' }, { outcome: 'reset', sendAt: null }], C.honest({ added: [NOTE('n1')], counts: { groupSends: 2 } })), ['silent', 'silent']);
  assert.deepEqual(r2Of([{ outcome: 'reset' }, { outcome: 'applied', sendAt: null }], C.honest({ added: [NOTE(`m${C.START + 1}`)], M: [`m${C.START + 1}`], counts: { groupSends: 2 } })), ['silent', null], 'beside a proven member of another identity');
  // Nothing new at all refutes every member whatever their identities.
  assert.deepEqual(r2Of([{ outcome: 'reset' }, { outcome: 'reset', sendAt: null }], C.honest({ counts: { groupSends: 2 } })), ['refutes', 'refutes']);
  // A member the transport record refuted (never connected) leaves D, so a group of a refused send and a reset with one note confirms the reset.
  assert.deepEqual(r2Of([{ outcome: 'refused' }, { outcome: 'reset' }], C.honest({ added: [NOTE('n1')], counts: { groupSends: 2 } })), [null, 'confirms']);
  // Lifecycle (a declined state): G's own note in a declared notApplied state is a final non-application, so the exact count refutes; a pending one blocks.
  assert.deepEqual(r2Of([{ outcome: 'reset' }], C.honest({ added: [NOTE('d1', { state: 'declined' })], lifecycle: true }), { variant: 'lifecycle' }), ['refutes']);
  assert.deepEqual(r2Of([{ outcome: 'reset' }], C.honest({ added: [NOTE('d1', { state: 'pending' })], lifecycle: true }), { variant: 'lifecycle' }), ['silent']);
  // Another identity's identical note (another credential) is not G's: the exact count is P, so G is refuted; it never confirms G.
  assert.deepEqual(r2Of([{ outcome: 'reset' }], C.honest({ added: [NOTE('x1', { author: 'jobs' })] })), ['refutes']);
  // A note with no author could be anyone's: it blocks the exact count, so neither side decides.
  assert.deepEqual(r2Of([{ outcome: 'reset' }], C.honest({ added: [NOTE('a1', { author: null })] })), ['silent']);
  // A pre-existing identical note is in the pre-image: never new, never a confirmation.
  assert.deepEqual(r2Of([{ outcome: 'reset' }], C.honest({ pre: [NOTE('old')] })), ['refutes']);
  // Normalized text (an item of G's identity that matches no member): no confirmation, and the cap leaves one possible application.
  assert.deepEqual(r2Of([{ outcome: 'reset' }], C.honest({ added: [NOTE('n1', { text: 'Hello' })] })), ['silent']);
  // An empty interval (two notes of G's identity for one in-doubt member, nothing proven): a conflict, failed.
  assert.deepEqual(r2Of([{ outcome: 'reset' }], C.honest({ added: [NOTE('n1'), NOTE('n2')] })), ['failed:read-conflict']);
});

test('4b. refutation and the cap read a missing new item, so they hold only on a POST whose host declares minted ids; a write that changes an item in place, or a host without minted ids, only confirms', () => {
  // Note N1 exists; the in-doubt write applied and changed N1 in place, so S1 to S3 list the same ids as S0.
  const N1 = NOTE('N1', { text: 'older' }), inPlace = C.honest({ pre: [N1] });
  for (const [variant, resource] of [['patch', 'PATCH /tickets/T-1/notes'], ['put', 'PUT /tickets/T-1/notes']]) {
    const clauses = [{ ...C.count(0), select: C.sel(resource, 'resolved') }, { ...C.EXISTS, select: C.sel(resource, 'resolved') }];
    const d = decide([{ outcome: 'reset', resource }], inPlace, { variant, effects: clauses });
    assert.deepEqual([d.r2, d.fates, d.verdicts], [['silent'], ['in-doubt'], ['missing', 'missing']], `${variant}: never refuted, so count(0) never passes`);
    assert.deepEqual(recomputeEffectTrace(json(effectTrace(d.decisions, [d.window], C.META)), undefined, [C.RECORDS[variant]]).decisions.map(x => x.verdict), d.verdicts, `${variant}: the validator agrees`);
    // A note the write did create still confirms (a new item of the identity is an application on any route).
    assert.deepEqual(decide([{ outcome: 'reset', resource }], C.honest({ pre: [N1], added: [NOTE('n1')] }), { variant, effects: clauses }).r2, ['confirms'], `${variant}: confirms`);
  }
  // The same POST route on a host that declares no minted ids: no refutation, confirmation unchanged.
  assert.deepEqual([r2Of([{ outcome: 'reset' }], C.honest(), { variant: 'noMinted' }), r2Of([{ outcome: 'reset' }], C.honest({ added: [NOTE('n1')] }), { variant: 'noMinted' })], [['silent'], ['confirms']]);
  // A route whose write creates two items per application (the note and an audit entry by the same identity in the same collection): the
  // second item matches no member, so nothing is confirmed, and two new items cap nothing below the members: in doubt, one reset or two.
  const audit = NOTE('a1', { text: 'audit: note added' });
  assert.deepEqual(r2Of([{ outcome: 'reset' }], C.honest({ added: [NOTE('n1'), audit] })), ['silent']);
  assert.deepEqual(r2Of([{ outcome: 'reset' }, { outcome: 'reset' }], C.honest({ added: [NOTE('n1'), audit], counts: { groupSends: 2 } }), { effects: [C.count(2), C.count(1)] }), ['silent', 'silent']);
  // The record says which route a send bound, and the derivation reads the route's method from it: a POST group still refutes as before.
  assert.deepEqual(r2Of([{ outcome: 'reset' }], C.honest()), ['refutes']);
});

test('5. derivation: every read failure and bound violation fails the group; every missing precondition leaves it silent', () => {
  const ok = C.honest();
  const failed = (edit, reason, members = [{ outcome: 'reset' }]) => { const r = structuredClone(ok); edit(r); assert.deepEqual(r2Of(members, r), members.filter(m => m.outcome === 'reset').map(() => `failed:${reason}`), reason); };
  const zero = x => ({ ...x, complete: false, ...Object.fromEntries(['total', 'missingPre', 'newIds', 'newInM', 'mInRead', 'credItems', 'credNew', 'credApplied', 'credNotApplied', 'credOther', 'credUnmatched', 'credChanged', 'anonNew', 'lateNew'].map(k => [k, 0])) });
  for (const [k, outcome, reason] of [['pre', 'abandoned', 'pre-image-abandoned'], ['pre', 'status', 'pre-image-status'], ['s1', 'status', 'read-s1-status'], ['s1', 'unproven', 'read-s1-unproven'], ['s2', 'not-json', 'read-s2-not-json'],
    ['s2', 'over-cap', 'read-s2-over-cap'], ['s2', 'shape', 'read-s2-shape'], ['s1', 'ids', 'read-s1-ids'], ['s2', 'incomplete', 'read-s2-incomplete'], ['s1', 'timeout', 'read-s1-timeout'], ['s3', 'failed', 'read-s3-failed']]) {
    failed(r => { r[k] = zero({ ...r[k], outcome }); }, reason);
  }
  failed(r => { r.s3 = zero({ ...r.s3, outcome: 'not-run', atMono: null, doneMono: null, atWall: null }); }, 'read-s3-not-run');
  failed(r => { r.s1.atMono = 1050 + C.SETTLE - 1; r.s1.atWall = C.OFFSET + r.s1.atMono; }, 'read-before-bound');
  failed(r => { r.s2.atMono = r.s1.atMono + C.SETTLE - 1; r.s2.doneMono = r.s2.atMono + 5; r.s2.atWall = C.OFFSET + r.s2.atMono; }, 'reads-too-close');
  failed(r => { r.s3.atMono = r.s2.doneMono - 1; }, 'read-order');
  failed(r => { r.pre.doneMono = 2000; r.pre.atMono = 1999; r.pre.atWall = C.OFFSET + 1999; }, 'pre-image-late');
  // The sealed forward start must follow the pre-image's end (the recorder makes every member's forward wait for it).
  assert.deepEqual([r2Of([{ outcome: 'reset', forwardMono: 1000 }], C.honest()), r2Of([{ outcome: 'reset', forwardMono: null }], C.honest())], [['failed:pre-image-late'], ['failed:pre-image-late']]);
  failed(r => { r.group = 'f'.repeat(64); }, 'group-mismatch');
  failed(r => { r.credential = C.CRED.jobs; }, 'credential-mismatch');
  failed(r => { r.groupSends = 2; }, 'group-other-window');
  failed(r => { r.s3.missingPre = 1; }, 'read-late-removal');
  // S3: a late note of G's identity, or a late note of anyone, that no later send to the object explains.
  assert.deepEqual(r2Of([{ outcome: 'reset' }], C.honest({ s3extra: [NOTE('late')] })), ['failed:read-late-item']);
  assert.deepEqual(r2Of([{ outcome: 'reset' }], C.honest({ s3extra: [NOTE('late', { author: null })] })), ['failed:read-late-item']);
  assert.deepEqual(r2Of([{ outcome: 'reset' }], C.honest({ s3extra: [NOTE('late')], counts: { laterCred: 1, laterTouching: 1 } })), ['refutes'], 'explained by a later send under the credential');
  // A pre-image item gone at S3 with no later removal sent: withdrawn. A later non-POST send to the object explains it, so the group is not
  // failed, but refutation still needs every pre-image id on S1, S2 and S3: silent.
  const old = NOTE('old', { text: 'older' });
  assert.deepEqual(r2Of([{ outcome: 'reset' }], lists({ pre: [old], s3: [] })), ['failed:read-late-removal']);
  assert.deepEqual(r2Of([{ outcome: 'reset' }], lists({ pre: [old], s3: [], counts: { laterRemovals: 1 } })), ['silent']);
  // Two members took a pre-image, or none: the order is not one the recorder makes.
  assert.deepEqual(r2Of([{ outcome: 'reset' }, { outcome: 'reset', preImage: 'first' }], C.honest({ counts: { groupSends: 2 } })), ['failed:pre-image-order', 'failed:pre-image-order']);
  // Two members carrying different reads of one group: not one recorder's read, so the connector fails both (readBackDisagreeing; the validator
  // refuses such a run, consistentReadBackRun); bound directly, the derivation reads them as a mismatch.
  assert.deepEqual(r2Of([{ outcome: 'reset' }, { outcome: 'reset' }], (e, i) => (i === 0 ? C.honest({ counts: { groupSends: 2 } }) : { ...C.honest({ counts: { groupSends: 2 } }), early: true })), ['failed:record-inconsistent', 'failed:record-inconsistent']);
  {
    const events = [C.send({ seq: 1, end: 1050 }), C.send({ seq: 2, end: 1060, preImage: 'member', firstSeq: 1 })], w = C.windowOf(events);
    bindResolutions([w], [C.supplied(events[0], C.honest({ counts: { groupSends: 2 } })), C.supplied(events[1], { ...C.honest({ counts: { groupSends: 2 } }), early: true })]);
    assert.deepEqual(events.map(e => boundRecords(e).find(r => r.resolver === 'r2').reason), ['record-mismatch', 'record-mismatch']);
    // A member with no read at all: the group is unresolved.
    bindResolutions([w], [C.supplied(events[0], C.honest({ counts: { groupSends: 2 } }))]);
    assert.equal(boundRecords(events[0]).find(r => r.resolver === 'r2').reason, 'group-unresolved');
  }
  const silent = (edit, members = [{ outcome: 'reset' }], opts = {}) => assert.deepEqual(r2Of(members.map(m => ({ ...m })), (() => { const r = structuredClone(ok); edit(r); return r; })(), opts), members.map(() => 'silent'), String(edit));
  silent(r => { r.early = true; });
  silent(r => { r.intervening = 1; });
  silent(() => {}, [{ outcome: 'reset', authorInBody: true }]);
  silent(r => { r.pre.mInRead = 1; r.pre.total = 1; });
  // Another group's send to the same ticket in the window (another note body) intervenes even when the recorder's count says none.
  assert.deepEqual(r2Of([{ outcome: 'reset' }], C.honest(), { others: [{ outcome: 'applied', binding: 'other text', end: 1080, minted: 'zz' }] }), ['silent']);
  // ... while a send to another ticket on a route that declares touches, or to another backend, does not.
  assert.deepEqual(r2Of([{ outcome: 'reset' }], C.honest(), { others: [{ outcome: 'applied', object: 'T2', resource: C.NOTES_T2, credential: 'jobs', end: 1080, minted: 'zz' }, { host: C.ALT, resource: C.ALT_RES, outcome: 'applied', end: 1080, minted: 'zy' }] }), ['refutes']);
  // A proven member without exactly one minted id: M is unknown.
  assert.deepEqual(r2Of([{ outcome: 'reset' }, { outcome: 'applied', minted: null }], C.honest({ counts: { groupSends: 2 } })), ['silent', null]);
});

test('6. derivation: refutation needs every positive control and documented guarantee; confirmation needs exclusivity', () => {
  const rb = C.honest(), ra = C.honest({ added: [NOTE('n1')] });
  // C1: a proven member's minted note not visible on S1 or S2: blind. C2: no item of G's identity on S1, S2 or a control read: blind.
  // A minted note never listed also trips S3's removal alarm (failed); one listed only at S3 leaves S1 and S2 blind (silent).
  assert.deepEqual(r2Of([{ outcome: 'reset' }, { outcome: 'applied' }], C.honest({ M: [`m${C.START + 1}`], counts: { groupSends: 2 } })), ['failed:read-late-removal', null], 'C1 and the S3 alarm');
  const minted = NOTE(`m${C.START + 1}`);
  assert.deepEqual(r2Of([{ outcome: 'reset' }, { outcome: 'applied' }], lists({ s1: [], s2: [], s3: [minted], M: [`m${C.START + 1}`], counts: { groupSends: 2, laterTouching: 1, laterCred: 1 } })), ['silent', null], 'C1');
  assert.deepEqual(r2Of([{ outcome: 'reset' }], C.honest({ control: false })), ['silent'], 'C2 without a control read');
  assert.deepEqual(r2Of([{ outcome: 'reset' }], { ...C.honest({ control: false }), controlStart: C.honest().control }), ['refutes'], 'C2 through the control read taken at the recorder\'s start');
  assert.deepEqual(r2Of([{ outcome: 'reset' }], C.honest({ control: false, pre: [NOTE('own-old', { text: 'older' })] })), ['refutes'], 'C2 through an item of the identity in the read itself');
  // Each guarantee, absent or weaker: RB is no longer refuted, RA still confirmed.
  for (const variant of ['noGuarantees', 'noComplete', 'noView', 'eventual', 'observed', 'removable', 'appOnly', 'partialView']) {
    const reads = variant === 'noComplete' ? [rb, ra].map(r => { const x = structuredClone(r); for (const k of ['pre', 's1', 's2', 's3']) x[k].complete = false; return x; }) : [rb, ra];
    assert.deepEqual([r2Of([{ outcome: 'reset' }], reads[0], { variant }), r2Of([{ outcome: 'reset' }], reads[1], { variant })], [['silent'], ['confirms']], variant);
  }
  // No match declared: refutation stands (it never reads a match), confirmation is gone.
  assert.deepEqual([r2Of([{ outcome: 'reset' }], C.honest({ matchDeclared: false }), { variant: 'noMatch' }), r2Of([{ outcome: 'reset' }], C.honest({ added: [NOTE('n1')], matchDeclared: false }), { variant: 'noMatch' })], [['refutes'], ['silent']]);
  // A deferred field set, a query string or an undeclared tenant header on any member, or a clock offset that moved: no refutation.
  for (const m of [{ sendAt: '2026-10-20T00:00:00Z' }, { query: true }, { scopeUndeclared: true }, { wall: C.OFFSET + 1100 + 5000 }]) {
    assert.deepEqual(r2Of([{ outcome: 'reset', ...m }], rb), ['silent'], JSON.stringify(m));
    assert.deepEqual(r2Of([{ outcome: 'reset', ...m }], ra), ['confirms'], `confirmation unaffected: ${JSON.stringify(m)}`);
  }
  // A pre-image note missing from S1: no refutation and no confirmation.
  assert.deepEqual(r2Of([{ outcome: 'reset' }], lists({ pre: [NOTE('old', { text: 'older' })], s1: [NOTE('n1')], counts: { laterRemovals: 1 } })), ['silent']);
  // Exclusivity: another send under G's credential, or an unknown one, overlapping [pre-image, S2] (the recorder's count): no confirmation; the
  // refutation, which reads no author, still stands.
  assert.deepEqual([r2Of([{ outcome: 'reset' }], { ...ra, credOthers: 1 }), r2Of([{ outcome: 'reset' }], { ...rb, credOthers: 1 })], [['silent'], ['refutes']]);
  // An unmapped credential (a rotated token): no identity, so neither side decides.
  assert.deepEqual([r2Of([{ outcome: 'reset' }], { ...rb, identity: null }), r2Of([{ outcome: 'reset' }], { ...ra, identity: null })], [['silent'], ['silent']]);
});

test('7. the profile clashes: the read credential is ScopeHaven\'s alone (names at load, values at run start); a read-back host is on one recorder only', () => {
  const p = C.profileOf([[C.EXISTS]]);
  validateTargetFile({ schemaVersion: 1, targets: [p] });
  const clash = mutate => { const q = structuredClone(p); mutate(q); return readBackClash(q); };
  assert.equal(readBackClash(p), null);
  assert.match(clash(q => { q.actors.member.credentialEnv = 'SCOPEHAVEN_TARGET_CRM_READ'; }), /read-back credential .* actor "member"/);
  assert.match(clash(q => { q.observers[0].destinations[0].readBack.credential.env = 'SCOPEHAVEN_TARGET_CRM_PROOF'; }), /forward proof/);
  assert.match(clash(q => { q.observers[0].destinations[0].readBack.identities.app.env = 'SCOPEHAVEN_TARGET_ALT_PROOF'; }), /an identity .* names the forward proof/);
  assert.match(clash(q => { q.observers.push({ ...C.declaration({ port: 41001, upstream: 47201 }), id: 'sink2', destinations: [{ host: C.CRM }] }); }), /declared on one recorder only/);
  assert.throws(() => validateTargetFile({ schemaVersion: 1, targets: [(() => { const q = structuredClone(p); q.actors.member.credentialEnv = 'SCOPEHAVEN_TARGET_CRM_READ'; return q; })()] }), /read-back credential/);
  const env = { SCOPEHAVEN_TARGET_CRM_READ: 'same-value-0001', SCOPEHAVEN_TARGET_CRM_APP: 'same-value-0001' };
  assert.match(readBackSecretValueClash(p, env), /must be ScopeHaven's alone/);
  assert.equal(readBackSecretValueClash(p, { ...env, SCOPEHAVEN_TARGET_CRM_APP: 'app-value-0002' }), null);
});

test('8. timing: the plan reserves two settles and three reads per observed check, the run end reserves the same, and a route settle past the horizon is refused', () => {
  const p = { ...C.profileOf([[C.EXISTS], [C.count(1)]]), timing: { effectHorizonMs: 1000, runBudgetMs: 600000 } };
  const terms = plannedTimingTerms(p, { controlPlan: identityControlPlan(p) });
  assert.equal(readBackReserveMs(p.observers), 2 * C.SETTLE + 3 * 1000);
  assert.equal(terms.readBack, 2 * (2 * C.SETTLE + 3 * 1000));
  const plain = { ...C.profileOf([[C.EXISTS]], { readBack: false }), timing: { effectHorizonMs: 1000, runBudgetMs: 600000 } };
  assert.equal(Object.hasOwn(plannedTimingTerms(plain, { controlPlan: identityControlPlan(plain) }), 'readBack'), false, 'no read-back: the plan as without it');
  const slow = structuredClone(p); slow.observers[0].destinations[0].readBack.routes[0].settleMs = 2000; slow.observers[0].destinations[0].readBack.routes[0].guarantees.settleMs = 2000;
  assert.throws(() => validateTiming(slow, { controlPlan: identityControlPlan(slow) }), /timing-read-back-settle/);
  assert.ok(READ_BACK_BOUNDS.preImageMs === 1000);
});

// --- The reader, through a real egress recorder, against the loopback system of record ------------------------------------------------
const ENV = Object.freeze({ SCOPEHAVEN_TARGET_CRM_PROOF: 'synthetic-proof-secret-crm-0000000000000000', SCOPEHAVEN_TARGET_ALT_PROOF: 'synthetic-proof-secret-alt-0000000000000000',
  SCOPEHAVEN_TARGET_CRM_READ: 'tok-read-0000', SCOPEHAVEN_TARGET_CRM_APP: 'tok-app-0000', SCOPEHAVEN_TARGET_CRM_JOBS: 'tok-jobs-0000' });
const TOKENS = { 'tok-app-0000': 'app', 'tok-jobs-0000': 'jobs' };
// One recorder over a fresh stub: writes are sent through it as its proxy, then its run-end resolver read. sends: [{ ticket, text, token, key, delayMs }].
async function recorderRun(t, { plan = () => ({}), readHook = () => ({}), sends = [{}], capMs = 6000, wait = 260, variant = 'full', extra = {} } = {}) {
  const stub = await createReadBackStub({ secret: ENV.SCOPEHAVEN_TARGET_CRM_PROOF, tokens: TOKENS, readToken: ENV.SCOPEHAVEN_TARGET_CRM_READ });
  t.after(() => stub.close());
  stub.seed('T-CTRL', { text: 'seed', author: 'app' });
  stub.plan(plan); stub.readHook(readHook);
  for (let attempt = 0; attempt < 5; attempt++) {
    const [port] = await freePorts(1);
    const recorder = createEgressRecorder({ ...C.declaration({ port, upstream: stub.port, altUpstream: 47999, variant, extra }), instanceId: C.INST, env: ENV, wallClock: () => Date.now(), signingClock: () => Date.now() });
    try { await recorder.start(); } catch { continue; }
    t.after(() => recorder.stop());
    await new Promise(resolve => setTimeout(resolve, wait));
    const send = ({ ticket = 'T-1', text = 'hello', token = 'tok-app-0000', key = 'k-1', delayMs = 0, extraHeaders = {} }) => new Promise(resolve => setTimeout(() => {
      const target = `http://${C.CRM}/tickets/${ticket}/notes`, body = JSON.stringify({ body: text });
      const req = request({ host: '127.0.0.1', port, method: 'POST', path: target, headers: { host: C.CRM, authorization: `Bearer ${token}`, 'idempotency-key': key, 'content-type': 'application/json', ...extraHeaders } }, res => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
      req.on('error', () => resolve(null)); req.end(body);
    }, delayMs));
    const statuses = await Promise.all(sends.map(send));
    const records = await recorder.resolutionRecords(null, { capMs });
    return { stub, records, statuses, recorder, port };
  }
  throw new Error('no free port');
}
const readOf = x => x.records[0].read;

test('9. the reader: reset after and before apply, each read failure in doubt, the pre-image before any member is forwarded, and nothing secret or identifying sealed', async t => {
  // RA and RB through the recorder: the sealed read counts what the backend held.
  const ra = await recorderRun(t, { plan: () => ({ reply: 'reset' }) }), rb = await recorderRun(t, { plan: () => ({ reply: 'reset-before' }) });
  const a = readOf(ra.records[0]), b = readOf(rb.records[0]);
  assert.deepEqual([a.identity, a.early, a.groupSends, a.pre.total, a.s1.credNew, a.s1.credApplied, a.s2.credChanged, a.s3.lateNew, a.control.credItems], ['app', false, 1, 0, 1, 1, 0, 0, 1]);
  assert.deepEqual([b.s1.newIds, b.s2.newIds, b.s3.newIds, b.control.credItems], [0, 0, 0, 1]);
  assert.ok(validReadBackRead(a) && validReadBackRead(b));
  // The control object is read when the recorder starts (the destination declares no scope headers), before any write, and again at run end.
  assert.deepEqual([a.controlStart?.outcome, a.controlStart?.credItems, a.controlStart?.atMono < a.pre.atMono], ['ok', 1, true]);
  const controlReads = ra.stub.log.reads.filter(r => r.ticket === 'T-CTRL');
  assert.ok(controlReads.length === 2 && controlReads[0].at < Math.min(...ra.stub.log.writes.map(w => w.at)), 'one control read before the write, one at run end');
  assert.ok(a.s1.atMono >= a.pre.doneMono + C.SETTLE && a.s2.atMono >= a.s1.atMono + C.SETTLE && a.s3.atMono >= a.s2.doneMono, 'reads after the bound, at least settleMs apart');
  // The reads carried the read credential, the write the app's; only the read token reached the read endpoint.
  assert.ok(ra.stub.log.reads.every(r => r.token === 'read') && ra.stub.log.writes.every(w => w.identity === 'app'));
  // Nothing identifying: no note id, token, proof secret or ticket path in the records.
  const text = JSON.stringify([ra.records, rb.records]);
  for (const secret of [...Object.values(ENV), ...ra.stub.notes('T-1').map(x => x.id), 'tok-app', 'T-1', 'T-CTRL', '/tickets']) assert.ok(!text.includes(secret), `no "${secret}"`);
  // Each read failure, as the recorder seals it (by read number on T-1: 1 the pre-image, 2 S1, 3 S2, 4 S3).
  // Each hook counts its own reads of T-1 (the control object's reads, at start and at run end, are on T-CTRL).
  const T1 = hook => { let k = 0; return ({ ticket }) => (ticket === 'T-1' ? hook(++k) : {}); };
  const cases = [['5xx', T1(n => (n === 2 ? { status: 503 } : {})), r => r.s1.outcome, 'status'], ['unproven', T1(n => (n === 3 ? { unproven: true } : {})), r => r.s2.outcome, 'unproven'],
    ['non-JSON', T1(n => (n === 2 ? { raw: 'not json' } : {})), r => r.s1.outcome, 'not-json'], ['shape', T1(n => (n === 2 ? { raw: { notes: 'x', complete: true } } : {})), r => r.s1.outcome, 'shape'],
    ['over cap', T1(n => (n === 3 ? { cap: READ_BACK_BOUNDS.items + 1 } : {})), r => r.s2.outcome, 'over-cap'], ['ids', T1(n => (n === 2 ? { raw: { notes: [{ text: 'x', author: 'app' }], complete: true } } : {})), r => r.s1.outcome, 'ids'],
    ['complete false', T1(n => (n === 2 ? { complete: false } : {})), r => r.s1.outcome, 'incomplete'], ['timeout', T1(n => (n === 2 ? { delayMs: 1300 } : {})), r => r.s1.outcome, 'timeout'],
    ['abandoned pre-image', T1(n => (n === 1 ? { delayMs: 1300 } : {})), r => r.pre.outcome, 'abandoned']];
  for (const [name, readHook, get, want] of cases) {
    const run = await recorderRun(t, { plan: () => ({ reply: 'reset' }), readHook });
    assert.equal(get(readOf(run.records[0])), want, name);
    assert.ok(validReadBackRead(readOf(run.records[0])), name);
  }
  // The abandoned pre-image held the write at most min(1000 ms, timeoutMs) and the write still went on (the app is never blocked longer).
  const slow = await recorderRun(t, { plan: () => ({ reply: 'reset' }), readHook: T1(n => (n === 1 ? { delayMs: 1300 } : {})) });
  assert.equal(slow.stub.log.writes.length, 1);
  // Two members of one group sent together: exactly one takes the pre-image, and the read happens before either is forwarded.
  const pair = await recorderRun(t, { plan: () => ({ reply: 'reset' }), sends: [{ key: 'k-1' }, { key: 'k-1' }], readHook: T1(n => (n === 1 ? { delayMs: 150 } : {})) });
  assert.equal(pair.records.length, 2);
  const pr = readOf(pair.records[0]);
  assert.deepEqual([pr.groupSends, pair.stub.log.reads.filter(r => r.ticket === 'T-1').length >= 4, pair.stub.log.writes.length], [2, true, 2]);
  assert.ok(pair.stub.log.reads.find(r => r.ticket === 'T-1').at < Math.min(...pair.stub.log.writes.map(w => w.at)), 'the pre-image reached the backend before either write');
  // Scope headers: two writes to T-1 under different X-Tenant values are two groups, each read with its own header copied;
  // a tenant header from the fixed list that the destination does not declare is flagged on the send.
  const tenants = await recorderRun(t, { plan: () => ({ reply: 'reset' }), extra: { scopeHeaders: ['x-tenant'] }, sends: [{ key: 'k-a', extraHeaders: { 'x-tenant': 'tenant-a' } }, { key: 'k-b', extraHeaders: { 'x-tenant': 'tenant-b' } }] });
  assert.equal(new Set(tenants.records.map(x => x.records[0].read.group)).size, 2, 'two groups');
  assert.deepEqual([...new Set(tenants.stub.log.reads.filter(r => r.ticket === 'T-1').map(r => r.tenant))].sort(), ['tenant-a', 'tenant-b'], 'each group read under its own tenant');
  assert.ok(tenants.records.every(x => x.records[0].read.pre.outcome === 'ok' && x.records[0].read.groupSends === 1));
  assert.ok(tenants.records.every(x => x.records[0].read.controlStart === null), 'with scope headers, the control object is read at run end only');
  assert.equal(pair.records.filter(x => x.records[0].read.group === pr.group).length, 2, 'both members carry the group\'s one read');
});
