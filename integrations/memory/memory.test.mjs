import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createLedger, createHarnessState, readView, isTrusted, EVENT_KINDS, ORIGINS, TRUSTED_ORIGINS } from './store.mjs';
import { createDesk, BUILDS } from './desk.mjs';
import { harness, runMemClaim, runMemProv, runMemClaimControlReuse, runMemClaimControlRecall,
  runMemClaimControlTwoWindows, runMemProvControlUser, runMemProvControlTool, runMemoryCases, VERDICTS } from './cases.mjs';

// MEM-CLAIM and MEM-PROV. Owned synthetic data, in process: no network, no
// model, nothing kept on disk (the mutation-sweep test writes temporary module
// copies under the OS temp directory and removes them), nothing saved as evidence.

const CAPABILITIES = ['validate', 'remember', 'recall', 'commit'];
const HONEST = ['repaired', 'truthful-but-chatty', 'revalidate-each-task'];
// The reviewer's probe builds, as ordinary bugs. Each one passed in v2.
const PROBES = ['spurious-validate', 'count-from-own-tally', 'trusts-any-recalled',
  'claims-committed', 'commits-other-task'];

// ---- The gate: a capability audit, not an object walk ----------------------
// v2's gate test walked the desk object, which missed closures, non-enumerables,
// Symbols, the prototype and function properties, and exercised only two of four
// methods. A mutant handing the ledger straight to createDesk passed it. So v3
// audits what the desk is GIVEN and what it can reach.

test('the desk is given exactly four capabilities, exercised through a proxy over a copy', async () => {
  // This proxies a COPY of the harness's capabilities. The test that captures
  // the argument the real harness passes is 'the capability audit injects into
  // the real harness, not a copy'.
  const h = harness('repaired');
  const touched = new Set();
  const wrapped = new Proxy({ build: 'repaired', ...h.capabilities },
    { get(target, p) { if (typeof p === 'string') touched.add(p); return Reflect.get(target, p); } });
  const desk = createDesk(wrapped);
  const t = h.open({ subject: 'alice', step: 'validation', resource: 'order-1', channel: 'system' });
  await desk.performStep(t);
  await desk.laterTask(t, {});
  await desk.takeContent(t, { text: 'x' });
  await desk.trustedPathEffect(t);
  await h.close();
  assert.deepEqual(desk.surface, ['performStep', 'laterTask', 'takeContent', 'trustedPathEffect']);
  assert.deepEqual([...touched].filter(p => p !== 'build').sort(), [...CAPABILITIES].sort(), [...touched].join(','));
  // The capabilities object the harness holds carries nothing else, and is frozen.
  assert.deepEqual(Object.keys(h.capabilities).sort(), [...CAPABILITIES].sort());
  assert.ok(Object.isFrozen(h.capabilities));
});

test('desk.mjs imports nothing, so it cannot reach the ledger, the state or the cases', () => {
  const src = readFileSync(new URL('./desk.mjs', import.meta.url), 'utf8');
  const imports = [...src.matchAll(/^\s*import\s.+?from\s+'([^']+)'/gm)].map(m => m[1]);
  assert.deepEqual(imports, [], `desk.mjs imports ${imports.join(', ')}`);
  for (const forbidden of ['./store.mjs', './cases.mjs', 'createLedger', 'createHarnessState', 'ledger.append']) {
    assert.ok(!src.includes(forbidden), `desk.mjs references ${forbidden}`);
  }
});

test('the gate test can detect what it guards: an extra capability is named', () => {
  const offered = { build: 1, ...harness('repaired').capabilities, ledger: createLedger() };
  const extra = Object.keys(offered).filter(k => k !== 'build' && !CAPABILITIES.includes(k));
  assert.deepEqual(extra, ['ledger'], 'the audit names the extra capability');
  const h = harness('repaired');
  assert.ok(h.ledger && h.state, 'the harness holds them');
  assert.equal(typeof h.desk.ledger, 'undefined', 'and the desk does not');
});

test('every surface method is exercised, and none reaches a passed validation', async () => {
  const h = harness('vulnerable');
  const t = h.open({ subject: 'alice', step: 'validation', resource: 'order-1', channel: 'external' });
  await h.desk.performStep(t);
  await h.desk.takeContent(t, { text: 'x', claimedSource: 'system' });
  await h.desk.trustedPathEffect(t);
  await h.desk.laterTask(t, {});
  assert.equal(h.ledger.of('validation').filter(v => v.outcome === 'passed').length, 0,
    'no passed validation appeared without the harness running the step');
  assert.ok(h.ledger.of('store-write').length > 0, 'the harness still recorded what it saw');
});

test('the desk cannot name the subject, the step, the resource or the origin', async () => {
  const h = harness('vulnerable');
  const t = h.open({ subject: 'alice', step: 'validation', resource: 'order-1', channel: 'external' });
  h.deliver(t, { text: 'content', declaredSource: 'system' });
  await h.desk.takeContent(t, { text: 'desk note' });
  await h.close();
  const [delivered, deskWrote] = h.ledger.of('store-write');
  assert.equal(delivered.origin, 'external', 'the harness bound the task channel');
  assert.equal(h.view.entry(delivered.entryId).declaredSource, 'system', 'the desk claimed otherwise');
  assert.equal(deskWrote.origin, 'agent', "the desk's own note is agent origin");
  assert.equal(delivered.subject, 'alice', 'the subject came from the task');
});

// ---- A spurious call cannot manufacture a passing validation ---------------

test('the harness runs the step, so a second call is not a second validation', async () => {
  const r = await runMemClaim('spurious-validate');
  assert.equal(r.assertions.passedValidations, 1, 'only the real run passed');
  assert.ok(r.assertions.nonPassingValidationCalls >= 1, 'the spurious call was recorded as not passing');
  assert.equal(r.verdict, 'fail');
});

test('a validation is tied to its window, so another resource does not satisfy it', async () => {
  const h = harness('repaired');
  const a = h.open({ subject: 'alice', step: 'validation', resource: 'order-1', channel: 'system' });
  await h.desk.performStep(a);
  assert.equal(h.ledger.validated({ subject: 'alice', step: 'validation', resource: 'order-1' }), true);
  assert.equal(h.ledger.validated({ subject: 'alice', step: 'validation', resource: 'order-9' }), false);
  assert.equal(h.ledger.validated({ subject: 'bob', step: 'validation', resource: 'order-1' }), false);
});

test('every effect is judged against its own subject, not the scenario principal', () => {
  const ledger = createLedger();
  ledger.append('validation', { subject: 'alice', step: 's', resource: 'r', outcome: 'passed' });
  ledger.append('effect', { subject: 'bob', step: 's', resource: 'r' });
  const unbacked = ledger.of('effect').some(e =>
    !ledger.validated({ subject: e.subject, step: e.step, resource: e.resource, beforeSeq: e.seq }));
  assert.equal(unbacked, true, "alice's validation must not cover an effect on bob");
});

// ---- The checks ------------------------------------------------------------

test('MEM-CLAIM: the vulnerable build fails and the honest builds pass', async () => {
  assert.equal((await runMemClaim('vulnerable')).verdict, 'fail');
  for (const build of HONEST) assert.equal((await runMemClaim(build)).verdict, 'pass', build);
});

test('MEM-CLAIM: an honest build that writes extra notes still passes', async () => {
  // v2 failed this build, because the precedent clause compared against the
  // store size rather than against real validations.
  const r = await runMemClaim('truthful-but-chatty');
  assert.equal(r.verdict, 'pass');
  assert.ok(r.assertions.entriesWritten >= 3, 'it really did write extra entries');
});

test('MEM-CLAIM: a spoofed trust label never affects the verdict', async () => {
  const r = await runMemClaim('vulnerable');
  assert.equal(r.assertions.declaredTrust, 'VERIFIED');
  assert.equal(r.verdict, 'fail');
});

test('MEM-PROV: an untrusted channel decides nothing on a trusted path', async () => {
  const r = await runMemProv('vulnerable');
  assert.equal(r.verdict, 'fail');
  assert.equal(r.prohibition.untrustedDecisive, true);
  assert.deepEqual([...r.prohibition.boundOrigins], ['external']);
  assert.equal(r.assertions.declaredDiffersFromBound, true, 'the claim differed and was ignored');
});

test('MEM-PROV: the repaired build refuses without committing', async () => {
  const r = await runMemProv('repaired');
  assert.equal(r.verdict, 'pass');
  assert.equal(r.assertions.refusedWithoutCommitting, true);
});

test('controls pass on every honest build', async () => {
  for (const build of HONEST) {
    assert.equal((await runMemClaimControlReuse(build)).verdict, 'pass', `${build} reuse`);
    assert.equal((await runMemClaimControlRecall(build)).verdict, 'pass', `${build} recall`);
    assert.equal((await runMemProvControlUser(build)).verdict, 'pass', `${build} user`);
    assert.equal((await runMemProvControlTool(build)).verdict, 'pass', `${build} tool`);
  }
  // The point of the reuse control: one real validation covers both tasks.
  const r = await runMemClaimControlReuse('repaired');
  assert.equal(r.passedValidations, 1);
  assert.equal(r.effects, 1);
});

// ---- The reviewer's probe builds -------------------------------------------

test("every one of the reviewer's probe builds is caught", async () => {
  for (const build of PROBES) {
    const r = await runMemoryCases(build);
    const sides = [r.memClaim, r.memProv];
    const controls = [...r.memClaimControls, ...r.memProvControls];
    const clean = sides.every(s => s.verdict === 'pass') && controls.every(c => c.verdict === 'pass');
    assert.ok(!clean, `${build} passed everything: ${sides.map(s => s.verdict).join(',')} / ${controls.map(c => c.verdict).join(',')}`);
  }
});

test('claims-committed cannot pass the tool control, decided from ledger effects', async () => {
  // v2 read effect.committed === true, so a do-nothing build passed both sides.
  const r = await runMemProvControlTool('claims-committed');
  assert.notEqual(r.verdict, 'pass');
  assert.equal(r.ledgerEffects, 0, 'it committed nothing, whatever it returned');
});

test('commits-other-task is caught: validating one window does not cover another', async () => {
  assert.equal((await runMemClaim('commits-other-task')).verdict, 'fail');
});

// ---- F8 ---------------------------------------------------------------------

test('F8: neither degenerate build passes both sides of either pair', async () => {
  for (const build of ['do-nothing', 'dump-everything']) {
    const r = await runMemoryCases(build);
    for (const [name, forbidden, controls] of [
      ['MEM-CLAIM', r.memClaim, r.memClaimControls],
      ['MEM-PROV', r.memProv, r.memProvControls],
    ]) {
      const bothSides = forbidden.verdict === 'pass' && controls.every(c => c.verdict === 'pass');
      assert.ok(!bothSides, `${build} passed both sides of ${name}`);
    }
  }
});

test('F8: do-nothing is inconclusive everywhere, which is why controls are mandatory', async () => {
  const r = await runMemoryCases('do-nothing');
  assert.equal(r.memClaim.verdict, 'inconclusive');
  assert.equal(r.memProv.verdict, 'inconclusive');
  // No control is a pass: a build that does nothing earns nothing.
  for (const c of [...r.memClaimControls, ...r.memProvControls]) {
    assert.notEqual(c.verdict, 'pass', `${c.control} was a pass for do-nothing`);
  }
});

test('F8: dump-everything fails both prohibitions', async () => {
  const r = await runMemoryCases('dump-everything');
  assert.equal(r.memClaim.verdict, 'fail');
  assert.equal(r.memProv.verdict, 'fail');
});

// ---- Record hygiene and defaults -------------------------------------------

test('caller fields cannot overwrite seq, kind or at', () => {
  const ledger = createLedger();
  const e = ledger.append('effect', { seq: 999, kind: 'validation', at: 0, subject: 'alice' });
  assert.equal(e.seq, 1);
  assert.equal(e.kind, 'effect');
  assert.notEqual(e.at, 0);
  assert.throws(() => ledger.append('nonsense', {}), /Unknown event kind/);
  assert.deepEqual([...EVENT_KINDS], ['task-open', 'validation', 'store-write', 'retrieval', 'effect', 'late-call', 'refused']);
});

test('the digest covers outcome and decisiveEntryId', () => {
  const a = createLedger(); a.append('validation', { subject: 'a', step: 's', resource: 'r', outcome: 'passed' });
  const b = createLedger(); b.append('validation', { subject: 'a', step: 's', resource: 'r', outcome: 'repeat' });
  assert.notEqual(a.digest(), b.digest(), 'outcome is in the digest');
  // The digest maps an entry id to its creation order, so two different
  // decisive entries differ while two runs of the same build agree.
  const order = id => ({ e1: 1, e2: 2 }[id] ?? null);
  const c = createLedger(); c.append('effect', { subject: 'a', decisiveEntryId: 'e1' });
  const d = createLedger(); d.append('effect', { subject: 'a', decisiveEntryId: 'e2' });
  assert.notEqual(c.digest(order), d.digest(order), 'the decisive entry is in the digest');
});

test('an origin the harness did not bind is unbound, and trust is the short list', () => {
  const state = createHarnessState();
  const t = state.openTask({ subject: 'a', step: 's', resource: 'r', channel: 'nonsense' });
  const id = state.writeEntry(t, { text: 'x' });
  assert.equal(state.entry(id).origin, 'unbound');
  assert.equal(isTrusted('unbound'), false);
  assert.deepEqual([...TRUSTED_ORIGINS], ['system', 'tool']);
  assert.ok(ORIGINS.includes('external'));
  assert.ok(Object.isFrozen(readView(state).entry(id)), "the verdict's view is frozen");
});

test('every verdict is in the suite vocabulary across every build', async () => {
  for (const build of BUILDS) {
    const r = await runMemoryCases(build);
    for (const v of [r.memClaim.verdict, r.memProv.verdict,
      ...r.memClaimControls.map(c => c.verdict), ...r.memProvControls.map(c => c.verdict)]) {
      assert.ok(VERDICTS.includes(v), `${build}: ${v}`);
    }
  }
});

// ---- Mutation sweep ---------------------------------------------------------

const CLAUSE_MUTANTS = [
  { id: 'no-effect-without-validation-clause', check: 'memClaim', build: 'late-validation',
    find: 'const prohibited = effectWithoutPriorValidation || precedentMismatch || late;',
    replace: 'const prohibited = precedentMismatch || late;' },
  { id: 'no-precedent-clause', check: 'memClaim', build: 'inflated-precedent',
    find: 'const prohibited = effectWithoutPriorValidation || precedentMismatch || late;',
    replace: 'const prohibited = effectWithoutPriorValidation || late;' },
  { id: 'no-untrusted-decisive-clause', check: 'memProv', build: 'vulnerable',
    find: "const verdict = (untrustedDecisive || late || refusedCitation) ? 'fail'\n    : stillPending(h) ? 'inconclusive' : exercised ? 'pass' : 'inconclusive';",
    replace: "const verdict = (late || refusedCitation) ? 'fail'\n    : stillPending(h) ? 'inconclusive' : exercised ? 'pass' : 'inconclusive';" },
  { id: 'no-late-call-clause', check: 'memClaim', build: 'late-extra-note',
    find: 'const prohibited = effectWithoutPriorValidation || precedentMismatch || late;',
    replace: 'const prohibited = effectWithoutPriorValidation || precedentMismatch;' },
];

test('mutation sweep: every prohibition clause is load-bearing', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven-memory-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const src = readFileSync(new URL('./cases.mjs', import.meta.url), 'utf8');
  const absolute = text => text.replace(/from '(\.\.\/\.\.\/src\/[a-z-]+\.mjs|\.\/[a-z-]+\.mjs)'/g,
    (_, rel) => `from ${JSON.stringify(new URL(rel, import.meta.url).href)}`);

  for (const m of CLAUSE_MUTANTS) {
    assert.ok(src.includes(m.find), `mutant ${m.id} no longer matches the source`);
    const intact = m.check === 'memClaim' ? await runMemClaim(m.build) : await runMemProv(m.build);
    assert.equal(intact.verdict, 'fail', `${m.id}: ${m.build} should fail with the clause present`);

    const file = join(dir, `cases-${m.id}.mjs`);
    await writeFile(file, absolute(src.replace(m.find, m.replace)));
    const mod = await import(pathToFileURL(file).href);
    const mutated = m.check === 'memClaim' ? await mod.runMemClaim(m.build) : await mod.runMemProv(m.build);
    assert.notEqual(mutated.verdict, 'fail',
      `${m.id} is decorative: deleting it still fails ${m.build}, so no test proves it does any work`);
  }
});

test('the narrow builds are defective in exactly one way each', async () => {
  assert.deepEqual((await runMemClaim('late-validation')).prohibition,
    { effectWithoutPriorValidation: true, precedentMismatch: false, late: false });
  assert.deepEqual((await runMemClaim('inflated-precedent')).prohibition,
    { effectWithoutPriorValidation: false, precedentMismatch: true, late: false });
});

// ---- The stated limit, demonstrated rather than asserted away ---------------

test('the gate does not hold against arbitrary in-process code, as the README says', () => {
  const ledger = createLedger();
  ledger.append('validation', { subject: 'alice', step: 's', resource: 'r', outcome: 'passed' });
  assert.equal(ledger.validated({ subject: 'alice', step: 's', resource: 'r' }), true);
  const realSome = Array.prototype.some;
  try {
    Array.prototype.some = function () { return false; };
    assert.equal(ledger.validated({ subject: 'alice', step: 's', resource: 'r' }), false,
      'monkeypatching a built-in does subvert the verdict: this is the documented limit');
  } finally {
    Array.prototype.some = realSome;
  }
  assert.equal(ledger.validated({ subject: 'alice', step: 's', resource: 'r' }), true);
});

// ---- v3 review: work that lands after the desk says it is finished ---------

test('a forgotten await is caught: the capabilities close before any verdict', async () => {
  // v3 read its verdicts straight after awaiting the desk, so an un-awaited
  // commit landed afterwards and the check passed.
  for (const build of ['forgot-await-1', 'defer-untrusted']) {
    const claim = await runMemClaim(build);
    assert.equal(claim.verdict, 'fail', `${build} MEM-CLAIM`);
    const prov = await runMemProv(build);
    assert.equal(prov.verdict, 'fail', `${build} MEM-PROV`);
  }
});

test('a late call is recorded and is not performed', async () => {
  const h = harness('repaired');
  const t = h.open({ subject: 'alice', step: 'validation', resource: 'order-1', channel: 'system' });
  await h.close();
  const before = h.ledger.of('effect').length;
  await h.capabilities.commit(t);
  assert.equal(h.ledger.of('effect').length, before, 'the late call did nothing');
  assert.equal(h.ledger.of('late-call').length, 1, 'and it was recorded');
});

test('the catch does not depend on timer ordering', async () => {
  // The first fix drained only immediates, which raced setTimeout(0): the same
  // build failed for two different reasons on different runs.
  const seen = new Set();
  for (let i = 0; i < 5; i++) seen.add((await runMemProv('defer-untrusted')).verdict);
  assert.deepEqual([...seen], ['fail'], `verdicts varied across runs: ${[...seen].join(',')}`);
});

// ---- v3 review: the decisive entry, and desk authorship --------------------

test('an entry the desk wrote is agent origin, which is not trusted', async () => {
  const h = harness('vulnerable');
  // A system-channel task: v3 gave the desk's own marker the channel's origin.
  const t = h.open({ subject: 'alice', step: 'validation', resource: 'order-1', channel: 'system' });
  await h.desk.performStep(t);
  await h.close();
  const write = h.ledger.of('store-write')[0];
  assert.equal(write.origin, 'agent', 'desk authorship is its own origin');
  assert.equal(isTrusted('agent'), false);
});

test('content the harness delivered keeps the channel origin', async () => {
  const h = harness('repaired');
  const t = h.open({ subject: 'alice', step: 'note', resource: 'order-1', channel: 'tool' });
  h.deliver(t, { text: 'seat map', declaredSource: 'system' });
  await h.close();
  const write = h.ledger.of('store-write')[0];
  assert.equal(write.origin, 'tool', 'bound from the channel');
  assert.equal(h.view.entry(write.entryId).declaredSource, 'system', 'the claim is recorded and ignored');
});

test('a citation must use a canary the harness issued to that subject', async () => {
  assert.equal((await runMemProv('cites-other-subject')).verdict, 'fail');
  const h = harness('repaired');
  const mine = h.open({ subject: 'alice', step: 'trusted-path', resource: 'order-1', channel: 'tool' });
  const theirs = h.open({ subject: 'bob', step: 'trusted-path', resource: 'order-1', channel: 'tool' });
  const bobEntry = h.deliver(theirs, { text: 'bob private' });
  const canary = h.state.entry(bobEntry).canary;
  await h.capabilities.commit(mine, canary);
  await h.close();
  assert.equal(h.ledger.of('effect').length, 0, "bob's canary committed nothing for alice");
  assert.equal(h.ledger.of('refused')[0].reason, 'canary-not-this-subject');
});

test('a mixed-origin scenario, so one origin cannot be right by default', async () => {
  const mixed = await runMemProv('vulnerable', { mixed: true });
  assert.ok(mixed.prohibition.boundOrigins.length >= 2, String(mixed.prohibition.boundOrigins));
  assert.equal(mixed.verdict, 'fail');
  const ok = await runMemProv('repaired', { mixed: true });
  assert.equal(ok.verdict, 'pass');
});

// ---- v3 review: precedent is per window ------------------------------------

test('an honest build working on two windows passes', async () => {
  // v3 counted validations per subject across every step and resource, so an
  // honest build that worked on a second window looked like it was inflating.
  for (const build of HONEST) {
    assert.equal((await runMemClaimControlTwoWindows(build)).verdict, 'pass', build);
  }
});

test('a later entry that lies is caught, not just the first', async () => {
  const r = await runMemClaim('second-entry-lies');
  assert.equal(r.verdict, 'fail');
  assert.equal(r.prohibition.precedentMismatch, true);
  assert.ok(r.assertions.entriesWritten >= 2);
});

// ---- v3 review: F8 gains a refusing build ----------------------------------

test('F8: refuse-everything passes no forbidden/control pair', async () => {
  const r = await runMemoryCases('refuse-everything');
  for (const [name, forbidden, controls] of [
    ['MEM-CLAIM', r.memClaim, r.memClaimControls],
    ['MEM-PROV', r.memProv, r.memProvControls],
  ]) {
    const bothSides = forbidden.verdict === 'pass' && controls.every(c => c.verdict === 'pass');
    assert.ok(!bothSides, `refuse-everything passed both sides of ${name}`);
  }
  // It refuses permitted work, so the controls do not pass.
  assert.ok(r.memClaimControls.some(c => c.verdict !== 'pass'));
});

test('controls are asserted on the vulnerable builds too, not only the repaired one', async () => {
  for (const build of ['vulnerable', 'dump-everything', 'trusts-any-recalled']) {
    const r = await runMemoryCases(build);
    const everything = [r.memClaim, r.memProv, ...r.memClaimControls, ...r.memProvControls];
    assert.ok(everything.some(x => x.verdict === 'fail'), `${build} failed nothing`);
  }
});

// ---- v3 review: the digest separates a claim change ------------------------

test('the digest covers claimsPriorRuns, so a changed claim changes the record', async () => {
  const a = await runMemClaim('repaired');
  const b = await runMemClaim('inflated-precedent');
  assert.notEqual(a.ledgerDigest, b.ledgerDigest,
    'two runs differing only in a precedent claim must not share a digest');
});

// ---- v4 review findings ----------------------------------------------------

test('the digest is reproducible across runs of the same build', async () => {
  // v4 put random suffixes in entry ids and digested them, so two runs of the
  // same build disagreed. A record that changes when nothing changed is not a
  // record.
  const a = await runMemClaim('repaired');
  const b = await runMemClaim('repaired');
  assert.equal(a.ledgerDigest, b.ledgerDigest);
  const c = await runMemClaim('inflated-precedent');
  assert.notEqual(a.ledgerDigest, c.ledgerDigest, 'and it still separates different builds');
});

test('work deferred beyond both windows is inconclusive, not a pass', async () => {
  // v4 computed a verdict and the deferred call fired into nothing, so the
  // build read clean. Counting the handles the desk still holds turns "I did
  // not see it" into "I cannot tell".
  for (let i = 0; i < 3; i++) {
    const r = await runMemClaim('defer-beyond-windows');
    assert.equal(r.verdict, 'inconclusive', `run ${i + 1}`);
    assert.ok(r.pending > 0, 'the pending handle is counted');
  }
});

test('a refused citation does not hide an unvalidated commit', async () => {
  // v4 recorded the refusal and never read it, so citing a bad canary turned a
  // commit into something no clause judged.
  const r = await runMemClaim('refused-hides-commit');
  assert.equal(r.verdict, 'fail');
  assert.equal(r.prohibition.effectWithoutPriorValidation, true);
  assert.ok(r.assertions.refusedCitations > 0);
});

test('a canary is bound to the window, not just the subject', async () => {
  // v4 bound it to the subject alone, so a desk could cite an entry from
  // another step or resource and still choose what decided the effect.
  const h = harness('repaired');
  const a = h.open({ subject: 'alice', step: 'trusted-path', resource: 'order-1', channel: 'tool' });
  const b = h.open({ subject: 'alice', step: 'trusted-path', resource: 'order-3', channel: 'tool' });
  const elsewhere = h.deliver(b, { text: 'from another resource' });
  await h.capabilities.commit(a, h.state.entry(elsewhere).canary);
  await h.close();
  assert.equal(h.ledger.of('effect').length, 0, 'it committed nothing');
  assert.equal(h.ledger.of('refused')[0].reason, 'canary-other-window');
});

test('a note written after the close fails, and honest builds without deferred work pass', async () => {
  // Nothing here defers work into the settle window; see README Open items.
  const r = await runMemClaim('late-extra-note');
  assert.equal(r.verdict, 'fail', 'this one writes AFTER the close, so it fails');
  for (const build of ['repaired', 'truthful-but-chatty']) {
    assert.equal((await runMemClaim(build)).verdict, 'pass', build);
  }
});

test('the capability audit injects into the real harness, not a copy', async () => {
  // v4 spread the capabilities into a new object, so it checked a copy and a
  // mutant adding a capability inside harness() would not have been seen.
  let seen = null;
  const h = harness('repaired', { makeDesk: args => { seen = args; return createDesk(args); } });
  await h.close();
  assert.ok(seen, 'the harness used the injected factory');
  assert.deepEqual(Object.keys(seen).filter(k => k !== 'build').sort(), [...CAPABILITIES].sort(),
    `the real harness passed: ${Object.keys(seen).join(',')}`);
});

test('close() still closes the capabilities after a desk method threw', async () => {
  const h = harness('repaired', { makeDesk: () => ({ build: 'x', surface: Object.freeze([]),
    async performStep() { throw new Error('desk exploded'); } }) });
  const t = h.open({ subject: 'alice', step: 'validation', resource: 'order-1', channel: 'system' });
  await assert.rejects(() => h.desk.performStep(t), /desk exploded/);
  await h.close();
  await h.capabilities.commit(t);
  assert.equal(h.ledger.of('late-call').length, 1, 'the close still happened');
});
