// The core practice cases through the shipped entry points: ./scopehaven assess and ./scopehaven gate against the
// owned practice app (app.mjs), for the lifecycle phase, creator versus actor and settlement, each with its
// allowed, forbidden, missing-observer and failed-control case. Loopback only, synthetic data, a private
// temporary directory per case; no model, no provider, no hosted write.
import test from 'node:test';
import assert from 'node:assert/strict';
import { runCase } from './run-cli.mjs';
import { LATE_TRIGGERS } from './profiles.mjs';
import { validateHttpRunEvidence } from '../../src/contracts.mjs';

const status = (run, id) => run.results.find(r => r.id === id).status;
const CASES = [
  // [kind, case, build, observers, assess exit, gate exit, gate reasons that must be present, rows and their statuses]
  ['lifecycle', 'allowed', {}, true, 0, 0, [], { 'CAROL-REUSE-ME': 'pass', 'CAROL-REUSE-DELETE': 'pass', 'BOB-NOTE-AFTER': 'pass' }],
  ['lifecycle', 'forbidden', { staleSession: true }, true, 1, 1, ['checks-failed'], { 'CAROL-REUSE-ME': 'fail', 'CAROL-REUSE-DELETE': 'fail', 'BOB-NOTE-AFTER': 'pass' }],
  ['lifecycle', 'missing-observer', {}, false, 1, 1, ['inconclusive-evidence'], { 'CAROL-REUSE-ME': 'inconclusive', 'CAROL-REUSE-DELETE': 'inconclusive' }],
  ['lifecycle', 'failed-control', { suspendBroken: true }, true, 1, 1, ['required-controls-not-passed', 'inconclusive-evidence'], { 'ADMIN-SUSPEND-CAROL': 'fail', 'CAROL-REUSE-ME': 'inconclusive', 'CAROL-REUSE-DELETE': 'inconclusive' }],
  ['creator', 'allowed', {}, true, 0, 0, [], { 'CELL-MEMBER-BY-OTHER': 'pass', 'CELL-ADMIN-BY-MEMBER': 'pass', 'CELL-MEMBER-BY-ADMIN': 'pass' }],
  ['creator', 'forbidden', { creatorBypass: true }, true, 1, 1, ['checks-failed'], { 'CELL-MEMBER-BY-OTHER': 'pass', 'CELL-ADMIN-BY-MEMBER': 'fail' }],
  ['creator', 'missing-observer', {}, false, 1, 1, ['inconclusive-evidence'], { 'CELL-MEMBER-BY-OTHER': 'inconclusive', 'CELL-ADMIN-BY-MEMBER': 'inconclusive' }],
  ['creator', 'failed-control', { createBroken: true }, true, 1, 1, ['checks-failed', 'inconclusive-evidence'], { 'ADMIN-NOTE-B': 'fail', 'CELL-ADMIN-BY-MEMBER': 'inconclusive', 'CELL-MEMBER-BY-OTHER': 'inconclusive' }],
  ['settlement', 'allowed', {}, true, 0, 0, [], { 'BOB-DELETE-ADMIN-NOTE': 'pass', 'BOB-DELETE-MEMBER-NOTE': 'pass' }],
  ['settlement', 'forbidden-gap', { refusedCommit: LATE_TRIGGERS.gap }, true, 1, 1, ['inconclusive-evidence'], { 'BOB-DELETE-ADMIN-NOTE': 'inconclusive', 'BOB-DELETE-MEMBER-NOTE': 'pass' }],
  ['settlement', 'forbidden-next-window', { refusedCommit: LATE_TRIGGERS['next-window'] }, true, 1, 1, ['inconclusive-evidence'], { 'BOB-DELETE-ADMIN-NOTE': 'inconclusive', 'BOB-DELETE-MEMBER-NOTE': 'pass' }],
  ['settlement', 'forbidden-tail', { refusedCommit: LATE_TRIGGERS.tail }, true, 1, 1, ['inconclusive-evidence'], { 'BOB-DELETE-ADMIN-NOTE': 'inconclusive', 'BOB-DELETE-MEMBER-NOTE': 'pass' }],
  ['settlement', 'missing-observer', {}, false, 1, 1, ['inconclusive-evidence'], { 'BOB-DELETE-ADMIN-NOTE': 'inconclusive' }],
  ['settlement', 'failed-control', { ownDeleteNoop: 'alice' }, true, 1, 1, ['checks-failed', 'required-controls-not-passed'], { 'ALICE-DELETE-OWN': 'fail', 'BOB-DELETE-ADMIN-NOTE': 'pass' }],
];

for (const [kind, name, build, observers, assessExit, gateExit, reasons, rows] of CASES) {
  test(`${kind} ${name}: ./scopehaven assess exits ${assessExit} and ./scopehaven gate exits ${gateExit}`, async () => {
    const assess = await runCase({ kind, build, observers, command: 'assess' });
    assert.equal(assess.code, assessExit, why(assess));
    validateHttpRunEvidence(assess.run);
    for (const [id, expected] of Object.entries(rows)) assert.equal(status(assess.run, id), expected, `assess ${id}`);
    const gate = await runCase({ kind, build, observers, command: 'gate' });
    assert.equal(gate.code, gateExit, why(gate));
    assert.equal(gate.output.exitCode, gateExit);
    for (const reason of reasons) assert.ok(gate.output.reasons.includes(reason), `${reason} in ${gate.output.reasons}`);
    if (gateExit === 0) assert.deepEqual(gate.output.reasons, []);
    for (const [id, expected] of Object.entries(rows)) assert.equal(status(gate.run, id), expected, `gate ${id}`);
  });
}

// An exit that was not expected says why: the CLI's stderr, or every row that did not pass with the reasons its effect
// windows were not complete (a bare "1 !== 0" cannot tell a verdict change from a disturbed run).
function why(result) {
  if (result.stderr) return result.stderr;
  return (result.run?.results ?? []).filter(r => r.status !== 'pass').map(r => {
    const reasons = [...new Set((r.trace ?? []).flatMap(t => t.data?.windows ?? []).map(w => w.reason).filter(Boolean))];
    return `${r.id} ${r.status}${reasons.length ? ` (${reasons.join(', ')})` : ''}`;
  }).join('; ') || 'no run was saved';
}
