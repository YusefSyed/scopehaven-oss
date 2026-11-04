import test from 'node:test';
import assert from 'node:assert/strict';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateTargetFile } from '../src/contracts.mjs';
import { makeLabProfile } from '../examples/http-lab.mjs';
import { compareRuns } from '../src/runner.mjs';
import { assertRuntime } from '../src/runtime.mjs';

test('dedicated target credential namespace excludes unrelated process secrets before execution', async () => {
  const profile = makeLabProfile('http://127.0.0.1:4319'); profile.actors.member.credentialEnv = 'OPENAI_API_KEY';
  let requests = 0;
  await assert.rejects(runHttpAssessment(profile, { env: { OPENAI_API_KEY: 'synthetic-never-send' }, transport: async () => { requests++; } }), /dedicated SCOPEHAVEN_TARGET_/);
  assert.equal(requests, 0);
});
test('explicit inapplicability sends no request, needs no unused credential, and never counts as a pass', async () => {
  const profile = makeLabProfile('http://127.0.0.1:4319');
  profile.checks = [profile.checks[0], { ...profile.checks[2], actorId: 'unused', applicability: { applies: false, reason: 'This test build does not expose that capability.' } }];
  profile.actors.unused = { principalId: 'unused-test-actor', credentialEnv: 'SCOPEHAVEN_TARGET_UNUSED_TOKEN' };
  profile.requiredControlIds = ['WHOAMI']; let requests = 0;
  const options = { env: { SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN: 'synthetic-token' }, transport: async () => { requests++; return { status: 200, complete: true, jsonParsed: true, json: { role: 'member' }, bytes: 17 }; } };
  const before = await runHttpAssessment(profile, options), after = await runHttpAssessment({ ...profile, buildLabel: 'second' }, options);
  assert.equal(requests, 2); assert.equal(before.counts.inconclusive, 1, 'The cut-down profile has no identity control, so the member login is not proven and its control is inconclusive.'); assert.equal(before.counts.not_applicable, 1);
  const comparison = compareRuns(before, after); assert.equal(comparison.summary.fixed, 0); assert.equal(comparison.summary.notApplicable, 1);
  assert.equal(comparison.rows[1].transition, 'not-applicable');
  const active = structuredClone(profile); delete active.checks[1].applicability;
  const activeRun = await runHttpAssessment(active, { ...options, env: { ...options.env, SCOPEHAVEN_TARGET_UNUSED_TOKEN: 'synthetic-other' } });
  assert.equal(compareRuns(before, activeRun).compatible, false);
});
test('required permitted-use controls cannot be excluded and every scope exclusion needs a reason', () => {
  const p = makeLabProfile('http://127.0.0.1:4319'); p.checks[0].applicability = { applies: false, reason: 'Attempt to hide required control' };
  assert.throws(() => validateTargetFile({ schemaVersion: 1, targets: [p] }), /required control/);
  delete p.checks[0].applicability; p.checks[2].applicability = { applies: false, reason: '' };
  assert.throws(() => validateTargetFile({ schemaVersion: 1, targets: [p] }), /applicability/);
});
test('runtime guard refuses versions below each supported line (and lines 20, 23, 25+) and accepts the 22 and 24 LTS floors', () => {
  const refusal = /requires Node\.js 22 LTS at 22\.16\.0 or newer, or Node\.js 24 LTS at 24\.0\.0 or newer \(engines >=22\.16\.0 <23 \|\| >=24\.0\.0 <25\); this runtime is /;
  for (const version of ['22.0.0', '22.15.9', '23.0.0', '23.99.0', '20.20.2', '25.0.0', '26.0.0', '24.22', '22.23.4-rc.1', '']) assert.throws(() => assertRuntime(version), refusal, version);
  for (const version of ['22.16.0', '22.23.3', '22.23.4', '22.24.0', '24.0.0', '24.18.0', '24.22.1', '24.22.2', '24.23.0']) assert.doesNotThrow(() => assertRuntime(version), version);
});
