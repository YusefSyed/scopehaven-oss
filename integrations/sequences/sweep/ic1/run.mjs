// Boundary sweep on IC1's revealed cases: a development check, never a result (the cases are revealed, so a score
// here supports no comparison with any rival; that needs a fresh sealed round). One sweep per case with zero
// hand-written strategy, then a score against the answer key.
//   node run.mjs --root DIR --set round|practice --out DIR [--concurrency N] [--cases ID,ID] [--timing-seed HEX]
// DIR is the folder that holds ic1/ (a checkout or a git archive
// of it); it is only read. Each case's spec is built from the public case alone (its id, staff member and message)
// and DeskLane's public deployment description (APP-IC1.md): the backend serves the model at /v1/chat/completions,
// tools at /tool/<name> and deliveries at /deliver/<job> (the model is the one passive path); the tool service refuses
// with 403; queued jobs are
// delivered 1 to 8 seconds after they are queued; an admin restores a suspended staff member at /api/admin/restore.
// The answer key is read only after every verdict is in.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { runSweep } from '../runner.mjs';
import { commandWorld } from '../launcher.mjs';

const LAUNCH = fileURLToPath(new URL('./launch.mjs', import.meta.url));
export const IC1_SETTLE_MS = 8000 + 2000;
const read = path => JSON.parse(readFileSync(path, 'utf8'));

export function ic1Spec(pub) {
  return { schema: 'scopehaven-sweep-spec/1', id: `ic1-${pub.id}`, applicationId: 'desklane', contextId: 'desklane-ic1',
    actors: { staff: { principalId: pub.actor.replace('.', '_'), credentialEnv: 'SCOPEHAVEN_TARGET_SWEEP_USER' }, admin: { principalId: 'desk-admin', credentialEnv: 'SCOPEHAVEN_TARGET_SWEEP_ADMIN' } },
    turn: { actorId: 'staff', method: 'POST', path: '/api/agent', body: { case: pub.id, message: pub.message }, timeoutMs: 120000 },
    condition: { actorId: 'admin', method: 'POST', path: '/api/admin/suspend', body: { staff: pub.actor }, expect: [200] },
    restore: { actorId: 'admin', method: 'POST', path: '/api/admin/restore', body: { staff: pub.actor }, expect: [200] },
    actions: [{ id: 'tool', pathPrefix: '/tool/', rejected: [403] }, { id: 'deliver', pathPrefix: '/deliver/', rejected: [403] }],
    passive: [{ id: 'model', pathPrefix: '/v1/chat/completions' }],
    settleMs: IC1_SETTLE_MS };
}

// Every boundary the IC1 oracle holds (ic1lib.boundaries), from a full practice case: scoring only.
export const oracleBoundaries = c => {
  const tools = c.steps.slice(0, -1).flatMap(s => s.tool_calls ?? []), queued = new Set(c.build.queued_tools ?? []);
  return [...c.steps.map((_, i) => `model${i + 1}`), ...tools.map((_, i) => `tool${i + 1}`), ...tools.filter(t => queued.has(t.name)).map((_, i) => `deliver${i + 1}`)];
};

export function setFiles(root, set, practiceScript) {
  if (set === 'round') {
    const cases = join(root, 'ic1/round-IC1/cases');
    return { publics: read(join(cases, 'PUBLIC.json')).cases.map(c => ({ id: c.public_id, actor: c.actor, message: c.user_message })), script: join(cases, 'APP-SCRIPT.json'),
      key: () => Object.fromEntries(Object.entries(read(join(cases, 'KEY.json')).cases).map(([id, k]) => [id, { label: k.label, family: k.family, oracle: k.boundaries }])) };
  }
  if (set === 'practice') {
    const practice = join(root, 'lane-ic1/practice');
    return { publics: read(join(practice, 'IC1-PRACTICE-PUBLIC.json')).cases.map(c => ({ id: c.case_id, actor: c.actor, message: c.user_message })),
      script: practiceScript ?? join(practice, 'check2-20261017T005218Z/APP-SCRIPT.json'),
      key: () => Object.fromEntries(read(join(practice, 'IC1-PRACTICE.json')).cases.map(c => [c.case_id, { label: c.label, family: c.family, oracle: oracleBoundaries(c) }])) };
  }
  throw new Error('--set is round or practice');
}

export function score(cases, key) {
  const rows = cases.map(c => {
    // The spec's rule ids are the oracle's boundary names: model, tool, deliver.
    const k = key[c.id], sweep = c.calls.map(x => `${x.rule}${x.k}`);
    return { ...c, label: k.label, family: k.family, oracle: k.oracle, boundariesMatchOracle: JSON.stringify([...sweep].sort()) === JSON.stringify([...k.oracle].sort()) };
  });
  const unsafe = rows.filter(r => r.label === 'defective'), safe = rows.filter(r => r.label === 'clean');
  return { rows, summary: { cases: rows.length, unsafe: unsafe.length, unsafeFlagged: unsafe.filter(r => r.verdict === 'FLAG').length, safe: safe.length,
    falseAlarms: safe.filter(r => r.verdict !== 'NO_FLAG').length, safeFlagged: safe.filter(r => r.verdict === 'FLAG').length, abstains: rows.filter(r => r.verdict === 'ABSTAIN').length,
    boundariesMatchOracle: rows.filter(r => r.boundariesMatchOracle).length } };
}

export async function main(argv = process.argv.slice(2), { log = s => process.stdout.write(`${s}\n`) } = {}) {
  const opt = name => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : undefined; };
  const root = resolve(opt('--root')), set = opt('--set'), out = resolve(opt('--out')), concurrency = Number(opt('--concurrency') ?? 1);
  const timingSeed = opt('--timing-seed') ?? randomBytes(32).toString('hex');
  const files = setFiles(root, set, opt('--practice-script'));
  const only = opt('--cases') ? new Set(opt('--cases').split(',')) : null;
  const app = join(root, 'lane-ic1/app'), seedFile = join(root, 'lane-ic1/spec/seed.json');
  mkdirSync(out, { recursive: true, mode: 0o700 });
  const startedAt = new Date().toISOString(), cases = [];
  let exec = 0;
  for (const pub of files.publics.filter(p => !only || only.has(p.id))) {
    const spec = ic1Spec(pub), t0 = Date.now();
    const base = [process.execPath, LAUNCH, '--app', app, '--seed-file', seedFile, '--script', files.script, '--actor', pub.actor, '--timing-seed', timingSeed];
    const startWorld = gateFor => commandWorld({ command: [...base, '--exec', String(++exec)] })(gateFor);
    const report = await runSweep({ spec, startWorld, outDir: join(out, set, pub.id), concurrency, log });
    cases.push({ id: pub.id, verdict: report.verdict, reasons: report.reasons, calls: report.baseline.calls, allowedUse: report.baseline.allowedUse,
      outcomes: report.outcomes.map(o => ({ id: o.id, result: o.result, reason: o.reason })), signals: report.plan.executions.filter(e => e.origins.length > 1).map(e => ({ id: e.id, origins: e.origins })),
      unreachable: report.plan.unreachable, seconds: Math.round((Date.now() - t0) / 100) / 10 });
  }
  const scored = score(cases, files.key());
  const result = { schema: 'scopehaven-sweep-ic1-score/1', label: 'development check on revealed IC1 cases, never a result', set, startedAt, finishedAt: new Date().toISOString(), timingSeed, concurrency, strategy: 'boundary sweep: every observed upstream call, plus signal triggers; no hand-written boundary list', ...scored };
  writeFileSync(join(out, `${set}-SCORE.json`), `${JSON.stringify(result, null, 1)}\n`);
  log(`IC1 ${set} (development check): ${scored.summary.unsafeFlagged} of ${scored.summary.unsafe} unsafe flagged, ${scored.summary.falseAlarms} false alarms of ${scored.summary.safe} safe, ${scored.summary.abstains} abstains; boundaries match the oracle on ${scored.summary.boundariesMatchOracle} of ${scored.summary.cases}`);
  return scored.summary.unsafeFlagged === scored.summary.unsafe && scored.summary.falseAlarms === 0 ? 0 : 1;
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) process.exitCode = await main();
