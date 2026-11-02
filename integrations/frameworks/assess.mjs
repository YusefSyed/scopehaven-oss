// Framework mode from the CLI: `./scopehaven assess --framework <langgraph|mastra> --template <path> ...`
// runs a frozen framework scenario end to end through run.mjs's own steps (the template checkout at the pinned commit,
// the seeds at their sha256, the adapter under the turn-runner contract with the scripted model stub), judges the record,
// and saves an ordinary core run (run-record.mjs) in the run store. The report, SARIF and run history read it as they
// read any run. Nothing is installed and no network call is made: the adapter runs with the turn runner's isolated
// environment (no provider variables, proxies pointed at a dead loopback port).
//   --framework langgraph|mastra   which template family; its reset-after-commit scenario is the default
//   --template DIR                 the template checkout (git), at the scenario's pinned commit
//   --runtime PATH                 the template's Python (langgraph) or the tsx package folder (mastra), absolute
//   --stub ID                      the scripted model persona from the scenario
//   [--scenario NAME|FILE]         a scenario of that family: a name under scenarios/ or an absolute file
//   [--data DIR]                   where the scenario's seed files are (needed when it declares seeds)
//   [--adapter-arg --variant --adapter-arg NAME]  the template's build switch (for example fixed-update); no other adapter argument
//   [--label NAME] [--out DIR]     a run label; the run store (default: the project's data/)
import { readdirSync, readFileSync, rmSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { basename, isAbsolute, join, resolve } from 'node:path';
import { validateScenario } from './scenario.mjs';
import { runScenario } from './turn-runner.mjs';
import { checkTemplate, prepareWorkdir, adapterCommand, FRAMEWORKS_DIR } from './run.mjs';
import { frameworkModeRun, allowedUseControlOf, FrameworkModeError } from './run-record.mjs';
import { createStore } from '../../src/store.mjs';
import { assertRuntime } from '../../src/runtime.mjs';
import { digest } from '../../src/domain.mjs';

export const FRAMEWORKS = Object.freeze({
  langgraph: Object.freeze({ template: 'langgraph-cs', scenario: 'langgraph-cs.reset-after-commit' }),
  mastra: Object.freeze({ template: 'mastra-billing', scenario: 'mastra-billing.reset-after-commit' }),
});
const VALUED = { '--framework': 'framework', '--template': 'template', '--runtime': 'runtime', '--stub': 'stub', '--scenario': 'scenario', '--data': 'data', '--label': 'label', '--out': 'out' };
const SCENARIO_NAME = /^[a-z0-9][a-z0-9.-]{0,79}$/;
const NAME = /^[a-z0-9][a-z0-9-]{0,39}$/;
// ScopeHaven's measuring code outside the evaluator: every adapter file (the Python shim's ledger, fault and stub player, the
// JavaScript tool ledger, plain-data reads), the turn runner and the out-of-process SQLite reader. Recorded in each run.
const MEASURING_FILES = [...readdirSync(join(FRAMEWORKS_DIR, 'adapters')).sort().map(name => `adapters/${name}`), 'turn-runner.mjs', 'sqlite-state.mjs', 'contract.mjs', 'run.mjs'];
export const MEASURING_HASH = digest(MEASURING_FILES.map(name => [name, readFileSync(join(FRAMEWORKS_DIR, name), 'utf8')]));

/** The options as given; every value is checked here, before anything runs. */
export function parseFrameworkArgs(args) {
  const options = { adapterArgs: [] };
  for (let i = 0; i < args.length; i += 2) {
    const flag = args[i], value = args[i + 1];
    if (typeof value !== 'string' || value.length === 0 || (value.startsWith('--') && flag !== '--adapter-arg')) throw new FrameworkModeError('invalid-options');
    if (flag === '--adapter-arg') { options.adapterArgs.push(value); continue; }
    const key = VALUED[flag];
    if (!key || Object.hasOwn(options, key)) throw new FrameworkModeError('invalid-options');
    options[key] = value;
  }
  if (!Object.hasOwn(FRAMEWORKS, options.framework)) throw new FrameworkModeError('framework-unsupported');
  for (const key of ['template', 'runtime', 'stub']) if (typeof options[key] !== 'string') throw new FrameworkModeError('invalid-options');
  if (!isAbsolute(options.runtime) || (options.label !== undefined && !NAME.test(options.label))) throw new FrameworkModeError('invalid-options');
  checkAdapterArgs(options.adapterArgs);
  return options;
}

/** Only the template's build switch passes through: one --variant NAME. Any other argument (a second --template, another
 * passenger) would change what runs or what it starts from without the checks or the identity seeing it. */
export function checkAdapterArgs(args, scenario = null) {
  const ok = Array.isArray(args) && (args.length === 0 || (args.length === 2 && args[0] === '--variant' && NAME.test(args[1])));
  if (!ok || (args.length && (scenario?.adapter.args ?? []).includes('--variant'))) throw new FrameworkModeError('adapter-arg-refused');
  return args;
}

/** The frozen scenario a framework run uses: the family's default, a name under scenarios/, or an absolute file of that family. */
export function frameworkScenario(framework, scenario = null) {
  const family = FRAMEWORKS[framework];
  if (!family) throw new FrameworkModeError('framework-unsupported');
  const name = scenario ?? family.scenario;
  let file;
  if (isAbsolute(name)) file = name;
  else if (SCENARIO_NAME.test(name)) file = join(FRAMEWORKS_DIR, 'scenarios', `${name.replace(/\.json$/, '')}.json`);
  else throw new FrameworkModeError('invalid-options');
  let parsed;
  try { parsed = validateScenario(JSON.parse(readFileSync(file, 'utf8'))); } catch { throw new FrameworkModeError('scenario-invalid'); }
  if (parsed.template.id !== family.template) throw new FrameworkModeError('scenario-other-framework');
  if (!allowedUseControlOf(parsed)) throw new FrameworkModeError('no-allowed-use-control');
  return parsed;
}

/**
 * Runs one scenario and saves its core run. Checks come first: the stub is the scenario's, the scenario has an allowed-use
 * control, the adapter arguments are only the build switch, the template checkout is at the pinned commit with no local
 * edits, and every seed matches its sha256. The run store is opened only after them.
 */
export async function runFrameworkAssessment({ scenario, stub, runtime, template, data = null, adapterArgs = [], label = null, out }) {
  if (!Object.hasOwn(scenario.stubs, stub)) throw new FrameworkModeError('stub-unknown');
  if (!allowedUseControlOf(scenario)) throw new FrameworkModeError('no-allowed-use-control');
  checkAdapterArgs(adapterArgs, scenario);
  if (label !== null && !NAME.test(label)) throw new FrameworkModeError('invalid-options');
  if (scenario.workdir.seed.length && typeof data !== 'string') throw new FrameworkModeError('data-required');
  const checkout = checkTemplate(template, scenario);
  const { workdir, seeds } = prepareWorkdir(scenario, data ?? FRAMEWORKS_DIR);
  try {
    const store = createStore(out); await store.ready;
    const adapter = adapterCommand(scenario, { runtime, template: resolve(template), adapterArgs });
    const record = await runScenario(scenario, { stubId: stub, adapter: { command: adapter.command, args: adapter.args, env: adapter.env }, workdir, label,
      adapterInfo: { ...adapter.info, checkout, seeds, runtimeName: basename(runtime), measuring: MEASURING_HASH } });
    return await store.save(frameworkModeRun(record, scenario, { id: randomUUID(), createdAt: new Date().toISOString() }));
  } finally { rmSync(workdir, { recursive: true, force: true }); }
}

/** 0 only when every row passed. */
export const exitFor = run => (run.counts.fail || run.counts.error || run.counts.inconclusive || run.counts.pass !== run.checksTotal ? 1 : 0);

/** The CLI entry (src/cli.mjs routes `assess --framework ...` here): prints the saved run's summary; exit 0 clean, 1 not clean, 2 refused. */
export async function frameworkAssessMain(args, { defaultOut }) {
  try {
    assertRuntime();
    const options = parseFrameworkArgs(args);
    const scenario = frameworkScenario(options.framework, options.scenario ?? null);
    const run = await runFrameworkAssessment({ scenario, stub: options.stub, runtime: options.runtime, template: options.template, data: options.data ?? null,
      adapterArgs: options.adapterArgs, label: options.label ?? null, out: options.out ? resolve(options.out) : defaultOut });
    console.log(JSON.stringify({ id: run.id, target: run.targetId, framework: options.framework, scenario: run.suiteId, counts: run.counts, requiredControlIds: run.requiredControlIds,
      overall: run.scenarioEvidence.overall, evidenceDirectory: options.out ? resolve(options.out) : defaultOut, evidenceOrigin: run.evidenceOrigin, scope: run.scopeLabel }, null, 2));
    return exitFor(run);
  } catch (error) {
    console.error(`Scopehaven could not run the framework scenario: ${error instanceof FrameworkModeError ? error.code : error?.message ?? 'error'}`);
    console.error('Usage: ./scopehaven assess --framework langgraph|mastra --template DIR --runtime PATH --stub ID [--scenario NAME|FILE] [--data DIR] [--adapter-arg --variant --adapter-arg NAME] [--label NAME] [--out DIR]');
    return 2;
  }
}
