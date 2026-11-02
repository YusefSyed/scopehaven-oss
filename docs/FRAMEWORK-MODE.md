# Framework mode: assess an agent template inside its framework

`./scopehaven assess --framework langgraph|mastra` runs a frozen framework scenario on a pinned agent template (LangGraph's customer-support tutorial, Mastra's billing example) and saves an ordinary run in the run store. The HTML report and SARIF read it like any other run. The frameworks adapter (`integrations/frameworks/`, its README) does the work; this mode wires it into the CLI and the run store.

Framework mode is available but outside the tested modes of this release ([KNOWN-LIMITS.md](KNOWN-LIMITS.md#present-in-the-repository-but-outside-the-tested-modes-of-this-release)).

## Run it

```sh
./scopehaven assess --framework langgraph --template /abs/langgraph-checkout \
  --runtime /abs/venv/bin/python --data /abs/seed-data --stub checks-then-reports --out /abs/evidence
./scopehaven assess --framework mastra --template /abs/mastra-checkout --runtime /abs/node_modules/tsx \
  --stub blind-retry --out /abs/evidence
```

| Option | Meaning |
| --- | --- |
| `--framework langgraph\|mastra` | The template family. Its reset-after-commit scenario is the default. |
| `--template DIR` | The template's git checkout. It must be at the scenario's pinned commit, with no local edits to the template's files. |
| `--runtime PATH` | Absolute. The template's Python for LangGraph; the tsx package folder for Mastra. Nothing is installed. |
| `--stub ID` | The scripted model persona, one of the scenario's stubs. |
| `--scenario NAME\|FILE` | Optional: a scenario of that family by name under `integrations/frameworks/scenarios/`, or an absolute file. |
| `--data DIR` | Where the scenario's seed files are, when it declares seeds (LangGraph's SQLite database). Each must match its sha256. |
| `--adapter-arg --variant --adapter-arg NAME` | The template's build switch only (for example `fixed-update`). Any other adapter argument is refused (`adapter-arg-refused`): a second `--template` or another passenger would change what runs, or what it starts from, without the checks or the identity seeing it. |
| `--label NAME`, `--out DIR` | A run label (1 to 40 lowercase letters, digits or hyphens), and the run store (default: the project's `data/`). |

`setup/langgraph-cs.sh` and `setup/mastra-billing.sh` in the adapter folder prepare a checkout and runtime from local caches. The command prints the saved run's id, counts, required control and the judge's overall verdict, and exits `0` when every row passed, `1` otherwise, and `2` when it refused before running (with a code: `framework-unsupported`, `scenario-other-framework`, `no-allowed-use-control`, `stub-unknown`, `adapter-arg-refused`, `data-required`, `scenario-invalid`, `invalid-options`) or the template, seed or adapter checks failed.

## The run record

- **Evidence origin** `framework-scenario-local`, runtime mode `framework-scripted-local`. The run keeps the turn-runner record and the frozen scenario whole (`scenarioEvidence`).
- **Rows**, each recomputed from that record by the adapter's judge:

  | Row | Severity | What it checks |
  | --- | --- | --- |
  | `FW-EXEC` | low | The run is usable (a precondition). |
  | `FW-FAULT` | low | The planned fault fired (a precondition). |
  | `COLLATERAL-01` | high | Nothing persisted outside the declared set. |
  | `COLLATERAL-GOAL` | control | The requested change persisted. This is the required allowed-use control, so an agent that refuses everything or does nothing never passes. |
  | `FW-CONTENT` | medium | The expected rows have the declared content (when declared). |
  | `FW-SAID-DID` | high | The final reply agrees with what persisted (when the scenario declares claims). |

  `COLLATERAL-02` stays in the kept verdict only: two snapshots show net change, so it can fail but never pass.
- **A run that is not usable can fail, never pass.** When `FW-EXEC` does not pass, or the planned fault did not fire (`FW-FAULT`), every other pass reads inconclusive ("Not counted: ..."), as the judge's own overall verdict does. A fail stands. Every row the scenario implies is present (a record the judge stopped on reads inconclusive), and a row status the mapping does not know is refused (`verdict-unrecognized`).
- **Supported scenarios** are those whose requested change should persist: `decide: 'goal'`, or `'said-did'` under a fault that lets the tool body commit (`reset-after-commit`, `duplicate-delivery`). A timeout before the tool body, a no-change scenario and a said-did scenario under an environment condition have no persisted change to require, so they are refused (`no-allowed-use-control`); run them with `integrations/frameworks/run.mjs`.
- **Identity.**
  - **Suite:** the scenario (its digest).
  - **Policy:** its expectations, claims and fault.
  - **Fixture:** its declared seeds.
  - **Profile hash:** also binds the scripted model persona (stub id and digest). Another persona is another model behaviour, not a repair of the application.
  - **Adapter version:** the turn-runner protocol, ScopeHaven's adapter file and its sha256, the framework, and the digest of ScopeHaven's harness and adapter code that measured the run (`measuring@...`; every adapter file, the turn runner and the SQLite reader). A record made before this field reads `measuring-unrecorded`.
  - **Evaluator hash:** the judge's whole static import closure.
  - **Build** (`targetBuildHash`): the agent the run exercised (template commit, variant, adapter arguments, framework and tools). It is the part a repair is expected to change.
- **History.** Run-history pages leave out the kept record (`scenarioEvidence`), as they leave out other evidence bodies.
- **Validation.** `validateFrameworkModeRun` recomputes the whole run from its own record and scenario under the current evaluator and refuses any difference (`run-not-reproduced`), an unknown key, or a run from another evaluator (`evaluator-changed`). A verdict never rests on a stored status.

## Limits

- The model is ScopeHaven's scripted stub. The run shows how the template's code and tools behave under that script, not how a live model behaves.
- Only the SQLite files and object paths the scenario projects are observed. There is no Postgres or generic HTTP read-back in framework mode.
- An object path is read inside the agent's process (custody `in-process`), which is weaker than a SQLite file read out of process. The run's limitations say which custody applied.
- Two snapshots show net change only: a write undone between them is invisible.
- The regression gate does not accept this origin.
- No authorization record is read: the run contacts no endpoint (the adapter's proxies point at a dead loopback port and no provider variable passes through), and templates run on synthetic seed data only.

## The verified retest (VR1)

`compareRuns` compares two framework-mode runs natively, after recomputing each from its own kept record (a run that does not reproduce is refused: `Evidence origin does not match its producer family or observations.`). `retestVerdict(comparison)` (`src/runner.mjs`) reads the result in three words:

- **INCONCLUSIVE**: the pair is not comparable, or a row is unverified or not applicable with no observed regression (partial evidence: an unusable run, a fault that did not fire, a missing snapshot).
- **NO_VERIFIED_REPAIR**: a row that passed in the baseline fails in the candidate (for example the allowed-use control under a fix that refuses or does nothing; an observed regression outweighs partial evidence, so an unusable candidate with a pass-to-fail row reads this way), the required controls did not all pass, or nothing was restored.
- **FIXED_VERIFIED**: only when the comparison's label is one of compareRuns's repair labels (`REPAIR_LABELS`, an allowlist; for framework mode, `Local controls restored`). Any other label, such as a repair not attributed to the application, reads NO_VERIFIED_REPAIR.

A pair is not comparable when:

- **The request changed**: another scenario, so another suite hash.
- **The template commit changed**: it is part of the suite, until the suite identity can flag a migration between runs (a catalog fingerprint). A fix is a variant of the pinned commit (`--variant`).
- **The scripted model persona changed** (stub id or digest, in the profile hash): a change in the model's behaviour is not a repair of the application, as HTTP mode withholds a repair the model made.
- **The measuring side changed**: ScopeHaven's adapter file, the framework name or ScopeHaven's harness code digest (adapter version), the seeds (fixture) or the evaluator.
- **A tool was removed**: the candidate agent lacks a tool the baseline agent had, or the tool the planned fault targets. Removing a tool is not a repair.
- **The origins differ**: a framework run is never compared with an HTTP run.

The template variant, the framework's package versions and the tools added are the build, and may differ.

Proved in `integrations/frameworks/vr1.test.mjs`:

- **LangGraph reset-after-commit (the real template's acceptance records, re-judged):**
  - `checks-then-reports` to the same persona with `fixed-update` reads FIXED_VERIFIED.
  - A vacuous fix of the same persona, where the tool still runs but nothing persists, reads NO_VERIFIED_REPAIR: the allowed-use control regresses.
  - The `do-nothing`, `reports-failed` and `claims-done` runs are other personas, so they are not comparable.
- **Mastra:** the acceptance records hold no application-side fix, only other personas (`checks-then-reports`, `do-nothing` against `blind-retry`). Those pairs read INCONCLUSIVE, never a repair.
- **The billing shape's fix, run end to end:** this uses the fake adapter's refund app through the CLI's own checks. The same `blind-retry` persona on the buggy build, the idempotent build (`--variant idempotent-refund`) reads FIXED_VERIFIED; the refusing build (`--variant refuse-refund`) reads NO_VERIFIED_REPAIR.
- **Still open:** a FIXED_VERIFIED on the real Mastra template needs a fixed variant of its adapter and a run of the template.

Not yet: a `migration-between-runs` flag waits for the catalog fingerprint in the suite identity.

## Checks

```sh
.runtime/node-v24.22.2-darwin-arm64/bin/node --test integrations/frameworks/assess.test.mjs integrations/frameworks/vr1.test.mjs
```

The tests use no Python and no network:

- They map and re-judge the acceptance records of the real templates.
- They run the fake adapter end to end through the same template, seed and adapter checks, in a throwaway git checkout.
- They spawn `src/cli.mjs` for its refusals.
