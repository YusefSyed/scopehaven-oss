# ScopeHaven

[![Tests](https://github.com/YusefSyed/scopehaven-oss/actions/workflows/test.yml/badge.svg)](https://github.com/YusefSyed/scopehaven-oss/actions/workflows/test.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Node 22 or 24 LTS](https://img.shields.io/badge/node-22%20%7C%2024%20LTS-brightgreen.svg)](.node-version)

**ScopeHaven checks what an AI agent actually did in your app, not what it said.**

It runs an agent's tasks against a local copy of your application as different users, then decides every check from
the app's own records when you declare an observer, or from the HTTP responses when you don't, and says which one it
used. It tests whether an agent's actions remain authorized when access changes, and whether "done" matches what
actually happened. No model takes part in a verdict. By default nothing leaves your machine except traffic to the target you name; the opt-in exceptions (a model provider, a
timestamp authority) are listed in [docs/DATA-HANDLING.md](docs/DATA-HANDLING.md).

It is for teams whose agents write into their own product: refunds, credits, plan changes, account updates, exports.

![The false-success refund on our test support app](docs/demo/false-success-refund.gif)

On our test support app a synthetic customer asks for a refund, the record shows a denial and no refund, and the scripted
reply still says it was processed: ScopeHaven flags the false success, then compares the repaired build with the baseline
(26 fixed, 18 preserved); the HTML exports behind this recording are in [docs/demo/](docs/demo/).

## Sixty seconds

You need Node.js 22 or 24 LTS (`>=22.13.0 <23 || >=24.0.0 <25`) and nothing else: there are no npm packages to install.

Already on Node 22 or 24 LTS? Nothing to add: clone and run. Below that line's October 2026 security release (22.23.4 or 24.22.1) it runs and prints a warning, so update before pointing it at anything you care about.

```sh
git clone https://github.com/YusefSyed/scopehaven-oss.git && cd scopehaven-oss
./scopehaven assess --target demo-vulnerable --out /absolute/private/evidence    # exit 1: 26 of 44 checks fail
```

On Node 22 the one `ExperimentalWarning: SQLite` line is Node's notice about `node:sqlite`, not a result. On Node 20
(end of life, no `node:sqlite`) or with no Node at all, get one official LTS build first, for example `nvm install 22`
or the installer from https://nodejs.org/en/download, then run the same two commands. The launcher never downloads
anything itself; `./scopehaven doctor` prints which Node it selected and, if none qualifies, where to get one.

```sh
git clone https://github.com/YusefSyed/scopehaven-oss.git
cd scopehaven-oss
./scopehaven doctor                                                              # local checks; installs, downloads and starts nothing
./scopehaven assess --target demo-vulnerable --out /absolute/private/evidence    # exit 1: 26 of 44 checks fail
./scopehaven assess --target demo-repaired  --out /absolute/private/evidence     # exit 0: all 44 pass
./scopehaven start                                                               # the local dashboard on 127.0.0.1:4317
```

### Install from npm (after publication)

ScopeHaven is not on npm yet. The package is built and tested, and [packaging/RELEASE.md](packaging/RELEASE.md) has the
steps that remain. Once it is published, a folder of your own with Node 22 or 24 LTS is enough, on macOS or Linux (npm
refuses the install on Windows, which is not verified):

```sh
npx scopehaven doctor
npx scopehaven assess --target demo-vulnerable --out ./scopehaven-evidence    # exit 1: 26 of 44 checks fail
```

`npx scopehaven` takes the same actions as `./scopehaven`, the name the rest of these docs use. The package has no
dependencies and runs nothing when it installs. Relative paths mean the folder you are in. Give `--out` every time:
without it, runs go inside the installed package, where the next install or a cleared npx cache removes them. `start`
keeps its dashboard data there too, so use a clone if you want to keep that history.

The two built-in targets are the same synthetic support-agent app, once with deliberate defects and once repaired.
On that test app (suite 2.3.0, 44 checks) the vulnerable build fails 26 checks, including a paused refund that still
committed after the user's access was removed mid-task. The repaired build passes all 44. Comparing the two runs
shows 26 failures fixed and all 18 allowed-use controls still passing, so a fix that over-blocks a covered workflow
fails instead of passing. Local synthetic data on loopback; no production system, customer data or real users.

One finding from that run: a synthetic member asked for a refund. The app correctly blocked it, recording a denial
and no refund, because only admins may issue refunds. But the test app's scripted reply said "Your refund of 20 CAD
has been processed." A check that grades only the reply would call that a success. ScopeHaven flags it as a false
success, because the record says otherwise.

To see the comparison yourself, run the one-shot gate twice into the same private directory:

```sh
./scopehaven gate --target demo-vulnerable --out /absolute/new/gate-dir
./scopehaven gate --target demo-repaired  --out /absolute/new/gate-dir --baseline BASELINE_RUN_ID
```

## Use it from CI or from your agent

Two ways in. **In CI.** The repository root is a GitHub Action. One step after your app is up on the runner's loopback runs the
checks under your authorization record, gates them against a saved run, uploads the evidence and, if you ask, SARIF:

```yaml
- uses: YusefSyed/scopehaven-oss@v0.7.0
  env:
    SCOPEHAVEN_TARGET_APP_A: ${{ secrets.SCOPEHAVEN_TARGET_APP_A }}
  with:
    profile: scopehaven/targets.json
    authorization: scopehaven/authorization.json
    wait-url: http://127.0.0.1:3000/health
    baseline-run: scopehaven/baseline-run.json
    upload-sarif: 'true'
```

[docs/guides/ci-in-five-minutes.md](docs/guides/ci-in-five-minutes.md) has the whole workflow, the baseline step and
what the job summary shows.

**From your agent.** Start the owned MCP server behind ScopeHaven's recording proxy, point Claude Code or Cursor at it
with one identity's token, open a window, and let the agent call tools. The rows are judged from the proxy's record and
the server's own audit table, not from what the agent said:

```sh
export SCOPEHAVEN_TARGET_MCP_VIEWER=choose-a-synthetic-viewer-token
export SCOPEHAVEN_TARGET_MCP_AGENT=choose-a-synthetic-agent-token
export SCOPEHAVEN_TARGET_MCP_ADMIN=choose-a-synthetic-admin-token
node docs/guides/examples/mcp-target-launch.mjs --dir /absolute/private/mcp-target --port 4810
claude mcp add --transport http scopehaven-target http://127.0.0.1:4810/mcp --header "Authorization: Bearer $SCOPEHAVEN_TARGET_MCP_VIEWER"
./scopehaven sequence --sequence docs/guides/examples/mcp-agent-window.sequence.json --origin http://127.0.0.1:4810 \
  --observers /absolute/private/mcp-target/observers.json --authorization /absolute/private/mcp-target/authorization.json \
  --out /absolute/private/mcp-target/runs
```

[docs/guides/mcp-target-from-claude-code-and-cursor.md](docs/guides/mcp-target-from-claude-code-and-cursor.md) has the
client configuration for both tools, what each record can and cannot show, and how to put your own MCP server in its place.

## How a check decides

- **Five row statuses**: pass, fail, inconclusive (unobservable or missing evidence), error (an observer or the run
  itself failed, read as observer failure) and not applicable. Missing evidence never reads as a pass. An action still in flight makes its window partial. An aborted sequence never passes.
- **Attribution**: an effect counts only when it is attributed to the acting user and tenant; an unattributed actor
  blocks a pass.
- **Custody**: a pass of an observed effect needs an observer held outside the application (a hold gate, an egress
  recorder, an SMTP sink, a database snapshot the app cannot edit). A pass decided only by records the app itself
  writes reads inconclusive, while those records can still fail a check.
- **Allowed-use controls** run beside every forbidden check, so a repair that blocks legitimate work is a failure, not
  a pass.
- **Human notes never change a computed verdict.** Notes are stored apart from runs, and exports carry the verdict,
  not the note.
- **Stored verdicts are recomputed, not trusted**, and an evidence pack ships a standard-library Python checker
  that re-derives them on another machine.

## Point it at your own app

1. Run your app on loopback (`127.0.0.1`) with synthetic test accounts. `./scopehaven init` drafts a profile from a
   running app, or `./scopehaven watch-first` records what the app did and drafts the declarations from that.
2. Write (or accept) the **profile**: who the test actors are, which endpoints they may and may not use, which
   responses count. Credentials are referenced as `SCOPEHAVEN_TARGET_*` environment variables and never stored.
3. Declare **observers** on the app's own records: `sqlite-audit`, `sqlite-snapshot`, `pg-snapshot`,
   `mysql-snapshot`, `http-audit`, `audit-file`, an `egress-recorder` for outbound HTTP, an `smtp-sink` for mail, a
   `provider-feed`, a `dns-stub`, an MCP or OpenTelemetry source. [integrations/observers](integrations/observers/README.md)
   lists each one and what it can and cannot prove.
4. Seal an **authorization record** that names the target, every endpoint and every test account
   ([docs/RULES-OF-ENGAGEMENT.md](docs/RULES-OF-ENGAGEMENT.md)). Nothing runs against a configured target without it.
5. `./scopehaven assess --config /absolute/private/profile.json --target ID --authorization /absolute/private/authorization.json --out /absolute/private/evidence`,
   then `gate` before and after a change, then `export` or `evidence-pack` to hand the result on.

[docs/QUICKSTART.md](docs/QUICKSTART.md) walks from a running app to a first decided row;
[docs/ONBOARDING.md](docs/ONBOARDING.md) is the long version.

**Supabase + Next.js in ten minutes.** [docs/guides/supabase-next-10-minutes.md](docs/guides/supabase-next-10-minutes.md) goes from `supabase start` and `npm run dev` on your own app to a first decided row, step by step, with a time budget per step.
It uses `init --stack supabase` or the ready-to-fill templates in [examples/supabase-next/](examples/supabase-next/): a two-tenant profile with a cross-tenant read, a member's admin-only write and an ended session, a `pg-snapshot` observer on the local Postgres, and the authorization record.
The guide says what a FAIL or INCONCLUSIVE row means at each step; nothing in it reaches a hosted project.

## What it checks

Each folder under `integrations/` is one check family or mechanism, with its own README and tests:

| Family | Question it asks |
|---|---|
| `access-change`, `kill-switch`, `revocation-clock` | Can work that started legitimately still produce an effect after the authority behind it changed? When an owner removes access mid-turn, does the turn stop, and how late? |
| `claim-check`, `groundedness`, `conversations`, `multiturn`, `memory` | Does what the assistant told the customer match what the app did? Across turns, identities, and later tasks? |
| `collateral`, `decision-effect`, `enforcement-locus`, `grant-use` | Did anything change that the task did not call for? Did the app act only where its policy engine allowed? Who enforces each declared denial? What was granted, used, and held unused? |
| `sequences`, `temporal-contracts`, `metamorphic` | Timed steps with a hold gate and settle rules; a refund lifecycle contract; run a task twice, change one thing, compare the record deltas. |
| `payments-pack`, `payments-stripe` | Judge an agent that moves money from the provider's ledger, not from what the app wrote down (stage 1 runs on a loopback provider stand-in). |
| `model-identity`, `model-path`, `model-standin`, `pass-k` | Which model served the run, whose change a verdict change is, repeated trials with exact pass^k fractions, a scripted OpenAI-shaped stand-in so a first run needs no key. |
| `frameworks` | Run ScopeHaven on an agent inside LangGraph, Mastra and other frameworks through adapters, scenarios and planted mutations on public templates. |
| `policy-import`, `connectors`, `init`, `watch-first`, `coverage-report` | Read expected permissions from the app's own declarations (Supabase RLS, OpenAPI, route tables), per-stack connector files, and a coverage report that says before any run which actions the suite checks and which it cannot. |
| `regression-gate`, `schedule`, `github-action`, `mcp-target`, `monitor`, `tickets`, `reviews` | A one-shot release gate, scheduled drift, a GitHub Action, an MCP server as a target, a trace checker, offline ticket export, reviewer sign-off recorded beside the verdict and never inside it. |
| `attest`, `verdict-check`, `ledger`, `retest-ledger`, `evaluation-import`, `data-handling` | Signed exports (DSSE, Ed25519), re-derived verdicts, a hash-chained run ledger, finding history across runs, a minimized Promptfoo import, and the generated sheet of every network call site in this repository. |

## Evidence you can hand on

Every export is signed into a DSSE envelope with a local Ed25519 key. `./scopehaven evidence-pack` writes one folder:
the exports, the signer's public key, a Python verifier for the envelope, `verify_verdicts.py` (standard library,
shares no code with ScopeHaven) and `VERIFY.md` with the exact commands. SARIF 2.1.0 export carries tags from OWASP
LLM 2025 and its 2026 renumbering, OWASP Agentic 2026 (ASI), MITRE ATLAS 2026.09 and CWE, each with a per-check
rationale. A tag means the check is mapped to that identifier, never that a framework requirement is met. A
signature shows the files are unchanged since signing, not that the verdicts are right; the checker is for that.

## In CI

[integrations/github-action](integrations/github-action/README.md) is a composite action that starts your app on the
runner's loopback, runs the assessment, gates it against a saved baseline and uploads SARIF. This repository's own
[workflow](.github/workflows/scopehaven-action.yml) runs it against the owned lab twice and asserts that the gate
catches exactly the planted regression. [scopehaven-drift.yml](.github/workflows/scopehaven-drift.yml) re-runs the
gate on a schedule and writes the drift since the last successful run into the job summary.

## What it does not do

- It tests a **local copy** of your app over loopback, or a staging origin you name in a signed authorization record
  over HTTPS. It never tests production, never follows redirects, never retries on its own.
- Without a declared observer, a check on an outside app is **response-level**: the result says
  "response contracts restored", not "backend effects verified". Declare observers to get effects.
- **Inconclusive is not a pass.** A green result that checked nothing is reported as inconclusive, and the coverage
  report says beforehand what the suite cannot see.
- It checks the policies you declare and the checks you run. It does not find every defect, and a passing run is
  evidence about those checks on that build, not a security certification.
- [docs/KNOWN-LIMITS.md](docs/KNOWN-LIMITS.md) and [docs/SUPPORTED-MODES.md](docs/SUPPORTED-MODES.md) list the rest.

## Editions

This repository is the **open edition**, under Apache-2.0: the engine, the observers, the check families above,
the synthetic fixture and HTTP lab, signing and verification, the Action, the MCP target and the Promptfoo import.
Nothing in it is crippled, and it will stay free.

Kept separate and commercial: the check-pack library beyond the five bundled samples (`integrations/packs-v2/packs`),
the class templates and incident replays, the adversarial carrier fixtures used to harden pass semantics, the assessor
and insurer pack, and every hosted service (shared run history, team dashboards, signed-evidence custody, support).
If you want those, write to <hello@scopehaven.dev>.

## Commands

```
./scopehaven doctor|start|test|assess|check-config|lab|connector-demo|gate|gate-demo|import-evaluation|export|evidence-pack|sequence|attest|policy|monitor|payments|watch-first|pack|init
```

`assess` exit codes: 0 every check passed, 1 failed, inconclusive or error evidence, 2 setup failure. `gate`: 0 clean,
1 failed or incomplete evidence (including not-applicable rows), 2 runtime, configuration or error-status failure. `sequence`: 0 every row passed, 1 a row failed, 3 nothing failed but a row
is inconclusive or an observer failed, 2 configuration error.
The launcher selects Node from `SCOPEHAVEN_NODE`, then a project-local `.runtime/`, then `PATH`.

## Contributing, security, licence

Read [CONTRIBUTING.md](CONTRIBUTING.md) (DCO sign-off, no dependencies, every check needs its failing case).
Report security problems in ScopeHaven itself through [SECURITY.md](SECURITY.md), never in a public issue.
Licensed under the [Apache License 2.0](LICENSE); third-party notices are in [NOTICE](NOTICE).
