# Scopehaven dependencies

Scopehaven currently has **zero external npm runtime dependencies**. The SupportDesk/HTTP examples need Node only. Framework mode (`assess --framework`) runs a template's own Python or Node environment, which you supply. This guide installs or moves nothing.

## Runtime

`package.json` requires Node `>=22.13.0 <23 || >=24.0.0 <25`: the 22 LTS line from 22.13.0, or the 24 LTS line from 24.0.0, each that line's first release with `node:sqlite` and no flag. The server, CLI and HTTP assessment runtime gate (`src/runtime.mjs`) enforce the same two floors; Node 23 and the end-of-life 20 line are refused (20 has no `node:sqlite`, which the SQLite observers and fixtures use). Below a line's October 2026 security release (22.23.4 or 24.22.1) the launcher prints a warning and `doctor` shows `[warn]`, and it still runs; those floors are the recommendation. The pinned download is 24.22.2 and the full suite runs on it; the 22 line was checked with the runner, HTTP connector, storage, SQLite observer, sequence, evidence-pack and launcher test files. On 22, `node:sqlite` needs no flag, but Node prints one `ExperimentalWarning: SQLite` line per process that loads it; that is Node's notice, not a result. Run everything through `./scopehaven`, which selects one Node binary in this order:

1. `SCOPEHAVEN_NODE`, if set (a relative path is resolved from your current directory). There is no fallback when it is set.
2. The project-local `.runtime/node-v24.22.2-darwin-arm64/bin/node`, if present and runnable on this machine. It is an Apple Silicon macOS build and is not in git.
3. The first `node` on `PATH`.

The launcher checks the selected version before every action. If it is outside the range (for example a global `20.20.2` or `24.18.0`), nothing starts: it exits with code 2, names the binary and where it came from, and explains how to get a supported runtime. npm is optional; `npm run` would use whatever `node` is on `PATH`.

To get a supported runtime, download Node.js 22 LTS at 22.23.4 or newer, or 24 LTS at 24.22.1 or newer (24.22.2 is the pinned version), from the official [nodejs.org download page](https://nodejs.org/en/download): the installer, or the `node-v2x.y.z-<platform>.tar.gz` tarball checked against that release's `SHASUMS256.txt` (and, for a check that does not trust the download site, that file's detached signature against the Node release keys). A version manager's `nvm install 22` or `nvm install 24` gives the same official build. Then put it first on `PATH` or set `SCOPEHAVEN_NODE=/absolute/path/to/bin/node`. Scopehaven never downloads or installs a runtime itself. On another Unix platform, use the matching official build and confirm it with `./scopehaven doctor`. Storage uses Unix owner IDs and permission modes, and the launcher uses a POSIX shell; Windows operation is not verified.

### Dependency check

```sh
./scopehaven doctor [--data-dir DIR] [--port N]
```

`doctor` runs local checks only: no install, download, network request, server start or assessment. It reports:

| Check | Fails when | Effect |
| --- | --- | --- |
| Node | No runnable binary, or its version is outside `>=22.13.0 <23 || >=24.0.0 <25`. Also shows a `PATH` node that is not used. | `[fail]`; later Node-based checks are skipped. Below the October 2026 security release: `[warn]`, and the checks continue. |
| Workbench modules | `src/registry.mjs` or a target adapter cannot load, for example when a target adapter's files are missing. | `[fail]`: start, assess, check-config and most tests would stop. |
| Data directory | It exists but is a symlink, not owned by you, not mode `0700` or not writable; or it is absent and its parent is not writable. | `[fail]` with the fix. |
| Loopback port | `127.0.0.1:<port>` is taken (`[warn]`) or invalid (`[fail]`). | `start` would fail; tests use ephemeral ports. |

Exit code 0 means no `[fail]` lines.

## Built-in inventory

| Node facility | Current purpose |
| --- | --- |
| `node:http` | Loopback dashboard, fixture and lab servers; bounded direct HTTP requests. |
| `node:crypto` | Random tokens/IDs, constant-time capability comparison and SHA-256 evidence/configuration identities. |
| `node:fs`, `node:fs/promises` | Safe-open flags, local profiles, run records, notes, reports, private launch files, ownership/permission checks and source hashing. |
| `node:path`, `node:url` | Resolve local paths and module/file URLs. |
| `node:perf_hooks` | Assessment timing. |
| `node:child_process`, `node:events` | Owned connector-demo lifecycle. |
| `node:test`, `node:assert/strict`, `node:os` | Built-in test runner, assertions and isolated temporary-directory support. |
| Node globals | `fetch`/`AbortSignal.timeout` for fixture transport; `Buffer`, `URL`, JSON, timers, `process` and `structuredClone`. |

The browser UI uses ordinary DOM and Fetch APIs, served with local HTML/CSS/JavaScript. It has no installed frontend framework, external asset CDN or analytics dependency.

## What a target adds

The owned SupportDesk fixture and separate HTTP lab use synthetic data with no model APIs or database service. A configured application can have its own dependencies, real side effects or provider costs. Those are the target's requirements, not packages Scopehaven automatically supplies or installs. Inspect them before assessing it.

A target profile and test-account bearer tokens are configuration, not npm packages. Keep token values in the process environment rather than the JSON profile. Credential references must use the `SCOPEHAVEN_TARGET_` namespace, such as `SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN`. The generated `data/http-lab.env` and `data/local-access.html` are private local files; the latter carries a separate workbench access capability. Neither should be printed or shared. Browser access keeps that capability in memory only, with no cookie/localStorage/sessionStorage persistence. Database-admin credentials are not required to begin response-contract testing.

The storage implementation uses owner-only `0700` directories and files with permissions no broader than `0600`, bounded quotas and paginated history. These are local implementation controls, not an installed database service or a hosted identity system. Use one writer process per evidence directory.

## When to add a package

Add a future dependency only for a concrete missing capability: an approved protocol adapter, a necessary parsing format, or an explicitly chosen evaluation/provider integration. Review its data flow, maintenance/security implications, installation and operating cost, then verify it against the relevant acceptance checks. Do not assume that a named tool or SDK is already installed or that importing its results makes them independently verified backend evidence.

For example, remote staging access and an observer on someone else's application need a separate trust design; adding a generic HTTP library does not provide that evidence. Provider-assisted scenario generation would need an agreed provider, credentials, data boundary and spend before use. Neither is implemented by this inventory.

## Read-only setup verification

From the repository root:

```sh
./scopehaven doctor
./scopehaven check-config
./scopehaven assess --list
```

`doctor` is described above. `check-config` and `assess --list` report configuration and target readiness with `connectionTested: false`; HTTP readiness checks configured credential references. They do not run assessments, establish account access or prove security requirements. See [ONBOARDING.md](ONBOARDING.md) for commands that create assessments and local evidence.

This inventory matches this release. Scopehaven remains a local prototype, with testing separate from application runtime enforcement and continuous monitoring; production assessments, and assessments of systems you do not own, remain outside the verified scope.

The regression-gate and external-evaluation-import modules add no external packages. The gate reuses the core registry/store/comparison modules; the importer uses a local bounded JSON parser and Node built-ins without installing or executing Promptfoo. The launcher provides `gate`, `gate-demo`, `import-evaluation` and `export`; their recorded checks and scope limits remain in the guide. The accepted dashboard uses local modules under `public/dashboard/` and the host in `public/workbench-host.js`, including separate external-preview and saved-run gate controls. See the release walkthrough (not in the open edition) for exact commands and current limits.
