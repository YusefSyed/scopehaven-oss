# Changelog

All notable changes to the open edition of ScopeHaven are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- The launcher and runtime guard accept Node 22 from 22.16.0 and Node 24 from 24.0.0 (`>=22.16.0 <23 || >=24.0.0 <25`). Below a line's October 2026 security release (22.23.4 or 24.22.1) the launcher warns and runs instead of refusing, and `doctor` shows `[warn]`.
- `assess` prints a summary to stderr: each failing check and how to see the findings. The JSON on stdout is unchanged. Observed values appear only for synthetic runs.

## [0.7.0] - 2026-11-01

First public release of the open edition, cut from the private 0.7.0 tree.

### Included

- The local workbench and CLI (`./scopehaven`): assess, gate, compare, export, evidence pack, sequences, attest,
  policy import, monitor, watch-first, packs and `init`, with no npm dependencies.
- The deterministic effect and evidence engine: five row statuses (pass, fail, inconclusive, error, not_applicable),
  actor attribution, settle and in-flight rules, custody tags, and the rule that missing evidence never passes.
- Observers on an application's own records (SQLite audit and snapshot, HTTP audit, audit file, Postgres and MySQL
  snapshots, egress recorder, SMTP sink, provider feed, DNS stub, MCP, OpenTelemetry).
- The owned SupportDesk fixture with its baseline and repaired builds, the owned HTTP lab, and the synthetic
  refund-lifecycle contract.
- Framework reach for agent templates (LangGraph, Mastra and others).
- Signed exports (DSSE, Ed25519), the evidence pack with its standard-library Python verifiers, SARIF export with
  OWASP, ATLAS and CWE tags, the GitHub Action, the MCP target, the Promptfoo import, the payments pack with its
  loopback provider stand-in, and the scheduled drift workflow.
- The npm package is ready but not published: the launcher as its `bin`, a `files` list equal to the release's shipped set, public metadata, and the publish steps in `packaging/RELEASE.md`. `private` stays true until the release commit.

### Runtime and packaging

- The LangGraph model-path stack has no default interpreter: set `SCOPEHAVEN_LANGGRAPH_PYTHON` to one.
- The launcher and runtime guard accept Node 22 LTS from 22.23.4 alongside Node 24 from 24.22.1 (`>=22.23.4 <23 || >=24.22.1 <25`); Node 22 prints one SQLite experimental warning per process. The install notes and dependency guide follow.
- The launcher follows a symlink to find its project. From an npm install it stays in the caller's folder, so relative paths mean that folder, and its hints name `npx scopehaven`. `./scopehaven` in a clone behaves as before.
- The release tarball does not carry `.github/`, `.editorconfig`, `.gitattributes` or the README's GIF, so it and the npm package ship the same files.
- With no package list in the release, a release carries no VEX. The SBOM stays.

### Not included

Check packs beyond the five bundled samples, the class templates, incident replays, adversarial carrier fixtures,
the assessor pack, the private tree's pinned teaching targets (they could run only where their reviewed Python
environment and sealed prototypes existed, so everywhere else they read "unavailable") and every hosted service. See `README.md`, section "Editions".

[Unreleased]: https://github.com/YusefSyed/scopehaven-oss/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/YusefSyed/scopehaven-oss/releases/tag/v0.7.0
