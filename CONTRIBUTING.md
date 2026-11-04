# Contributing to ScopeHaven

Thanks for looking. This file says how to set up, what a good change looks like, and how a pull request gets in.

## Before you start

- **Ask first for anything large.** Open an issue (or a discussion) that says what you want to change and why,
  before writing more than a day of code. Small fixes, docs and tests need no issue.
- **Read the scope.** `README.md` says what ScopeHaven does and does not do, and `docs/KNOWN-LIMITS.md` lists the
  limits of what a result can show. A change that widens a claim needs the test that proves it.
- **Security findings** go through `SECURITY.md`, never a public issue.

## Set up

ScopeHaven has no npm dependencies. You need Node.js 22 or 24 LTS in the range `package.json` states (`>=22.13.0 <23 || >=24.0.0 <25`); the suite is run on the pinned 24.22.2.

```sh
git clone https://github.com/YusefSyed/scopehaven-oss.git
cd scopehaven-oss
./scopehaven doctor        # checks Node, modules, data directory and the loopback port; installs nothing
./scopehaven test          # the whole suite (about 10 minutes on a laptop, 4 shards in CI; it starts loopback servers on 127.0.0.1 only)
```

`./scopehaven test --test-shard=1/4` runs a quarter of the files, the way CI does. A single file:

```sh
./scopehaven test test/runner.test.mjs
```

The launcher selects Node in this order: `SCOPEHAVEN_NODE`, a project-local `.runtime/node-v24.22.2-darwin-arm64`
(not in git), then `node` on `PATH`.

`package.json` keeps `"private": true` on purpose: it flips only in the release commit, as `packaging/RELEASE.md` says.

## What a change needs

1. **A test.** Every behaviour change comes with a test in `test/` or next to the module in `integrations/<name>/`.
   A check that cannot fail is broken: when you add a check, add the case where it fails.
2. **Fail closed.** Missing evidence reads inconclusive, never pass. A verdict never changes because of a human note
   (`src/store.mjs` keeps notes apart from runs). Keep both.
3. **Wording.** Product output follows `test/claims-wording.test.mjs`: counts carry their limits, and nothing says
   "fixed" outside the owned synthetic fixture. Documentation describes what a result shows and what it does not.
4. **No network beyond loopback.** Tests and fixtures bind `127.0.0.1` only. A change that contacts anything else
   needs a reviewed exception in `docs/DATA-HANDLING.md` (regenerate it with
   `node integrations/data-handling/render.mjs --write`).
5. **No dependencies.** Standard library only, in Node and in the Python verifiers. Say so in the PR if you think
   one is unavoidable, and expect a discussion.
6. **Style.** Match the file you are in. ES modules, two-space indent, no build step.

## Commits and sign-off

Every commit carries a Developer Certificate of Origin sign-off, which says you have the right to submit the change
under this repository's licence (Apache-2.0):

```sh
git commit -s -m "observers: refuse an unattributed pg-snapshot window"
```

That adds `Signed-off-by: Your Name <you@example.com>`. The DCO text is at <https://developercertificate.org/>.
Commits without it are not merged. Write the subject as `area: what changed`, in the present tense.

## Pull requests

- One change per PR. Describe what it does, why, and how you tested it. Fill in the template.
- Keep the PR in **draft** while you iterate; CI runs the full suite when you mark it ready.
- CI must be green on the final head. A flaky file gets one automatic rerun; two failures are a real failure.
- Expect a review that asks about the failing case and about limits. That is normal here.

## Good first issues

Issues labelled `good first issue` are scoped, have a named file and a named test, and need no knowledge of the
whole system. Comment on one to take it; nobody is assigned silently. The drafts they are opened from live in
`.github/GOOD-FIRST-ISSUES/`, one file per issue with its pointers, acceptance line, test to add and effort note, and
`test/good-first-issues.test.mjs` keeps every path they name real. If the one you want is not open yet, open it from
its draft, or ask in Discussions.

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). Reports go to <hello@scopehaven.dev>.
