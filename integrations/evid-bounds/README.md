# Evidence bounds and pair verdicts (M2)

Every result should say how much of it was decided, and whether a forbidden check held because the app works correctly or because it refuses everything. This folder computes both from a saved run. **Presentation only:** it never feeds a verdict, a count, `compareRuns`, a gate outcome or any identity hash, and it is new files only.

## What it reports

**Evidence bounds per side**, following Gao and Zhou's evidence-supported bounds:
- For the forbidden checks and, separately, the allowed-use controls: with N checks, P passed and U undecided, the share that holds lies in **[P/N, (P+U)/N]**.
- U is broken down by contract verdict: `missing`, `conflicting`, `not-exercised`, `observer-failure`, `unobservable`.
- These are partial-identification bounds, not confidence intervals.
- When every check of a side is undecided, the line reads "no claim supported".

**Pair verdicts**, for each declared (forbidden, control) pair:

| Verdict | Meaning |
| --- | --- |
| `held-and-useful` | the forbidden check passed and its allowed-use control passed |
| `held-by-inaction` | the forbidden check passed but its control did not |
| `violated` | the forbidden check failed |
| `undecided` | the forbidden check reached no pass or fail |

When allowed actions were refused and none worked, the pair line begins "held only by refusal: 0% of allowed actions still work". Controls that are only undecided are not a refusal, and get no such label. The labels never say secure, safe or certified. The spec's wording was "safe by refusal", and the word "safe" is avoided on purpose.

**Degenerate baselines:** what the do-nothing and dump-everything builds score on the same rows. Neither holds a single pair usefully on suite 2.3.0.

**Comparison support:** a change is "supported" only when four things hold:
- the runs are comparable: `compareRuns` finds them compatible (the same application, suite, policy, fixture or profile, and context). A run of another application, or a synthetic run against an HTTP one, reads "?" and says why;
- the candidate's lower bound on the forbidden checks is above the baseline's upper bound on the same checks;
- every allowed-use control of the candidate passed;
- both runs match the expected suite the target exports (`expectedSuite`, from the registry's `currentSuite` or `exportSuite`, never rebuilt from a stored run: see Limits), checked as the regression gate checks it. Without the suite the bounds are still shown, but the label is "?": an edit made consistent in both stored runs (a row deleted with `checksTotal` changed to match, the required controls narrowed) cannot be ruled out without it.

Otherwise it reads "?", with the reason. This is a support rule, not a significance test, and it is about the share held, not each check. A check either run never sent counts as missing on both sides: a forbidden check never sent is undecided, and a control never sent did not pass. So a slow, unchanged app whose budget ran out on a failing check, or a candidate whose control was never exercised, reads "?". When the share is supported while some candidate checks are undecided, or some chosen checks held in the baseline and fail in the candidate, the label says how many ("supported (1 undecided, 1 regression)"), and the checks are named (`undecidedInCandidate`, `regressedInCandidate`), never credited. A hang on one forbidden write gives [0%, 0%] to [50%, 100%]: supported on the decided evidence, with the undecided check named. `checkIds` naming a check one of the runs does not have is refused. `expectedSuite` is applied to both runs, whatever their kind. The control half is required. Against the vulnerable build (forbidden held [0%, 0%]), the do-nothing build reaches [30.8%, 38.5%] and dump-everything reaches [3.8%, 11.5%]. Both clear the bound rule alone, and both read "?" because 0 and 13 of their 18 controls pass.

`checkIds` narrows the forbidden side to the named checks. An id either run does not have, and an allowed-use control (every control always counts), are refused. The result echoes the compared ids (`compared`). Evidence either run fails (the suite, the row checks) makes the result not comparable, with the side and the reason named.

## Where the verdicts come from

- **Synthetic runs:** from the evidence-contract view (`src/contract-views.mjs`), which recomputes each check from its retained evidence. A stored "pass" that the evidence does not support is counted as what the evidence shows, not as a pass. The tests show this with a missing snapshot.
- **HTTP runs:** connector v2/v3 runs have no contract view yet (`http-version-pending`), so they are read only after `validateHttpRunEvidence` has recomputed every row it recomputes: every row except a not-applicable one, which is checked here (below). An inconclusive row takes the verdict word of its first undecided effect assertion, and is `missing` otherwise. Rows are read as the v1 projection in `src/contract-http.mjs` reads them: a not-applicable row is `not-exercised` and an error row is `observer-failure`, both undecided and in N. A target that hangs, resets or answers too much is not infrastructure. Roles follow the same file: a required control is an allowed-use control, and every other row counts on the forbidden side.

A row whose request was never sent, because the run budget ran out, stays in N as `missing`, in one run's bounds and in a comparison alike; the count is printed ("Never sent: ..."). An HTTP run whose row count differs from its `checksTotal`, that repeats a row id, in which two sent rows share a `requestId`, or that fails validation gets no bounds. The first three read `check-set`; with a suite, a deleted or repeated row id is refused first by the suite's row ids (`unexpected-suite-evidence`). Every sent request gets its own `requestId`, so only a copied row repeats one; not-applicable rows send nothing and carry none. **Not-applicable rows** are not recomputed by the shared validator. With a suite it does refuse one the suite does not declare not applicable (`unexpected-suite-evidence`, applicability-mismatch), so a relabelled row is refused there first; the full check is here: a not-applicable row must be one the connector wrote (it recomputes as not applicable, and its digest is the digest of its declaration), and, with `expectedSuite`, the suite must declare that check not applicable. **With `expectedSuite`** (any run type: synthetic, HTTP v1 through its contract view, HTTP v2/v3), a run whose row ids, required controls, suite hash (an HTTP run's `profileHash`) or per-check severity differ from the suite gets none, reason `unexpected-suite-evidence`, as the gate refuses it.
- **Pairs:** the suite 2.3.0 pairs are `test/self-check.test.mjs`'s `SELF_CHECK_PAIRS`. A test compares the two by reading that file's text, never by importing it. A pack's own pairs are passed in and validated: an unknown id, a forbidden check used as a control (or the reverse) and a duplicate pair are refused. A control the run never sent reads `missing`, so its pair is at best held by inaction. A run with no declared pairs reports none rather than guessing.

## Measured on suite 2.3.0

| Build | Forbidden held | Allowed working | Pairs |
| --- | --- | --- | --- |
| repaired | [100%, 100%] of 26 | [100%, 100%] of 18 | 26 held and useful |
| vulnerable | [0%, 0%] | [100%, 100%] | 26 violated |
| do-nothing | [30.8%, 38.5%] (2 not exercised) | [0%, 0%] | 0 held and useful, 8 held only by inaction, 16 violated, 2 undecided |
| dump-everything | [3.8%, 11.5%] | [72.2%, 72.2%] | 0 held and useful, 1 held only by inaction, 23 violated, 2 undecided |

On a loopback notes app with its observers off, the forbidden bounds are [0, 1] and no claim is supported.

## Proposed shared-path diff

The hooks are presentation only. The exact diff was applied to a temporary worktree of this branch's commit and the full suite run there. The diff and its suite result are kept outside this repository. `evidenceSupport` inherits the comparability rule above, so it never reads "supported" beside an incompatible verdict. It:
- moves `bounds.mjs` to `src/evidence-bounds.mjs`, with its imports made local, and leaves `integrations/evid-bounds/bounds.mjs` as a one-line re-export. `src/` does not import from `integrations/`, and the copied review server in `test/security-review.test.mjs` takes `src/` whole but only named integration files;
- `src/report.mjs`: prints the bounds lines under the allowed-use line, and adds `evidenceSupport` to `comparisonDocument`. `comparisonDocument` takes an optional fourth argument, `{ expectedSuite }`, passed to `comparisonSupport`. `src/export-cli.mjs` does not pass it yet, so an exported comparison reads "?" for evidence support until the target's suite is wired in;
- `integrations/regression-gate/gate.mjs`: adds `evidenceBounds` (both sides' bounds, the pair counts and `neverSent`, or null) to the gate summary's `current`, read against the expected suite the gate already holds;
- `test/allowed-use.test.mjs`: the pinned list of comparison-document keys gains `evidenceSupport`;
- `test/security-review.test.mjs`: the copied server also takes `integrations/groundedness/groundedness.mjs`. The report now reads the contract view, and `src/evidence-contract.mjs` imports that file.

A first attempt imported the module from `integrations/` into `src/report.mjs`, and it failed those two tests.

A later step, not done here: make `comparisonDocument`'s `verdict: 'comparable-controls-passed'` also require `evidenceSupport.supported`. That changes an existing export field, so the tests that pin it would move with it.

## Limits

- Bounds describe one run. They are not an estimate of a rate across runs; that is `stats.mjs`.
- A pair label depends on the control's quality. A weak control makes "held and useful" easy.
- **The suite must come from the registry** (`currentSuite` or `exportSuite` in `src/registry.mjs`), never be rebuilt from a stored run. The module trusts the suite object it is given, exactly as the regression gate's `validateRun` does: the suite's hash covers private profile fields, so neither can recompute it. A suite shaped by the caller to match edited runs (its required controls narrowed, a check marked not applicable, or ids, controls and hash copied from a run) is accepted by both. The export path passes no suite today, so it reads "?"; when it is wired, it should take the suite from the registry.
- **A copied row.** A passing row copied verbatim into another check's slot of the same method, actor and assertion kinds, with its id and title set back, is refused here because it repeats a `requestId`. The shared core now refuses that copy too: `validateHttpRunEvidence` and the gate's `validateRun` reject a repeated `requestId` (`duplicate-request-id`), and `compareRuns` reads the pair as incompatible (the test pins all three). A copy whose `requestId` is also rewritten and its digest recomputed is not caught by the guard; with the suite it reads [100%, 100%] and "supported". A row's digest covers its evidence and assertions, not the check id or the request path, and the shared validator does not bind the request path to the check. With the suite, "supported" still rests on stored runs no one edited that way.
- An HTTP v1 run never matches a current suite export (the suite hash covers the assertion schema version), so with a suite it is always refused; without one its contract view is read.
- HTTP undecided reasons come from effect assertions only. An inconclusive row with no undecided effect (an unproven login, for example) reads `missing`.
- Without `expectedSuite`, a stored run edited consistently (a not-applicable relabel with its digest recomputed, a row deleted from both runs with `checksTotal` changed to match) is read as it stands. That is why no comparison is "supported" without the suite.
- A proposed diff is described above, but this PR changes no shared file: `comparisonDocument` and the gate summary show nothing until it is applied.
