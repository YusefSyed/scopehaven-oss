# Coverage report

A coverage report tells an operator, before any run, which actions of their application the suite actually checks, and which it cannot. It covers both sides:
- **Forbidden side:** cells the policy says must be refused, and whether a check tries them.
- **Allowed side:** cells the policy says must keep working, and whether an allowed-use control is drafted to exercise them.

Forbidden coverage without allowed coverage is how a fix that blocks everything reads as a fix.

**Scope.** It is computed only from the files it is given (inventory, contract, profile and, when given, the exported suite and stored runs). It sends no request and observes nothing, so it says which cells have a check, not what the application does. Every report says so.

**Presentation only.** It never feeds a verdict, a count, `compareRuns`, a gate outcome or any identity hash. It is new files only, and it reads `src/` without changing it. It is a coverage report, not a ledger: `integrations/ledger/` is the evidence-ledger workstream.

**In exports.** Given the same inventory, contract and targets files (`./scopehaven export ... --coverage-inventory ABS --coverage-contract ABS --coverage-targets ABS`), the exporter renders this report in the "Coverage and residual" section of the HTML report and the comparison exports, for the run's target, with the run's check ids as the suite (the candidate's, for a comparison).

## Inputs

1. **An inventory** (`scopehaven-coverage-inventory/1`): what the application exposes. Route tables, schemas and tool manifests belong here. They are inventory, never intent.
   - **Operations.** Each has an `id`, a `surface`, `auth` (`none` or `session`) and `tenantScoped`.
     - A request operation names an upper-case `method` and a `path` (or `paths`). Templates use `:name` parameters and match with or without one trailing slash.
     - A tenant-scoped operation with an id in its path names the `object` type the id refers to. With several parameters it names its `idParam`.
     - `refs` lists object ids read from the query or body, for example `{ "in": "body", "field": "ticket_id", "object": "tickets" }`.
     - `writes` optionally lists the datastores the operation writes.
     - A tool the model runs has `reach: "model-turn"`. It says whether it takes an object id (`addressable`), and names the request that starts the model turn (`via`).
   - **Tenants and roles,** and which roles have a user in each tenant (`members`).
   - **Datastores.**
   - **Which tenant owns each fixture object** (`objects`).
2. **A stated policy contract** (`scopehaven-coverage-contract/1`): who may do what. Each rule names one operation, the roles allowed (or `anyone`), and the roles allowed only under a condition. Cross-tenant access is denied.

   Intent comes from a stated contract, never from the implementation under test. The report carries that warning in two cases:
   - a contract whose `basis` is `app-declaration`;
   - checks drafted by policy import (category `Declared policy`). Policy import also never drafts a check for a cell the declarations leave undeclared.
3. **A validated target profile:** its actors (with `role` and `tenantId`), checks, `requiredControlIds` and observers.
   - Optionally, the exported suite (`GET /api/suite/export.json`) of this exact profile version. Its check ids are the reference count.
   - Optionally, a stored HTTP run of this target, and a list of stored runs.

## Cells

A cell is one role × tenant × surface × operation × object scope.
- **`own`:** an object of the caller's tenant.
- **`cross`:** another tenant's object. This exists only where a caller can name one: an id in the path, query or body, or an addressable tool. Where no other tenant owns an object of that type, the cross cell is unreachable.
- **`none`:** for the anonymous caller and for operations that are not tenant-scoped.

An operation anyone may call without a session has two cells, `anonymous` and `signed-in`, rather than one per role and tenant.

**Stated decision.** Each cell is `allow`, `conditional`, `deny`, or `null` when no rule covers its operation.

**Drafts.** Every check of the suite lands in exactly one cell:
- the actor's role and tenant;
- the most specific operation whose template matches (more literal segments first). Two operations matching equally well are an ambiguity, not a placement;
- own or cross from the fixture owners of the ids the request names. Ids, object types, member tenants and body fields are looked up as the maps' own keys only, so a name such as `constructor` or `__proto__` never resolves to a built-in. When a query names a parameter twice, its first value is read; a non-string body value is read as its string form;
- side `allowed` when the profile gives the check severity `control` (required or not), `forbidden` otherwise. That is the one rule for what a control is.

A check declared not applicable (`applicability.applies: false`) is counted apart and drafts nothing.

A check that fits no cell is listed with its reason:
- `operation-not-in-inventory`
- `operation-ambiguous`
- `object-owner-unknown`
- `actor-role-not-in-inventory`
- `actor-tenant-not-in-inventory`
- `unknown-actor`
- `not-in-profile`

**Marks.** Each cell gets the first of these that applies:

| Mark | Meaning |
| --- | --- |
| `drafted` | at least one check exercises it |
| `unreachable` | `no-user-with-this-role-in-this-tenant`, `no-other-tenant-object` or `no-user-in-any-tenant` |
| `not-judgeable` | `reached-only-through-a-model-turn`, or `connector-sends-get-and-post-only`: a profile check sends GET and POST only, though a sequence can send more |
| `needs-actor` | `no-actor-for-this-role-and-tenant`: an authoring gap, closed by adding an actor |
| `stated-only` | stated and judgeable, but no check |
| `unstated` | no rule in this contract covers the operation. Whether the application guards it is not observed here; it is the CWE-862 shape to look for |

A check sent to a request that starts a model turn is listed apart (`modelTurnChecks`). The model chooses which tool it reaches, so the tool cells stay not judgeable, and each names the checks that could have reached it.

**No row carries a severity.** A cell is about whether a check exists, not how bad a miss would be.

## Numbers

- **Reconciliation, in both directions.** Drafted plus declared-not-applicable against the suite's check count, with duplicates and unplaced checks listed, and every profile check the suite leaves out listed too (`missingFromSuite`). An export edited to drop a check therefore never reads as equal, whatever its own hash says. This is the first line of the in-sample acceptance.
- **Not judgeable.** The fraction of reachable cells, with and without the cells that need an actor. The held-out validation fails a holdout application above 0.50. The report cannot tell whether the application it is given is in the holdout pool.
- **Allowed side.** N of M reachable `allow` or `conditional` cells have a twin. M counts role × tenant × operation × scope. The plan's role × operation × surface count is printed beside it.
- **Forbidden side.** N of M reachable `deny` cells have a forbidden check. A required control on a deny cell covers nothing there and is listed as a disagreement.
- **Breakdowns.** Each side is broken down by role, by surface and by tenant, with covered, not-judgeable and needs-actor counts. A group whose cells are all unreachable keeps its row, with its unreachable count, rather than disappearing.
- **Listed apart, never counted as cell coverage:**
  - forbidden checks on permitted cells (a leak through a listing, a boundary on a conditional approval);
  - checks on cells no rule covers;
  - operations with no rule.
- **Datastores.**
  - Per datastore, which declared observers read its table: snapshot tables, or a SQLite audit table.
  - Observers of the application's own record (an audit endpoint, a log, traces) are listed apart, since they are not mapped to a table.
  - Where the inventory declares `writes`, the drafted checks on operations that write only unobserved stores are counted: their backend effects can only read inconclusive.
- **A stored run's findings** (`runFindings`, `--run`): its own failed checks, failed controls, inconclusive, errors, not applicable and passed.
  - Only HTTP runs the regression gate's run validator (`validateRun`, which applies the shared `validateHttpRunEvidence`) accepts are read. Other evidence origins, rows listed twice, unknown statuses, a row whose not-applicable status disagrees with the profile, and edits the shared validators detect (rows that are not internally consistent) are refused. A fully consistent edit of a run passes both checks: they verify consistency, not who wrote the file.
  - Whether a row is a control comes from the profile, never from the row.
  - A control that passes on records the application can write is listed with custody's stated limit: such a record may show an allowed action happened when it did not.
  - They are printed beside the not-judgeable count and never added to it. This is the negative control: on a correct application the finding count is zero while the not-judgeable count may be large.
  - The run must be of this target with exactly this suite's checks. A profile digest that moved is reported.
- **Run comparability** (`runComparability`, `--runs`). This is the plan's "someone owns the incomparability migration".
  - Stored runs compare only within one application and target, and only where `compareRuns` would compare them.
  - Runs are ordered by parsed time, then by id, so precision and offsets compare correctly.
  - A run that is not comparable with the one before it either starts a new series or continues an earlier series it compares with. The report names that run, and the reasons are `compareRuns`' own.
  - Full stored runs go through `compareRuns` itself. Summaries without results (`GET /api/history`) are compared on its identity keys only, and the report says so.

```
node integrations/coverage-report/cli.mjs --inventory inventory.json --contract contract.json --targets targets.json \
  [--target ID] [--suite exported-suite.json] [--run stored-run.json] [--runs runs.json] [--json]
```

Exit codes:
- 0: every suite check is drafted once or declared not applicable, and every profile check is in the suite;
- 1: a check is outside the inventory, missing from the profile, missing from the suite or listed twice;
- 2: a configuration error. That includes a `--suite` exported from another version of the profile, and a `--run` of another target or suite.

## Measured

**Shipped example profiles.** `examples/` holds an inventory and a stated contract for the synthetic two-company support app that `docs/profiles/*.example.json` describe. The test computes the allowed side for all four example profiles, which is the in-sample clause. That app has no code in this repository, so its inventory lists the operations those profiles address.

**Clean helpdesk practice app.** This is the owned helpdesk practice app 0.4.0 clean, with its v2 profile (32 checks, 10 required controls) and the registry's exported suite.
- **Sources.** The inventory comes from the app's router registrations, static handler and tool manifest, with query and body references read from each route handler. The contract comes from the builder's written receipt. Inputs and receipts are kept outside this repository.
- **Reconciliation:** 32 drafted of 32 suite checks. No row has a severity.
- **Allowed side:** 10 of 166 legitimate cells have a twin (8 of 86 by role, operation and surface).
- **Forbidden side:** 15 of 196 stated-deny cells have a forbidden check.
- **Not judgeable:** 158 of 369 reachable cells (42.8%), and 51.2% counting the 31 that need an actor. The 158 are 98 tool cells reached only through a model turn, and 60 PATCH, DELETE or HEAD cells.
- **Unstated:** one operation, `HEAD static`. The code serves HEAD, and the receipt states GET only.
- **Datastores:** 0 of 10 have a table-mapped observer; that profile declares none.
- **Negative control:** the stored clean run of 2026-10-05 has 0 findings, printed beside the 158 not-judgeable cells. Its profile digest predates assertion schema http-contract/4, and the report says so.
- **Broken inputs:** each acceptance check was run on an input built to break it, and each failed there (`BROKEN-INPUTS.json`).

## Not built yet

These are named so their absence is not read as coverage:
- boundary twins on the allowed side (C3);
- the fix-verification line;
- the measured false-block rate on clean builds;
- cross-run dedup with a baseline and expiring suppressions;
- per-finding reproduction commands;
- the taxonomy map for the CWE and OWASP API / ATLAS nodes; this report would need its own map rather than reusing `src/standards-map.json`.

Further limits:
- Which datastore an operation writes is declared by hand. The practice-app inventory does not declare it.
- Held-out validation needs a holdout pool.
- Surfaces the inventory cannot see, and whether the stated intent is itself correct, stay outside any coverage report.
