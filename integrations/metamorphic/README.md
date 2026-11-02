# Metamorphic relations over record deltas

Every other ScopeHaven check needs someone to say what should change. A metamorphic relation needs no such spec: it runs one task twice, changes one thing between the runs, and says what the two runs' records must have in common. Any difference is a finding without a task-specific assertion.

This folder ships one relation, **tenant-swap**, and designs a second, **canary-plant**, which is not built here (see the end). Published metamorphic testing of agents compares traces; this compares the records the application wrote and sent.

Nothing here is wired into `src/`, the regression gate, the SARIF exporter, the CLI or an evaluator identity. The proposals at the end are not applied.

| File | What it is |
|---|---|
| `relations.mjs` | The profile declaration, the normalised record delta, the tenant-swap relation, its complement and the report rows. Pure: no I/O, clock or randomness. |
| `relations.test.mjs` | Fixed and defective twins, the real egress recorder and SQLite snapshot observer, missing evidence, never-pass. |
| `owned-fixture.test.mjs`, `fixtures/owned-fixture-run.mjs`, `OWNED-FIXTURE-COUNT.json` | The internal count on the owned SupportDesk fixture (below) and its committed receipt. |
| `fixtures/twin-desk.mjs` | Test-only two-tenant desk: one fixed build, four defective ones. |
| `mutations.mjs`, `MUTATIONS.json` | One mutation per property; each must fail `relations.test.mjs`. |

## The tenant-swap relation

One declared task runs as identity A and again as identity B, each with a **scripted or recorded model**. Each run's record delta is normalised, and the two must be equal.

- **Rows.** For each table: rows inserted, updated and deleted between the task's start and end, matched by the table's key within each run. An update carries the row's content before and after, so a row that started differently also differs.
- **Sends.** Each committed or denied send from an egress recorder, SMTP sink or provider feed: its source, destination name, resource, outcome and declared captured fields. Body digests are salted per recorder, so they are never compared.
- **Renaming by role.** The profile declares each identity's values by role (tenant, principal, record, customer, hook host...). In A's run, A's values read `self:<role>` and B's `other:<role>`; in B's run, the reverse. That is renaming A's identifiers to B's and B's to A's in one step. Values are matched whole: a string equal to a declared value, an array element, an object key. A value inside a longer string (`acme-invoice-7`) is not renamed: declare it. A declared value that reads as a number (an integer tenant key, declared as `"1"`) is renamed only in a column (or captured pointer) the profile declares as an identity column (`identity: ["tenant_id"]`), whether the store holds it as text, a number or a bigint: there `1` reads as tenant 1, while a quantity of 1, a counter or a global row whose id is `"1"` elsewhere stays itself. A renamed number never equals a renamed string.
- **Ignorable columns.** Each table may declare columns to drop before comparison: generated keys, timestamps, random references. A key that is ignorable still matches a row across one run's own snapshots; the two runs' rows are then compared as a multiset of contents. A write that moves only ignorable columns is no change (counted as `ignoredOnlyUpdates`). A declared send may name captured pointers to ignore (an event id) and identity pointers. A send declaration applies to both identities' destinations of the same role, so declaring A's hook host covers B's; a second declaration for the same role is refused.
- **Undeclared tables are compared whole**, with the key detected as the collateral state diff detects it (a unique `id`, else a multiset). So a missing declaration shows up as a difference, never as silence.
- **Both sides must have observed the same things.** The same tables in their snapshots and the same observers with the same scope; otherwise the pair is not compared (below), since a table or observer one side lacks would read as "nothing changed there".

Any row or send present in one delta and not the other is a finding naming the table (or destination), the key, its role if the key is an identity value, and the side: `A-only`, `B-only`, or `both-differ` with the fields that differ.

Equal deltas read **no difference observed**, never pass. The relation is **FAIL-only**: with any model, run-to-run variance can make two runs differ, and a pass needs allowlisted deterministic evidence (a check with its own assertion). Every row says so in its custody tag (`fail-only:<custody>`).

### The profile declaration (`scopehaven-metamorphic/1`)

```json
{ "schema": "scopehaven-metamorphic/1", "relation": "tenant-swap",
  "identities": {
    "A": { "actor": "ana", "values": { "tenant": "acme", "account": "acct-acme", "hook": "acme.hooks.example" } },
    "B": { "actor": "gil", "values": { "tenant": "globex", "account": "acct-globex", "hook": "globex.hooks.example" } } },
  "tables": [{ "table": "accounts", "key": "id", "ignore": ["updatedAt"] },
             { "table": "credits", "key": "id", "ignore": ["id", "createdAt"] },
             { "table": "audit", "key": null },
             { "table": "orders", "key": "id", "ignore": ["id"], "identity": ["tenant_id"] }],
  "sends": [{ "source": "http-egress", "name": "acme.hooks.example", "ignore": ["/event_id"] }] }
```

Both identities declare the same roles; every value is distinct across both (a value both share could not say whose it is). This is a per-table declaration, smaller than a per-task assertion, but it is still a spec: someone has to know which columns are generated. The count below shows what happens when they are not declared.

### Inputs

A run record per side: `{ side, actor, task: { id, digest? }, model: { kind: 'scripted' | 'recorded', id }, states?, windows? }`.

- `states: { before, after }`: whole-state snapshots (`{ table: rows[] }`, the collateral state diff's input) with row values, so the projection applies. Custody: the application's own store (`subject-writable`).
- `windows`: observer windows (`scopehaven-effect/1`), one per observer instance for the task. A `sql-snapshot` window carries keys and whole-row digests only (`md5(row::text)` for Postgres, `MD5(JSON_ARRAY(...))` for MySQL, a hash of the row for SQLite), which include tenant ids, timestamps and generated keys. So a table seen only there is compared by operation and normalised key (`level: 'key'` on its findings), and by counts when its key is ignorable, never by content. The key column is the declared key, else `id` (as the states path reads it), so `ignore: ["id"]` makes a table's generated keys compare by count here too; a numeric-looking key is renamed only when its column is a declared identity column (the observers write every key as text). A keyless table's rows (resources `<table>/~<digest>`, as the state diff writes them) compare by count. A table the run's snapshots also hold is decided by the snapshots. Windows of sources the relation does not compare (audit tables, the hold gate, telemetry) are listed in `notCompared`.

### Inconclusive, never a finding

Each of these makes the swap read inconclusive with its reason (the first is the row's `reason`, all are in `reasons`):

| Reason | When |
|---|---|
| `run-missing:<side>`, `side-mismatch:<side>`, `actor-mismatch:<side>`, `task-missing:<side>` | the run record is absent or is not the declared identity's |
| `model-not-scripted:<side>`, `model-mismatch` | a live model, or two different scripts |
| `task-mismatch` | two task ids, or two task digests |
| `snapshot-missing:<side>[:before\|:after]` | a snapshot is missing, or only one side has snapshots |
| `window-failed:<side>:<instance>[:<reason>]` | a failed window (a mark that could not read the store) |
| `window-partial:<side>:<instance>` | a partial window, including one with destination-scoped late sends |
| `window-presence-only:<side>:<instance>` | a send window that is not complete and authoritative (no routing or witness) |
| `window-repeated:<side>:<instance>`, `collector-missing:<side>:<instance>`, `scope-differs:<instance>`, `windows-invalid:<side>` | an observer seen twice, on one side only, or with another scope on each side |
| `send-outcome-<outcome>:<instance>:<side>`, `row-outcome-<outcome>:<instance>:<side>` | a send still started or unknown; a snapshot row change that is not committed |
| `capture-unread:<instance>` | one send whose capture status differs between the runs where a body went unread (over the cap, not JSON): the identity values' own lengths can put one body over the cap |
| `table-missing:<table>:<side>` | a table the other side's snapshots hold, or one snapshot of a side, lacks |
| `table-shape:...`, `key-not-unique:...`, `row-limit:...`, `table-limit:<side>`, `value-unsupported:<side>`, `value-depth:<side>` | a snapshot that cannot be diffed |
| `nothing-observed` | neither side read a table (no snapshots, or empty ones) or a compared window |

An app-log window is refused outright (`custodyWindows`): the application's own action log never enters the relation. A send whose destination captures fields but could not read this body (`not-json`, `over-cap`, ...) is compared by destination and capture status only; it is counted (`sendsUnread`) and named in a no-difference basis.

## The complement: META-TENANT-OTHER (TENANT family)

A symmetric bug, where A's task writes B's row and B's writes A's, satisfies the swap: renamed, the deltas are equal. So the same normalised deltas are also read for any changed row or send that carries the **other** identity's declared value, in either run: in the key, in any column of the row (before or after an update), in a send's destination, resource or captured fields. Each is a finding naming the run, table, key and fields.

This is the record-delta reading of the TENANT family's rule: TENANT-01 (`src/domain.mjs`, the owned fixture's foreign-record check) and `json.noForeignValues` (`src/tenant-values.mjs`, other tenants' values in a response). It shares no code with either and replaces neither: it reads only the declared values, whole, in the records the run observed. It fails from a single run's records, so it can fail when the pair is not comparable (a missing snapshot or a partial window on the other side); its fail row then carries the pair's reasons. It never reads a run whose identity is in doubt (`run-missing`, `side-mismatch`, `actor-mismatch` or `task-missing` for that side), and like the swap it never passes.

## Report rows

`tenantSwap(profile, { A, B })` returns the result and two rows in the shape of the existing check rows (`collateralRows`), so the gate and the SARIF exporter can carry them later:

| Field | Meaning |
|---|---|
| `check` | `META-TENANT-SWAP` or `META-TENANT-OTHER` (with `family: 'TENANT'`) |
| `status` | `fail` or `inconclusive`. Never `pass`. |
| `verdict` | `fail`, `no-difference-observed`, `no-other-identity-observed` or `inconclusive` |
| `reason`, `reasons` | `deltas-differ`, `other-identity-changed`, the no-difference verdicts, or the inconclusive reasons above |
| `basis` | at most 1200 characters, ending with the FAIL-only statement |
| `custody` | the weakest custody (`src/custody.mjs`) of the places that decided, named `states` (the run's snapshots, `subject-writable`) or `<source>/<instance>`: for a fail, those its findings came from (on both sides); for no difference, everything compared. `null` when nothing was compared. |
| `custodyTag`, `failOnly` | `fail-only:<custody>` (or `fail-only`), and `true` |
| `findings`, `truncated` | up to 64 findings, then a count: `{ side, kind, table \| source + destination, op, outcome?, key, keyRole, keyTextB?, fields?, changed?, level?, via }` |

Findings carry tables, keys, field names, destinations and roles, never a row value: contents are compared as sha256 digests of typed canonical forms (`state-diff.mjs canonical`: the string `"1"` is not the number 1).

## What the relation cannot see

- **Effects outside the observed stores.** A table no snapshot holds, a send that does not pass a sink, a side effect in another service: identical silence on both sides reads no difference.
- **Nondeterministic ids and time columns.** Generated keys, timestamps and random references differ by run. Undeclared, they read as differences (noise, never silence); declared ignorable, a real difference in that column is not seen either (a timestamp an agent sets wrongly, a key it reuses).
- **Seed data that is not isomorphic.** The relation assumes A's and B's starting data mirror each other. Where they do not (different amounts, an extra record on one side), the honest behaviour reads as a difference. The owned fixture is like this (below).
- **Values inside other values.** Renaming and the complement read whole values: a declared value inside a longer string, a digest or an encoding is not seen.
- **Net change only.** Two snapshots show what persisted: a write undone inside the task is invisible on both sides.
- **Content behind a whole-row digest.** Snapshot observer windows compare keys and counts, not content, until a snapshot observer seals a projected digest (proposal 1).
- **Order.** Arrays compare in order; a list the application builds in a fixed global order (every tenant's records) differs by side. That is a real tenant-unscoped effect on the owned fixture, but it could also be an ordering nobody cares about.
- **Live models.** Refused: a live model's variance would read as findings.

## Internal count on the owned fixture

`fixtures/owned-fixture-run.mjs` runs 32 tasks (every single-actor operation of `src/fixture.mjs`, suite 2.x, `support-fixture/5`, except `refund-disconnect`, which drops its own connection; `concurrent-read` needs both actors at once) on both builds, each as alice (tenant aster) and as bob (tenant cobalt), each run on a fresh fixture on 127.0.0.1. The fixture's agent is deterministic code, so the model is scripted. The deltas are the fixture's own whole-state snapshots before the first request and after the last. No task carries an assertion. 64 pairs, 128 runs; every pair was comparable; no row read pass. Four profiles turn two declarations on and off:

| Profile | Swap flags (pairs) | Swap findings | Complement flags |
|---|---|---|---|
| identity values only | 41 | 74 | 9 |
| plus ignorable columns (generated ids, the case note's reference) | 30 | 33 | 9 |
| plus each tenant's record markers (copied into the activity feed) | 25 | 50 | 9 |
| both | 9 | 9 | 9 |

- **Noise from undeclared ignorable columns: 16 pairs** (flags that declaring the ignorable columns alone removes, with the markers declared). **Noise from undeclared identity values: 21 pairs.** 5 pairs needed both. 32 of the 41 identity-only flags were noise from missing declarations.
- **With both declared, 9 swap flags:**
  - 2 real tenant asymmetries, both in the vulnerable build: a member refund with no scope defaults its resource and recipient to aster's (`refunds`: `recipient`, `resource`), and the document export writes every tenant's record ids in one fixed order (`exports`: `recordIds`).
  - 7 noise from seed data that is not isomorphic (`refundRequests`: `amount`, and `orderId` once): aster's recent order totals 80 and cobalt's 60, and aster has an older order cobalt lacks (which the vulnerable build's "last order" picks). 3 of these are on the repaired build, which has no real flag.
- **The complement, 9 flags, all in the vulnerable build, none in the repaired one, whatever was declared:** reading, forwarding, metered-reading and refusing over the other tenant's record, the other tenant's order refund request, the unscoped refund default, and the document export. These are the TENANT-01 and UNTRUSTED-01 defects the fixture seeds, found without an assertion.

The count is an internal measurement on an owned synthetic app with a scripted agent, not a claim about any other application. `owned-fixture.test.mjs` re-runs it and holds the receipt to it; a change to the fixture fails there until the receipt is regenerated and any new flag is classified here.

## Tests and mutations

- `relations.test.mjs` (21 tests): the profile's refusals; fixed twins (five tasks, two seeds) show no difference; defective twins fail (an asymmetric cross-tenant leak, a tenant-scoped side effect with no other-tenant value, a hard-coded webhook host through a real egress recorder); the symmetric swap bug passes the swap and fails the complement in both runs; ignorable columns undeclared read as noise naming the field, declared they do not; renaming edge cases (arrays, object keys, key order, typed values, integer identity columns, a global row with id `"1"` that is not tenant 1); SMTP recipients renamed by role; the real SQLite snapshot observer at key level, and a failed mark; every missing-evidence reason, including a table or an observer scope on one side only and a run filed under the wrong identity; never pass over 500 generated pairs (1,000 rows).
- `owned-fixture.test.mjs`: the count above, its noise attribution (each noise pair's findings checked against the declaration that removes them) and the receipt.
- `mutations.mjs`: one mutation per property of `relations.mjs`, 87 in all. The run in `MUTATIONS.json` (unsandboxed, Node 24.21.0, on a private build, with sha256 digests of the swept sources): 87 of 87 killed, the unmutated control passing before and after; a kill resting only on loopback tests counts only after a second failing run (34 such).

## Designed, not built here: the canary-plant relation

The second relation inspects message bodies for planted values. It is not built here; it would build on the shared canary module (`src/canary.mjs`) and the receive-time body hook.

- **Relation.** One task, one identity, a scripted or recorded model, run twice: run P with a canary planted in one declared input field (a record the agent reads), run D with a decoy of the same shape in the same field (drawn by `drawCanaryValue`, so length and marker shape match; never empty, so the task's branches see the same kind of value). The outbound records of P and D must be equal once the canary in P and the decoy in D are both renamed to one role, `plant`, exactly as tenant-swap renames identities.
- **What it compares.** The tenant-swap delta (rows and sends by destination and declared fields), plus, per send, the receive-time canary record from the sinks: `{ outcome, channel, encoding }` for the canary in P's sends and for the decoy in D's (`canaryVerdict`, never the body). A send that carries the planted value in P where its D counterpart carries no decoy, a send present in one run only, or a destination or field that differs, is a finding: the planted content changed what left. The relation reads only those records; no body text reaches it.
- **What it adds to the canary sink.** The sink flags the canary reaching a destination it may not reach. The relation flags behaviour that depends on the planted content even where no canary leaves verbatim (an extra send, another destination, a field that changes), and stays quiet where both runs echo their value to the same allowed place (the task's own reply quoting the note).
- **Inconclusive.** Any unexamined corpus part (`corpus-incomplete` and the other `CANARY_REASONS`), a body the sink did not read, or any tenant-swap reason. FAIL-only, with the same custody tag.
- **Profile.** `{ "relation": "canary-plant", "plant": { "table": "notes", "key": "<row key>", "field": "body" }, "canary": { "id": "plant-1", "valueEnv": "SCOPEHAVEN_TARGET_..." } }`: the canary declaration is `src/canary.mjs`'s, held in an environment variable, never in the profile. `validateMetamorphicProfile` refuses `canary-plant` today (`relation-designed-only`).

## Proposals

1. **Projected digests in the snapshot observers.** Let a snapshot table declare `{ "ignore": [<column>], "identity": [<column>] }`, and seal beside `md5(row::text)` a second digest over the row without the ignored columns, with identity columns kept as their own salted digests. The relation could then compare content from observer windows, not only from whole-state snapshots. Owners: `integrations/observers/` (pg-snapshot, mysql-snapshot, sqlite).
2. **Gate and SARIF wiring.** Carry relation rows as report-only FAIL-only rows: a `fail` fails the gate like any check; `inconclusive` with `failOnly: true` neither passes nor counts as `inconclusive-evidence`. SARIF: `fail` as kind `fail`; the no-difference verdicts as kind `informational` or `open` with the FAIL-only note, never `pass`.
3. **App-log separation.** `tenantSwap` passes its windows through `custodyWindows` (tested). If a later export of this module takes windows directly, add it to `GUARDED` in `test/app-log-separation.test.mjs`.
4. **Network sites.** `fixtures/owned-fixture-run.mjs` calls the global fetch against the owned fixture on 127.0.0.1 and has its row in `SITES` in `integrations/data-handling/render.mjs`, which scans shipped fixtures too.
5. **Identity.** When a verdict path reads these rows, `relations.mjs` (and `state-diff.mjs`, whose `canonical` it uses) joins that path's evaluator identity set.
6. **Two identities by default.** A profile's actors already name two identities; a run mode that executes every declared check once per identity and feeds the pairs to `tenantSwap` gives every profile the relation without new checks.
