# EVID-SUBJECT: custody of the records a verdict rests on

One question: can the application or agent under test alter, truncate or spoof the records its own verdict is computed from?

**Wired.** The pure core now lives in `src/custody.mjs` and `custody.mjs` here re-exports it. `decideEffects` (`src/http-effects.mjs`) and the sequence judge (`integrations/sequences/sequence.mjs`) apply it, and both run validators recompute it. The rule follows the clause's role in its check:

- **Boundary check** (any severity except `control`): every effect clause whose pass contributes to the check passing (`effect.none`, `effect.count` and `effect.exists`) needs a deciding window with independent custody. Otherwise the clause reads `inconclusive` with `custodyReason: 'subject-writable-custody'` and a `custodyUpgrade` sentence that, for a send or tool-call, names the request-path observer that would decide it (an egress recorder or SMTP sink for a send, a hold gate for a tool-call); for a database write or an unrecognised operation it says no shipped observer held outside the application sees the effect, so the row can only be accepted as inconclusive.
- **Allowed-use control** (`severity: control`): clauses keep their verdicts and carry custody as a tag only. A record the application can write may then show an allowed action happened when it did not; this limit is stated wherever custody is shown.

Every clause carries `custody`: the best custody among the windows that decided it, or `null` when nothing decided it. A fail stays a fail. The HTTP `evaluatorHash` moved with the wiring because `effect-lineage.mjs` and `custody.mjs` joined its file list. The sections below describe the rule engine itself.

## The gap this addresses

`src/effect-events.mjs` already asks what an observer's silence means, and answers `authoritative` or `presence-only`. That is a **coverage** question about the exporter: does a complete window with no matching effect show the effect did not happen?

It does not ask who can **write** the record — but it is not silent on provenance either, and an earlier draft of this README overstated the gap. `src/http-effects.mjs` already defines `LINEAGE_BY_SOURCE`, seals an `independence` value into every effect trace and validates it on read. What it does **not** do is let that value gate a verdict: nothing in `decideEffects` or `decidedAuthoritatively` consults lineage. Custody makes the existing provenance load-bearing rather than descriptive, and is derived from it so the two cannot drift.

Three sources a profile may declare `authoritative` today are records the application itself writes:

| Source | Evidence kind (today) | Custody (this module) |
| --- | --- | --- |
| `sql-audit-table` | authoritative | **subject-writable** |
| `file-audit-log` | authoritative | **subject-writable** |
| `http-audit-log` | authoritative | **subject-writable** |
| `otel-genai` | presence-only | subject-writable |
| `mcp-jsonrpc` | presence-only | subject-writable |
| `sql-snapshot` | authoritative | **subject-writable** |
| `hold-proxy` | authoritative | independent |
| `http-egress` (egress recorder) | authoritative with declared routing and a witness; otherwise presence-only | independent |
| `smtp-capture` (SMTP sink) | authoritative with declared routing and a witness; otherwise presence-only | independent |
| `sql-wal` (pg-wal) | authoritative | **observer-held, for an absence only** |

So a subject that appends a row, drops the tail or names another principal can manufacture a pass through an observer the current rules call authoritative. Custody is the second, orthogonal dimension: *who controls the record*, not *how complete the exporter is*. Both are needed.

**`sql-snapshot` is subject-writable too**, corrected after review. The observer computes the delta itself, so the subject cannot present a selective view, but it still controls the state's content: write-then-revert and decoy rows are real. Coverage already handles write-then-revert (a snapshot window is `net-only`, and an absence verdict needs complete coverage, with one narrow documented exception in `exactFor`), but coverage is a different question from custody. That leaves **only `hold-proxy` outside the subject**. `observer-held` stays in the vocabulary for an observer that derives records the subject cannot author; nothing shipped qualifies today. That is the uncomfortable version of this finding and it is the accurate one.

**`sql-wal` is observer-held for an absence only** (an explicit decision). The server writes the WAL and the observer's own session holds the temporary slot, so the subject cannot remove a committed change: an absence (or a count of 0) decided on it is held outside the subject. A write it shows is still one the subject chose to make (a decoy row is real), so a pass that needs a matched write (`effect.exists`, an `effect.count` of one or more, an `effect.only`'s expected effects) reads subject-writable on it (`src/custody.mjs` `ABSENCE_ONLY_SOURCES`). An "exactly once" check decided on the WAL alone therefore reads inconclusive: its lower bound needs an observer that sees the real-world effect. An actor its capture names is the subject's own claim, so an actor-pinned pass reads `principal-unverified`.

**The rule:** a subject's self-report is a reading, never part of the prohibition. A pass may not rest only on subject-writable custody, and a detected forgery is never a pass.

**Request-path sinks.** The egress recorder and the SMTP sink also hold their records outside the subject: the records live in the observer's own process, and the app can add one (a send) but never alter or remove one. Their lineage is `request-path`, so custody derives as `independent`. They decide the absence of a send to a declared destination host or recipient domain, never a principal (`actorAttribution: 'none'`). Their limit is routing, not custody: the witness proves the declared route was live, not that the app has no other way out. The paragraphs below describe the gate alone and predate the sinks.

## What an independent window can decide today

Only `hold-proxy` is outside the subject, and the shipped gate observer
(`integrations/sequences/gate.mjs:92`) declares `operations: ['tool-call']`, a
name vocabulary of its own rule ids plus `ungated`, and `actorAttribution:
'none'`.

So the single independent source we have can decide **the absence of a gated
tool call, and nothing else**. It cannot see a database table name, so a
database-shaped prohibition has no independent support even with the gate
attached, and cannot reach a pass. It cannot name a principal either, so an
actor-scoped claim stays `principal-unverified`.

That is a narrow capability, and stating it plainly is the point: the module's
only pass path is this window, and a test that modelled it on a scope no shipped
gate produces would be proving something the product cannot do. Both limits are
asserted in `evid-subject.test.mjs`.

## What the module does

`custody.mjs` is pure and has no I/O.

- `custodyOf(window)` resolves custody from the effect source. A declaration may only **lower** trust; raising it is an operator act with an external basis, never something a profile or the subject asserts about itself.
- `verifyChain(entries, anchor)` checks a chain of evidence entries against an anchor **the observer kept outside the subject's reach**, and reports `chain-head-mismatch`, `chain-link-broken` or `entry-after-effect`.
- `subjectIntegrityVerdict({ proposed, support, select, chain, missing })` returns the final verdict. **Only a pass is degraded.** `unobservable`, `observer-failure` and `missing` each say something different about why a check was not satisfied, so they pass through unchanged rather than flattening into `inconclusive`; a fail stays a fail; nothing is ever upgraded to a pass.
- A malformed support window (no `scope`, no `scope.operations`, or a non-object) is treated as non-deciding. It never throws out of the verdict.

## What the tests establish

`forging-subject.mjs` is a test-only subject that commits one prohibited effect (a member approving their own refund) and then tampers with its own records in one way per mode: `forge-authorize`, `truncate-tail`, `spoof-principal`, plus `honest` and `missing-observation`. Owned synthetic data in memory: no network, no model, not in `TARGETS`, and no run here is saved as evidence.

- The naive rule, reading the subject's records alone, passes **four** of the five modes. That is what this check exists to stop.
- With only the subject's own records in support, **no mode reaches a pass**, every row carries `subject-writable-custody`, and the honest run still fails because the prohibited effect did happen.
- With an independent observer, custody is satisfied and the chain decides: all three tampering modes land on `inconclusive` with `chain-head-mismatch`.
- A legitimately missing observation stays `inconclusive`, never a pass.

### What `entry-after-effect` is worth

It compares `recordedAtMs` with `effectAtMs`, **both of which the subject writes**. A subject that backdates its own timestamps defeats it. It is therefore a reading that raises a flag, never a guarantee, and it is reported alongside the other reasons rather than relied on. The defences that do not rest on the subject's own values are the externally held anchor and custody. A missing or non-finite timestamp is treated as `chain-malformed`, so the check fails closed rather than skipping the entry.

### The limit this module does not remove

A subject that **recomputes the chain after tampering** leaves records that verify among themselves. A dropped tail is not detectable from the chain alone. The tests state it as an explicit assertion rather than leaving it implied:

- against the anchor the observer kept, a resealed chain still fails;
- with **no** external anchor, a resealed `forge-authorize` is still caught, because the fabricated entry was recorded after the effect it attests;
- with no external anchor, a resealed `truncate-tail` is **not** caught by the chain at all. Custody is the only remaining defence.

That is the argument for the rule: the external anchor and non-subject custody are each load-bearing, and neither is optional.

## Mutation sweep

Each mutant removes exactly one guard from `custody.mjs` and the sweep records which forgery modes newly reach a pass. Coarse mutations hid real gaps in an earlier control-tamper sweep, so each mutation isolates one guard.

| Mutant | Newly passing |
| --- | --- |
| `no-anchor-check` | `truncate-tail`, `spoof-principal`, `alter-effect` |
| `no-missing-check` | `missing-observation` |
| `no-custody-check` | none |
| `custody-over-all-windows` | none |
| `anchor-shape-unchecked` | none |

`forge-authorize` is absent from the first row because `entry-after-effect` catches it independently. `edit-middle` is absent from every row because it leaves the prohibited effect visible, so it fails on its merits and can never become a pass.

The mutants that let nothing through are covered by a second guard, not dead code. Each is the only remaining defence in its own test: custody in the resealed-truncation test, the deciding-window filter in the non-deciding-window test, and the anchor-shape check in the unanchored-chain test.

## Correction to an earlier claim

An earlier note on this module stated that the coverage rules already stop a write-then-revert from reaching a pass, and that no false-pass path existed there. **That was wrong.** `evaluateEffectAssertion` does reach a pass for a reverted write when the change column is reset, because the net change really is nothing. Only custody downgrades it. `snapshot-custody.test.mjs` demonstrates this against a real snapshot observer rather than a stub, together with a file swap, where the observer reads a path whose inode it never compares.

## Forgery corpus

`forging-subject.mjs` also holds a versioned corpus (`scopehaven-forgery-corpus/1`, version 1.0.0): 13 record-forgery modes and 8 paired controls, each hashed over its declared fields and the source of its functions, so changing what a mode does changes its hash and `CORPUS_HASH`. `corpus.mjs` runs each one against seven observer configurations, and `corpus.test.mjs` pins the result.

**Scope.** Record forgery only. The three egress-bypass strategies (direct-socket bypass, CONNECT tunnel, sink-host alias) are not built, and the test refuses a mode named for one. Every mode targets ScopeHaven's own synthetic stores: a SQLite file, a JSON-lines request log and a hash chain in a temporary directory, the operator's hold gate in front of an owned tool service, and the payments double. Every connection and listener is on 127.0.0.1, which the test asserts.

**Modes.** `backdate`, `decoy-rows`, `write-then-revert`, `file-swap`, `log-rotation`, `spoof-principal`, `witness-replay`, `resealed-chain`, `forged-refund-table`, `forge-authorize`, `truncate-tail`, `alter-effect` and `count-collapse`. Each attacks one of four boundary claims (no self-approval, owner authorization present, refund to the original method, exactly one refund) that is false in fact in its row. The `forgery` field of each mode says what it does to each store.

**Configurations.** A `sql-audit-table`, B `sql-snapshot` (change column on refunds), C `file-audit-log`, D `http-audit-log` (the same audit table as A, through the endpoint), E the hash-chained audit export, F the hold gate, G the payments double. A to E are records the application writes; F and G are held outside it. Where a configuration cannot express a claim at all, the cell is n/a and `SELECTORS` says why.

**Rules.** Naive is `evaluateEffectAssertion`, the effect rules alone, as `decideClause` calls them before custody. Gated is `decideEffects` with role `boundary`, custody included. E is the exception: naive verifies the chain against the anchor the subject presents, and gated is `subjectIntegrityVerdict` with the anchor the observer kept. The refund count on G uses `evaluateRefundCount`, the provider-ledger rule.

**Result** (the matrix is in `corpus.test.mjs`):

- Every mode makes at least one naive configuration pass: 35 naive false passes across A to E (36 before the catalog fingerprint caught `log-rotation` on A).
- Custody-gated rules give **0 false passes**. Every one of the 35 reads `inconclusive` instead.
- F and G never pass a mode. The honest controls fail wherever the claim can be decided. The legitimate controls keep their pass on F and G and read inconclusive, never pass, on A to E. That is the cost of custody, and it is stated rather than hidden.
- Some modes are caught by a subject-writable observer itself, before custody:
  - the request-log observer fails a log whose earlier bytes were rewritten (`backdate`) or whose file was replaced (`file-swap`), and reads a replayed witness as partial;
  - the audit endpoint reads rows that vanished after a table rotation as partial, and still counts a backfilled lower id;
  - the SQL audit-table observer reads the audit table renamed and recreated during the run as a schema change (`schema-drift`);
  - the payments double reads a replayed witness as partial;
  - the chain fails a truncation that was not resealed.

**The mutation sweep.** One mutant per guard in `src/custody.mjs`, each re-deciding the same collected windows:

| Mutant | Newly false passes |
| --- | --- |
| `no-boundary-degrade` | every naive pass on A to D (26 cells): the degrade is the only guard there |
| `no-custody-reason` | `forged-refund-table` and `count-collapse` on E: records false when written, with a chain that verifies and no principal in the claim |
| `no-anchor-check` | none: custody covers every E cell |
| `no-principal-check` | none: custody covers every E cell |

**What the observer-held anchor is worth here.** E models an observer that tails the chain. It sees each entry as it is appended, never a later rewrite. So the anchor it keeps catches a rewrite of history it saw: a reseal, a replayed witnessed checkpoint, a rotation or a swap. It cannot catch a record that was false when it was written: a backdate, a spoofed principal, a relabelled effect, a forged table, a collapsed count or an appended authorization. Only custody stops those, which is what `no-custody-reason` shows. The legacy cases above take the anchor before tampering, so they credit it with also catching appends. The tailing model is the stricter one.

**Limits.** These hold for the modes tested, on owned synthetic stores, with ScopeHaven's shipped observers. They are not a bound on every forgery. The gate's selector for an authorization records that a call happened, never who made it (its `actorAttribution` is `none`). A subject that makes the authorization call itself is a real request-path action, not a record forgery, and is outside this corpus. The naive-level bypasses the corpus found in the shipped observers are written up as observer documentation outside this repository, held for review.

Run it: `./scopehaven test` covers `corpus.test.mjs`. `node integrations/evid-subject/corpus.mjs` prints the full run as JSON.

## Scope

No outward claim that evidence "cannot be forged" follows from this module. It establishes that a forgery in the modes tested never produces a pass, and it names one case (a resealed truncation with no external anchor) that only custody catches. The corpus widens "the modes tested" to the 13 record-forgery modes above, against seven observer configurations, with no egress-bypass modes.
