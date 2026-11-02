# Grant versus use

At the end of an engagement the application's owner asks three things: what the agent was granted, what it actually used, and what it holds that it never used. Cloud IAM access analyzers answer the same questions for roles, and auditors file the answer. This folder answers them from ScopeHaven's own records: the declarations name the grant, and the observers' sealed windows show the use.

**Presentation only,** like the coverage report. It never feeds a verdict, a count, `compareRuns`, a gate outcome or any identity hash. It is new files only, and it reads `src/`, `integrations/observers/`, `integrations/coverage-report/` and `integrations/sequences/` without changing them.

**Scope.** It is computed only from the declarations and the validated runs it is given. It sends no request and observes nothing itself. Only the runs given count: an unused grant is excess for these runs, not proof that it is unneeded.

## Inputs

1. **The grant (declarations).**
   - **Declared reach.** What the profile's observers name (for a sequence: its `observers.json` and `gate.json`):
     - egress destinations: each declared path of a host, or the whole host when it declares no paths;
     - mail domains: SMTP sink and provider feed;
     - snapshot tables: SQLite, Postgres and MySQL;
     - actions: audit-table and audit-endpoint actions, and audit-log rules;
     - tools: the hold gate's rules.

     Witnesses are the harness's own and are never part of the grant (the sinks never record the test's own witness units as effects). Denial names (`deniedActions`) and the gate's `ungated` name refusals and unmatched calls, so they are never part of it either. The declarations name this reach for the application, not per actor, so every actor is held against all of it: a payments host that only the operator's sessions reach is excess for the member, which is the scoping question the application's owner asks.
   - **Operations.** With an inventory and a stated contract (the coverage report's inputs), the reader adds the operations the contract permits each actor's role and tenant. These are read from the coverage report's own cells (`coverageReport(...).cells`, stated `allow` or `conditional`), never re-derived.
2. **The use (validated runs).**
   - **Profile runs.** Stored HTTP runs of this target. Each run is refused unless all of these hold:
     - it carries this exact profile digest;
     - it passes the regression gate's run validator (`validateRun`, the shared HTTP evidence validator), as the coverage report's `runFindings` does;
     - its rows are this profile's checks (actor, method and path digest).
   - **Sequence runs.** Each sealed sequence run must pass the sequence run validator against the sequence and its observer and gate configuration. Give the configuration the runs used: the run seals each observer's scope but not its settle, so a settle declared only in the configuration given is not checked against the run.

```
node integrations/grant-use/cli.mjs --targets targets.json [--target ID] --runs runs.json [--inventory inventory.json --contract contract.json] [--json]
node integrations/grant-use/cli.mjs --sequence seq.json --observers observers.json [--gate gate.json] --runs runs.json [--json]
```

`--runs` holds one run or a list. The CLI prints the Markdown rendering, or with `--json` the report itself.

Exit codes:
- 0: the report was produced. An inconclusive excess is a result, not an error.
- 2: a configuration error, or a run the validators refuse.
- Anything else is a fault of the tool: it is thrown, never reported as a configuration error.

## What counts as a use

A use is a **committed** effect event in a sealed observer window: an egress send, a mail recipient, a table insert, update or delete, an audit row, or a tool call through the hold gate. A refused (denied) audit row is not a use. Telemetry (OTel traces, MCP logs) and the application's own action log are the application's account of itself, so they are not read as uses.

For an operation, a use is one of the actor's own requests that the application answered with a complete 2xx. Operations are never excess, because the actor's requests are the suite's. The other outcomes:
- **Refused:** an allowed request the application answered with a complete response of another status. The allowed use did not work, which is a failed control, not excess.
- **Not observable** (reason `request-unanswered`): an allowed request that got no complete response (a reset, a timeout). The application may or may not have acted on it. A complete response whose body is not JSON (an empty 204, an HTML page) is an answer, as `src` counts it.
- **Not observable** (reason `no-check-requests-it`): an allowed operation no check of the suite requests as the actor. The coverage report lists the allowed cells no check exercises.

Every use cites:
- its run;
- its record: check window, gap or barrier between checks, sequence window, or HTTP response;
- the check or window;
- the observer and event seq, and the principal the record names, when it names one;
- its custody class (`src/custody.mjs`: `independent` for the request-path sinks and the hold gate, `subject-writable` for the application's own tables and audit records);
- how it was attributed.

## Who used it

Attribution is conservative. Only a record that names the principal, or the actor's own check, makes a use that actor's:

| Set | When |
| --- | --- |
| used | The record names the actor's principal (an observer with `actorAttribution: "principal"`, such as an audit table, whose `principals` list holds it). Or the event sits in the actor's own check window (an HTTP effect row whose request was attempted), fits no declared background source, and comes from an observer that names no principal. Or it sits in a sequence window only that actor's requests could have caused. |
| possibly used | Shared by every actor who could have caused it, and never excess for any of them. The cases: <br>a settlement gap or barrier between checks (a gap's candidates are the actors of every sent row in it, plus the effect rows on both sides: the one before for its late sends, the one after for its identity probe point; under a timing plan the run-end probes of every credentialed actor are inside the last gap, and with lifecycle entries the cross probes before a change check send other actors' credentials, so every credentialed actor is a candidate in every gap); <br>the window of a row whose request was never attempted (the run budget ran out), shared by the actors of the rows sent before it; <br>a sequence window, whose candidates are every actor whose request was sent before its end mark, since an earlier request's effect can commit late; <br>a principal the record leaves null or names `unlisted:` (a value outside the observer's `principals`, which `src` reads as possibly the selected actor); <br>a declared background source (`attribution.background`, which `src/http-attribution.mjs` attributes to no check); <br>a send its recorder carried late into a later window; <br>a tunnel (`CONNECT`), or a send whose path read ambiguously, which can be any declared path of its host (`pathUnknown`). |
| excess | Granted, neither used nor possibly used, and observable by an authoritative observer window. A **clean** entry (`excess.entries`) is one a record held outside the application could have shown: an egress or SMTP sink, the hold gate, or a provider feed whose key the application does not hold. Other entries go to **qualified** (`excess.qualified`), never counted as never exercised. The basis: <br>`application-records-only`: only the application's own tables or audit records could have shown it, and the application can write, omit or revert those; <br>`net-change-only`: a snapshot table, which reads net change, so a write undone inside one window is not seen; <br>`no-settle-declared`: in a sequence whose observers declare no post-response settle, so each end mark follows the last request at once. |
| not observable | Granted, but only presence-only telemetry could see it (silence there proves nothing), no observer window could, or (for an operation) no check requests it, or its cell cannot be reached. Neither used nor excess. |
| refused | An allowed operation the actor requested and the application did not accept. |
| used but not granted | A host, path, mail domain, table, action or tool call no declaration grants, or an operation the contract denies the role. It is listed once, linked to the failing rows that already hold it. When no failing row holds it, it is marked `unchecked`, and this report is where it shows. A use from a shared window is marked `shared`. |
| recorded under another principal | The record names a principal other than the actor for an effect inside that actor's own check window: a service identity, or another declared actor. This is the grant-versus-use join that FORESIGHT card F-03 (delegated authority widens scope) needs. A principal no actor declares is listed under `undeclaredPrincipals`, never credited to an actor. |

## Incomplete records read inconclusive

An actor's excess is `inconclusive` when its records could have missed a use. It then carries `notSeen` (what the records did not show), `undetermined` (each entry with its reasons) and `reasons`, and never an `entries` or `qualified` list, so no consumer can read a least-privilege statement off it. The reasons:
- **A partial or failed window,** a missing snapshot among them.
  - A scoped window is partial only because of its entries: late, in-flight, ambiguous-path or sibling-host. It casts doubt only on the grant entry each of those entries could be (same name, and for an egress path the same path).
  - A late entry that no later row window of the same observer, and no quiescent run-end drain, follows is read window-wide, as `src` reads it (`unfollowedLate`, `followedDrains`).
- **A recorder that did not drain** at the run end (`settlement.drains`).
- **A sequence request no window spans.** A window spans a request when the request was sent after the window's first mark and answered (or, in the background, awaited) before its end mark.
- **A stopped sequence.**
- **No request at all as the actor:** a row whose request was never attempted (the run budget ran out) does not count.
- **A run that declares observers but kept no settlement record,** so its other checks ran unobserved. Current runs always keep one when any check is observed, so this guards older records.

A snapshot's `net-only` coverage does not make the records incomplete; it qualifies the tables (above).

The same holds per run: each run's excess reads that run alone, and is inconclusive in a run that sent no request as the actor.

## Output

`scopehaven-grant-use/1`:
- `headline`: per group (destinations, tables, actions), the counts granted, used, possibly used, refused, clean excess and qualified (or `notSeen` when inconclusive), and unobservable, plus how many uses were not granted.
- `grant.entries`: each entry with its key and group, for example `egress api.pay.example /v1/refunds`, `mail customers.example`, `table refunds`, `action refund.create`, `tool refund` or `operation POST /api/refunds none`. Reach entries also name their declaring observers (`declaredBy`); operation entries name the cell's surface and scope.
- `application`: the sets over every actor, every use whoever caused it.
- `actors[]`: per actor:
  - `granted`, `used` (with run counts and citations), `possiblyUsed`, `refused`, `excess`, `unobservable`, `usedNotGranted`;
  - `usedUnstated` (an accepted operation no rule covers) and `delegated`;
  - `perRun`: used, possibly used, refused, excess and uses not granted for each run.
- `undeclaredPrincipals`, `caveat`, `scope`, `note`.

`render.mjs` turns it into the findings memo's Markdown:
- the headline sentences, for example: "Granted 6 destinations, 3 tables and 13 actions; used 3, 2 and 10 across 1 run; 3 destinations, 0 tables and 0 actions were never exercised. 1 table and 1 action more were not seen, but only in records that cannot show a grant went unused (the application's own, or a snapshot's net change, or end marks taken with no declared settle).";
- the caveat line;
- a per-actor table, with the qualified count in its own column;
- the uses not granted with their linked findings;
- what another principal did inside an actor's check;
- each actor's sets;
- the incomplete records;
- what the report cannot say.

## Tests

`node --test integrations/grant-use/grant-use.test.mjs` (about 10 s) uses owned synthetic records only. The HTTP runs are real connector runs (`runHttpAssessment`) over the support-desk fixture in `fixtures/support-desk.mjs`: an injected transport and in-memory observers on a virtual clock, with no socket, database, model or provider. Every run passes `validateHttpRunEvidence`. The fixture's audit observer names only its declared `principals` and records anything else as `unlisted:`, as the real one does. The sequence runs are real `runSequence` runs over in-memory observers with the hold gate's declared scope.
- **Fixed and defective twins.** In the defective build, the summarize agent charges a card, posts to an undeclared host, and writes a payout under a service principal. A member's refund is accepted, and the status page fires a webhook between checks. The known grants and uses are asserted per actor, per run and across runs.
- **The other builds:**
  - a missing snapshot;
  - a recorder that did not drain;
  - a late send carried into another actor's window;
  - a late entry nothing follows;
  - an `unlisted:` principal;
  - a declared background source;
  - a tunnel;
  - an allowed operation refused, one whose request got no response, and one answered with a body that is not JSON;
  - rows left unattempted by the run budget, one with a background send in its window;
  - sequences with a request no window spans, an earlier request's delayed effect, overlapping windows, and no declared settle.
- **Refusals.** Runs of another profile version, an edited run, another target, duplicates, half the coverage inputs, and a sequence run under another observer configuration are each refused.
- **Mutation sweep.** Each of the 41 properties is checked on the reader and then on one mutant that breaks that property alone; every mutant fails its check.

## Not built yet

- **Combined report.** Profile runs and sequence runs are read in separate reports: their actors are separate declarations. A combined report would join them by principal.
- **Telemetry and app logs.** They are not read as uses, so a tool seen only in an MCP log is not observable here.
- **Untested paths:**
  - per-check settlement barriers (no fixture run uses `settlement.mode: "per-check"`);
  - the check-unobserved guard for runs with no settlement record (current runs cannot produce one);
  - the gap candidates under lifecycle entries (no fixture profile declares one);
  - an operation served only to a role the contract denies, which counts as a use for the application.
- **Wiring.** The HTML report and the engagement kit's findings memo do not include this report yet. The hook is proposed, not wired.

## What the report cannot say

- Nothing about grants ScopeHaven does not see: database roles and row-level policies, cloud IAM, provider API key scopes, OAuth scopes, or tools the declared observers do not cover. Excess here is excess of the declared reach only.
- Unused for these runs is not unneeded: a workflow the runs never exercised (a month-end job, a rare escalation) may still need the grant.
- Window attribution credits two things inside an actor's check window to that actor: a background job no declared background source names, and an earlier check's effect that commits after its own settle. Only a principal-naming record, or a declared background source, separates them.
- An effect that commits after the last end mark is in no record: after an HTTP run's final settle and drain, or after a sequence's last mark. A sequence whose observers declare no settle takes its end marks right after the last request, so its excess is qualified (`no-settle-declared`). The sealed sequence run states the same limit.
- What only the application's own tables and audit records show unused is qualified, never clean: the application can write, omit or revert those records (custody `subject-writable`), and every use cites its custody.
