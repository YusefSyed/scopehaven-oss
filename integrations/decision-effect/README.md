# Decision effect (DECISION-EFFECT-01)

This module checks whether the application acted only where its policy engine allowed it. It judges that from two records with different custodians:

| Record | Custodian | Reader |
|---|---|---|
| The engine's decision log | the engine (OPA uploads it to a loopback sink) | `decision-log.mjs` |
| The application's audit table | the application | the sqlite audit observer, through an ordinary sequence run |

The checks never restate the policy, because the engine owns it. A policy change needs no change to the checks.

## The checks

| Row | Passes when | Fails when | Otherwise |
|---|---|---|---|
| DE-01 | every effect the engine governs has an allow on its own input, on the declared decision path; the log and the audit window are complete; every effect's input is known; the whole sequence ran | an effect has no allow on its input: `effect-after-deny` (the engine denied that very input) or `effect-without-decision` (no decision on it at all; an allow for another input does not count) | inconclusive: a partial log, a partial audit window, an effect whose input cannot be rebuilt, an aborted run |
| DE-02 | the engine denied every forbidden attempt's input, and the log is complete | the engine allowed a forbidden input. This is checked first: the allow is the engine's own record | inconclusive: `not-reached`, or the log is partial |
| DE-C1, DE-C2 | the paired allowed-use controls landed (from the audit table) | | |
| DE-R1 | the viewer's refund is absent, judged from the application's records alone (for comparison); under custody its pass reads inconclusive (`subject-writable-custody`), since the app can write those records | | |

**Binding an effect to its decision.**
- **A read** is its committed audit row.
- **A refund** is a row that a snapshot of the `refunds` table shows created in the window. It must meet three conditions:
  - it is the row the snapshot sealed: its content digest matches;
  - it names one committed `refund` audit row, by the same principal on the same ticket;
  - no other refund row names that audit row.

  Otherwise DE-01 fails as `effect-unbound`, whatever the log says. That covers a refund row with no audit row, one naming a denied or missing audit row, one sharing an audit row with another refund, and one written as another principal or on another ticket than its audit row.
- **A refund row changed or removed.** A refund row the snapshot shows updated or deleted in the window is `effect-unbound`. So is an id the table issued in the window but no longer holds: the refunds table's AUTOINCREMENT sequence is read before and after the run, and a gap means a row was inserted and deleted between the marks.
- **The input.** Each effect's input is rebuilt as `{ principal, action, resource }` from its audit row, plus the refund amount from its refund row. That input is digested, and the effects with one digest must not outnumber the engine's allow decisions on it. Only decisions from the engine that answered the window's sentinel count.

So none of these covers the refund the desk made:
- a pre-flight question asked with amount 0;
- an old allowed input replayed;
- an allow for the 20 refund;
- a forged allow.

A partial log cannot fail DE-01, because the missing decision could be the allow. An allow on a forbidden input fails DE-02 on its own.

## The decision log

`decisionWindow` opens before the sequence and closes after it.

To close, it asks the engine one sentinel question, then waits up to `flushTimeoutMs` (default 5000 ms) until two things hold:
- the sentinel is logged;
- the log holds as many decisions as the engine says it served. The count is OPA's own `http_request_duration_seconds_count` over every handler except health and metrics. A metrics document with no such series yet reads 0; text that is not a metrics document reads unreadable.

**Who can write the log.**
- The sink accepts uploads only with its bearer token. A token is made per sink, and the harness makes one sink per run. The engine gets the token through its service credentials (OPA's `credentials.bearer`), in a 0600 config file inside its own 0700 directory. File modes keep out other users of the machine, not other processes running as the same user, so the token stops casual or misdirected uploads rather than a determined local process. A forged allow that does get in carries another engine's label: it reads partial, and it never counts as the engine's.
- Every decision in the window must carry the engine label (`labels.id`) of the window's own sentinel.
- Only that sentinel is set aside. A late sentinel from an earlier window stays an ordinary logged decision.

| Coverage | Meaning |
|---|---|
| `complete` | every decision the engine served is in the log, all from the sentinel's engine |
| `partial` | the log is late, short of or longer than the engine's count, holds another engine's decision, or the sink refused a batch (including an unauthenticated one) |
| `failed` | the engine's count could not be read, or the sentinel question failed |

Only `complete` supports a pass. Each decision is reduced to its principal, action, resource, result, timestamp, engine label and an input digest; the input itself is not kept. A result reads `allow` only when it is `true` or `{ allow: true }`.

## The practice desk

The desk is synthetic and runs on loopback. Before acting, it asks the engine at `POST /v1/data/desk/allow`. A refund always answers `202 {"status":"received"}`, so the reply never differs between builds. The scenario waits 300 ms before its end mark.

| Build | Behaviour | Reading (live, OPA 1.21.1) |
|---|---|---|
| `checked` | asks every time and acts only on an allow | every row passes; the log is complete, 5 of 5 |
| `cached-allow` | planted: reuses a principal's first refund allow | DE-01 fail, `effect-without-decision`; DE-R1 (the records alone) looks clean and reads inconclusive under custody |
| `ignore-deny` | planted: refunds whatever the engine said | DE-01 fail, `effect-after-deny`; DE-R1 fail |
| `preflight` | planted: asks with amount 0, then the real amount, and acts on the first answer | DE-01 fail, `effect-after-deny`; the log is complete, 8 of 8 |
| `replay-cached` | planted: re-asks with the first allowed input, and acts on that | DE-01 fail, `effect-without-decision` |
| `double-commit` | planted: asks once and commits twice | DE-01 fail, `effect-without-decision` |
| `wrong-audit-row` | planted: a later refund row names the first refund's audit row | DE-01 fail, `effect-unbound` |
| `split-one-audit` | planted: one audit row, with refund rows of 480 and 20 | DE-01 fail, `effect-unbound` |
| `denied-audit` | planted: audits `refund.denied` and refunds anyway | DE-01 fail, `effect-unbound` |
| `unaudited` | planted: the refund row names no audit row | DE-01 fail, `effect-unbound` |
| `top-up` | planted: raises an earlier refund row by the denied 500 | DE-01 fail, `effect-unbound` (`refund-row-update`) |
| `service-identity` | planted: re-asks as the agent for the viewer, audits as the agent, writes the row as the viewer | DE-01 fail, `effect-unbound` (`refund-row-not-its-audit-row`) |
| `transient-row` | planted: on a denied refund, writes a refund row and deletes it | DE-01 fail, `effect-unbound` (`refund-row-vanished`) |
| `edit-in-window` | planted: writes the allowed refund's row as 500, then edits it to 20 | DE-01 **pass**: the net-change limit below |

`preflight` and the rows from `replay-cached` down are a reviewer's variants.

The policy is `policy/desk.rego`, with role data in `policy/data.json`. Any role may read, an agent may refund up to 50, and a viewer may not refund.

## Engines

- **`startOpa`** runs the real OPA binary (`SCOPEHAVEN_OPA_BIN`). It runs on loopback, logs to the sink, and has telemetry and the version check off.
- **`startStandIn`** is a stand-in that speaks OPA's decision-log and metrics formats, so the tests run without OPA. Its fault options produce the late, short and missing log readings:
  - `noLog`
  - `flushDelayMs`
  - `dropEvery`

Neither engine accepts a sink or an engine that is not literal loopback HTTP, and the harness's own requests never follow a redirect. OPA refuses to start without the sink token.

## Records

A record (`scopehaven-decision-effect-run/2`) holds:
- the inner `scopehaven-sequence-run/2`;
- the decision window;
- the app's refund rows, read from a copy of its database after the run, each with its audit row id, actor, ticket, amount and content digest;
- the refund ids the table had issued before and after the run (`refundsIssued`);
- the scenario;
- the engine kind and version;
- the target;
- the limitations;
- the DE rows.

It is sealed with `recordDigest`. `validateDecisionEffectRun(record, { actors })` refuses a record when any of these is true:
- the seal does not match;
- the scenario is not the one written here (it is pinned, so a record that governs nothing cannot pass);
- the inner run fails `validateSequenceRun`;
- the logged count does not match the events;
- the log coverage does not follow from its counts;
- a sink error is unknown;
- the refund rows are malformed, or a refund id appears twice;
- the issued ids are malformed, or a row holds an id the table never issued;
- a DE row is not what the stored events give.

## Limits

- **Synthetic.** This measures the method on the owned desk, not a production application.
- **Binding by input.** An effect is bound to a decision by its rebuilt input: `{ principal, action, resource }` plus the amount for a refund. An engine input carrying other fields does not match, and an application that asks the engine after acting, with the same input, is matched.
- **Net change.** The refunds table is compared at the start and end marks. A row inserted and deleted in the window is seen only through the gap it leaves in the AUTOINCREMENT sequence, which the application could reset. A row inserted and then edited in the window is judged by its end state: `edit-in-window` reads pass.
- **Settle.** A refund the app commits more than 300 ms after its last reply is outside the audit window. The desk's 202 "received" reply does not wait for the refund.
- **The engine's counter counts every call.** It also counts calls that are not decisions, such as a policy push during the window. That reads `partial`, never pass.
- **One engine and one scenario so far.** OPA through its decision-log plugin, with the desk scenario. Identity-provider events (Keycloak) and revoke-at-the-IdP are the item's second part.
- **Unkeyed digest.** The record's digest has no key. A forgery that is consistent in every field is outside the validator's scope.

## Tests

`decision-effect.test.mjs` runs on the stand-in engine. It covers:
- the clean build;
- both planted defects, including that the replies match the clean build's;
- a policy that allows a forbidden attempt;
- missing, late and short logs;
- the judge's matching rules;
- the validator;
- the sink.

One more test runs against OPA when `SCOPEHAVEN_OPA_BIN` is set.

## The gate-outage drill (DE-03)

DE-01 asks whether the application acted only where its engine allowed it. The drill asks what the application does when its engine cannot answer at all. The drill tests the fail-closed claim made for policy engines, tool-call firewalls and approval services, and judges it from the application's own records, whichever gate the application uses.

`gate-outage.mjs` runs it. A fault gate (`startGateFault` in `engines.mjs`) sits between the desk and the engine, and the desk asks it as if it were the engine.

**Which requests fail.** The gate fails every request that names the drill ticket, wherever and however it names it:
- any method and any path: the data API with or without a query string or trailing slash, its v0 and GET forms, the default decision at `/`;
- the path or query, percent-decoded;
- the body: raw, gunzipped when marked gzip, and every string and key in it when it is JSON;
- case-insensitive, and not as part of a longer name (`tickets/T-10` is forwarded).

Those requests never reach the engine. A request the gate cannot read (a gzip body that does not inflate, or JSON with more than 64 levels of arrays or objects, `GATE_JSON_DEPTH`) fails too, and is logged. Every other request is forwarded with its reply, carrying only the `Content-Type`, `Content-Encoding` and `Accept` headers.

**The guarantee is the judge's leak check, not the gate's name match.** The gate decodes the forms above, but not every encoding: for example a double-encoded query, JSON inside a JSON string, or a ticket split into separate fields. A request it does not recognise reaches the engine, with two possible outcomes:
- if the engine logs the drill ticket as the decision's resource, DE-03 reads `fault-leaked`;
- if it cannot, no allow can cover an effect on the drill ticket, so that effect fails.

Either way there is no pass. The judge matches the drill ticket the way the gate does: case-insensitive, and not as part of a longer name.

**The gate's log** (`scopehaven-gate-fault/2`) is the harness's record, which the application never writes. It holds:
- each failed request: method, path, the input's principal and action, and an input digest;
- the number of requests forwarded, not counting health and metrics or their subpaths, as the engine's own count does not;
- the errors it hit. An unreadable request is `unreadable-request`: it might name the drill ticket, so it is failed, and the log reads partial.

| Mode | What the application gets for a request about the drill ticket |
|---|---|
| `unreachable` | the connection closes with no reply |
| `timeout` | no reply. The request is held until the application gives up. The drill is decidable only when that happens within the outage requests' 10000 ms (`OUTAGE_REQUEST_TIMEOUT_MS`); otherwise the run aborts and DE-03 reads `sequence-aborted` |
| `error` | 503 |
| `rate-limited` | 429 with `Retry-After` |
| `malformed` | 200 with a body that holds no result |

**The sequence** runs in three phases on three tickets:
- **Before** (T-2): the gate works. The viewer reads and the agent refunds 20. These are preconditions.
- **The outage** (T-1): every request about T-1 fails. The viewer reads and refunds 20; the agent refunds 20 and 500. Any reply is accepted, and the records judge.
- **After** (T-3): the gate works again. The before-phase requests run again, plus the two forbidden refunds.

**DE-03 fails** as `effect-during-gate-fault`, on a complete decision log, when either:
- a governed effect on the drill ticket has no engine allow on its own input (listed in `duringFault`, each with `askedGate`); or
- the engine made no decision about the drill ticket at all, and the application still committed a governed audit row there, or left a refund row there that binds to no audit row (listed in `unanswered`).

  This covers a committed refund audit row with no refund row, a refund row with no audit row, and a refund row beside a `refund.denied` audit row.

On a partial log, the same evidence reads inconclusive, since the missing decision could be the allow.

**DE-03 is otherwise inconclusive** at the first of these, in order:

| Reading | When |
|---|---|
| `fault-leaked` | the engine decided something about the drill ticket. The request leaked past the gate or went around it. The decisions are listed in `leaked` |
| `effect-unbound` | any refund row binds to no audit row elsewhere. This includes a row inserted and deleted in the window, whose ticket went with it |
| `effect-input-unknown` | any effect's input cannot be rebuilt |
| `gate-log-partial` | the gate hit an error |
| `sequence-aborted:<why>` | the run stopped |
| `fault-not-induced` | the application never asked about an outage attempt |
| `decision-log-<coverage>` | the decision log is not complete |
| `gate-bypassed` | the engine's count, less the sentinel, is not the gate's forwarded count |
| `audit-<coverage>`, `snapshot-<coverage>` | the audit window or snapshot is not whole |
| `controls-not-landed` | a control before or after the outage did not land, so an application that refuses everything cannot pass by being dead |

**DE-03 passes** only when none of these holds.

| Row | Reads |
|---|---|
| DE-03 | as above |
| DE-01, DE-02 | as above, on the same run |
| DE-C1 to DE-C4 | the controls before and after the outage |
| DE-R2 | the agent's outage refund is absent, judged from the application's records alone (for comparison; a pass reads inconclusive under custody) |

**Planted builds** (`desk.mjs`), as read by the tests on the stand-in engine:

| Build | Behaviour | DE-03 |
|---|---|---|
| `checked` | an engine failure is a 503 and no action; a reply with no result is a deny | pass in every mode, including `timeout` at the desk's default 3000 ms |
| `fail-open` | acts on every request the engine failed to answer, and still replies 503, so its replies match `checked` | fail (4 effects) in `unreachable`, `timeout`, `error` and `rate-limited`; pass in `malformed` |
| `fail-open-timeout` | acts only on a timeout | fail in `timeout`; pass in `error` |
| `lenient-parse` | reads any result that is not `false` as an allow | fail in `malformed`; pass in `error` |
| `cached-on-outage` | reuses the principal's last allow for that action | fail in `error` (3 effects: the viewer's refund was never allowed, so it is not cached); pass in `malformed` |
| `breaker-stays-open` | after one failure, refuses everything without asking | inconclusive, `fault-not-induced`; the controls after the outage never land |
| `fallback-engine` | asks a second engine origin directly when the gate fails | inconclusive, `fault-leaked` (DE-01 passes: the engine did answer) |
| `retry-query` | asks the same origin again with `?pretty=true` when the gate fails | pass: the gate fails the retry too (8 faults), and the engine hears nothing about the drill ticket |
| `denied-audit`, `unaudited` (DE-01 builds) in `malformed` | act on a deny the planted way on the drill ticket | fail: three unbound refund rows on it, listed in `unanswered` |
| `transient-row` (DE-01 build) in `malformed` | writes and deletes a refund row | inconclusive, `effect-unbound` |

**A record** (`scopehaven-gate-outage-run/1`) holds:
- the sequence run, the decision window and the refund rows, as in `scopehaven-decision-effect-run/2`;
- the gate log;
- the scenario with its mode;
- the rows.

`validateGateOutageRun` recomputes every row from the stored logs. It refuses a record when:
- the gate log does not match its own counts, its mode or its fault resource, or its forwarded count is not a whole number;
- the scenario is not the one written here for that mode;
- the seal does not match.

**Limits of the drill:**
- **Scoped by input, not by time.** The gate fails every request about the drill ticket, so the run is deterministic. A breaker that opens after some number of failures and then fails open is exercised only as far as the outage's four requests.
- **One mode per run.** A mixed outage (a timeout, then a 503) is not exercised.
- **HTTP only.** The drill reaches a gate the application asks over HTTP, at an origin the harness can point at the fault gate. A policy library inside the application's process is out of its reach. A request that names the drill ticket some other way (an id the gate cannot recognise) and reaches the engine shows up as `fault-leaked` only if the engine logs the drill ticket as its resource.
- **Three headers.** The gate forwards only `Content-Type`, `Content-Encoding` and `Accept`. An engine that needs a token refuses every forwarded request, so the controls never land and DE-03 reads inconclusive.
- **Deleted rows lose their ticket.** A refund row inserted and deleted inside the window leaves only a gap in the table's sequence, so it reads `effect-unbound`, not a fail on the drill ticket.
- **No live OPA run yet.** The fault gate forwards to OPA as it does to the stand-in, but it has not been run against a real OPA binary here (as of 2026-10-16). The OPA test in `gate-outage.test.mjs` is skipped without `SCOPEHAVEN_OPA_BIN`. The stand-in answers the data API with a query string or trailing slash, as OPA does.

`gate-outage.test.mjs` covers:
- the checked desk in every mode, and in `timeout` at a 3000 ms gate timeout;
- each fail-open build in the modes it fails open on and in one where it does not;
- the two non-vacuity builds and the query retry;
- the DE-01 bookkeeping builds on the drill ticket;
- every reading of the judge, including the unbound and unknown record shapes, the leak and the abort order, each pinned by a one-mutation sweep;
- the validator;
- the fault gate: every request form, case, encoding, gzip, nesting depth (5000 and 30000 deep in a body, 1000 in a query value), the `T-10` look-alike and the forwarded headers;
- a case-shifted drill ticket in a hand-built record (`TICKETS/t-1`) reads as the drill ticket.
