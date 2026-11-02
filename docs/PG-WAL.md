# Postgres logical-decoding observer (`pg-wal`)

`integrations/observers/pg-wal.mjs` reads every row change the Postgres server committed to the declared tables between two marks, from the write-ahead log, through a temporary `test_decoding` slot. It has no npm dependency (it uses the observer's own wire client, `pg-wire.mjs`).

**What it is, and what it is not.** It is a Postgres completeness upgrade beside `pg-snapshot`, not the answer to the bypass corpus. Nineteen of the twenty false passes in the bypass corpus were egress-route bypasses, which confinement and a declared-channel rule address, and `pg-snapshot` already reads Postgres directly. On the observed tables it adds three things:

- **Writes made and undone between the marks.** An insert and a delete of the same row, or an update and its revert, are each decoded. `pg-snapshot` sees net change, so an insert and delete in one window is invisible to it.
- **Exact inserts and deletes.** Every decoded change is an event, so `effect.count` on inserts or deletes is decided. `pg-snapshot` is net-only, and its counts read missing.
- **Absence without a quiescent cluster.** A committed write to another table, a platform's background job included, never enters an observed table's stream. `pg-snapshot` decides a table-wide or prefix absence only when nothing at all committed in the cluster during the window.

It is a profile observer type. Its windows carry a source of their own, `sql-wal`: lineage `database-log`, custody `observer-held` (`src/effect-lineage.mjs`, `src/custody.mjs`). So a database-only prohibition on the observed tables can pass on it, beside an allowed-use control whose positive clause shows it sees such a write (pairing). That custody holds for an absence only (`ABSENCE_ONLY_SOURCES`). A write the WAL shows is one the application chose to make, so a pass that needs a matched write reads `subject-writable` on it: an `effect.exists`, an `effect.count` of one or more, or an `effect.only`'s expected effects. A boundary pass whose selector pins an actor reads `principal-unverified`, because the actor names come from the application's own session. Its collector is `pg-wal/5` (`src/collector-identity.mjs`), in each run's observer record. Its digest covers `src/pg-readback.mjs` and these files in `integrations/observers/`: `factory.mjs`, `pg-wire.mjs`, `pg-wal.mjs`, `catalog.mjs`, `end-barrier.mjs`, `run-lease.mjs`, `ignore-lists/ignore-list.mjs`, `ignore-lists/supabase.json`, `ignore-lists/litestream.json`, `pg-actor.mjs`, `supabase-rules.mjs` and `pg-net-wire.mjs`. pg_net's unlogged request queue reads `table-not-in-wal` unless the observer declares `pgNetWire` ([integrations/observers/PG-NET-WIRE.md](../integrations/observers/PG-NET-WIRE.md)), and even then only in a window that is complete and observer-held. What is not wired yet is listed in "What is left" at the end.

## How it reads

- `start()` opens one session as a role with the `REPLICATION` attribute, pins the output settings (`DateStyle`, `TimeZone`, `IntervalStyle`, `extra_float_digits`, `bytea_output`, `lc_monetary`, `standard_conforming_strings`) and creates a **temporary** logical slot with `test_decoding`. The server drops a temporary slot when its session ends for any reason. While the session lives, no other session can read, advance or drop it (SQLSTATE 55006, observed live), so the application cannot consume its changes.
- It reads `test_decoding` over SQL, never through a `pgoutput` publication. A publication covering UPDATE and DELETE makes those statements fail on tables without a replica identity, which would change the target's behaviour. Nothing on the target changes: the observer creates no publication and alters no table.
- **Each mark**, in order:
  1. the catalog of every declared table and descendant;
  2. the write locks other sessions (and prepared transactions) hold or are waiting for on them;
  3. the WAL insert position;
  4. the slot's state;
  5. the write locks again;
  6. the catalog again.

  The catalog fingerprint covers the relation, its descendants, columns and types, replica identity, persistence, row-level security flags, policies, triggers, indexes, constraints and schema, and each of those catalog rows' `xmin`.
  - **Changes made and reverted:** including `xmin` means a change made and reverted between two marks still changes the fingerprint.
  - **What that catches:** a replica identity moved through its indexes (a primary key dropped and added again), and a table or its schema renamed away and back. `test_decoding` prints a change made meanwhile under the other name.
- **`collect(from, to)`** waits for the end barrier, checks the slot, and reads with `pg_logical_slot_peek_changes`, never `get_changes`, which consumes before the read is kept.
  - **One stretch at a time:** it reads one stretch between consecutive marks at a time, each up to that stretch's end mark. Each stretch is parsed against that end mark's catalog, because `test_decoding` prints each change under the relation name and columns it had when it was written. A rename of a table or its schema after a mark, or windows collected out of order, therefore never misread a change.
  - **A failed mark inside a stretch:** its changes are parsed with the next good mark's catalog. If the catalog changed in between, those changes may land among the other tables. Every window across it then reads `schema-drift`: that costs evidence (a forbidden write reads missing instead of fail), never a pass.
  - **Cost:** each stretch is its own peek, and each peek decodes from the slot's restart point. Many unread marks behind a long-running transaction can therefore reach the statement timeout. That ends as a lost slot and an inconclusive window, never a pass.
  - **The ledger:** each decoded transaction goes into the observer's own ledger, deduplicated by its commit LSN and tagged with the catalog it was parsed under. Only then does it advance the slot (`pg_replication_slot_advance`).
- **Which transactions are in the window:** a transaction is in the window when its commit record ends after the start mark's position and at or before the end mark's.
- **Streaming of in-progress transactions is off**, so a transaction is decoded only once it commits.

### What leaves the server, and what the observer keeps

The server projects each decoded row before it is sent:

| Decoded row | What leaves the server |
|---|---|
| A change to a declared table or one of its partitions or inheritance children (matched against the stretch's end mark's own names, sent as literals) | The whole line (at most 1 MiB; over that, the window reads `change-too-large`) |
| A TRUNCATE line | The line (relation names and flags only) |
| A change to any other table | Only its schema-qualified name |
| A logical message, anything else | Only its kind |

Of a declared table's columns:

- **Declared value columns** (`values`) are kept as text, exactly as Postgres prints them with the pinned settings.
- **Sensitive columns:** a value column whose name reads as a secret or personal data must also be listed under `sensitive`, and its value is then sealed under a salt the observer holds (unless listed under `reveal`). The name rule is the one `src/pg-readback.mjs` uses.
- **Every other column** is kept only as an HMAC-SHA256 under that salt, computed as the change is parsed. So no undeclared value leaves the observer's process, matching `pg-snapshot`'s promise.
- **What each change carries:** its operation, its key, the transaction id, the commit LSN and its own LSN.

### Events and the record

- `collect` returns `{ events, coverage, reason, wal }`, and `collectWindow` builds the effect window from it.
- **Events:** one per row operation (`insert`, `update`, `delete`), named by table, with the resource `<resourcePrefix>/<key>`.
  - **Partitions:** a partition's change is named by its declared parent.
  - **Two declared trees:** a relation in two of them (a table and its own partition, both declared) reports the change under both names, as `pg-snapshot` does.
  - **Padded keys:** a blank-padded `character` key, or a domain over one, reads without its padding, as `pg-snapshot`'s `::text` does.
- **Key moves:** an UPDATE that moves the key is an update of both keys (an `effect.count` of updates counts it twice).
- **The `wal` record** (`scopehaven-pg-wal/1`, with a digest) seals, per table:
  - the inserted, updated and deleted keys;
  - exact counts;
  - each change, with its values and digests;
  - the other tables' change counts, with a per-platform ignore list;
  - the number of logical messages;
  - the slot generation;
  - the barrier;
  - both catalog fingerprints.
- **Value checks:** `observer.judgeValue(record, { table, key, column, equals })` judges a value check. The last change of the key in the window decides it:
  - a delete fails it (`row-deleted`);
  - a key that was not written in the window is inconclusive (`row-not-written-in-window`): the observer reads changes, never the table;
  - a record that is not complete decides nothing.

## Setup (profile shape)

```json
{ "id": "wal", "type": "pg-wal", "host": "127.0.0.1", "port": 5432, "database": "app",
  "credentialEnv": "SCOPEHAVEN_TARGET_APP_DB_WAL",
  "tables": [{ "table": "orders", "key": "id", "values": ["status", "refund"] },
             { "table": "payouts", "key": "id", "values": ["amount"] }],
  "platform": "supabase", "ignore": ["public.heartbeats"], "barrierMs": 3000, "settleMs": 1000 }
```

`settleMs` is read by the connector, as for `pg-snapshot`; the other fields are the observer's. `src/contracts.mjs` checks the shape when the profile loads:
- `{ id, type, host, port, database, credentialEnv, tables, settleMs?, statementTimeoutMs?, barrierMs?, actorCapture?, platform?, ignore?, queues?, drainTimeoutMs?, pollMs?, runLease? }`;
- `host` the literal `127.0.0.1`, plain identifiers, the credential only through `credentialEnv`;
- `tables` lists 1 to 32 `{ table, key, schema?, resourcePrefix?, values?, sensitive?, reveal? }`, each name once;
- `platform` is `none` or `supabase`; `drainTimeoutMs` and `pollMs` need `queues`;
- `actorCapture` as for `pg-snapshot` (`integrations/observers/pg-actor.mjs`).

The observer's own rules (sensitive names, the key never a value, an ignore entry never naming an observed table, queue kinds) run when the factory builds it, before any request. `pg-snapshot` takes the same `platform`, `ignore`, `queues`, `drainTimeoutMs`, `pollMs` and `runLease` from a profile.

**With pg-snapshot on the same table.** Their windows carry different sources (`sql-wal` and `sql-snapshot`), so a clause names the one it reads by its `source`, and each decides on its own window. A clause on `sql-snapshot` keeps the snapshot's custody (`subject-writable`).

- **Server:**
  - `wal_level = logical` (a restart);
  - one free replication slot (`max_replication_slots`);
  - PostgreSQL 13 or later. It was run live on 15 and 17; 13 and 14 have not been run.
- **Role:** `CREATE ROLE scopehaven_wal LOGIN REPLICATION PASSWORD '...'` with SCRAM-SHA-256.
  - It needs no `SELECT` on any table, and connects as an ordinary session (no `replication` line in `pg_hba.conf`).
  - The REPLICATION attribute lets the role decode every table's changes in the database. The server-side projection above is what keeps the other tables' values in the server. Give the role to ScopeHaven only, never to the application.
- **Credential:** `SCOPEHAVEN_TARGET_APP_DB_WAL` holds `user:password`. The host is the literal `127.0.0.1`.
- **Platform ignore lists:** `platform` names a checked-in list read by the one reader every database observer uses (`integrations/observers/ignore-lists/`). `supabase` names the tables Supabase's own services write as bookkeeping: Auth's audit entries, refresh tokens, sessions, flow state and method claims, pg_cron's run details, pg_net's responses, Realtime's subscriptions, the services' migration histories, and the `_realtime`, `_analytics`, `_supavisor` and `supabase_migrations` schemas. Tables that carry an effect stay off it on purpose (accounts, files, broadcasts, `cron.job`, `net.http_request_queue`, secrets). `ignore` adds `schema` or `schema.table` entries.
  - **Declared tables and queues are never ignored:** a platform entry that would cover an observed table or a declared queue is overridden for it, and a profile entry naming one is refused (as is a schema-wide entry on its schema).
  - **The record:** ignored, queue and unlisted changes are counted apart in the record's `others`, with the effective list's digest.
  - **Unlisted changes hold absence back:** a change to a table that is neither observed, a declared queue nor ignored makes the window partial (`unlisted-table-changed`), and so does a logical message (`logical-message`). Ignored changes never touch coverage.
  - **Tables the WAL never carries:** each mark lists the database's unlogged and foreign tables. One that is neither observed, a queue nor ignored, at either mark, makes the window partial (`table-not-in-wal`): its writes cannot be seen. pg_net's request queue is unlogged, so on Supabase with pg_net every window reads this until the profile lists `net.http_request_queue`, which it should do only once those requests are observed on the wire. A table made unlogged, or created and dropped, between two marks is not listed.
- **End barrier (`queues`):** with job tables declared, each mark first waits for them to drain on a second, short session (the role then needs `SELECT` on them). It reads the WAL insert position P0, the write locks on the queue tables, then the pending counts, and then takes the mark at P. A window whose end mark was not drained, or whose WAL holds a queue change committed in (P0, P], reads `queue-not-drained`; a failed drain read reads `queue-unreadable`. A queue that is unlogged, temporary, a view or a foreign table is refused (`queue-not-in-wal`): the (P0, P] check reads the WAL. The drain session reads at READ COMMITTED. Write locks on the queue tables count as in-flight writers at the end mark.
- **Run lease (`runLease`, default on):** the observer's session holds a shared advisory lock keyed by run. `start()` refuses while another run holds one on this database, and a window either of whose marks saw one reads partial with `shared-database` (its events stay, so a fail stays a fail).
- **The database's catalog fingerprint (`integrations/observers/catalog.mjs`):** the declared tables' own catalog above stays the within-window instrument. It carries oids and row versions, so a `TRUNCATE` moves it too, and it is never compared across runs. Beside it, each mark reads the whole database's catalog fingerprint before and after its own reads, on a second short session, and `start()` reads one there as the run's baseline.
  - **Why a second session:** printing a view or a policy locks the tables it names, and an error in the observer's own session would end its slot. A read that fails at a mark, including one that waits more than a second for a lock, reads `catalog-unreadable`.
  - **At the start:** a baseline that still does not read after a few tries refuses the start, and the slot goes with it.
  - **The declared tables' policies** are read as their stored trees, never printed, for the same reason.
  - **What it covers:** schemas, relations, columns, constraints, indexes, policies, triggers, rules, functions, types, extensions, event triggers, foreign servers, publications, default privileges, operators and casts, as the server prints them.
  - **What is left out:** the schemas a platform's list names whole, and partitions as relations. A partition's own grants and column grants, row-level security and trigger state stay in, at every level, and an extension's own objects are read like any other.
  - **When a window reads `schema-drift`:** when either of its marks' definitions differ from the baseline's, or when the catalog changed between its marks or while one was read (a function replaced and restored, a policy on another table, row-level security switched off and on). A window without a readable fingerprint reads `catalog-unreadable`.
  - **The run record:** `catalog()` returns the record a run keeps: counts and sha256 digests per kind, never names or definitions. The full rules are in [ONBOARDING.md](ONBOARDING.md#observe-what-the-app-recorded-the-default) ("Schema changes during a run").

## Custody

**Why the absence is held outside the application.** The WAL is written by the server, not by the application, and the slot is held by the observer's own session. So an absence decided from it, on the observed tables, does not rest on anything the application chose to route through a recorder. The application cannot remove a committed change from the stream:

- **Dropping or consuming the slot** needs the observer's session to end, which reads `connection-lost` or `slot-lost`.
- **A WAL segment the slot needed being removed** reads `wal-status-lost` (or the server ends the session).
- **Making a table unlogged, renaming it or its schema, or changing its replica identity (directly or through its indexes), columns, policies, triggers or constraints** changes the catalog fingerprint (`schema-drift`), or refuses the mark. All of these were checked live, including a primary key swapped away and back within one window and a schema renamed away and back.

**What it cannot see**, each either out of the check's declared scope or inconclusive:
- reads, cross-tenant reads included;
- Redis and in-process caches;
- files;
- direct external API calls;
- queues and jobs that finish after the end mark, unless declared as `queues` (the end barrier above);
- LISTEN/NOTIFY;
- large objects;
- sequences;
- DDL (it is caught only as catalog drift);
- unlogged and temporary tables (refused);
- other databases on the server;
- a superuser who ends the observer's session or disables decoding, which reads inconclusive.

**Writes that never commit are invisible by design.** A write that was rolled back (a whole transaction, or to a savepoint) is never decoded. Neither is an UPDATE that row-level security filtered to zero rows, nor a large transaction that aborted (streaming is off, so it is never decoded in streamed blocks). All of these were observed live.

**Scope of a pass.** An absence check may pass only on the observed tables, never as "nothing else changed".

## What makes a window inconclusive

A window whose marks were read but that cannot be decided reads `partial`, with its reasons comma-joined. The changes it did read stay events, so a forbidden write it saw still fails a check. A mark that cannot be read fails its windows (`failed`).

| Reason | Meaning |
|---|---|
| `slot-created-after-baseline` | The slot that reads the end mark did not exist at the start mark (the observer reopened after a loss); the changes between are in neither slot |
| `connection-lost` | The observer's session, and with it the temporary slot, ended between the marks |
| `slot-lost` | The slot is gone. **Any ERROR raised in the observer's session also ends its slot:** the server drops a backend's temporary slots on ERROR (observed live), so the generation ends and the next mark opens a new slot |
| `wal-status-lost` | The server removed WAL the slot needed (`max_slot_wal_keep_size`); an active slot's session may instead be ended, which reads `connection-lost` (observed live). A read that the server refuses as no longer possible reads `slot-unusable` |
| `wal-barrier` | The flushed WAL did not reach the end mark's insert position within `barrierMs` (below) |
| `schema-drift` | A declared table's catalog fingerprint differs between the marks, changed while a mark was read, or differs from the catalog a transaction in the window was parsed under |
| `transaction-in-flight-at-window-end` | Another session or a prepared transaction holds or waits for a write lock (RowExclusive or stronger) on an observed relation, at either lock read of the end mark: its write could commit after it. Write locks on other tables do not count. A writer that commits in the instant between the position and the second lock read is not seen there; its commit is after the end mark, which the post-response settle covers |
| `table-truncated` | A TRUNCATE of an observed table, alone or among others (TRUNCATE also gives the table a new `pg_class` row, so `schema-drift` appears with it) |
| `key-not-in-replica-identity` | An UPDATE or DELETE whose old key the WAL does not carry, because the declared key is not in the table's replica identity (for example a table with no primary key). Inserts on such a table stay exact, and an UPDATE's new key stays an event |
| `key-unreadable`, `key-too-long` | A change whose key is NULL, an unchanged TOAST value, or longer than the resource limit |
| `decode-unparsed`, `change-too-large`, `decode-limit`, `decode-failed`, `statement-timeout`, `event-limit` | The stream could not be read in full (`decode-limit`: a transaction past the ledger's budget of 200,000 kept changes keeps none) |
| `unlisted-table-changed` | A table that is neither observed, a declared queue nor on the ignore list changed |
| `logical-message` | A logical decoding message was written in the window, an outbox other decoders read |
| `table-not-in-wal` | An unlogged or foreign table that is neither observed, a queue nor ignored existed at either mark |
| `queue-not-drained`, `queue-unreadable`, `queue-not-in-wal` | The end barrier did not hold at the end mark |
| `shared-database` | Another run's lease was held on this database at either mark; the events stay |
| `schema-drift` (the database's catalog) | Either mark's catalog definitions differ from the run's baseline, or the catalog changed between the window's marks; the events stay |
| `catalog-unreadable` | The baseline or either mark has no readable catalog fingerprint, a lock wait past a second included |

The mark refuses a declared table that is unlogged (`unlogged-table`), temporary, a system catalog (`system-catalog-refused`: catalog changes are never decoded as rows), not a heap table, or that has an unlogged or temporary descendant (`descendant-not-decoded`). It also refuses a key whose text is not fixed by its stored bytes (`key-type-refused`, the same rule as `pg-snapshot`), a standby, and a server whose `wal_level` is not `logical`.

**The end barrier.** A window waits until the server's flushed WAL has reached the end mark's insert position.

- **Why insert, not write:** an asynchronous commit is visible before it is flushed, so the write position could miss it.
- **What stalls it:** one cluster-wide condition remains. An open transaction that has written anywhere in the cluster, and has not committed, can leave WAL on a partially filled page that the server does not flush until some commit does. The window then reads `wal-barrier` (observed live, with a writer left open on an unrelated table). It is inconclusive, never a pass.
- **What does not stall it:** committed background writes do not hold the barrier; they flush the WAL before them.
- **Page headers:** an insert position just past a WAL page header is reached by a flush at that page's start. The header is exactly 24 bytes, or 40 at a segment start; any other gap has not been reached.

**A second cluster-wide condition: creating the slot.** Creating the slot, at start or after a loss, waits for every transaction then writing anywhere in the cluster to end, for at most the statement timeout. When it does not end in time, `start()` fails, or the mark that reopens fails. It never yields a window that reads complete.

**TOAST.** An UPDATE that leaves a large out-of-line value unchanged carries a marker, not the value. A value check on that column reads an earlier change of the same window, or is inconclusive (`toast-unchanged`).

## Tests

- **Unit:** `integrations/observers/pg-wal.test.mjs`, against a scripted session with no server. It covers the parser, the window bounds, peek before advance, deduplication, the barrier, slot and session failures, drift, in-flight writers, TRUNCATE, replica identity, key moves, digest at decode, sealing, the value judge, mark refusals and partitions.
- **Live:** `integrations/observers/pg-wal.live.test.mjs` runs against a disposable server named by `SCOPEHAVEN_PG_LIVE=user:password@127.0.0.1:port/db`, the same variable `pg.live.test.mjs` uses. It skips with the reason when the variable is unset or the server's `wal_level` is not `logical`. One test changes `max_slot_wal_keep_size` and runs only with `SCOPEHAVEN_PG_LIVE_ALTER_SYSTEM=1` on a server of your own.
  - **A disposable server:** `docker run --rm -e POSTGRES_PASSWORD=... -p 127.0.0.1:55432:5432 postgres:17-alpine -c wal_level=logical`.
  - **What it covers:**
    - an owned refund app's fixed and defective twins;
    - a write through a second connection that bypasses the app;
    - the completeness comparison with `pg-snapshot`;
    - the independent review's probes (renames after a mark, collected out of order; a primary key swapped within a window; a schema renamed away and back; a system catalog; overlapping trees; a char-domain key).
  - **Reasons reached live:** `slot-lost` (a session error), `connection-lost` (a terminated session, and removed WAL), `slot-created-after-baseline`, `wal-barrier`, `schema-drift`, `transaction-in-flight-at-window-end`, `table-truncated`, `key-not-in-replica-identity`, `unlogged-table` and `system-catalog-refused`.
  - **Reasons reached by the unit tests only:** `wal-status-lost`, `slot-not-held`, `key-unreadable`, `key-too-long`, `change-too-large`, `decode-unparsed`, `decode-failed`, and the start refusals.
  - **Not exercised:** `decode-limit`, `event-limit` and `statement-timeout`.

## What is left (design note)

This is the smallest slice that reaches a verdict: pg-wal as a profile observer type with its own source and custody, its contracts shape, the factory, the authorization record's endpoint, the self-test's model and the run's limitations line. It is proved by:
- `test/pg-wal-profile.test.mjs`, over pg-wal's scripted session;
- `integrations/observers/pg-wal-profile.live.test.mjs`, on a local Supabase stack: the fixed twin's database-only prohibition passes `observer-held`, and the defective twin's fails on the decoded write.

Not wired yet, in the order that would add the most:

1. **The sealed `wal` record in the run.** `collect()` returns `wal` (`scopehaven-pg-wal/1`, with its digest) beside the window, and `collectWindow` drops it.
   - Bind it beside each check window in the effects trace (`src/http-effects.mjs` `effectTrace`), validated against its digest and the window's events by the run validator. The exact counts and the decoded values are then re-derivable from the run.
   - About 4 hours.
2. **Value checks** (amount-level verdicts):
   - an assertion kind reading one declared value column of one key at the window's end, decided by `judgeWalValue`;
   - pg-snapshot's `readBack` tables (`src/pg-readback.mjs`), which the contracts validator would then allow (`tables[].readBack`), decided by its read-back record;
   - without the assertion, widening the validator alone would accept configuration that reaches no verdict, so it waits for it;
   - needs item 1; about 8 to 12 hours.
3. **The run budget** (`src/http-timing.mjs`): reserve `barrierMs` per collect and `drainTimeoutMs` per mark, as `settleMs` is reserved. The connector does not bound those waits, so today a timed run can overrun `runBudgetMs` by up to `barrierMs` per collect plus `drainTimeoutMs` per mark, and is then cut: its later checks read inconclusive, never a pass. About 2 hours.
4. **rls-zero-row on pg-wal:** zero-row facts from pg-wal's per-window ledger read. `allowedWrites` reads pg-snapshot captures only. About 3 hours.
5. **The actor capture's install step** in the run, with its installation record as a change to the target. The operator installs it today. About 4 hours.
6. **The run-end re-collection of `wal-barrier` windows** and an opt-in flush. About 3 hours.
7. **The self-test's actor-pinned negatives** for captured observers (`src/known-negative.mjs` models them at `actorAttribution: 'none'`). Conservative today: such clauses read unprovable. About 2 hours.
8. **The per-row scope statement** (`src/absence-scope.mjs`): an absence pass decided on `sql-wal` gets no per-row statement in the report or SARIF ("on the observed tables only, never nothing else changed"). Only the run's limitations line says it. About 1 hour.
9. **The coverage report and app-log rules** do not know pg-wal: `integrations/coverage-report/coverage.mjs` (`TABLE_OBSERVERS`) and `src/app-log-rules.mjs` (`OBSERVED_AS.named`). Both under-claim: the report leaves pg-wal's tables out of what is covered, and an app-log rule cannot declare `observedAs: ["sql-wal"]`. About 2 hours.
10. **Sequences and collateral.** A sequence cannot use pg-wal: the factory builds one only for an HTTP assessment's observers (`pgWal: true`, which the connector passes), because sequences have no pairing stage and their validator knows no `postgres-wal-decode` scope. Collateral (`integrations/collateral/collateral.mjs`) judges what persisted on `sql-snapshot` windows only, and the upgrade text its degraded rows carry still names no observer for a database write, although its what-happened check (`effect.only`) could be decided on `sql-wal` windows. About 4 hours for sequences (pairing first), 1 hour for the collateral text.
11. **An actor-pinned absence beside a held window that names principals** (deferred in review). The clause rule reads `principal-unverified` only when no independent window that decided it names principals itself, so a capture-named WAL window beside such a window keeps the pass. No shipped observer names principals itself (egress, SMTP and feed record no actor), so it cannot be reached today. For the first one that does: fire the rule for an absence when any deciding window is capture-named, as `onlyClauseCustody` already does. About 1 hour.

### Decided in review

- **Custody is for an absence only**, as above. A pass on `sql-wal` that needs a matched write reads `subject-writable`, including a row the application stamped itself: an `effect.exists`, an `effect.count` of one or more, or an `effect.only` whose expected effect the WAL window holds. An absence and a count of 0 keep `observer-held`. An actor-pinned boundary pass decided on a window whose actor names the actor capture supplies (`CAPTURED_ACTOR_SOURCES`, `sql-wal` today) reads `principal-unverified`, because those names are the application's own session claims. A window held outside the application that names principals itself keeps its pass (pairing's same-principal twin reads such windows); no shipped one does today.
- **The trade-off, recorded:** an "exactly once" boundary decided on the WAL alone reads inconclusive. Its lower bound needs an observer that sees the real-world effect, for example the provider's send on an egress recorder.
- **Declared channels** (`src/channels.mjs`): `CHANNEL_OBSERVERS.store` and the port observers include `pg-wal`, so a store channel can be watched by it, and a write it records on no channel's names reads `channels-undeclared`, as pg-snapshot's does.
- **The independent verifier and the custody pin** mirror `sql-wal` and `pg-wal`: `integrations/verdict-check/verify_verdicts.py` (with the absence-only and principal rules) and `integrations/evid-subject/`.
- **The upgrade a degraded row names** (`src/custody.mjs`): in an HTTP assessment, an absence (`effect.none`, or an `effect.count` of 0) of an insert, update or delete that pins no actor names a pg-wal observer on the table, selected by source `sql-wal`, when a Postgres observer's window decided it. So does an `effect.only` whose held operations are all writes and whose expected selectors cannot be a database write, with a Postgres window in scope. Another engine's snapshot and an audit table keep their text.
- **Earlier records still validate**: the text is part of the custody fields the run validator recomputes, so a run recorded before this change carries the earlier text. The validator recomputes with the pg-wal text and, only if that disagrees, with the earlier text (`decideEffects`'s `walUpgrade`). Custody and its reason are bound either way, and any other text is refused. The validator does not know when a run was recorded, so the reverse also holds: in a run recorded since this change, a row's pg-wal upgrade text can be swapped for the earlier text (with the row's unkeyed `evidenceDigest` recomputed) and the run still validates, because `walUpgrade` changes only that advice text while the verdict, custody and custody reason are recomputed and bound the same either way. `test/pg-wal-profile.test.mjs` validates a run recorded and sealed before this change (`test/fixtures/pre-pgwal-run-9d2e44a6.mjs`). A presence, an actor-pinned clause, a sequence and a collateral row keep their text (collateral is item 10).
- **Credentials:** a pg-wal `credentialEnv` equal to an actor's is refused at load.
