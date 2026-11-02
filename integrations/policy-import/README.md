# Policy import: expected permissions from the app's own declarations

Scopehaven tests what an application *should* allow. Until now a person wrote every expectation by hand. Policy import reads the expectations the application already declares and turns them into a cited matrix and draft checks:
- Postgres row-level security;
- OpenAPI security requirements;
- Open WebUI access grants.

A person confirms the draft checks before anything is tested.

It reads local files only. It never connects to a database or service, and it never changes the application.

## The matrix (`scopehaven-policy-matrix/2`)

An import gives one layer of one application. Each cell is a role, a resource and an action, and it holds one of these decisions:

| Decision | Meaning |
|---|---|
| `allow` | A declared, unconditional grant |
| `conditional` | A declared grant gated by a predicate or setting. The expression is kept verbatim (normalized) in `conditions` |
| `deny` | A declared refusal: explicit, or the documented default of a mechanism the source turned on (RLS enabled with no applicable permissive policy) |
| `undeclared` | The layer says nothing about this cell |
| `unknown` | The source tried to say something the importer couldn't read completely. The decision it would have computed is kept in `computedDecision`, and every reason it is unknown in `unknownReasons` |

The rules every importer keeps:
- **Undeclared never becomes deny.** A table without RLS is `undeclared` (table privileges govern it, and they aren't evaluated). An operation without a security requirement is `undeclared`.
- **Gaps never become guesses.** These make the affected cells `unknown`:
  - an unreadable statement, or one PostgreSQL would reject (clauses out of order, renaming onto an existing table, dropping a schema that has tables without `CASCADE`, trailing tokens);
  - unbalanced parentheses, which would hide later statements;
  - code that runs during the migration:
    - a `DO` block or `EXECUTE`;
    - a `SELECT`/`CALL`/`PERFORM`/`WITH`/`VALUES` that calls a function other than a short safe list (`set_config`, `pg_notify`, `setval`...);
    - any call of a function these files define, outside definitions;
    - a write to a table whose trigger or column default calls such a function;
    - an event trigger.

    Defining, granting, altering, commenting on or dropping a function runs nothing, and neither does a plain view or an index, so those are not gaps;
  - any `CASCADE`, except on `DROP POLICY` and `TRUNCATE` and foreign-key `ON DELETE`/`ON UPDATE` actions, since it drops dependent objects, which can include policies;
  - an `ALTER TABLE` whose `DEFAULT`, `USING` or `CHECK` calls a function these files define, since it runs on existing rows;
  - a `BEGIN ATOMIC` body that never closes;
  - a `U&"..."` name or `U&'...'` string anywhere in a statement, for every table: its escapes are not decoded, so the name could be any table's;
  - a `set_config` whose setting name is not one plain string literal, for every table: it could change any setting below, or the search path. An `E'...'` name with a backslash escape is not one, since PostgreSQL decodes it: `E'client\x5fencoding'` and `E'\143lient_encoding'` are `client_encoding`;
  - where a `'...'` string ends depending on `standard_conforming_strings`, for every table: a statement that sets it other than on (`SET`, `ALTER ROLE` or `ALTER DATABASE ... SET`, `set_config`), or a `'...'` string with a quote after an odd run of backslashes, which ends elsewhere when the setting is off (wherever it was set). `SET standard_conforming_strings = on`, which `pg_dump` writes, `DEFAULT` and `RESET` are read, and so are `E'...'` strings;
  - `DROP OWNED BY` and `REASSIGN OWNED`;
  - `ROLLBACK`, `ABORT` and `PREPARE TRANSACTION`, for every table: transactions are not modelled, so statements already applied may not have happened;
  - a search path the reader can't be sure PostgreSQL set as written, for later unqualified names:
    - a transaction-scoped one (`SET LOCAL`, `SET LOCAL SCHEMA`, `set_config(..., true)`);
    - a value it would have to decode or split as PostgreSQL does: an `E'...'` escape, an empty name, a trailing comma, a non-ASCII unquoted name;
    - a `set_config` of `search_path` in a `SELECT` that is more than a list of `set_config(<literal>, <literal>, false)` calls (a `FROM`, `WHERE` or `LIMIT`, a computed value or flag);
    - a `set_config` of `search_path` in any other statement (a CTE, `VALUES`, `EXPLAIN ANALYZE`, an `INSERT`, `CREATE TABLE AS`, a column default, a view, a rule or a policy), for the rest of the history, since it may run on a later statement;
  - role membership, role renames or `BYPASSRLS`/`SUPERUSER` changes, for that role. Role settings (`ALTER ROLE ... SET`) are not gaps, except `standard_conforming_strings` and `client_encoding`;
  - a table owner, or a member of the owning role (known from a catalog dump), without `FORCE ROW LEVEL SECURITY`;
  - a table `pg_database_owner` owns without `FORCE ROW LEVEL SECURITY`, or a policy aimed at `pg_database_owner`, for that table: its one member is the database owner, implicitly, which no grant row or dump shows, so any role could be it;
  - in a catalog dump, a role reached only through a grant that is not inherited but can still be used with `SET ROLE` (from PostgreSQL 16 unless `SET FALSE`; before 16 always), or through a `NOINHERIT` role's grant whose `inherit_option` the dump does not show (a dump from an older `CATALOG_DUMP_SQL`), for the cells that role's policies or ownership decide;
  - in a catalog dump, a role that may `SET ROLE` to a `BYPASSRLS` or superuser role (a chain of grants without `SET FALSE`), for its cells on RLS tables: those attributes are not inherited, so `SET ROLE` is the only way to them;
  - in a catalog dump, any role the matrix role could grant to itself (through a grant `WITH ADMIN`, or `CREATEROLE` before PostgreSQL 16), which is read like a role it may `SET ROLE` to;
  - `client_encoding` set other than UTF8 (`SET`, `SET NAMES`, `SET LOCAL`, `set_config`, `ALTER ROLE` or `ALTER DATABASE ... SET`), for every table: the server reads the file's bytes in that encoding, so a byte this reader takes as a backslash or a quote can be part of a character. `SET client_encoding = 'UTF8'`, which `pg_dump` writes, `DEFAULT` and `RESET` are read;
  - a policy aimed at `current_user`;
  - an undefined security scheme or an unresolved `$ref`;
  - malformed or missing group data, or a malformed grant row.

  Procedural code makes every table unknown, since it could grant anything. A catalog dump reads the result instead.
- **The catalog dump is the authoritative input; migration replay is best effort.** Replaying migrations models declared DDL. Code that runs during a migration is flagged where it is detected but can't be ruled out, and every replayed matrix says so in `assumptions`, along with what replay does not follow (attribute-notation and operator calls, foreign-key actions firing triggers on other tables, triggers a partition inherits).

  `CATALOG_DUMP_SQL`, run on the migrated test database, reads policies and row-security flags plus:
  - **table owners**: an owner bypasses RLS unless `FORCE ROW LEVEL SECURITY` is set, and so does every role with the owner's privileges through membership (PostgreSQL's owner check is `has_privs_of_role`);
  - **role attributes**: `BYPASSRLS` and superuser roles skip RLS;
  - **a dump made with an earlier `CATALOG_DUMP_SQL`** (before 2026-10-16) has no `admin_option`, `rolcreaterole` or `server_version_num`, so it cannot show the roles a role could grant itself: re-dump with the current SQL. One without `inherit_option` and `set_option` reads every `NOINHERIT` grant as unsure;
  - **memberships**: a member gets the policies, and an owner's bypass, of every role it inherits from, transitively. From PostgreSQL 16 inheritance is set per grant, so the dump records each grant's `inherit_option` and `set_option` (both null before 16); before 16 a `NOINHERIT` role inherits through none of its grants. A role that could only be reached with `SET ROLE`, or that a role could grant itself (a grant `WITH ADMIN`, or `CREATEROLE` before 16, which can grant any role but a superuser; the dump records `admin_option`, `rolcreaterole` and `server_version_num`, and a dump without the version is read as before 16), makes the cells it decides `unknown` rather than leaving them to the session role's own policies. That includes a `NOINHERIT` matrix role's own grants when the dump has no flag for them;
  - **function definitions**: hashed, so a changed function shows as a changed condition.

  For a matrix you will rely on, use the dump.
- **pg_dump output can be replayed.** `pg_dump` (the 2025 minor releases on) brackets its output in the psql meta-commands `\restrict <key>` and `\unrestrict <key>`. Exactly that pair is skipped: `\restrict` as the first line that is not a comment, `\unrestrict` with the same key as the last. Any other backslash command makes the file unreadable.
- **Gaps follow renames.** A gap stays on its table through `RENAME` and `SET SCHEMA`.
- **Every gap has an identity (`id`)**, so `diff` can tell a new gap from a standing one. It is a SHA-256 of:
  - its scope (the table, role or `*`);
  - its kind: the reason, without line numbers or row indexes;
  - its subject:
    - for a statement, its tokens: comments and spacing dropped, unquoted names folded as PostgreSQL folds them, every other token as written;
    - for a file that could not be tokenized, the whole file: nothing in it is read, and psql runs what is above a meta-command before reaching it;
    - otherwise, the unreadable dump row, export row, path item or security list;
  - for a replayed statement, its position: a digest of every statement before it in the history, across files in order (a file that could not be tokenized counts as its whole text). A `DO` block's effect depends on what ran before it;
  - for a `client_encoding` set other than UTF8, or a `set_config` whose name is not one literal, also the rest: a digest of everything after it in the history;
  - an occurrence count among gaps with the same basis.

  Comments, spacing, renumbered lines, a migration file renamed or split without reordering, reordered dump rows and migrations appended at the end keep every earlier gap's id. A new id, which gates, comes from:
  - a second copy of a statement;
  - a gap statement that changes in any way PostgreSQL could read differently;
  - any edit to a file that could not be tokenized;
  - moving, adding, removing or editing a statement before a replayed gap. Moving a `DO` block past `ENABLE ROW LEVEL SECURITY`, or deleting it and adding it in a new migration, is such a move.

  Once the history sets a non-UTF8 `client_encoding`, every later change is a new gap, so it gates. Catalog, OpenAPI and Open WebUI gaps have no order and no position. The file name is left out, so a dated catalog dump keeps its gaps. A reason reworded in a later Scopehaven release gives new ids, so compare matrices imported by the same release: after an upgrade, re-import the baseline's sources.
- **Every cell cites its source:** the file, line and statement, or the row index in a dump or export. Operator declarations, such as bypass roles, are cited as `operator-options`.
- **`matrixId`** is a SHA-256 over the matrix's canonical form. `diff` and `draft` refuse a matrix that was edited after import.
- **A `scopehaven-policy-matrix/1` matrix is still read** by `diff`, `draft`, `confirm`, `statement` and `write-plan`. It has no gap identities, so `diff` compares its gaps fail-closed (below).
- **`notEvaluated` and `assumptions` travel with every matrix.** For RLS, `notEvaluated` lists GRANT/REVOKE, owners, BYPASSRLS roles the operator didn't declare, security-definer functions and views. `assumptions` include that the files given are the complete, ordered history. A replayed matrix's `assumptions` also say that replay reads every statement as having succeeded, and that names are cut to 63 bytes as a server with UTF-8 encoding cuts them.

## Importers

| Layer | Input | Notes |
|---|---|---|
| `postgres-rls` | Migration `.sql` files or a directory (read in file-name order, as Supabase names them), or a catalog dump from `CATALOG_DUMP_SQL` run by the operator on a test database | Follows `CREATE/ALTER/DROP POLICY`, `ALTER TABLE` (row security, `OWNER TO`, `RENAME`, `SET SCHEMA`), `CREATE/DROP TABLE` (temporary tables shadow, as in PostgreSQL), `ALTER/DROP SCHEMA` and `search_path` (`SET`, `SET SCHEMA`, `RESET`, `DEFAULT`, `DISCARD ALL`, `set_config`; setting names in any case, quoted or not). Unqualified names resolve against known tables in path order, and a new table goes in the first schema listed. Unquoted names fold to lower case in ASCII only, and every name is cut to 63 bytes at a character boundary, as PostgreSQL does with a UTF-8 server encoding (a server in another encoding, such as `LATIN1`, cuts non-ASCII names elsewhere). Permissive policies combine with OR and restrictive ones with AND. `FOR ALL` takes `WITH CHECK`, falling back to `USING` for INSERT and UPDATE. A policy with no expression for a command grants nothing, as in PostgreSQL. When a policy calls a function these files define, the hash of its whole definition (body and attributes, all overloads, and the helpers its body calls) goes into the condition text, so a change shows in the diff. Migration files run in one session, in order: `search_path` and temporary tables carry over, until `ON COMMIT DROP` or `DISCARD`. Resource keys quote identifiers that need it (`public."My.Table"`) |
| `openapi-security` | An OpenAPI 3.0 or 3.1 JSON document, plus an optional role map `{ role: { scheme: [scopes] } }` | Without a role map, each distinct requirement becomes a role named `requirement:...`, so a scheme called "anonymous" can't stand for the anonymous caller. A relative server URL without a leading slash is left unresolved. Operation `security` overrides the document's. Requirements are alternatives; the schemes and scopes inside one requirement are all needed. `[]` and `{}` allow anonymous callers. The server path prefixes are kept in `context.serverBases`, and operations with their own `servers` are listed in `context.ownServers` |
| `openwebui-access-grant` | An export from `EXPORT_SQL` run on a **private copy** of `webui.db`. It holds ids, roles, owners and grant rows, never names or emails | The rules are Open WebUI 0.11.4's, read from its source: owner, exact-permission grants to `user:*`, a user or a group, admin bypass (`BYPASS_ADMIN_ACCESS_CONTROL`, default true, kept conditional unless the export states it), `anyone:*` (a route must opt in) and legacy `access_control` |

## Draft, confirm, explain

1. **`draft`** reads a matrix and a binding (`scopehaven-policy-binding/1`), which maps roles to profile actors and resources to requests.
   - Only GET checks are drafted, so a draft sends no write method. A write action bound to GET (an RLS INSERT, UPDATE or DELETE, an OpenAPI POST, PUT, PATCH or DELETE, an Open WebUI write) is not drafted: a GET cannot show whether a write was allowed or refused. This does not show that a GET changes nothing; a GET handler that writes is not seen.
   - `allow` cells become allowed-use controls (`status.equals`, 2xx). `deny` cells become refusal checks (`status.in`, 4xx only).
   - Refusals default to 401/403/404 for a path a person bound, and 401/403 for a path derived from an OpenAPI document. A derived path may not exist, so a 404 there is not a refusal.
   - Derived OpenAPI paths are drafted only when the document has exactly one server path; operations with their own servers need an explicit binding.
   - For PostgREST, an allowed SELECT must return at least one row, so seed one.
     - **Refusal by RLS (`postgrest.refusal: "empty"`, the default):** a denied SELECT expects 200 with no rows. It is drafted only when another mapped role is allowed to read that table, since an empty result alone proves nothing.
     - **Refusal by privilege (`postgrest.refusal: "privilege"`):** a denied SELECT expects 401 or 403 with PostgreSQL error code `42501`. The code tells a refusal from a gateway that turns away a request without an apikey.
     - Only public-schema tables are drafted, since another schema needs an Accept-Profile header the connector doesn't send.
   - The draft warns when one actor stands for several roles.
   - Conditional, undeclared and unknown cells are listed as not drafted, with what to write by hand.
2. **`confirm`** needs a named person, the draft, and the matrix and binding the draft came from.
   - The draftId only detects careless edits, since anyone can recompute it. So `confirm` verifies the matrix, re-drafts from the matrix and binding, and accepts only an identical draft.
   - As a second line of defence, it re-checks every promise on the checks themselves:
     - GET, with no body or extra fields;
     - each check carries its cell's id and title;
     - exactly one provenance entry per check;
     - the severity and assertions match the declared decision.
   - It adds the checks to the profile and makes the allowed-use controls required.
   - It runs the product's own `validateTargetFile` before writing anything.
   - It writes a sealed confirmation record (`scopehaven-policy-confirmation/1`, with a `recordDigest`). The record holds every confirmed check as the validator normalized it, its provenance, the contract fields of the actors those checks use, and a warning when the matrix names a different application from the profile target.
   - The guarantee is consistency with the given matrix, not with the sources, since every digest here can be recomputed. Re-import the sources to check a matrix.
3. **`explain`** lines a saved run up with the declarations.
   - It checks the run's checksum (a saved `{core, sha256}` file or an exported run).
   - It takes the profile the run used (`--profile`), which must hash to the run's `profileHash`.
   - It refuses an edited record, a run from another target or application, and a profile in which a confirmed check, one of its actors, or the target's origin or context changed after confirmation. Later confirmations may add checks to the same profile.
   - For each check it compares the run's recorded title, severity, actor and request-path hash with the confirmed check.
   - A failed refusal check reads "declared deny, not refused". It could have been a 200 or a 500, so it's never treated as proof of access.
   - A missing result reads "not run". A result whose title or severity differs from the confirmed check reads as a different check.
   - Exit codes: 0 when every check is consistent and the checksum held; 1 on a mismatch; 3 when anything couldn't be verified.
4. **`diff`** compares two matrices of the same application and layer.
   - It names each cell as widened, added-open, narrowed, conditions-changed, became-unknown, became-undeclared, added or removed.
   - It exits 1 when a release widens access, makes a cell unknown or undeclared (RLS turned off, a security requirement deleted), adds a cell that isn't declared closed (a new role, a renamed or new resource, a new table without RLS), or adds a gap.
   - Between two unknown cells it compares what each would have decided, so one gap in the history doesn't hide a later widening. A cell that would now be undeclared, from any other state (`unknown` included), is `became-undeclared` and gated, so RLS turned off after a standing gap still gates. A cell that stays unknown but gains a reason other than `source-gap` is `became-unknown` and gated. Examples are an owner that now bypasses RLS (`OWNER TO`, `NO FORCE ROW LEVEL SECURITY`), a policy aimed at `current_user`, or a catalog role reachable by `SET ROLE`. Every reason a cell is unknown is kept in its `unknownReasons`, a sorted set; a gap that already hid the cell says nothing about the new reason. A reason lost is listed (`removedReasons`), not gated. A `/1` cell recorded only its basis, so a cell unknown for several reasons gates once against a `/1` baseline. Any other move between two unknown cells reads as before: `widened` toward access, otherwise `changed`.
   - **It compares gaps by identity**, in `gapChanges`: `gap-added` (gated) and `gap-removed` (not gated). A new gap gates whatever its cells read. With one standing gap every cell is already `unknown`, so a release that hides a change behind a new gap (a `DO` block, a `client_encoding` or `standard_conforming_strings` change, a `U&` name) changes no cell, and the new gap is what shows it. So does a gap moved within the earlier history, or after an edited earlier statement, since its id holds its position.
   - **A matrix without gap identities fails closed.** When either matrix has a gap without one (a `scopehaven-policy-matrix/1` matrix), a new gap can't be told from a standing one: every gap of the after matrix is `gap-unidentified` (gated), `gapComparison` names the side and `gapNote` says why. Re-import that matrix from its sources to compare gaps. A `/1` matrix without gaps has nothing to identify.
   - A changed condition is listed but not judged.

```sh
node integrations/policy-import/cli.mjs import rls --app my-app --roles anon,authenticated --bypass-roles service_role supabase/migrations --out /private/matrix.json
node integrations/policy-import/cli.mjs draft /private/matrix.json --binding /private/binding.json --out /private/draft.json
node integrations/policy-import/cli.mjs confirm /private/draft.json --matrix /private/matrix.json --binding /private/binding.json --profile /private/my-app.targets.json --confirmed-by "Your Name" --out-profile /private/confirmed.targets.json --out-record /private/confirmation.json
./scopehaven assess --config /private/confirmed.targets.json --target my-app --out /private/evidence --authorization /private/authorization.json
node integrations/policy-import/cli.mjs explain /private/evidence/runs/<run>.json --record /private/confirmation.json --profile /private/confirmed.targets.json
node integrations/policy-import/cli.mjs diff /private/matrix-last-release.json /private/matrix.json
```

Outputs are new files (never overwritten), mode 0600. Keep matrices, drafts and profiles private: they describe the application's permission model.

## Policy statement (`scopehaven-policy-statement/1`)

A matrix says what the application declares. The statement says what the operator says should happen, and it is the only source of intent for generated coverage (R9). A matrix can propose candidates and supply agreement data, but it never states a rule.

1. **`statement propose`** reads matrices and writes a proposal with no rules.
   - Each declared `allow` or `deny` cell is a candidate, with its `adoptedFrom` (matrixId and cell key).
   - Conditional, undeclared and unknown cells are listed as not proposed.
2. The operator writes the rules. Each rule has a `ruleId`, a `role` from the statement's roles, a `resource`, an `action` and a `decision`: `allow` or `deny` only. Optional fields:
   - `relation`: `any` (the default), `own`, `other-same-role`, `other-role` or `cross-tenant`. A cross-tenant rule needs two tenants.
   - `creators` (1 to 5 roles) with `creatorRule`: `actor-must-differ` or `actor-must-equal`.
   - `state`.
   - `limit` (`pointer`, `cap`, `unit`, `inclusive`, `roles`), on an allow rule only, since over the cap is the prohibition. Left out, `inclusive` keeps the at-the-cap point unstated.
   - `lifecycle` (`transition`, `subject`, `after`), where `after` is the decision after the transition. A rule carries a limit or a lifecycle, not both.

   Each rule has one of two confidences:
   - **`stated`** cites one of the statement's own sources (`sourceId` and `locator`).
   - **`adopted-declaration`** takes a candidate as declared. It must keep the declaration's cell and decision, and carry no relation, state, creators, limit or lifecycle; narrowing a declaration is a stated rule. It keeps the "Declared policy" category, so the coverage report shows its declared-intent warning, and it is counted apart.

   A rule still marked `candidate` is refused.
3. **`statement seal`** needs a `statedBy` label (`--stated-by`) and the matrices any adoption names. The label is free text the caller supplies: nothing authenticates it, signs it or checks that a person approved the statement.
   - It refuses: unknown fields; a rule stated twice; overlapping rules that disagree (overlapping means the same cell, with relation, state and creators each equal or left open on one side); an adoption that changes the declared decision; and an adoption from a matrix that is missing or edited.
   - It writes the sealed statement with a `statementId`, the canonical SHA-256 the matrix uses. Like every digest here, it detects careless edits only.
4. **`defaults.unlisted: "deny"`** is the only way a cell the statement does not list becomes deny. That decision reads `stated-default`, with rule id `defaults.unlisted`. Without it, an unlisted cell is not stated, and an undeclared matrix cell never becomes deny.
5. **`statement check`** verifies the seal and lines the statement up with matrices of the same application.
   - A matrix declaration of `allow` or `deny` covers its whole cell, so every stated part of the cell is compared with it:
     - each rule, whatever relation, state or creators it names;
     - a limit's over-the-cap prohibition beside its allowance;
     - a lifecycle's decision after the transition;
     - the rest of the cell that no rule names, when `defaults.unlisted: "deny"` covers it.
   - Each part carries its comparison, and a limit or lifecycle stays in the output. Each cell reads one of:
     - `agrees`: every part matches and the parts cover the cell;
     - `agrees-where-stated`: every part matches but some of the cell is unstated;
     - `stated-stricter` or `stated-wider`: some part refuses what the declaration allows, or allows what it refuses;
     - `unresolved`: a conditional declaration beside more than one stated decision; the condition is not evaluated;
     - `declared-only`, `stated-only` or `neither`.
   - It exits 1 when any cell is stricter or wider. That is a question for a test, not a verdict: a matrix never changes a stated decision. It exits 3 when no cell differs but some cell is `unresolved`, so an incomplete comparison never reads as agreement; 0 only when every compared cell agrees or one side is silent. Precedence: 2 (an error) > 1 > 3 > 0.
   - Each row's `stated` is the whole-cell reading: a rule that covers the whole cell, or the default when no rule names the cell. It is null when only narrower rules state the cell; their decisions are in `parts`.
   - `verified: true` means the seal and the body checked locally, not that a verified person stated the policy.

```sh
node integrations/policy-import/cli.mjs statement propose /private/matrix.json --app my-app --out /private/proposal.json
node integrations/policy-import/cli.mjs statement seal /private/statement.json /private/matrix.json --stated-by "Your Name" --out /private/sealed-statement.json
node integrations/policy-import/cli.mjs statement check /private/sealed-statement.json /private/matrix.json
```

The statement drafts and runs nothing. Write cases are generated from it by the write plan below. `statedDecision` gives each cell's stated decision with its confidence and rule id, the shape the coverage accounting takes for a cell.

## Write cases from the statement

The statement says what should happen; a **write binding** (`scopehaven-policy-write-binding/1`, `write-binding.mjs`) says how to reach it. It is named so it never reads as a successor to binding /1, and it states no intent.
- **Routes**, per resource and action: method (GET, POST, PUT, PATCH or DELETE), `pathTemplate`, an optional `bodyTemplate` on a write, the `object` type the request acts on (null for a create on a collection), `allowStatus` (2xx), and the refusal.
  - The refusal is `{ kind: "status", statuses }`: 2 to 5 distinct 4xx statuses, never a 5xx, and 404 only with `notFoundIsRefusal: true`.
  - Or it is `{ kind: "silent", status }`, a 2xx answer that needs an effect observer.
  - Placeholders (`{{id}}`, `{{actor}}`, `{{tenant}}`) are whole path segments or whole body string values. A request on an object puts `{{id}}` in its path or body; a create does not.
  - A DELETE consumes its object.
- **Effects**, per resource and action: source, operation, the exact name, and whether the effect records the acting principal. A `sql-snapshot` update can declare `exactness`: `change-column` or `xmin`.
  - An effect is what its route does: a GET binds a `read` only, a route that consumes its object never binds an `update`, and a create on a collection binds neither an `update` nor a `delete`.
- **Other fields:**
  - objects, with a create route and capture, a GET precheck, and a revert (steps or an `environmentReset` label);
  - the actors standing for each role and tenant;
  - identity controls;
  - the observers config with its declared settle;
  - a budget.

**The inventory** (`write-plan.mjs`) expands every statement rule, binding route and matrix cell over relation and the rules' creators and states.
- A variant whose deciding rule has a limit also expands over the limit's under, at and over points. One whose rule has a lifecycle expands over its before, after and in-flight phases. A plain rule beside them in the same cell gets neither.
- Above `budget.inventoryLimit` the plan refuses and names the dimension that multiplies most. It never truncates.
- Every variant gets its stated decision, or exactly one reason it cannot be drafted, from the vocabulary the coverage accounting reads: `not-stated`, `candidate-only`, `unknown-gap`, `no-route-bound`, `role-not-mapped`, `needs-second-actor`, `no-allowed-use-on-route`, `silent-refusal-without-observer`, `prefix-effect-name`, `insufficient-observation`, `no-declared-revert`, `needs-hold-gate`, then `over-budget` at selection.
- Only a statement rule creates a case; a route or a matrix cell adds variants, never intent.
- **A prohibition's observer must decide absence for the acting principal.** That means an authoritative source that records the actor. A SQL snapshot qualifies only for an update with a change column or xmin, since its insert and delete absences are not exact.
- **Every case is padded** with GET requests. Each actor pads with the first GET the statement neither refuses it nor ties to a lifecycle: the object's precheck, then a GET on the collection. A cell with neither route, or a case with an actor that has none, reads `no-route-bound`.
  - **Under `defaults.unlisted: "deny"`,** an unstated read is a stated-default deny, so it never pads. State the read allowances (the precheck or a collection GET for each acting role). Otherwise a case that needs padding reads `no-route-bound`, and in practice the plan drafts nothing.

**The plan** (`scopehaven-write-plan/1`) fills one template per selected variant:

| Template | Case |
| --- | --- |
| T1 | The attacker's write on the owner's object V, refused; the owner's same-record pair control (or another actor the statement allows on V); the attacker's liveness control on its own object W, when allowed |
| T2 | A create refused; an allowed role's create on the same route. A create that is not refused leaves residue, so the plan warns to reset |
| T3 | Over the cap refused; under it allowed, as the pair; same actor and route. At the cap follows the stated inclusivity |
| T4 | T1 or T2 for each creator; vehicle P only |
| T5 | Each phase follows its stated decision, and every phase after the transition needs it performed by an actor the statement allows to perform it (never the attacker or the peer). **Allowed, then refused:** the before phase is one control. The after phase is the before-control, the transition, then the after-attempt paired with the before-control, plus the twin of a peer the transition leaves alone (another actor, tenant or role, by the lifecycle's subject). On a consuming route the before-control and the after-attempt use two objects. **Refused, then allowed:** the before phase is the attempt, the transition, then the same actor's control on the same object, which pairs with the attempt. The after phase is the transition, then the control. Vehicle S only. In-flight work stays `needs-hold-gate` |
| T6 | A control-only twin for a stated allow |

- **Pairing:** every prohibition names its paired control, a presence of the same effect, so a system that refuses everything cannot pass. On T1, T2 and T4 the pair is another actor the statement allows (the classifier uses the same choice, so a variant with no such actor reads `no-allowed-use-on-route`). On T3 and T5 it is the same actor at another turn: under the cap, or in the other lifecycle phase.
- **Order:** forbidden attempts, then non-consuming controls and padding, and the attacker's liveness late. A control that deletes an object comes after every other turn on that object, so no turn acts on an object a control has deleted. Actors are taken in id order and routes in name order.
- **Windows:** each judged identity has at least 3 turns, and a case at most 21.
- **Selection** is in priority order within `budget.maxCases`:
  1. one base prohibition with its pair per stated deny rule;
  2. allowed twins;
  3. ownership;
  4. creators;
  5. boundary points;
  6. lifecycle.

  It goes round-robin over operations, then by the canonical key. Shuffled inputs (rules, resources, actions and actors) give the same `planId`. The rest are `over-budget`, counted, never dropped.
- **A case id** is `WC-` and 12 hex characters of the sha256 of the cell, variant, decision, rule digest and template, so an edited rule makes another case.
- **A plan holds nothing above drafted;** nothing is sent.

**Confirmation** (`write-confirm.mjs`, `scopehaven-write-confirmation/1`) re-derives the plan from the statement, binding and matrices it came from, and accepts only an identical `planId`. As a second line it re-checks every case on the case itself:
- the declared refusal statuses, and no 5xx;
- controls expecting the route's 2xx;
- effect clauses only, no json predicates;
- every prohibition paired on the same effect;
- windows within the turns, and three turns per judged identity;
- GET-only padding, with no GET body;
- each turn's method and path matching its bound route;
- the vehicle its template allows;
- a shape that matches its stated decision: a deny is drafted as a prohibition, an allow as none.

`confirmedBy` is a label the caller supplies; it authenticates no one.

```sh
node integrations/policy-import/cli.mjs write-plan /private/sealed-statement.json /private/matrix.json --binding /private/write-binding.json --out /private/write-plan.json
node integrations/policy-import/cli.mjs write-confirm /private/write-plan.json /private/matrix.json --statement /private/sealed-statement.json --binding /private/write-binding.json --confirmed-by "Your Name" --out /private/write-confirmation.json
```

**Values** (`scopehaven-policy-values/1`) are the one place concrete ids enter a case. Each record is keyed by case and object (`WC-.../V`) and holds plain identifiers only; `valuesDigest` detects edits. The producer is `operator-seed` or `setup-receipt`; `capture` is reserved for core captures. `valuesNeeded(plan)` lists the records a plan needs, with the state an object must be in when its case is state-conditioned, and `missingValues` the ones a values file leaves out.

Not built yet: compiling a case for a vehicle (S through `./scopehaven sequence`, P as profile shards), the setup runner that produces values and checks readiness, and running anything (M3, M4). A confirmed plan is not executed coverage.

## What it does not establish

- A matrix is a reading of declarations, not an observation of behaviour. What the application actually does is what the confirmed checks test.
- Declarations can be incomplete or wrong. A person confirms the drafted checks; the matrix never confirms itself.
- A statement is what its `statedBy` label says one person stated. The seal records that label and the time, both supplied by the caller: it authenticates no one, and it does not show that the policy is complete or right.
- Replay reads every statement in the files as having succeeded, and every replayed matrix's `assumptions` say so. A statement the server rejects at run time inside `BEGIN ... COMMIT` rolls the whole transaction back, and the reader sees that only for the rejections it lists above. The usual runners (the Supabase CLI, `psql -v ON_ERROR_STOP=1`, migration frameworks) stop at the first error, so that deploy fails; a catalog dump reads the real result.
- After a `client_encoding` set other than UTF8, this reader and the server disagree about where later strings end: one `E'...'` string that ends elsewhere in that encoding shifts every later quote in the file. So the reader cannot see what changed after it. It fails closed instead: that gap's identity covers the rest of the history, so once a history sets such an encoding, every later change gates, even an appended migration. Gate on a catalog dump in such a repository.
- RLS cells show only a command's own policies. They leave out the SELECT policy that UPDATE and DELETE with a WHERE clause also need. They don't evaluate table privileges, or role memberships and attributes granted outside the files.
- OpenAPI declares who may call an operation, not which records a caller may touch.
- Open WebUI routes differ in places from the generic rules (some let admins through regardless of the setting). That's listed as not evaluated rather than guessed.
- Tests run on synthetic fixtures in the real formats, plus a run on a synthetic local install's real declarations (recorded on a private build; not reproducible from this repository). Neither is anyone's production application.


## Write-check drafting (`write-draft.mjs`, `scopehaven-write-draft/1`)

GET drafting leaves every write to a person. Write drafting reads the same matrices and drafts POST, PUT, PATCH and DELETE
checks with their bindings inferred from the declaration: path parameters from the OpenAPI path template, request bodies
from the operation's JSON request schema (`$ref`, `allOf`, enums, formats; the binding may override a body), routes and
key columns for RLS tables through PostgREST. It changes nothing in `draft.mjs`: its ids are `PW-…`, its schemas its own.

Every allowed write cell gets, in run order: `owner-read-before` (the other owner B reads the record the probe will aim
at; a required control, so a record used up by an earlier run blocks the comparison instead of reading as restored),
`own-read` (A reads its own record: the allowed-use GET on a protected route the connector brackets around A's
prohibitions, actor-identity/4; with `binding.surfaceReads` one `surface-read` control per actor stands at the top
instead), `twin-before` (A's allowed use), `foreign-owner` (A's write aimed at B's record, every path parameter B's,
parent included), `anonymous` (no credential; skipped when the layer's anonymous role, `anonymous` for OpenAPI and `anon`
for RLS, may do the operation; through PostgREST an anonymous UPDATE or DELETE is drafted only when `postgrest.anonymous`
says how the anonymous actor reaches it: `anon-key` (the anon role holds the write grant, so RLS answers 204 and the probe
is silent, aimed at B's row and decided by the read-back), `anon-key-no-grant` (refused with 401 or 403, aimed at B's row)
or `no-key` (the gateway's 401, which tests the gateway only); undeclared, it is listed as not drafted, because one
expected status for the wrong case would fail an enforcing app), `read-back` (B reads its record
again: through PostgREST its key is in the first row, since 200 `[]` is a row that is gone; a declared field unchanged;
over REST a DELETE's read-back is decided by its 200) and `twin-after`. Through PostgREST the owner and own reads assert
the row's key too. Delete twins use A's second and third values, so A's own read keeps the first and deletes
are drafted last. A deny cell gets one `role-refusal`. Each check's provenance carries `"draft, human-confirmed: no"`
until `confirmWriteDraft` turns it into `"confirmed by label; not authenticated"`: `--confirmed-by` is a label the caller
supplies, so a record never asserts that a human confirmed it. A probe is confirmed only together with its twins and,
where it has one, its read-back. The runner does not read provenance: a drafted `PW-` check pasted into a profile runs
without any confirmation record, so the confirmation gate exists in this tooling only. A silent refusal (PostgREST answers 204 whether or not
a row matched) is a `medium` probe that only records it was sent; the read-back decides it, and without one it is not
drafted. OpenAPI declares who may call, never which records, so its foreign-owner refusal is a proposal for the person
to confirm; an RLS policy that allows every row (`USING (true)`) gets no foreign-owner probe.

The binding (`scopehaven-write-draft-binding/1`): `pairs` (each matrix role to its two actors A and B, of that role in two
tenants), `anonymous`, `parameters` (per OpenAPI path parameter: `values { A: [...], B: [...] }`, the `read` template of one
record, which may carry parent parameters, `unchanged { pointer, B }`), `bodies` and `foreignFields` (for a create on a collection, the owned field and its
A and B values), `tables` (per RLS table: `key`, `values`, `insert { body, ownerColumn, owners }`, `update { body }`,
`unchanged { column, B }`), `postgrest.basePath` and `postgrest.anonymous` (`anon-key`, `anon-key-no-grant` or `no-key`; no default),
`surfaceReads`, and `statuses` (`created`, `ok`, `deleted`, `silent`,
`foreign`, `anonymous`, and `operations` per `"METHOD /template"`). OpenAPI drafting takes the document bytes the matrix
was imported from (`--document`); the matrix keeps only their digest.

```sh
node integrations/policy-import/cli.mjs write-draft MATRIX --binding binding.json --document openapi.json --out draft.json
node integrations/policy-import/cli.mjs write-draft-confirm draft.json --matrix MATRIX --binding binding.json --document openapi.json \
  --profile profile.json --confirmed-by "Name" [--check-ids PW-…,PW-…] [--reset reset.json] --out-profile profile.out.json --out-record record.json
```

`generatedShare(target, records)` counts a target's checks as generated (named in a confirmation record) or hand-written.

## Seed and reset (`reset.mjs`, `scopehaven-reset/1`)

A POST, PUT, PATCH or DELETE check is a real change on the target, and a timeout does not undo it: reset the target to the
same seed before every run a comparison uses (docs/ONBOARDING.md). The declaration says how: `reset { command (an argv
list, never a shell string), cwd, timeoutMs?, env? (plain values; a secret-looking name is refused) }` and what the seed
state is read from: `seed { files?, command?, http? { origin (loopback only), paths, credentialEnv? }, expected }`.
`ensureSeed` runs the reset in a minimal environment (PATH, HOME, TMPDIR and the declared values; never the caller's
secrets), hashes the sources in order and compares with `expected`; a different hash refuses the run and names the
sources. With `expected: null` it returns the hash and the declaration to write as a new file.

**Advisory only.** The seed check guards the `reset` command and any caller of `ensureSeed`. Nothing on the `assess`
path calls it, and a run record carries no seed hash, so a run, or a comparison of two runs, on a different seed is not
refused. Run `reset` before each run a comparison uses. Wiring it into `assess` (and stamping the seed hash into the run
record) belongs to the core owner; this folder does not edit `src/`. The write confirmation record names the
declaration's file digest under `reset`, nothing more. A reset that times out has its whole process group killed.

```sh
node integrations/policy-import/cli.mjs reset reset.json --record reset.recorded.json   # first time: records the seed hash
node integrations/policy-import/cli.mjs reset reset.recorded.json                       # exit 0 when the seed matches, 1 when it differs
node integrations/policy-import/cli.mjs seed-hash reset.recorded.json
```


## init hook (`init-hook.mjs`)

`scopehaven init` (`integrations/init/hooks.mjs`) calls `draftForInit({ profile, openapi, root })` and reports the drafted
count. With `--openapi` it drafts the write checks (init already drafts the GETs), binding every authenticated role to identity
`a` (and `b` when there are two), anonymous to `anonymous`, and the record parameter from the starter profile: the one segment
where `A-OWN-RECORD` and `B-OWN-RECORD` differ is the record id, and the document's path template that matches them names the
parameter (`recordsFromProfile`, `matchTemplate`). It returns `{ checks, notDrafted, warnings }` plus `draft`, `binding` and
`matrix`, so the draft can be written to a file and confirmed by a named person with `write-draft-confirm`; init confirms nothing.
Without `--openapi` it drafts nothing and says so. A delete twin needs two more of A's records than the profile names, so deletes
stay listed until the binding gives them.
