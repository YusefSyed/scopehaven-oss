# `scopehaven init` (v0)

From an app already running on loopback to a first decided row. Read [docs/QUICKSTART.md](../../docs/QUICKSTART.md) for the operator path; this file is for maintainers.

```sh
./scopehaven init --base-url http://127.0.0.1:3000 --env ids.env
```

**Files:**
- `cli.mjs`: the command, its options and its six printed steps (`main(argv, io)` is exported for tests).
- `authorization.mjs`: the five questions (client, hosts, permitted actions, data class, contact), the rules-of-engagement file and the `scopehaven-authorization/1` record. The record format has no fields for actions and data class, so they go into `rules-of-engagement.md`, whose sha256 the record binds.
- `probe.mjs`: GET-only discovery of login routes, the session-derived who-am-I route, the credential slot and each identity's own record.
- `profile.mjs`: the starter profile.
- `observers.mjs`: observer candidates from variable names and placeholder drafts.
- `findings.mjs`: the first FAIL row, or first INCONCLUSIVE row with its fired check.
- `hooks.mjs`: the inference hook.
- `clocks.mjs`: stage stamps (`init-stamps.jsonl`), the onboarding receipt with its two clocks, and the timing table.
- `onboarding.mjs`: `init start`, `init review`, `init receipt` and `init table`.
- `envfile.mjs`: the private credential file and name-only reads.
- `init.test.mjs`: focused tests against the owned lab (`examples/http-lab.mjs`, the server behind `./scopehaven lab`) and a small owned two-tenant app. They run in the full suite (`integrations/*/*.test.mjs`).
- `test/fixtures/`: the two-tenant app and the stub inference hooks the tests use.

## What it writes (in `data/init/<id>/` unless `--out`; every file 0600)

| File | What |
| --- | --- |
| `rules-of-engagement.md` | the five answers, the accounts and the window |
| `authorization.draft.json` | the record before sealing |
| `authorization.json` | the sealed record, written only after the operator confirms they are authorized to test this copy |
| `targets.json` | the starter profile |
| `observers.draft.json` | observer candidates with placeholders, not merged into the profile |
| `policy-draft.json` | with `--openapi`: unconfirmed GET checks from `policy-import` |
| `inference-draft.json` | inference hook proposals, unconfirmed: checks, notes, and the hook's draft and binding when it returns them |
| `init-report.json` | what was probed and chosen, each prohibition's allowed-use twin; `timing` (this run's stages) and, after the run, `starterRun` (its id, counts and FAIL check ids). It is written before the run and once more after it |
| `init-stamps.jsonl` | appended by every run in this folder, whatever its exit status (below) |
| `onboarding-receipt.json` | written by `init receipt` |
| `evidence/runs/<id>.json` | the starter run |

## The starter profile

All checks are GETs, so the starter run changes nothing in the app.

| Check | Kind | Twin |
| --- | --- | --- |
| `A-WHOAMI`, `B-WHOAMI` | identity control: `json.equals` on the probed pointer of the who-am-I route | |
| `A-OWN-RECORD`, `B-OWN-RECORD` | allowed-use control, also each actor's surface control | |
| `B-READS-A-RECORD` | B opens A's record: `status.in [403, 404]`, or judged by content (below) | `A-OWN-RECORD` |
| `A-READS-B-RECORD` | A opens B's record, the same way | `B-OWN-RECORD` |
| `ANON-READS-A-RECORD` | a signed-out request: `status.in [401, 403, 404]`, plus the app's sign-in redirect when the probe saw one, or judged by content | `A-OWN-RECORD` |
| `B-READS-A-RECORD-BACKEND` | the same prohibition with `evidenceRequirement: "backend"` | `A-OWN-RECORD` |

**How a prohibition is judged.** Init sends each prohibited read once during discovery (GET, under the sealed record).
- **A refusal (401, 403, 404 or a sign-in redirect):** the check expects one of those statuses.
- **An empty answer (`[]` or `null`):** PostgREST and Supabase answer a row that row-level security hides with `200 []`, and a status check would call that a cross-tenant read, a false FAIL. The check expects that status and keeps the shape, so any populated answer later fails whichever fields it holds. That is `json.exists /0 false`, or `json.equals null`. A list wrapped in an object, such as `{ data: [] }`, gets `json.exists /data/0 false`. That applies only to a member named like a list of rows (`data`, `items`, `results`, `rows`, `records`, `entries`, `list`, `hits`) whose other members are scalars, and with two identities the body is also judged by the other tenant's values. An empty `errors` array is not a list of rows.
- **Another 2xx body without the owner's values, with two identities:** the check expects that status plus `json.noForeignValues` over the whole body.
  - Each tenant's values are declared in `tenantValues`. They come from its own record as the owner received it: fields that name the record (ids, titles, names, emails, not times or kinds), with values both records share and any value that is, holds or sits inside a credential removed.
  - The signed-out actor is a tenant of its own whose one declared value is a marker that occurs nowhere.
  - With one identity there are no `tenantValues`, since assess refuses a single-identity profile that declares them. The check keeps the refusal statuses, and init says so.
- **A 2xx that already held the owner's values:** this is a leak seen during discovery. Init reports it before the run as a candidate FAIL, and the check keeps the refusal statuses, so the run decides FAIL on the status. Under the content rules an echoed id alone would read inconclusive.
- **Own-record controls:** when the owner's body has a field that names the record, the control adds a `json.equals` on it, so a bare 200 does not count as the record being served.

The profile records the refusal shape seen at init. If the app later changes how it refuses (from `200 []` to 403, say), the row fails with "expected HTTP 200" and init should be run again.

The backend row reads INCONCLUSIVE until an observer is wired. That row is the honest first decided row on an app that refuses the read: a response alone cannot show the app never loaded the record. With one identity (the owned lab), B's checks are left out and the foreign record is one A does not own.

## Exit status

| Status | Meaning |
| --- | --- |
| 0 | Set up, and the starter run has no FAIL row |
| 1 | Set up, and the starter run has a FAIL row (as `assess` exits) |
| 2 | Stopped before any request: a missing answer (every missing flag is listed at once), a refused input, or an unconfirmed authorization |
| 3 | Could not finish: the app did not answer as needed (for example no who-am-I route found), or a check refused the profile |

## Stage stamps and the two clocks

Every run appends one line per stage to `init-stamps.jsonl` in its output folder (0600, opened for append, never through a symlink) as each stage happens, whatever its exit status: `start` (with the product head when the checkout is a git repository), `identities-read`, `authorization-drafted`, `authorization-sealed`, `probe-start`, `whoami-found`, `records-probed`, `profile-written`, `config-checked`, `run-saved` (run id, counts, FAIL check ids), `first-decided-row` (verdict and check id), and `end` (exit status, and the stop code of an `init stopped (CODE)`). Stamps reach the folder once it exists: from the start when `--out` names an existing init or onboarding folder (one that holds stamps or init's own drafts, as after `init start`; before init has checked its inputs, never any other existing folder), otherwise from the moment init creates or opens it (`--out`, or `data/init/<id>`), with the stages before that written then. A run that stops on its inputs before the folder exists writes none; a run killed mid-way keeps the stages it reached, with no `end` line. Init's stamps hold stage names, times, codes, run and check ids and counts: no credential, path, host or value. The `init start` and `init review` lines also hold the operator's label and roles. A failed stamps append, or a failed rewrite of `init-report.json` after the run, is reported and never changes the exit status.

`init start` writes the onboarding start stamp before the operator opens the docs (one folder is one onboarding; it refuses a folder with stamps). Its label and role are checked for shape only: the patterns cannot tell a name from a label, so keeping company and person names out is the operator's job. `init table` refuses a folder given twice and two folders that are the same onboarding (a copy: the same start stamp, or without one, the same first run). `init review` records whether one FAIL row of a stamped starter run holds; it checks the row is a FAIL in the run file. `init receipt` computes:
- **first decided row:** minutes from the start stamp (or, without one, from the first run's start, and the receipt says so) to the first `first-decided-row` stamp;
- **first held FAIL:** minutes to the `run-saved` stamp of the earliest run with a FAIL row reviewed as holding; the review time is recorded beside it, since review is not the operator's time;
- every run's exit status and stop code, the FAIL rows held, false (reviewed `no`; the latest review of a row counts) and unreviewed.

`init table` puts several receipts side by side and states the onboarding done condition: at least five onboardings, median under 60 minutes and worst under 90 to the first decided row, no false and no unreviewed FAIL, at least two on apps ScopeHaven does not own, and every clock started at an `init start` stamp (a clock from the first init run leaves out reading the docs and earlier stops). An onboarding that never reached a row, including one with only its start stamp, keeps its row as "not reached" and leaves the median and worst unset, so the condition is unmet. Stamps are wall-clock and unkeyed; a line missing a field its stage needs stops the receipt rather than giving a wrong clock. The receipt's product head comes from the stamps only (null when no stamp carries one). Every table ends with a `Limits:` line, kept as `limits` in `--json`: the stamps carry no key, and what each operator had in context before the start stamp is only what the operator role says.

## Discovery

- **Who-am-I route:** the candidate routes include Auth.js, common REST shapes and GoTrue's `/auth/v1/user`.
- **Credential slots:** bearer, then cookie names the app set on any answer so far (from `Set-Cookie`; names only), then common defaults.
- **Identity field:** an exact identity key, or one ending in email, username or user id. A field under a business, org, team or workspace object ranks after the user's own.
- **A miss** says what was tried and what came back: every answer a 5xx (the app is unhealthy or compiling), routes that refused every slot (the session was not carried the app's way), or routes that answered both identities without telling them apart.
- **An app that answers nothing:** if no `--whoami` was given, every signed-out probe got a 5xx or no answer, and one signed-in request did too, the search stops early rather than waiting on every slot. A handler that fails only when signed out is still searched.
- **Progress:** each stage prints a line, with elapsed time on the who-am-I search.
- **Assistant routes:** routes such as `/api/chat` are listed. Assistant-turn checks are not drafted.

## Rules it keeps

- **Authorization comes first.** Nothing is sent before the record is sealed. Sealing needs `--confirm-authorization` or a typed `yes`. Each probe is checked against the record's target, origin, accounts and window (`windowGuard`).
- **Environment values stay off disk.** Credentials come from a 0600 env file the user owns, and only their names reach the profile (`credentialEnv`). Observer candidates come from variable names in the environment and an app `.env` (`--app-env`), whose values are dropped as each line is read. A value is read only after consent for that name (`--use-observer NAME`), only in memory, and only to report whether it points at loopback. Drafts carry placeholders. The test "no environment value ever reaches disk" plants marker values in the env file, the environment and the app `.env`, then searches every file init and the starter run wrote.
- **Reruns.** `rules-of-engagement.md` and `authorization.draft.json` are init's drafts, and each run rewrites them. A record sealed by an earlier run is removed before the new draft is written, so a declined rerun leaves no usable old record. The other outputs of an earlier complete run are replaced only with `--force`, and that is checked before anything is written. After "Stopped before any request", the same command with `--confirm-authorization` continues.
- **Inputs are checked before any request.** Paths given as flags must meet the profile loader's path rules (mirrored from `src/contracts.mjs`). A `header:` slot must be one the connector accepts. The drafted profile is validated with `validateTargetFile` before it is written.
- **The credential is never the identity.** A who-am-I field that equals, contains or is contained in a credential value is never chosen as the identity value. Only 301, 302, 303, 307 and 308 count as a sign-in redirect.
- **No pass wording.** The output names FAIL, INCONCLUSIVE and "not exercised" rows only. The workbench's reason texts that say a control "did not pass" are shown as "did not hold". Rows that met their contract are in the run file, not in the summary.
- **Loopback only.** The base URL must be `127.0.0.1` or `localhost` over http. A remote or https target uses the full setup in `docs/ONBOARDING.md`.

## Inference hook

With `--openapi FILE`, init calls `importOpenApi` and `draftChecks` from `integrations/policy-import`, binds the anonymous role to the anonymous actor and every authenticated requirement to identity A, and writes the draft unconfirmed. Confirming it stays a named person's step (`./scopehaven policy confirm ...`).

`LANE-D-HOOK` in `hooks.mjs`: init loads `integrations/policy-import/init-hook.mjs`, `integrations/session-import/init-hook.mjs` and `integrations/model-standin/init-hook.mjs` when they exist, and calls `draftForInit({ profile, openapi, root, session })`. Each returns `{ checks, notDrafted, warnings }` and optionally `draft`, `binding` and `confirm`. A missing module is reported as not available, a failing one as failed, and neither blocks. Init never edits those folders.

**`--session FILE`** is a recorded session of identity A, either a HAR file or the egress recorder's JSON-lines request log. It must be a private (0600) regular file the user owns. Init passes only the absolute path to the hooks, as `session`. It reads the file itself only to collect, in memory, the credential-like values it holds: header, cookie and query-parameter values, strings under keys that name a token, secret, password, key, cookie or session, and the same inside JSON and form bodies (a HAR's `postData.text` and `content.text`, a log's `body`) and URL queries.

Each hook's proposal is written to `inference-draft.json` only if it holds none of those values and none of the env file's credentials. Otherwise that module's output is withheld and the output says so. The match covers each value as written and as JSON escapes it, and the session path counts as one of the values. A hook's error text is printed only when it holds none of them. If the session file changed between init's check and the hooks' reads (device, inode, size or modification time), every proposal is withheld. The imported session a hook returns is never kept, and the session path is not recorded.

The session-hook test (`--session` reaching a hook by path) uses stub hooks in `test/fixtures/hooks/`, one of them deliberately careless.

## Limits (v0)

- Two identities at most, and the who-am-I route must name them with different string values. Admin, member and guest role splits are left to the full profile.
- Observer candidates come from `--app-env` names. Without it, this shell's names are listed as a labelled hint and never asked about. A SQLite audit table that no variable names is not found.
- A Supabase gateway that needs an `apikey` header beside the bearer token is not supported: an actor has one credential slot.
- Records are given by the operator (`--record-a`, `--record-b`). Init checks each opens for its owner and that the two paths differ, but does not discover them. Two different paths that both list the signed-in user's own records would still read as a cross-tenant FAIL.
- Observers are drafted, not wired: they need tables, routes and witness choices only the operator can make.
- No write-shaped checks. Write checks need a reset plan (docs/ONBOARDING.md) or the inference hook's drafting.
- Assistant-turn checks for a chat endpoint are not drafted.
