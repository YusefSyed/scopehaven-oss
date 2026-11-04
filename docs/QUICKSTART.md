# Quickstart: from a running app to a first decided row

This page takes an app you own, already running on your machine, to its first decided row: a **FAIL**, or an **INCONCLUSIVE** row that names the check that fired. Plan on under an hour. The first run sends only GET requests, to loopback, under an authorization record you confirm.

ScopeHaven tests what your app does, not what its reply text says. So it needs a little more than a URL: two signed-in test users in two tenants, and a record each of them owns. `init` finds the rest.

For an agent that runs in-process (LangGraph, Mastra) rather than behind HTTP, read [FRAMEWORK-MODE.md](FRAMEWORK-MODE.md) instead. For every option and rule, read [ONBOARDING.md](ONBOARDING.md).

## Before you start (about 15 minutes)

To time this onboarding, run this first, before anything else on this page:

```sh
./scopehaven init start --out data/onboarding/one --label first-try --owned yes --operator-role "engineer on the app team"
```

[Timing an onboarding](#timing-an-onboarding) explains the labels and the receipt.

1. **Run the app on loopback**, for example at `http://127.0.0.1:3000`. Use a local copy with synthetic data, never production. A dev server compiles routes on first use, so open one page in the browser first and check the app answers without errors.
2. **Check the runtime** from the repository root:

   ```sh
   ./scopehaven doctor
   ```

   If `doctor` says your Node is outside `>=22.16.0 <23 || >=24.0.0 <25`, or warns that it is below the October 2026 security release, install Node 22 LTS (22.23.4 or newer) or 24 LTS (24.22.1 or newer) from https://nodejs.org/en/download, or set `SCOPEHAVEN_NODE` to one; the launcher picks it up without any PATH change.

3. **Sign in two test users in two different tenants** (two orgs, two workspaces, or two plain accounts). Copy each session token or session cookie value from the browser's developer tools, or from your app's login route.
4. **Put both values in a private env file.** The names must start with `SCOPEHAVEN_TARGET_`:

   ```sh
   umask 077
   cat > ids.env <<'EOF'
   SCOPEHAVEN_TARGET_MYAPP_A=<user A's token or cookie value>
   SCOPEHAVEN_TARGET_MYAPP_B=<user B's token or cookie value>
   EOF
   chmod 600 ids.env
   ```

   `init` refuses a file other users can read. It never prints or writes these values. Only their names reach the profile.
5. **Have each user own one record.** Note a URL path for each, such as `/api/notes/12` for A and `/api/notes/31` for B. Create the records in the app if needed.

## No app at hand? Try n8n

A fresh n8n community 2.41.6 (`docker.io/n8nio/n8n@sha256:87e0bab2c93192e8dd885ff7b0697c22a1bd97489568a8c67cc140fd7dbb342d`, SQLite) on `127.0.0.1` works as a first target: create the owner with `POST /rest/owner/setup`, invite two `global:member` users with `POST /rest/invitations` and accept each with `POST /rest/invitations/accept` (the token from its `inviteAcceptUrl`), sign each in with `POST /rest/login` and keep its `n8n-auth` cookie, and have each create one workflow; the records are `/rest/workflows/<id>`. Run init with `--whoami /rest/login --credential cookie:n8n-auth`. Verified on 2026-10-29 on a private build (first decided row: INCONCLUSIVE B-READS-A-RECORD-BACKEND).

## Run init (about 5 minutes)

```sh
./scopehaven init --base-url http://127.0.0.1:3000 --env ids.env
```

Without flags, `init` asks for what it needs. It works in this order:

1. **Authorization first.** It asks five questions: whose app this is, which hosts the run may contact, what the run may do, what data the copy holds, and who agreed and can be reached. It drafts `rules-of-engagement.md` and the authorization record, then asks you to type `yes` to confirm you are authorized to test this copy. Nothing is sent to the app before that. The record's checksum detects edits; it is not a signature.
2. **Probes.** It finds the login routes, the "who am I" route that names each user, and how the app takes the session (a bearer token or a cookie). If it cannot find one, it asks. It checks that each record opens for its owner.
3. **Writes the starter profile.** Two users, a signed-out visitor, and these checks:
   - each user's identity control on the who-am-I route;
   - each user opens their own record (the allowed use);
   - B cannot open A's record, A cannot open B's, a signed-out request cannot open A's. `init` sends each of these reads once. If the app refuses with 401, 403 or 404, the check expects that. If it answers 200 and filters the row away, as PostgREST and Supabase do with `200 []`, the check judges the body: it fails only when the body holds the other user's record values;
   - the B-reads-A check again, requiring backend evidence.
4. **Lists observer candidates** from environment variable names only, such as `DATABASE_URL` or `SMTP_HOST`. It reads a value only if you say yes for that name, only in memory, and only to report whether it points at loopback. Without `--app-env`, init lists candidates from the shell you run it in, which holds your own tools' settings (for example `ANTHROPIC_BASE_URL`), not the app's. Give `--app-env` with the app's env file, or ignore those candidates.
5. **Runs** `check-config`, `roe check` and the starter assessment.

The same run with every answer given as a flag:

```sh
./scopehaven init --yes --base-url http://127.0.0.1:3000 --env ids.env --id myapp \
  --record-a /api/notes/12 --record-b /api/notes/31 \
  --client "My company" --contact "Your Name, Engineering lead" \
  --app-env ../myapp/.env --confirm-authorization
```

Useful options:
- `--whoami PATH` and `--credential bearer|cookie:NAME|header:NAME` when the probe cannot find them.
- `--openapi FILE` drafts more GET checks from an OpenAPI 3 JSON document. The draft stays unconfirmed until a named person confirms it.
- `--session FILE` passes a recorded session of user A (a 0600 HAR or request log) to the session drafter, which proposes more checks in `inference-draft.json`; no credential from it is written.
- `--out DIR` changes where files go (default `data/init/<id>/`). Add `--force` to replace what an earlier run wrote.
- `--no-run` stops after writing the files.

## Read the result (about 5 minutes)

`init` ends with the first decided row. Two examples:

```text
First decided row: FAIL  B-READS-A-RECORD  (high)  Identity B cannot open identity A's record
  fired check: HTTP status matches contract: expected HTTP 403 or 404; got HTTP 200
```

User B opened user A's record. That is a cross-tenant read to fix.

```text
First decided row: INCONCLUSIVE  B-READS-A-RECORD-BACKEND  (high)  The foreign record is not read inside the app (needs an observer)
  fired check: Trusted backend observation available: expected Independent backend evidence required; got Backend evidence unavailable
```

The app refused B over HTTP, but a response alone cannot show the app never loaded A's record. Wire an observer to decide it (next section).

`init` exits 0 when the starter run has no FAIL row, and 1 when it has one, as `assess` does. It exits 2 when it stopped before sending anything (a missing answer, a refused input, or an unconfirmed authorization), and 3 when it could not finish. A stop during probing (for example `whoami`) exits 3: init sent probe requests but could not finish.

The summary names FAIL, INCONCLUSIVE and "not exercised" rows only. A row that met its contract is not a clean bill of health: the starter profile tests a handful of reads. The run file has every row.

## What init wrote

Every file is private (mode 0600):

| File | Purpose |
| --- | --- |
| `targets.json` | the starter profile |
| `authorization.json` | the sealed record; `assess` refuses to run without it |
| `rules-of-engagement.md` | your five answers; the record binds its checksum |
| `observers.draft.json` | observer candidates with placeholders for you to fill in |
| `init-report.json` | what was probed and chosen; each prohibition's allowed-use twin; this run's stage times and the starter run's counts |
| `init-stamps.jsonl` | one line per stage of every init run in this folder: stage names, times, exit codes and check ids, never a credential or value |
| `evidence/runs/<id>.json` | the starter run |

## Next steps

1. **Rerun after a fix.** `init` prints the exact command. Load the env file first:

   ```sh
   set -a; . ./ids.env; set +a
   ./scopehaven assess --config data/init/myapp/targets.json --target myapp --authorization data/init/myapp/authorization.json
   ```

   The authorization window defaults to 8 hours (`--hours`, up to 72). After it ends, rerun `init` with `--force`, or seal a new record.
2. **Wire an observer** so backend and effect rows can be decided. Start from `observers.draft.json`, then read "Observe what the app recorded" in ONBOARDING.md. Add its `tcp://127.0.0.1:PORT` endpoint to the authorization record's hosts.
3. **Add the checks that matter for your app.** Write-shaped checks need a reset plan. Assistant-turn checks cover a chat endpoint. Both are in ONBOARDING.md.

## If init stops

| Message | What to do |
| --- | --- |
| `the env file has mode 644` | `chmod 600 ids.env` |
| `no who-am-I route named each identity` | Read the line above it: it says what was tried and what came back. Give `--whoami /api/me --credential cookie:session`, using your app's route and cookie name. For n8n: `--whoami /rest/login --credential cookie:n8n-auth`. |
| `every answer was a 5xx or no answer`, or a long wait | The app is unhealthy or still compiling. Open a page in the browser, check the app's own log, then rerun. |
| `Candidate FAIL before the run` | A user read another user's record and the answer held that record's values. Look at the FAIL row after the run. |
| `answered identity A with 403` | That path is not a record A can open. Give one A owns. |
| `hosts do not include the app's origin` | Add the base URL's origin to the hosts answer. |
| `Stopped before any request` | You did not confirm the authorization. Review the draft, then rerun with `--confirm-authorization`. |
| `--stack needs integrations/init/stack.mjs` | Your copy is missing `integrations/init/stack.mjs`, which is part of this repository (`./scopehaven init --stack supabase` works from a complete clone). Restore the file, or run init without `--stack`. |

## Timing an onboarding

To measure how long a first result takes someone new, give the onboarding its own folder and start its clock before opening this page, with the `init start` command at the top of [Before you start](#before-you-start-about-15-minutes).

`--label` is a neutral internal label and `--operator-role` a role, never a company's or a person's name (up to 80 letters, digits, spaces and `,.()/_-`; no apostrophes). Quote a label that contains spaces. `--owned no` marks an app ScopeHaven does not own, run by its owner's own staff. Then pass the same folder to every init run with `--out data/onboarding/one`; each run appends its stage stamps there, including runs that stop. The labels are checked for shape only, so keep names out of them yourself.

There are two clocks. The first decided row is the first starter run whose first row was a FAIL, or an INCONCLUSIVE row with its fired check: a first result, not a finding. The first FAIL that holds is the first starter run with a FAIL row a reviewer confirms. Review every FAIL row, one command each:

```sh
./scopehaven init review --out data/onboarding/one --run RUN_ID --check B-READS-A-RECORD --holds yes --reviewer-role "security reviewer"
```

`--holds no` records a false FAIL. Then write the receipt, and compare several onboardings:

```sh
./scopehaven init receipt --out data/onboarding/one
./scopehaven init table data/onboarding/one data/onboarding/two
```

The receipt (`onboarding-receipt.json`) holds both clocks in minutes from the start stamp, every init run's exit status, the product head, the role of whoever reviewed the held FAIL, and the false and unreviewed FAIL rows. The start and review lines also keep your label and roles. Its stamps come from this machine's clock and carry no key: it is a timing receipt, not evidence. The table ends with a `Limits:` line saying so, and that what each operator had in context before the start stamp is only what their role says (init cannot check it), so write it into `--operator-role`.

