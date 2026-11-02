# Operator-forwarded mode, end to end

In this mode ScopeHaven connects only to a literal `http://127.0.0.1:PORT` (direct HTTPS to a remote origin is the separate `operator-remote` mode, ONBOARDING "remote mode"). To test a staging app, the operator runs a forwarder on loopback that reaches staging, and declares the target `operator-forwarded` with a short label (docs/ONBOARDING.md, "Testing your own staging environment"). This folder pins how that mode behaves, including when the forwarder is set up wrong.

**Authorization and pairing:** a forwarded target runs only under an authorization record whose `forwarded.destination` names where the forwarder sends traffic (`src/authorization.mjs`, refusal `authorization-forwarded`), and a boundary pass counts toward a clean gate or a clean `assess` exit only when a required control with the same method on the same route passed in the same run (`src/forwarded-pairing.mjs`, gate reason `forwarded-pass-unpaired`). Rows keep their verdicts: the pairing is read from the saved run, outside the HTTP evaluator identity, so no identity hash moves.

## The loopback test (`forwarded.test.mjs`)

A loopback notes app stands in for staging, and a loopback forwarder plays the operator's proxy. It has a bearer actor, a cookie actor and an anonymous actor, and, in the row with the administrator control, a second bearer actor (the administrator).

| Forwarder | Logins | Forbidden checks | Gate |
| --- | --- | --- | --- |
| clean, with the administrator's control on `/admin/settings` | all established | all pass on the secure app | exit 0; run, gate, HTML and SARIF carry `operator-forwarded target: <label>` |
| clean, no control on `/admin/settings` | both established | all pass | exit 1, `forwarded-pass-unpaired` (OWNER-ADMIN has no same-route control); the same profile declared `local-app` exits 0 |
| clean, do-nothing app | logins work, controls fail (`control-not-passed`) | controls fail; every forbidden check reads inconclusive, the signed-out actor's too (its public-page control failed) | exit 1 |
| clean, dump-everything app | both established | forbidden checks fail | exit 1 |
| cookie-rewrite | the cookie actor's is not proven | that actor's check is not a pass; the bearer actor's is unaffected | exit 1 |
| strip-authorization | the bearer actor's is not proven | that actor's check is not a pass, although its 401 is one the check accepts; the cookie actor's is unaffected | exit 1 |
| redirect-signin | none proven | every row reads fail (302 is outside the statuses they accept); none reads pass | exit 1 |
| deny-admin (403 on `/admin/*` itself), owner-admin app | both established | **OWNER-ADMIN reads pass** on a build that leaks it (the row-level limit below) | exit 1, `forwarded-pass-unpaired` (exit 0 before same-route pairing) |
| deny-admin, with a required administrator control on `/admin/settings` | all three logins proven; the administrator reads `control-not-passed` (not established) | the control fails; OWNER-ADMIN still reads pass | exit 1 |
| deny-all (401 to everything), no anonymous control | none proven | **ANON-NOTES reads pass** although nothing reached the app (the known limit below) | exit 1 (unproven logins, and `forwarded-pass-unpaired`: its same-route control failed) |
| deny-all, with the anonymous public-page control | none proven | the control fails, and ANON-NOTES is not a pass | exit 1 |

A run of the same app declared `local-app` is never compared with the forwarded run (`Target context differs ...`), and the gate refuses the pair (`incompatible-baseline`).

## The live run against a TLS staging copy

The run was made on 2026-10-07 on a private build. Its receipt, forwarder and scripts are kept outside this repository, so the setup and results are summarized here. Recorded on a private build; not reproducible from this repository.

**Setup:**
- A synthetic Open WebUI 0.11.4 install (synthetic data) on an internal Docker network, with no published port and outbound connections blocked.
- nginx in front of it terminates TLS for `staging.scopehaven.test` on 127.0.0.1:4490, using a local practice CA. While setting it up, plain HTTP got 400, another hostname got 421, and a client without the CA failed verification; those setup checks were not kept as artifacts, so take them as the setup's intent, not as evidence.
- The forwarder listens on 127.0.0.1:4491. It reaches staging over TLS with the CA pinned and rewrites `Host`.
- The staging app sets its session cookie `Secure`. That is the app's configuration: ScopeHaven never reads `Set-Cookie`, so "Secure-cookie actor" below means an actor whose session is that cookie, not something ScopeHaven checked.

**Results:**
- **Clean:** 17 of 17 checks pass. Identity is established for two bearer actors and one Secure-cookie actor.
- **Drill:** the practice drill (Support given read on the Finance knowledge base) flips exactly B-SUP-FIN-KB, B-SUP-FIN-KB-FILES and B-SUP-FIN-RETRIEVE to fail. Restoring it brings them back, labelled "Response contracts restored".
- **Labels:** run, gate, HTML and SARIF carry `operator-forwarded target: Open WebUI staging (TLS forwarded).`
- **Local-app baseline:** the comparison is refused ("Target context differs") and the gate exits 1.
- **Cookie rewrite:** only the cookie actor's login is not proven, and its forbidden check reads inconclusive.
- **Stripped Authorization:** the two bearer actors' logins are not proven, and their six forbidden checks read inconclusive.
- **Redirected sign-in:** no login is proven and every row reads fail. Declaring `signInRedirectStatus: 302` does not change that: it only widens what the identity probes accept as a refusal.

## What this shows, and what it does not

- The three misconfigurations tried here apply to every request (cookie rewrite, stripped Authorization, redirected sign-in). None of them turned a forbidden check into a pass for an actor whose login it broke, on the loopback test or on the live TLS copy.
- A redirect-everything forwarder reads as failing checks, not as inconclusive ones. That is a false alarm, not a false pass. The identity rows say the logins were not proven, and a reader should look there first. Whether rows of an unproven actor should read inconclusive even when their status assertion fails is an open question (`src/http-connector.mjs`); this folder only pins the current behaviour.
- The forwarder is operator trust. The label states that the target was forwarded. The identity proof shows that each login reached whatever answers the identity route (`/me`) through the forwarder, and nothing more.
- Two practice checks that send a chat turn to a model (C-FIN-MODEL-TURN and B-SUP-TOOL-RUN) were left out of the live run, because the staging copy has no model connection.

## Limits

- **Identity proof covers the identity route only.** A forwarder that answers or alters one route itself makes a forbidden check on that route read pass, with every login proven; before same-route pairing the gate was clean too; now it is not without a passing same-route control. Examples: a deny rule on `/admin/*`, credentials stripped on that route only, the wrong upstream for it, or a response cache kept across runs. The test pins the deny rule.
  - **What a same-route control catches:** a forwarder that denies or strips on that route. A required positive control on the same route through the same forwarder (here, an administrator reading `/admin/settings`) then fails and the gate turns red, although the forbidden row itself still reads pass. The test pins this for a deny rule; for a strip rule it was shown by an earlier adversarial probe, not by a test here.
  - **What it does not catch, and no single run can show:** the wrong upstream serving the same accounts (the control and the forbidden check both reach it, so the control passes), a response cache kept across runs (both read the cached answers), and a gate in front of the app that refuses only signed-out requests while letting the public page through (the signed-out control passes while the signed-out forbidden row is answered by the gate). The forwarder is operator trust: the label says the target was forwarded, and these setups are the operator's to rule out.
  - **A rule keyed on one record or one account.** The pairing is by route shape: two different records on one route are the same route. So a forwarder or WAF rule that answers one record id itself (403 on `/notes/2`, `/notes/1` passed through) is paired by a passing control on another id of that route, and a rule that matches one account's credential is paired by another actor's passing control on the route. Both read clean. These are operator trust too.
  - What the gate does: a forwarded forbidden pass without a passing same-route required control is `forwarded-pass-unpaired`, and the gate is not clean. The row still reads pass. The comparison (`compareRuns`, the comparison export and report, `GET /api/compare`) reads such a candidate pass as `unverified` (`candidate-forwarded-pass-unpaired`), never restored or preserved, and SARIF projects it as kind `review` and lists it in the run's `unpairedPasses`.
- **A forwarder that answers everything.** An auth gate or WAF in front of the app that answers every request with 401 makes a signed-out forbidden row read pass, although nothing reached the app. The protection is the signed-out actor's required control (here, the public page): it fails, and the row is held back. A profile without one has no protection. The live staging profile has none: its signed-out check B-ANON-KB is unpaired.
- **Redirected sign-in reads fail, not inconclusive.** `docs/ONBOARDING.md` says a redirected sign-in makes results inconclusive. This folder pins that rows read fail (302 is outside the accepted statuses). The docs or the connector need to change to match.

