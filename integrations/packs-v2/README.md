# Check packs (v2): checks you reuse, pinned by a lockfile

A check pack is a directory of check templates with parameters, so the next engagement starts from the last one's checks. A profile references packs by name and version. `scopehaven pack lock` pins each one's digests in `scopehaven.lock`. Every profile load refuses a pack whose files no longer match the lock, and refuses a pack check that is not shown able to fail.

This is distinct from the earlier parked packs work and from `integrations/payments-pack` (the provider-ledger payments mode).

## The four shipped packs

Each pack is built from the owned fixture's checks, and the manifest's `derivedFrom` cites them. Packs are named by the behaviour they check, never by a regulation, and every manifest has `"regulation": null` until a mapping is approved.

| Pack | Checks (in order) | Built from |
| --- | --- | --- |
| `tenant-isolation` | `<as>-OWN` (control: the actor reads its own tenant's record, and the leak pointer is present); then the other tenant's owner, between its identity controls, reads that tenant's record (`<as>-OWNER-ID`, `<as>-FOREIGN-OWNER`, `<as>-OWNER-ID-CLOSE`); then `<as>-FOREIGN` (critical: the actor is refused that record, and the leak pointer is absent). The owner, an actor of another declared tenant (`different-tenant`), reads first, which shows the path exists. A mistyped path that answers 404 to everyone then fails that required control, so the run cannot read clean (`required-controls-not-passed`), although the refusal row itself still reads pass | TENANT-01, ALLOWED-01; the onboarding B-OWN-ORDER / B-NO-A-ORDER |
| `refund-window` | `<as>-IN-WINDOW` (control: a refund inside the window, one effect), then `<as>-OUT-OF-WINDOW` (high: refused, and no refund effect at all) | PROMISE-01, PROMISE-04 |
| `discount-cap` | `<as>-AT-CAP` (control: a discount at the cap, one effect), then `<as>-OVER-CAP` (high: refused, and no discount effect at all) | PROMISE-02, PROMISE-05 |
| `revocation` | `<as>-ID`, `<as>-BEFORE`, `<as>-WRITE-BEFORE`, `<as>-ID-CLOSE`, `<as>-REVOKE` (the user revokes its own session), then `<as>-AFTER` (high: the revoked credential's write is refused and makes no effect). Its refusals are 401, 403 or the actor's declared `signInRedirectStatus`: the `refusals` type accepts a 3xx, and the lifecycle rule refuses any status the actor does not declare. It adds the target lifecycle entry `{ changeCheckId: <as>-REVOKE, after: "refused" }` | REVOKE-01, MIDTASK-01; ONBOARDING "Account changes mid-run" |

`./scopehaven pack list` prints each pack's parameters (type, default, optional), and `pack show NAME` prints its templates.

**Absences are paired and settle by construction.** Each prohibition's absence clause pins the action's resource prefix, such as `POST /v1/refunds/`. The pack's own allowed-use control, placed before the prohibition, carries the same selector as an `effect.count`.
- **Paired:** the control shows the selector selects something in this observer's format. Without it, a pinned absence reads `selector-unpaired` (`src/http-pairing.mjs`).
- **Settled:** the control's effect lands before the prohibition's window opens.
- **Stronger claim:** the prohibition says no refund call happened at all, not just none for that one order.

**One prefix per pack in a run.** Two packs whose absences share a selector family hold each other: a later pack's control makes an effect that fits an earlier pack's absence, and the settlement rule reads it as possibly that check's late effect. The proof profile gives the revocation pack its own action (an order note to a CRM host) for this reason. When two packs must judge the same action, put them in separate targets.

**Custody still applies.** With an egress recorder on the request path, a prohibition can pass. With the application's own audit table, it can fail but never pass, which the self-test reads as `pass-unreachable`.

## Intake packs

The weekly incident pipeline also ships intake packs here (`blocked-route-egress`, built from a class template, not the owned
fixture). `pack list` lists them too; the class-template tooling that builds them is not part of the open edition.

## A profile with packs

```json
{ "schemaVersion": 1, "targets": [{
  "id": "my-app", "...": "the usual target fields, actors and observers",
  "checks": [ { "id": "B-WHOAMI", "...": "..." }, { "pack": "TI" }, { "pack": "RW" }, { "id": "B-WHOAMI-AFTER", "...": "..." } ],
  "requiredControlIds": ["B-WHOAMI", "B-WHOAMI-AFTER"],
  "packs": [
    { "name": "tenant-isolation", "version": "1.0.0", "as": "TI", "params": { "actor": "agentB", "foreignOwner": "agentA", "ownPath": "/api/orders/B-1", "foreignPath": "/api/orders/A-1", "leakPointer": "/order/customerEmail" } },
    { "name": "refund-window", "version": "1.0.0", "as": "RW", "params": { "actor": "agentB", "recentPath": "/api/orders/B-1/refunds", "stalePath": "/api/orders/B-9/refunds", "effectName": "payments.example", "resourcePrefix": "POST /v1/refunds/" } }
  ] }] }
```

```sh
./scopehaven pack lock --config my-app.targets.json      # writes scopehaven.lock beside it (a new file; --update replaces it)
./scopehaven pack verify --config my-app.targets.json    # checks the lock, as a load does; writes nothing
./scopehaven check-config --config my-app.targets.json
./scopehaven assess --config my-app.targets.json --target my-app --authorization authorization.json
```

**Placement.** A check entry `{ "pack": "TI" }` marks where that instance's checks go. Without one, they go after the target's own checks. `as` is the instance's id prefix, so one pack can be used twice with different parameters.

**Your own packs.** `"from": "packs"` reads a pack from a directory relative to the profile file (`packs/<name>/`) instead of the shipped ones. Every engagement can add a pack: write `manifest.json`, `checks.json` and `cases.json`, then run `scopehaven pack seal DIR`. It checks the manifest and templates and runs the pack's own cases in memory, and writes each file's sha256 into the manifest only when all of that holds.

**What a template may say.** A check template carries only a check's own fields: `id`, `title`, `category`, `severity`, `actorId`, `method`, `path`, `evidenceRequirement`, `assertions`, `body`, `timeoutMs`, `effects`, and `when`.
- **No `applicability`.** A check declared not applicable is never sent, so it could never fail. The load gate refuses one as well.
- **Required controls** must be the pack's own checks.
- **Lifecycle entries** must name the pack's own checks and an actor parameter. Expansion also refuses a placement where the pack's account change would make any of your own checks a post-change check of that actor (every later check of the actor is one), so place the pack after every other check of that actor.

**The lock.** One `scopehaven.lock` serves every profile in its directory.
- `pack lock --update` keeps the entries the other profiles there pinned, and lists them (`keptForOtherProfiles`).
- It never prunes an entry.
- It refuses an existing lock it cannot read rather than silently replacing it.

## Pack updates in CI

One version of each pack ships at a time (`packs/<name>/`), so a profile pinned behind it no longer loads (`pack-version-mismatch`). Two commands read where a profile stands; neither contacts a target (`pull.mjs`):

```sh
./scopehaven pack status --config my-app.targets.json             # each pin against the shipped version, and the shipped packs not used
./scopehaven pack pull --config my-app.targets.json --out DIR     # a copy in DIR taking each newer same-major version, with its own lock
```

- **States.** `current`; `pull` (newer shipped in the same major); `major` (a newer major, whose parameters may differ: taken by hand); `older` (the checkout predates the profile); `local` (an operator's own pack, `from`); `missing` (no longer ships).
- **pull** writes only into DIR, a new or empty directory (not a symbolic link, `pack-pull-out-symlink`): the copy, and a lock made by the same step as `pack lock` (each pack's own cases, then the load gate), so a pulled version that would not load for this profile is refused. It refuses a profile with a `major`, `older` or `missing` reference (`pack-pull-<state>`), and writes nothing when every shipped pin is current, even beside an operator's own pack. A `local` reference (`from`) is refused (`pack-pull-local`) only when another pin would be pulled, since the copy could not reach the operator's directory. The committed profile and lock are never written: to keep a pulled version, set it in the profile and run `pack lock --update`.
- **A new pack is listed, never added.** It needs this profile's parameters once (`pack show NAME`).
- The GitHub Action's `pack-updates` input runs these in its prepare step (`integrations/github-action/README.md`, "Check packs").

## What a load checks

`src/registry.mjs` `loadProfiles` expands packs only when a target has `packs`, so every other profile loads exactly as before. A load runs these steps, in order:

1. **The pack.** Each referenced pack is read (regular files only, size-bounded) and checked against its own manifest: every file present with the sha256 the manifest gives (`pack-digest-mismatch`), and the name and version the reference asks for (`pack-version-mismatch`).
2. **The lock.** `scopehaven.lock` must be a regular file beside the profile, not a link (`pack-lock-missing`, `pack-lock-invalid`). It must also be unedited (`pack-lock-invalid`, by its `lockId`). The lockId is a checksum: it catches an accidental edit or drift, not a deliberate re-seal, and like the packs the lock is not signed. It must pin the reference (`pack-not-locked`) with the same manifest and file digests (`pack-digest-mismatch`). Changing a pack, even re-sealed, means locking again on purpose (`pack lock --update`). Pack files are read the same way: each file must be the file itself, not a link, and is size-bounded. A linked directory above it is followed; the pinned digests keep its content fixed.
3. **The parameters.** They are checked against the manifest: type, required or default, constraints (`greater`, `different`), and actors the target declares (`pack-parameter-invalid`).
4. **The templates.** A string that is exactly `{{name}}` takes the parameter's value with its type. A `{{name}}` inside a string takes a string or integer. `{{actor.principalId}}`, `tenantId` and `identityValue` read the profile's actor (one field at most). `"when": "name"` on a list item (a check, an assertion, an effect) keeps it only when that optional parameter is given. Anywhere else, such as inside a request body, `when` is an ordinary key. Nothing else is evaluated.
5. **The self-test gate.** After expansion, the known-negative self-test (`src/known-negative.mjs`, LQ-5) runs over the target as loaded, with the profile's own observers. A pack check with any predicate not shown able to fail is refused, naming the predicate, its outcome and its reason (`pack-check-cannot-fail`). That covers `cannot-fail`, `always-fails`, `unprovable` and `error`. Both `proven` and `pass-unreachable` can fail. So a pack cannot load a check that cannot fail, and a pack whose effect clause this profile has no observer for is refused rather than run blind.

`pack lock` also runs each pack's own self-test cases (`cases.json`: parameter sets with the outcome every check must read), then the same expansion gate. A lock is never written for a profile that would not load.

## What the tests show (`packs.test.mjs`)

All four packs are run in one profile against `fixtures/pack-app.mjs` (loopback, synthetic data, no model, payment and CRM calls through an egress recorder):

| Build | Not passing |
| --- | --- |
| secure | nothing |
| cross-tenant | `TI-FOREIGN` fail |
| no-window | `RW-OUT-OF-WINDOW` fail |
| no-cap | `DC-OVER-CAP` fail |
| revocation-ignored | `RV-AFTER` fail |
| refuse-all | every control on an order route fails; no prohibition passes |

The tests also show:
- **The lock refuses** each of these: no lock, a linked lock, an unlocked reference, an edited pack (before and after re-sealing), a linked pack file, an edited lock, a wrong version, and a name that is not a pack name.
- **The load gate refuses** a check that cannot fail (`json.exists` at the root) and an effect clause no declared observer records. It also refuses after locking, when an edit to the profile (a removed settle) leaves a pack check unable to fail.
- **Templates are refused** with `applicability` or an unknown field, a foreign required control or lifecycle entry, or a placeholder that reads two fields.
- **A foreign path that does not exist** fails the owner's control.
- **One lock serves two profiles.**
- **`check-config`** exits 2 on a tampered lock.

## What it does not establish

- A pack checks the behaviour its templates state, with the parameters given. Whether those paths and resources are the right ones for an application is the operator's call, as with any hand-written check.
- No regulation is mapped. "Tenant isolation" is a behaviour, not a compliance claim.
- Packs ship as source in this repository. The lock pins their bytes, and nothing signs them.
