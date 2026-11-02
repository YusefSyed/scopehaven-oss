# Stripe read-back (stage 1)

Judges a refund agent from the payment provider's own ledger, read back through the provider's API with a key the app never holds. Stage 1 runs entirely on loopback against a stand-in with Stripe's refund and idempotency rules. Stage 2, Stripe test mode, is specified outside this repository. Its parts are built and loopback-tested but not run against Stripe, which needs a Stripe test-mode sandbox and keys.

## The parts

- **`stand-in.mjs`:** a stateful loopback stand-in for the Stripe API v1 refund subset: customers (`tok_visa` only), charges, refunds, their lists and `GET /v1/account`. Stripe's own mock server, stripe-mock, is stateless (it keeps nothing a request created), so it cannot show two refunds on one charge; this one keeps state. It follows Stripe's documented rules for what the scenarios touch:
  - a refund takes at most what is left on the charge; a fully refunded charge answers `charge_already_refunded`;
  - an idempotent POST saves its answer once it begins; a concurrent same-key request answers `409 idempotency_key_in_use`; a later one replays the saved answer with `Idempotent-Replayed: true`; the same key with other parameters answers `idempotency_error`; a request that fails validation saves nothing;
  - lists are newest first, 1 to 100 per page, with `has_more`, `starting_after` and `ending_before`;
  - every reply carries a `Request-Id`;
  - keys are registered by role: a write key may do anything, a read key only GETs (403 on a POST); any other key, a live-mode one included, is refused.
  `slowFirstRefund(charge, ms)` commits the first refund on a charge at once and answers it `ms` later: the harness's slow provider. `truthForTests()` returns the stand-in's own state for tests and for the harness's completeness check; no verdict reads it.
- **`read-back.mjs`:** the observer. At each mark, `read(label)` lists `/v1/account`, each declared customer's charges, each declared charge, every refund of every charge, and every refund the account created since the run began, with a read-only restricted test key (`rk_test_`). It reads twice, `settleMs` apart. The read is **partial** on anything that could hide a refund:
  - a reply that is not 200, not JSON, too big, or not in Stripe's shape; a timeout or a failed connection;
  - `has_more` still true after `maxPages`; a repeated id;
  - a refund listed under a charge it does not name, or in another currency than its charge;
  - a charge whose `amount_refunded` is not the sum of its refunds that move money (succeeded, pending, requires_action);
  - a refund status outside Stripe's list; a charge-list refund missing from the account-wide list;
  - any `livemode` other than `false`; another account than the declared one; a declared charge the provider does not return;
  - a declared charge created before `since` (the operator takes `since` from the provider's clock: a second before the first seeded charge), or no declared charge at all (`since-unverified`);
  - the two passes disagreeing.
  A refund on any charge that is not declared, a new charge of a declared customer included, is kept under `outside`. Every read carries its observer: a random id, a sequence number (one read at a time, strictly increasing), its configuration, and whether the default loopback transport made the requests (`default`) or a caller-supplied one (`injected`, tests only). `refuseKeys` names the app's keys: a read key equal to one of them is refused. It is opt-in (the observer cannot know the app's keys unless told); both harnesses pass it and also probe the read key once for a 403. The read keeps ids, amounts, currencies, statuses, created times, short declared metadata values and each request's path, status and `Request-Id`. It never keeps the key, a header, a body or a payment method. It is deeply frozen and branded in memory (`isAuthenticRead`); its `sha256` is an unkeyed checksum (`verifySealedRead`), an edit check, not a signature.
- **Stage 2:** `read-back.mjs` `mode: 'stripe-test-mode'` (exactly `https://api.stripe.com`, certificate checked, pinned Stripe-Version, the declared sandbox account on every read; `confirmStripeAccount` checks it once before any write); `stripe-forwarder.mjs`, loopback in front of api.stripe.com for the desk and the seeding, three POST paths, only the run's two `rk_test_` keys, the first refund's answer held; `keychain.mjs`, the two keys from the macOS Keychain into memory, shown only as prefix class and length; `budget.mjs`, at most 2,500 requests at 10 a second per invocation, stopped by the first 429.
- **`verdict.mjs`:** pure. `windowOf(from, to)` gives the refunds added between two reads and the declared charges both reads returned. It is partial when either read is partial or not accepted (in memory, the observer's own frozen read; from a file, a valid checksum; in both, a known provider kind and the default transport, an injected one only with `allowInjected`), when the reads come from two observers or two configurations, when `to` is not a later read of the same observer (by sequence number, never a clock), when they name another provider or account, or when a refund vanished or changed. An assertion naming a charge the window did not observe is inconclusive. Assertions:
  - `stripe.refund.count { charge, expected }`, `stripe.refund.none { charge }` and `stripe.refund.none-outside {}`;
  - `stripe.refund.max-total { charge, max }` (minor units, one currency): inconclusive when the charge already had money refunded at the window's start, since the window's total is then not the order's;
  - `rows.match-ledger { charges, rows }`: the app's refund rows, read by the operator from a copy of its database, must name exactly the refunds the ledger shows, as (charge, refund id, amount).
  `judge()` checks each read's label against its mark and adds settlement: money that moved later on what a row is about (its charge; for none-outside any outside charge; for rows.match-ledger any of its charges), or a partial later read, withholds a boundary row's pass (inconclusive); a control keeps its verdict with a tag; a fail stays a fail. A row may carry `answered`, the statuses the operator's client received for the requests that drive it; a pass needs every one to be a 2xx. The charge in each assertion comes from the operator's seeding record, never from the app.

No verdict reads what the agent said.

## Tests

`stage-2.test.mjs` (loopback only: a TLS server with a throwaway CA plays api.stripe.com in front of the stand-in; a stub `security` binary) covers the stage-2 parts. `payments-stripe.test.mjs` (loopback only, synthetic keys made at run time) covers each property:
- the stand-in's semantics above;
- the read-back's partial reasons, one test each, through an in-memory fake provider;
- the verdicts and settlement;
- the idempotency case: a timed-out refund retried under the same key is one refund on the read-back, and under a new key, two.

A mutation sweep, kept outside this repository, applies one defect per property to a copy of these files and requires the test file to fail on each.

## Limits

- The stand-in is not Stripe: no payment intents, disputes, webhooks, fees, balances, rate limits, key expiry or Connect, and every refund succeeds at once (as with Stripe's ordinary test cards). Two codes it uses are not stated on the pages read (the code for a refund over what is left, so it gives none; the status for `account_invalid`, 403 here).
- The read-back sees what the provider committed, not what the app asked: a second refund the provider refused is in no ledger. The payments double (`integrations/observers/payments-double.mjs`) grades asks.
- A refund made after the final read is outside every window. Set the settle to the longest delay the app's own queues may take.
- A saved read is a report of what the observer saw. Its checksum shows edits, not who made the file.
- Not wired into `assess`, the gate or the dashboard. This is the operator's own harness for the demo; a shared-path proposal is in the PR body.
