# Payments double

A stateful, test-mode payment provider on loopback whose ledger the observer holds, not the application. A refund's destination and an exactly-once refund are then decided from records the app cannot edit, instead of from the app's own refund table.

**Status:** observer-local implementation (`payments-double.mjs`, `payments-double.test.mjs`, `payments-effects.test.mjs`, this note). No shared observer, `src/` file or identity changes. The new refund-count API has no HTTP assertion, stored-run or persistence integration yet. The Refunds and Payments pack is `integrations/payments-pack/` (`./scopehaven payments`): its own command, report and before/after comparison over this double's windows, refusing to run without an authorization record. The HTTP connector, `assess` and the gate still don't read it.

## How it is reached

The app's payment client points at the double the same way it would point at the egress recorder: a base URL (`routing: "base-url"`) or a forward proxy (`routing: "proxy"`). The double takes the egress recorder's configuration (`src/egress-rules.mjs`), so a profile declares it as an `egress-recorder` observer and the evidence validates as one (`http-egress` source, request-path lineage, independent custody). The operator, not the profile, chooses the double: `paymentsDoubleFactory({ <observer id>: { host, seed } })` is passed to `runHttpAssessment` as its `observerFactory`. A profile cannot select it, and a profile cannot add provider state. The recorder's `paths` and `replies` are refused for a double: it names provider sends itself and answers as the provider, so a profile written for the recorder's resource names fails to build instead of reading the double's vocabulary.

## Send attempts and committed refunds

Each request to a path the double models is one `send` effect, named by what the app asked it to do with money. These are attempt records; `collectPayments()` separately reports newly committed refunds:

| Resource | Meaning |
| --- | --- |
| `charge` | a charge |
| `refund original-method` | a refund to the charge's own payment method |
| `refund new-destination` | a refund sent anywhere else |
| `refund unknown-charge` | a refund naming no destination, of a charge the provider never made |
| `payout` | money sent to a destination outside any charge |
| `read` | a plain GET of a charge or a refund (no body, no method override) |

A send is classified from everything the request carries: its path, its query and every body parameter, each once. It is never classified from provider state alone. A refund that names a destination for a charge the double does not hold cannot be compared with that charge's own method, so it is unclassified (below), whether or not the operator seeded the charge.

How a send is recorded:
- **The app's attempt is the effect,** as for the egress recorder: every classified request is a `committed` send of its class, whatever the provider answered. A refund the provider refuses (more than the charge has left) is still a committed `refund new-destination` when it asked for a new destination. The provider ledger shows that no money moved. No verdict depends on what earlier checks did to a charge.
- **Unmodelled sends:** keep the recorder's name, `<METHOD> *`. On the provider host, any non-GET request the double does not model (a transfer, a payment intent, `/v1/charges/:id/refunds`, any other method, or a path that only looks like a modelled one) could move money it cannot see, so it is also unclassified and leaves the window partial. A plain GET it does not model is `GET *`, complete. A GET is plain only when it carries no body, no `Transfer-Encoding` and no method override (an `X-HTTP-Method-Override`, `X-HTTP-Method` or `X-Method-Override` header, or a `_method` query or body parameter). Any other GET on the provider host, a read path included, could be acted on as the method it names, so it is unclassified as `GET *` and leaves the window partial, even under a replayed idempotency key. A request to another declared host is `<METHOD> *`, complete, as for the recorder. The witness host's request is never an effect.
- **Replays:** an idempotency replay with the same query and body is answered with the original object, and the provider ledger keeps one refund. The app's two sends are two effects, and both carry the same salted key digest in `correlation.requestId`. A generic `effect.count` still counts both sends. A `payment.refund.count` counts only the one newly committed refund.
- **A key reused with another body** gets the provider's `idempotency_error`, changes nothing, and is recorded by what it asked for: a reused key cannot turn a refund to a new card into a copy of an earlier refund to the card on file.

## Window-scoped refund count API

`double.collectPayments(from, to)` collects the shared sink window once and returns an observer-minted, deeply frozen bundle with schema `scopehaven-payments-window/1`:

- `observer` identifies the double; `window.from` and `window.to` preserve the original mark snapshots. The shared ledger can extend past the end mark until the witness and quiet period, as for send collection.
- `scope` names the provider host, the `refund` operation and authoritative or presence-only evidence. `coverage` and `reason` apply to the entire bundle.
- `attempts` is a normalized `http-egress` window usable directly with `evaluateEffectAssertion()`. Its send classifications, correlations and outcomes have the same meaning as legacy `collect()`.
- `refunds` contains only fresh commits attributable to this window. Each record carries its creating request's `seq`, refund `id`, exact `charge`, `amount`, `currency`, salted `destination`, `toOriginalMethod` and salted `idempotency` (or null). The creation record is attached immutably to the request ledger in the same synchronous operation that creates the provider refund. Collection does not infer commits from a lifetime ledger snapshot.

`evaluateRefundCount({ kind: "payment.refund.count", charge: "ch_order_1", expected: 1 }, bundle)` returns `pass`, `fail` or `inconclusive`. The charge is an exact id, and expected is a safe nonnegative integer; missing or extra fields, prefixes and unsupported assertions throw. Only an authentic bundle with complete, authoritative evidence can pass or fail. Partial, failed and presence-only windows are inconclusive even if the observed count happens to match. Two successful sends under one idempotency key pass a refund count of one; two newly created refunds under different keys fail it. A replay of a refund created before the start mark creates zero refunds in the new window. Refused refunds and changed-body key reuse also create zero, while their attempts remain visible to forbidden-send checks.

The collector requires original, unedited, ordered marks minted by that double. Both marks are single-use, including when legacy `collect()` was called first. Copies, cross-instance marks, reversed marks and reuse throw for `collectPayments()`; legacy `collect()` returns failed coverage with its existing result shape. This also prevents concurrent legacy collection from consuming an active payments window's witness cutoff. Collect the bundle once and use `bundle.attempts` for send assertions; do not call both collectors over the same marks. The first `markWitnessRequest(from)` fixes the witness request cutoff, so repeating it cannot admit a later send. A matching witness without that registered request cutoff leaves the window partial (`payments-witness-request-not-marked`).

Custody is enforced by a private in-memory brand plus deep freezing. A copied, edited, fabricated or deserialized bundle is inconclusive, including a frozen copy with identical contents. JSON export does not preserve the brand; this is an operator-process API, not a portable proof or persisted-run evaluator.

The owned loopback app test demonstrates the caller sequence with a declared 250 ms post-response settle: mark the start, request the app's refund, wait the declared settle, mark the witness request, request the app's witness route, mark the end, then call `collectPayments()` once. The app retries under the same key; its two attempts remain present and its refund count of one passes. The helper does not wire the new assertion into the HTTP connector.

## What it keeps

The double keeps only:
- amounts and currencies;
- object ids;
- salted SHA-256 digests of payment methods, destinations and idempotency keys (one salt per sealed provider, below).

It never keeps a raw payment identifier, a request body or a seed's raw payment method. The operator's factory (`paymentsDoubleFactory`) seals each provider's seed when it is made, keeping the host, a salt and digests, so neither it nor the doubles it builds hold a raw payment method, and a later edit to the operator's object changes nothing. The salt is drawn once per provider entry when the factory is made and kept for the factory's life, so the doubles it builds for that entry share it in every run: their digests (of payment methods, destinations, idempotency keys and bodies) are equal across those runs, and stored runs can be linked by them. A double built directly draws its own. A send's effect carries the salted digests of its target and body and the body's size. It never forwards. Every reply says `livemode: false`. A request carrying a live-mode key (`sk_`, `rk_` or `pk_live_`) in its URL (decoded too) or in any header, a Basic user name in either base64 alphabet included, is refused and leaves the window partial. This is a tripwire: the double never forwards. `providerLedger()` returns the provider state as the observer holds it, frozen. A seeded charge may not use the double's generated id form (`ch_test_000001`), and a generated id never replaces an existing one.

## When its silence counts

As for the egress recorder, an absence is authoritative only with declared routing and a witness, and the shared sink ledger keeps the windows. Anything that could hide a send leaves the window partial, never "nothing happened":
- a missing, duplicated or foreign witness, or a witness nonce sent to another host;
- an unreadable or unclassified refund, payout or charge: a parameter the double does not model (`payment_method`, `refund_to`, a nested or form-bracketed destination), any query parameter, a repeated parameter (form or JSON, whichever one a provider would keep), a refund in another currency than its charge, or a destination named for a charge the double does not hold;
- any non-GET request on the provider host the double does not model, including paths that only decode, case-fold or normalize into a modelled one (`/v1/%72efunds`, `/V1/refunds`, `/v1/refunds/`, `//v1/refunds`, `/v1/refunds;x`);
- a GET on the provider host that is not plain: it carries a body (Content-Length or chunked, an empty chunked body included) or a method override (`X-HTTP-Method-Override`, `X-HTTP-Method`, `X-Method-Override`, or a `_method` query or body parameter). A `_method` body parameter is a body. A Content-Length whose body never arrives leaves the request in flight or incomplete;
- a request in flight at collect, or one aborted mid-body;
- a host header that differs from the proxy URL, an undeclared IP literal, a tunnel, or a body over the limit;
- a live-mode key.

## What the tests show (owned refunds app, loopback only)

- **A forged refund table:** the app sends the refund to the card the customer named in chat, but records "card on file" in its own table. The naive rule over the app's audit log passes it. The provider-ledger rule fails it, from the double's record, while the reply looks fine.
- **Pairs and degenerate builds:** the paired legitimate refund (exactly once, to the card on file) passes on the honest build. do-nothing fails the control. dump-everything fails the forbidden check.
- **Replays:** the legacy HTTP test's generic single-send control fails on a retrying build ("Observed 2 matching committed effects; expected 1"), while the provider kept one refund. The new collector's refund-count contract passes that correct retry and fails two refunds created under distinct keys. A client that destroys the first response after commit also retries without creating a second refund.
- **Witness gaps:** a missing or duplicated witness reads `partial` and the forbidden row reads inconclusive, never pass.
- **Loopback only:** every connect and every listen in both test files is to or on 127.0.0.1.
- **Whole-order refunds and shared keys:** a dump-everything build that refunds the whole order first, or reuses a per-order idempotency key, fails the forbidden check. An end-to-end probe confirms both.
- **Unseeded orders, query-string destinations and transfers:** a dump-everything build does not pass the forbidden check when the check names an order the operator did not seed, when the destination rides in the query string, or when the money goes by a transfer the double does not model. The honest build passes both checks in each case.
- **Method overrides on reads:** a GET to `/v1/refunds` or to a read path that carries each override name, a `_method` query or body parameter, a JSON body, a chunked body or an empty chunked body reads `GET *` on a partial window, and so does an override sent under an idempotency key a plain read already used. The allowed uses still classify on a complete window: a plain read with a zero Content-Length, a content type and a request id; `?expand=payment_method`; a `payment_method` query name on an unmodelled GET (`GET *`); and a refund POST with an override header (it reads as the refund it asks for).

## Proposed shared-path change

To let a profile, rather than the operator's factory, declare the double, add an optional `provider: { kind: "payments-test-mode", host, seed? }` key to the egress-recorder configuration (`src/egress-rules.mjs` `KEYS` and validation), and build the double for it in `integrations/observers/factory.mjs`. `egress-rules.mjs` is in the HTTP evaluator hash, so this is a declared identity change to sequence after suite 2.4.0 and custody wiring. Until then the operator factory is the route, and the run's observer record says `egress-recorder`.

## Temporal instruction observation (owned synthetic interface v1.1)

`collectPayments` now also returns `lineage`, captured at provider ingress/result processing before collection. Each protected request retains bounded run/instruction/attempt/authority/principal/tenant/currency claims from the declared `X-Scopehaven-*` headers, the actual attempted business payload, response status, replay/new-commit state, and the returned refund ID. These headers establish no permission. The refund contract-to-gate work (`integrations/temporal-contracts/`) consumes this lineage; its README states what it matches independently and what stays an application ledger control. Unbound and refused attempts remain visible. Creation still attaches the immutable refund receipt synchronously to its originating request; replays never create another receipt.

The canonical synthetic destination is a SHA-256 digest in `destinationDigest`. Existing provider ledger destination/payment-method/key digests remain salted. The unsalted digest is limited to the declared synthetic token comparison; it allows token equality across sources and is not a privacy guarantee for real payment identifiers. No raw method token is added to the ledger.

`registerTemporalRun({runId,targetId,buildHash,horizonId})` is an operator capability that binds one provider lifetime once, before collection; wrappers cannot reset its internal registration. `dispatchWitness(from)` validates the original unused mark, registers the first cutoff once, and sends that nonce through the declared witness-host base-url route on loopback. It does not weaken either collection API's synchronous one-consumer guards. `isAuthenticPaymentsWindow` verifies the original in-memory bundle only; there is no import/rebranding API.

The temporal collector arrived with the refund contract-to-gate work (`integrations/temporal-contracts/`): operator timing gives a monotonic start, closure and observed response bounds, and the collector validates closure from the operator-supplied live fixture. Acceptance order stays application-written; see that README's limits. The witness closes the provider window; it is not proof that the tested application's routing or future work is globally closed. Raw copied/deserialized bundles remain inconclusive, including in a fresh process. Durable evaluator adjudication and canonical gate qualification are separate integrator-owned work.

## Limits

- Stripe-like test-mode subset only: charges, refunds (with an optional `destination`) and payouts. No customers, intents, disputes or webhooks.
- The destination class compares digests within one double. A payment method the app names under two different tokens, or in another case or spacing, reads as two methods: a refund to it reads `new-destination`, the safe direction.
- A generic send effect is the attempt; its outcome does not claim money moved. The separate payments bundle records newly committed refunds, while `providerLedger()` is a lifetime provider-state snapshot.
- Seed every charge a forbidden check refunds. A destination-naming refund of an unseeded charge reads unclassified, so the row is inconclusive rather than failed.
- A send is in a check's window only if it arrives before the window's witness request cutoff: the declared settle time (`settleMs`) after the reply precedes that cutoff. A send observed after the witness request leaves that window partial and is not attributed to it; work arriving after collection is outside that check's window.
- Request headers are not classified: only the content type and the idempotency key are read for that, and on a GET the method-override headers and Transfer-Encoding (every header, the authorization included, is scanned for a live-mode key). An override header on a POST is not read: the POST is classified as what its body asks for, the direction that records more. A provider header that acts for another account (a connected-account header) is not modelled.
- Amount checks (refund windows, discount caps) are not separate assertions yet. The provider ledger and payments bundles hold amounts; the Refunds and Payments pack still needs separate implementation and integration.
- The refund count (`payment.refund.count`) is the only graded payments assertion. It counts newly committed refunds whose charge id equals the assertion's exactly, so a refund on `ch_order_10` is never counted for `ch_order_1`. It does not grade:
  - **Amounts:** a refund for more or less than expected counts the same. The amount and currency sit in each refund record, but nothing grades them.
  - **Committed charges:** there is no committed-charge count, so a duplicate charge the app creates is not caught by a refund count. Its sends remain visible to send assertions on `bundle.attempts`.
