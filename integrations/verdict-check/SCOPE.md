# Verdict re-derivation: scope (written before the verifier)

Question: when a buyer or auditor receives a signed evidence pack, which PASS/FAIL verdicts can they re-derive on their own machine from the exported evidence alone, without running Scopehaven's code? Which can't they, and why?

## Is the gap already closed?

No. Verdicts are recomputed today only inside Scopehaven's own code, and every one of those validators imports `src/`:

- `src/conversation-native.mjs:50` `validateConversationRun` (re-exported by `integrations/conversations/validation.mjs`)
- `integrations/sequences/run-validator.mjs:92` `validateSequenceRun`, and `integrations/sequences/native.mjs` for the saved form
- `integrations/regression-gate/` rechecks synthetic effects with the core `evaluateCheck` (`src/evaluator-synthetic.mjs:397`)
- `src/contracts.mjs:1559` `validateHttpRunEvidence` for HTTP contract runs

The signed pack (`integrations/attest/`) carries an independent verifier, `verify_envelope.py`, but it checks who signed and which bytes (`integrations/attest/README.md:5-7`). It recomputes run identities and the keyless integrity hash, which "catches careless edits only: someone who edits a result and recomputes the hash can still sign it" (`README.md:23`). SARIF, HTML and sequence files are covered by their digests only (`README.md:55`). A search of `src/`, `integrations/` and the YC research folder found no independent verdict checker.

## What a pack contains

`src/export-cli.mjs:60` writes a run as `JSON.stringify(run)`, where the run is the store's run core plus `integrity` (`{ algorithm, sha256, scope }`) and `notes` (`src/store.mjs:107`). Sequence runs also travel as the run file the sequence CLI writes. Which verdicts can be re-derived depends on the evidence origin.

## 1. Synthetic fixture runs (`synthetic-local-http`)

Each row keeps `attempts`: the request id, the actor, the operation, the fixture manifest, the request-correlated backend evidence (ledgers before and after, events, the reply and its structured output) and any transport error (`src/runner.mjs:130`).

**Re-derivable:** every row status and every assertion status. `evaluateCheck(def, attempts)` is a pure function of the check definition and the kept attempts (`src/evaluator-synthetic.mjs:397-680`). The counts, the required controls and the policy and fixture hashes (from the declared policy and fixture data) are re-derivable too. The check definition (its `kind`) is not in the export. It comes from the pinned suite, and the run's `suiteHash` names that suite.

**Not re-derivable:**
- A harness-error downgrade. When the harness throws, `src/runner.mjs:124` turns a non-fail verdict into `inconclusive` (or `error` with no attempts). The thrown error is not kept, only its text in `summary`. A stored `inconclusive`/`error` row whose attempts grade `pass` is therefore listed as not re-derived, never accepted. A `fail` is never downgraded (same line), so a stored `fail` must always re-derive.
- Rows from suites other than 2.3.0 (`support-fixture/5`). The verifier pins only the current suite, policy and fixture data. Older runs are listed, not judged.
- Whether the attempts are true. The owned fixture writes its own evidence. A pass shows the verdicts follow from that evidence.

Reply-truth and promise checks read the fixture's fixed reply text through a declared table of patterns (`src/evaluator-synthetic.mjs:47-59`, `:125-182`, `:319-367`). An independent port re-derives them. Parity is tested on both demo builds, but not proven for arbitrary text.

## 2. HTTP contract runs (`local-http-response`)

Each row keeps a minimized response observation. For v3 rows it also keeps sealed effect windows.

Before 2026-10-29, each JSON predicate (`json.equals`, `json.exists`, `json.notContains`) kept only `{ kind, present, type, outcome }`, with no response body, pinned value or pointer. None of those outcomes could be recomputed from the export, and an outsider re-check rehearsal re-derived 0 of 80 rows. Since then each predicate keeps a record (predicate records in `src/contracts.mjs`), in the mode the run chose:

- `digest` (the default): the field's JSON pointer, `json.exists`'s expected true or false, and a SHA-256 of the configured value for `json.equals` and `json.notContains`, keyed with 32 random bytes the run never writes. `json.equals` also keeps one of the value the response held there, under the same key. Without the key, a guessable value cannot be tested against a digest.
- `value` (opt-in): the configured value and the response's value at the pointer, in clear.
- `outcome`: the earlier record, for runs made before predicate records or with `SCOPEHAVEN_PREDICATE_RECORD=outcome`.

ScopeHaven's own validator recomputes each record's outcome and assertion texts and refuses a record that disagrees (`src/contracts.mjs` validateHttpObservation).

**Re-derivable:** the status assertion, from the observed status and the accepted codes in its expected text (`src/contracts.mjs` evaluateHttpCheck). `json.exists`, from presence and the expected value. `json.equals`, from digest equality or the values. `json.notContains`, from a value-mode record. `json.noForeignValues`, from its recorded scan counts and the run's attributesAlone policy (`src/tenant-values.mjs` outcomeOf). The precondition and mirror-limit assertions, and the backend assertion of a row without windows, which the rules always write inconclusive. Then the roll-up (`src/contracts.mjs` validateHttpObservation), and under actor-identity/5 and later the row's decision. A row is re-derived when its known assertions fix its status: when one fails (beyond a mirror's limit), or when every assertion is known.

**Not re-derivable:**
- JSON predicates in outcome-only records (`predicate-not-carried`), and a digest-mode `json.notContains` over a present string (`predicate-value-not-carried`), because no digest shows containment.
- Effect, claim and read-back clauses, and the backend assertion beside them (`effect-clauses-not-carried`). They are decided from sealed windows through settlement, attribution, pairing, timing and later outcomes (`src/contracts.mjs` validateHttpRunEvidence and the modules it imports). That is several thousand lines, and porting it is out of scope here.
- Which rows carry the identity assertion, beyond the cases `rowIdentityReason` (`src/contracts.mjs`) decides from recorded fields. Those cases are recomputed:
  - an actor without a credential (control-not-passed);
  - a credentialed actor whose login the run established, from its refusal statuses, `refusesWith401` and surface controls (sign-in-redirect, unauthenticated-401, surface-unproven);
  - an actor with no identity control and no probe point (no-identity-control).

  For any other credentialed actor, and for mirror and lifecycle rows, the probe brackets, points and lifecycle rules are not carried. A carried assertion is read as recorded and listed as a stored input. It always reads inconclusive, so it can hold a row below pass but never hides a failure. A row without one, which the assertion could have held below pass, is listed (`identity-rules-not-carried`). Mirror-limit assertions are recomputed from the row's `mirrorOf` and the run's mirror-phase rate-limit statuses.
- Whether the observations are true. A digest shows two values are equal, not what they are. A forger who rewrites the observed digest to the expected one and reseals everything above it produces a consistent record.

The verifier also checks the integrity hash, each row's evidence digest, that no two rows record one request, that the counts tally the stored statuses, and that every required control has a row.

## 3. Conversation runs (`local-conversation`)

The run keeps `conversationEvidence`: the actor identity results, the conversation shape (actors, trials, policy, modes, expectation kinds, after-checks, victim observers) and every trial record (`integrations/conversations/validation.mjs:46-67`).

**Re-derivable:** each turn outcome (from its transport, `replyAvailable` and its expectation outcomes), each after-check outcome (from its assertion statuses), each victim outcome (from the observed state and its evidence kind), each trial outcome and judged count, each conversation status under its declared policy (confirmed, or a maximum failure rate), the counts, the failure rate, the scope note, the evidence digests and the run counts (`src/conversation-native.mjs:33-125`).

**Not re-derivable:** each reply-expectation outcome and each after-check assertion status. These are stored outcomes, because no reply text or response body is kept (`src/conversation-native.mjs:30-32`; the transcript record keeps `replyBytes` only, `integrations/conversations/conversation.mjs:387`). Each victim state (`changed`, `unchanged`, `unavailable`) is a stored reading too: the snapshots it compared are not kept (`integrations/conversations/conversation.mjs:459-462`). So are the actor identity results (`entry.reason`). The verifier re-derives every verdict above these inputs and lists them per conversation, with counts.

Found while building this: the rules derive `pass` for a conversation that recorded no trial (zero trials under a `confirmed` policy), in `src/conversation-native.mjs` as well as here. The runner never writes such a run, but a forged one would read as a pass. Since 2026-10-19 the shared validator refuses it (`no-trial-recorded`), with three siblings of the same reach: more than 50 trials (`trials-out-of-range`), a rate policy outside 0 to under 1 (`max-failure-rate-out-of-range`; at 1 or more a conversation whose every trial failed derives pass) and a run with no conversation (`no-conversation-recorded`) (`src/conversation-native.mjs:57-59`, `:73-77`, `:111`). The verifier mirrors all four and refuses such a pack under the same code.

## 4. Sequence runs (`scopehaven-sequence-run/3` and `/2`, and the saved `local-sequence` form)

The run seals the declared observers, every effect window (events, coverage, reason, scope), the assertions, the status assertions, the requests with actors, the responses, `aborted` and `runDigest` (`integrations/sequences/run-validator.mjs:92-176`). The saved form wraps one sealed run (`integrations/sequences/native.mjs:79-91`).

**Re-derivable:** every effect row's verdict and status from its windows, including corroboration, the early-stop rule and the custody hold: a boundary pass decided only by records the application can write reads `inconclusive` (`integrations/sequences/sequence.mjs:149-168`, `src/effect-events.mjs:546-658`, `src/custody.mjs:252-262`). Also re-derivable: every response-status row from the sealed requests and responses, including same-actor acceptance (`sequence.mjs:116-142`), the counts and the run digest. In the saved form, each row's status, verdict, custody and corroboration fields, response fields, the counts and the required controls are rebuilt from the sealed run.

**Not re-derivable:**
- `scopehaven-sequence/1` records, which keep window digests only (`run-validator.mjs:94`). Listed, never trusted.
- Whether an observer's scope names and evidence kind are what it was configured with. That configuration is not sealed (`run-validator.mjs:28-36`).
- Whether the windows are true.

## 5. Refusing wherever Scopehaven refuses (found in review)

Review found ways a pack could read as consistent here while Scopehaven refuses it. The verifier now mirrors each, except for the explanatory text named in the last item:
- Numbers. `JSON.parse` reads every number as a double, so `9007199254740993` and `9007199254740992` are one value to Scopehaven. Kept exact, two actor aliases or two instance ids that are one value to main were two here: a run main refuses passed, and a stored fail re-derived as inconclusive. The verifier now reads numbers as `JSON.parse` does.
- Run shape. The regression gate's `validateRun` (`integrations/regression-gate/gate.mjs:50`) refuses a run with no required control (`:124`), a malformed run hash such as `evaluatorHash` (`:54`), no `checksTotal` and other shape faults, whatever the origin's own validator accepts. The verifier applies the same rules to every run export (`invalid-run-evidence`).
- Whole sequence rows. `validateSequenceRun` compares each sealed row whole (`run-validator.mjs:173`, `sequence-verdict`) and refuses a run saved before custody (`:168`, `sequence-pre-custody`). `validateSequenceNativeRun` rebuilds the whole saved run (`integrations/sequences/native.mjs:136`) and refuses effect controls that cannot prove their use (`:130`). The verifier mirrors each, but it writes no explanatory text, so it does not compare five fields Scopehaven compares: a sealed sequence row's `basis` and `custodyUpgrade`, and a saved run's scope label, limitations and trace labels. Scopehaven refuses a run with any of the five edited, and the verifier reads it as consistent. In each case the verifier's verdicts still match Scopehaven's: it reports the run consistent where Scopehaven refuses it, and it never passes a verdict Scopehaven fails.

## What the verifier will do

A new folder only, `integrations/verdict-check/`, with no imports from `src/` or the other integrations: Python 3.8+ standard library, like `verify_envelope.py`.

1. Run `verify_envelope.py` as a separate process, require `verified`, and bind each run file it reads to a verified subject digest. Alternatively, with `--unsigned`, say that no signature was checked.
2. Re-derive every verdict listed as re-derivable above from the kept observations, under rules pinned by the run's declared identity (suite, policy and fixture hashes, or the schema versions). Refuse the pack when any stored label disagrees.
3. List each verdict it did not re-derive, by name and with its reason. A pack with any listed verdict never reads as fully re-derived.
4. After a pass, run negative controls through the same code: a flipped verdict, a resealed forged verdict, a dropped required control and an added row. Any accepted tamper gives `self-check-failed`.

A pass shows that the verdicts follow from the recorded observations under the pinned rules. It does not show that the observations are true or that the application is safe.
