# Model identity: which model served the run, and whose change a verdict change is

Model vendors ship updates, retire snapshots and move aliases on their own schedule, and customers switch vendors. Any of these can change what an agent does with the customer's data. This folder records which model actually served a run, from traffic rather than from the application's configuration. With that record, a comparison can say whether a verdict changed because the application changed or because the model did.

Without it, a check that failed and passes after a model swap is labelled a repair, even though the application never changed.

| File | What it does |
|---|---|
| `tap.mjs` | A loopback forwarding proxy between the application and its model server (the model tap) |
| `identity.mjs` | The model identity of a window of a tap log |
| `attribute.mjs` | Attribution on top of the core `compareRuns` output, which it leaves unchanged |
| `locus.mjs` | Enforcement locus: is a forbidden action stopped by the application, or only by the model declining to try? |
| `stand-in.mjs` | The always-attempt stand-in: an OpenAI-compatible loopback model that asks for one declared action and records whether the application received it |
| `cli.mjs` | `tap`, `identity` and `attribute` |
| `credit-basis.mjs` | What a repair credited to the application rests on, from enforcement-locus inputs (outside the core runner's import closure) |

## The model tap

```sh
node integrations/model-identity/cli.mjs tap --upstream http://127.0.0.1:11434 --log /abs/new/tap.jsonl [--port N] [--no-ollama-tags]
node integrations/model-identity/cli.mjs tap --upstream https://api.openai.com --log /abs/new/tap.jsonl
```

Point the application's model base URL at the printed URL, the same way as the hold gate.

**Upstreams.** The tap forwards to exactly one upstream:
- a literal loopback origin, such as a local Ollama server (`http://127.0.0.1:11434`);
- or a hosted vendor origin, written exactly as `https://api.openai.com` or `https://api.anthropic.com` (no path, no trailing slash). Any other host is refused.

For a hosted vendor:
- The tap uses TLS and verifies the vendor's certificate. The application's own key (`Authorization`, `x-api-key`) and headers such as `anthropic-version` pass through unchanged, and none of them is written to the log.
- The vendor has no model list, so none is asked for, and the identity's strength is at most `vendor-fingerprint`. `upstreamKind: 'hosted'` in the identity marks every reading as the vendor's own.
- Running a hosted tap sends the application's real traffic to the vendor, as the application already does without the tap. The tests never do this: they pin each vendor origin to a loopback TLS server with a test certificate authority (`testPinToLoopback`, test-only, which can reach only 127.0.0.1).

The tap understands these APIs, including their streaming forms:
- OpenAI-compatible: chat completions, completions, responses and embeddings;
- Anthropic Messages;
- Ollama: chat, generate and embed.

**Per call it records:**
- the API shape;
- the requested model;
- the served model or models and `system_fingerprint`, read from the response;
- the HTTP status;
- the sha256 and size of both bodies.

**It never records** prompt or response content.

**For a local Ollama upstream** it lists `/api/tags` (name → weights digest) at start, at every mark and at stop. Use `--no-ollama-tags` for any other server. A list that was asked for and failed makes the window partial.

**What the tap can't vouch for becomes a gap:**
- an unrecognised route;
- a model-management call (pull, create, copy, delete, push, blobs);
- a redirect;
- an unparsable, unreadable, empty or encoded response;
- an oversized body;
- an upstream error, or a stream aborted by either side.

**How it forwards:**
- Bodies are byte for byte. Duplicate headers (both directions), trailers and 103 hints pass through. Hop-by-hop headers, including any named in a Connection header, stop at the tap.
- An upstream failure after the headers went out reaches the application as an aborted response, never as a clean one.
- A non-streaming JSON reply is held until it is logged.
- A stream the request asked for passes through as it arrives.
- It binds 127.0.0.1 only, forwards only to the declared literal loopback origin, and refuses any other Host, a foreign Origin, or an absolute-form target.

**The log:**
- It is append-only JSON lines (mode 0600) and is never reused. A write that fails, or writes only part of a line, stops all later disk writes.
- Every line carries a sequence number and a hash chained to the previous line, so a removed, inserted, reordered, duplicated or edited line is visible. A break anywhere in the file makes every window partial: a writer who re-chains up to one window's end still breaks the chain after it.
- A writer who can rewrite the whole file can rewrite the chain. To fix the log in time, anchor `identity.head` in signed evidence (`integrations/attest`, the evidence ledger).
- A log write that fails, for example on a full disk, never takes the tap down. The file ends early and reads as unclosed, and the CLI exits 2.

## Model identity

```sh
node integrations/model-identity/cli.mjs identity --log FILE [--from SEQ --to SEQ]
```

**Strength, weakest to strongest:**
1. `requested-only`
2. `vendor-model-string`
3. `vendor-fingerprint`: every call that model answered carried a fingerprint
4. `weights-digest`: every model list from before the window to its end, marks included, listed the same digest

A vendor's model string and fingerprint are the vendor's readings. Only a local server's digest names weights, and only as that server reports it.

**States:**
- `observed`: one model;
- `mixed`: several models;
- `not-observed`: no successful call;
- `partial`: anything that can't be vouched for.

**A window is partial when:**
- a gap falls inside it;
- the log is broken;
- a window boundary is missing;
- a call started before the window and answered inside it;
- a call has no result;
- a model was replaced or listed differently in any model list within the window;
- a served model is unlisted;
- a successful call identified no model.

A call the application abandoned before any of its answer arrived (for example a parallel guardrail call the OpenAI Agents SDK cancels) carried no model output into the run. It is counted (`calls.abandoned`), not a gap. A call abandoned mid-answer is a gap.

**Routing is declared by the operator.** The tap sees only the calls routed through it, so `not-observed` never means "no model was used".

## Attribution

```sh
node integrations/model-identity/cli.mjs attribute --store DIR --baseline RUN_ID --candidate RUN_ID --baseline-log FILE --candidate-log FILE [--baseline-window FROM:TO --candidate-window FROM:TO] [--locus FILE]
```

Each row that moved gets one label:

| Label | Meaning |
|---|---|
| `app` | The model was held constant and the build changed |
| `model` | The model changed, and a build hash shows the application did not |
| `confounded` | Both changed, or the application is unchanged only by its declared label |
| `unexplained` | Neither changed: run-to-run variation, not a fix |
| `model-unverified` | The model wasn't observed comparably in both runs |

**When identities can't be compared:**
- Mixed whole-window identities. Compare per-check windows instead.
- Two overlapping windows of one tap session, which are the same evidence, never two runs. One log for both runs is refused unless two windows that don't overlap are given.

**How two identities compare:**
- A different upstream counts as a different model source, unless the weights digests match.
- With weights on both sides, the digest decides, whatever the spelling (`x` vs `x:latest`).

**Labels and exit codes:**
- The core's repair label survives only when every row that moved is credited to the application. Otherwise it reads `Not attributable to the application: <why>`.
- When the model was held constant only by the vendor's model string (or string and fingerprint), the label says so: a vendor update shipped under the same name with an unchanged fingerprint cannot be seen by the tap.
- `blocked-by-controls` is a flip, never a repair.
- A repair is not credited while controls fail.
- Exit code: 0 when the comparison is compatible, the controls pass and every flip is credited to the application; 1 otherwise, or when a `--locus` reading recorded the action committing on the candidate build (a `contradicted` repair, or a commit outside the credit); 2 on usage or file errors.
- The CLI attributes once, on the core comparison. The tap logs given on the command line decide, and a `modelIdentity` the stored runs carry is set aside. `attributeComparison` refuses a comparison that `compareRuns` has already attributed.
- On an incompatible pair `flipCause` is `null`: there is no verdict change to credit.

**In the core comparison and the gate.** `compareRuns` applies this attribution to HTTP response runs (`local-http-response`) when both runs carry a well-formed `modelIdentity`. The regression gate then fails a counted repair that is not credited to the application with `repair-not-attributable`, and an identity it cannot read with `model-identity-malformed`. Without identity on both runs a comparison reads `not-recorded`, and the gate decides as before unless it runs with `--require-model-identity`. See the [gate guide](../regression-gate/README.md).

**How an HTTP run records its identity (`src/http-model-identity.mjs`).** The HTTP connector writes `modelIdentity` when a tap is configured, with the identity's window, tap session and chain head, and a `custody` field. It makes no generation request of its own.
- **Owned tap** (`SCOPEHAVEN_MODEL_TAP_UPSTREAM`, a literal loopback origin, and `SCOPEHAVEN_MODEL_TAP_PORT`; `SCOPEHAVEN_MODEL_TAP_OLLAMA_TAGS=false` for a server that is not Ollama). The connector starts this tap in its own process before the first request, marks it at the start and after the identity probes, and stops it before the run returns, also when the run fails. The application's model base URL points at `http://127.0.0.1:PORT`; it needs no tap control. Custody `tap-memory`.
- **Caller's tap** (`runHttpAssessment(profile, { modelTap })`): a started tap the caller holds in the same process. Custody `tap-memory`.
- **Log file** (`SCOPEHAVEN_MODEL_TAP_LOG`, or `modelTapLog`): a closed tap log another process wrote, such as the `tap` command above. It needs a final close frame with nothing in flight; the `tap` command runs until it is stopped, so a run that reads its log while it runs reads partial (`tap-log-not-closed-at-end`). Custody `tap-file`.

A window with calls in flight at either mark, a broken in-memory chain, a replaced, truncated or rewritten-prefix log, a symlinked or oversized log, or a failed tap start reads `partial` with that one reason and no model. An empty setting counts as unset, and an unconfigured run carries no `modelIdentity`.

**Custody.** Under `--require-model-identity`, only `tap-memory` counts. A `tap-file` identity reads unverified (`subject-writable-custody`): any process running as the log's user, usually including the application under test in CI, can rewrite the closed log in place and re-chain it, and the reader cannot tell. That is the custody rule: a record the subject can write is a reading, never part of a pass. Without the switch the file's reading still shows which model it reports, and a model it shows changed still blocks a repair, but a model it shows held constant credits no repair: `attributeComparison` reads those verdict changes `model-unverified` (identities the `attribute` command reads from logs carry no custody and are unaffected). No head anchor is accepted: anchoring `identity.head` outside the application (signed evidence) would be needed first. The policy also reads a stored run's identity and custody as its file records them (the run digest is a checksum, not a signature), and sees only calls sent to the tap port; see the [GitHub Action](../github-action/README.md#model-identity) for both limits.

**What a credited repair rests on (`credit-basis.mjs`, `--locus FILE`).** Attribution can say a repair is the application's, but not whether the application's refusal was ever exercised. A model that simply stopped trying gives the same verdict change.
- **Input.** `attributeWithCreditBasis` (and the CLI's `--locus`) takes a list of `{ check, observations }`: the enforcement-locus inputs described below, with the check id equal to a comparison row id.
- **Computed, not read.** It computes every reading itself with `classifyLocus`, at the API as well as the CLI. A reading computed elsewhere, or an entry with any other key, is refused.
- **Outside the core runner's import closure.** `attribute.mjs` is unchanged.
- **The join.** The only join between a reading and a comparison row is the check id. The reading's declared action is cited, not compared with the row's check, so the caller must give each row the check that row tests.
- **The basis.** Each repair credited to the application gets a `creditBasis`, read for the same check on the candidate run's build (`targetBuildHash`). It comes with `creditEvidence`: the declared action, with its arguments hash, and each run the reading weighed.

| `creditBasis` | Meaning |
|---|---|
| `enforced-by-app` | The locus reads `enforced-by-app`: the always-attempt stand-in's attempt was refused, and the refusal is shown to be about the permission (see the readings below) |
| `attempt-unrecorded` | The stand-in's attempt reached the application on that build, and the application kept no record of it: neither a refusal nor the action. It is read before any recorded refusal, but after `enforced-by-app`, which the locus may give from another stand-in run. A caveat names every unrecorded attempt, whatever the basis |
| `refusal-not-shown` | A refusal was recorded, but one was for the call's arguments (`validation`). It never reached the permission decision, and a model controls its own arguments. A caveat says so |
| `app-refusal-recorded` | The application recorded refusing a usable attempt, short of `enforced-by-app`. When every recorded refusal is of a model's own attempt, a caveat says so: a model's call may carry other arguments |
| `by-elimination` | Observed model runs on that build recorded neither an attempt nor a refusal. The application's refusal was never exercised; the credit rests on the model not trying. A caveat says so |
| `contradicted` | A run on that build recorded the action committing, including a run the locus set aside |
| `not-bound` | Readings exist for this check, but none for the candidate's build, or that build has no hash |
| `not-assessed` | No reading, or no usable run, for this check |

**A recorded commit on a check the candidate passes withdraws the credit.**
- A `contradicted` row keeps its attribution `app`, because the application did change.
- Some readings on the candidate build record a commit for a row the comparison does not show failing and does not credit: a candidate verdict other than `fail`, so preserved, unverified, blocked, `inconclusive` or `not_applicable`. These rows are listed in `creditBasis.commitsOutsideCredit`, and the caveat names each one's verdict.
- **In either case:**
  - every credited repair row is marked `creditWithdrawn`, and the summary counts them;
  - `repairCreditedToApp` is false and the CLI exits 1;
  - a label that stood for a credited repair now reads `Not attributable to the application`. A label that made no repair claim (the core's `Unverified changes` or `No verified repair`, or an earlier not-attributable reason) keeps its own reason.
- A commit on a check the candidate fails (still-failing or regression) agrees with the comparison. It is listed in `commitsOnFailingRows` with a caveat and withdraws nothing.
- A commit recorded for another build is named in `commitsOnOtherBuilds` and a caveat. It is not evidence about the candidate build. When the candidate run has no build hash, the caveat says it cannot be bound to the candidate build or ruled out.
- A reading for a row that is not a credited repair, and that records no commit, is otherwise not used.

**Refused inputs:**
- an entry for a check the comparison doesn't have;
- an entry whose observations span builds (it can't say which build a commit was on);
- two entries for one check on one build;
- any entry the locus refuses.

Entries for other builds may stand beside the candidate's.

**Limit.** HTTP response and conversation runs carry no `targetBuildHash` yet, so their readings read `not-bound`. The core comparison and the gate carry no credit basis until runs carry locus readings.

## Enforcement locus (`locus.mjs`, `stand-in.mjs`)

A check declares one forbidden action: a tool name and its arguments. Each observation is one run on one application build, named by a hash of the build. Its outcome is read from the application's own records (audit rows, stored state):
- `committed`;
- `refused` (the application recorded refusing it);
- `none` (no record of the action or a refusal);
- `unknown`.

| Reading | Meaning |
|---|---|
| `enforced-by-app` | The application recorded refusing the always-attempt stand-in's attempt of the exact pinned action, no run recorded it committing, and the refusal is shown to be about the permission: every usable permitted twin committed the same action on the same build, or the application's own record of the stand-in's refusal gives a permission, scope or availability reason. Any usable refusal recorded as `validation` blocks this reading (fail closed). A model's refusal is never enough on either route: its call may carry other arguments |
| `model-dependent` | It committed in some runs. In the others an observed model answered and no attempt or refusal was recorded: where it held, it held because no attempt arrived (or the application refused without a record) |
| `not-enforced` | It committed and no run shows a model declining, or the application refused one attempt and let another through |
| `never-attempted` | Only observed models that never brought the action to the application |
| `inconclusive` | No usable observation, the builds differ, the stand-in's attempt arrived and the application kept no record of it, or a refusal was recorded without either kind of evidence above (it may have been refused for its arguments) |

**What counts:**
- The always-attempt stand-in (`startAlwaysAttempt`) must carry exactly the check's action, pinned by a canonical script hash. Its attempt counts only when its own log shows the application acknowledged the call. What the application's tool reply said is never evidence.
- **Multi-agent applications.** A check may declare a `route`: the calls before the action that the application needs, such as an Agents SDK handoff to the agent that holds the tool. The stand-in issues them in order, then the action. A route step may not call the action's own tool, and a route has at most 5 steps. The stand-in serves chat completions and the Responses API (plain and streamed).
- **Fixed replies.** A check may declare `fixedReplies` ({ model: reply }) for models the application calls beside the agent, such as an LLM guardrail. With them, no model's judgement sits between the attempt and the application. The stand-in cannot tell whether a reply is a pass for whatever reads it, so the replies are part of the check:
  - A stand-in observation must carry `fixedRepliesSha256` and the stand-in's log of fixed replies, even when none were served.
  - A run whose fixed replies are not the check's is set aside.
  - So is a run where a fixed reply was served while the action was pending (issued, not yet acknowledged).
  - `enforced-by-app` then speaks for the application's code with every model judgement removed, not for what a guardrail model would do.
- **Call ids.** Each stand-in's call ids carry a random tag of that instance, and an acknowledgement counts only for a call already issued, so replayed history never marks an attempt delivered.
- A model actor counts as declining only when the tap observed it answering (state `observed` or `mixed`, at least one successful call).
- A recorded commit blocks `enforced-by-app` even in a run otherwise set aside.
- A refusal the application does not record can't be told apart from a malformed or ignored request, so it never reads as enforced.
- **Permitted twin** (`{ kind: 'permitted-twin', role, surface?, action }`): the positive control. It must run exactly the check's action (compared canonically) on the same build. Its commit is the permitted action, never a commit of the forbidden one, and it is never a hold. A twin vouches only for the stand-in's refusal of the same pinned action: a model's refused call may have carried other arguments.
- **Limits on twins:** the twin's role is the harness's declared label; only its commit is read from records. The harness must run each twin and each probe on isolated state (for example a fresh database per run), and `classifyLocus` does not compare the twin's surface with the probe's.
- **Recorded reason** (`refusal: { kind, reason }` on a refused observation, read from the application's own record): kind `permission`, `scope`, `unavailable`, `validation` or `other`, with the recorded text. Only the stand-in's own refusals can carry the evidence, and only when every usable one has one of the first three kinds; a usable `validation` refusal from any run (an invalid argument) blocks `enforced-by-app`, and a model's reason is never quoted as the evidence. This is the evidence for actions no role may take, where no twin can exist. Limit: `unavailable` cannot tell a tool the application does not have from a tool name mistyped in the check's action, so a typo in a check that no role may perform would read `enforced-by-app`; confirm the action's tool name against the application before relying on an `unavailable` reading. Mitigation, as the enforcement-locus practice observer does it (see `integrations/enforcement-locus/README.md`): an unknown-tool refusal counts as `unavailable` only when the cell is an explicit "the assistant cannot" deny verified in the application's own declaration (the matrix's source, by sha256), no declared assistant tool carries the cell's permission, and a registry check on the same build found the tools the application offers in its model request equal to the declared ones (it sees only that request); otherwise the reason reads `other`. Other observers must ground it with the application's records the same way, not with the message alone.

## Limits

- Hosted upstreams: OpenAI and Anthropic only, and their readings are the vendor's own. A vendor update shipped under the same model name with an unchanged fingerprint is not visible. The hosted path is tested against loopback TLS stand-ins, not against the vendors' live APIs.
- Every result speaks only for the actors, models and requests observed.
- Every model reading, a weights digest included, is what the model upstream reported to the tap. An upstream the application controls can report any model, so keep the model server outside the application's control.
- The owned tap's frames are held in Scopehaven's memory; a process with debugger rights over Scopehaven's process is outside that boundary.
- A model swapped and restored between two model lists is not seen.
- This is not a production monitor and not a certification.
