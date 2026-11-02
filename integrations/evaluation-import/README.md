# Offline external evaluation import

This dependency-free Node module previews a local Promptfoo JSON export as a separate, minimized external evidence record. The importer does not run Promptfoo, providers, assertions, scripts, models, HTTP requests, assessments or repairs. It does not persist anything. The integration owner owns API, UI and storage wiring. The authenticated core endpoint, actual mounted dashboard preview, and lock/clear behavior have passed isolated synthetic acceptance; evidence is in `verification/ui-acceptance.json`.

## Versioned input contract and source grounding

The caller must select **`promptfoo-output/0.123.1-summary-v3`**. This maps the `OutputFile` envelope containing `EvaluateSummaryV3` from Promptfoo release **0.123.1**, pinned to official commit **`34f74d34e140b5e17d23770dfb2340057b1936b8`**. The source package identifies that version. This is not a claim that the submitted file was produced by that release or even by Promptfoo: the JSON does not authenticate its producer. Both producer identity and actual package version remain `unverified` in every record.

Primary sources, pinned rather than floating:

- [Package version](https://github.com/promptfoo/promptfoo/blob/34f74d34e140b5e17d23770dfb2340057b1936b8/package.json).
- [OutputFile, EvaluateSummaryV3, EvaluateResult, ResultFailureReason and GradingResult types](https://github.com/promptfoo/promptfoo/blob/34f74d34e140b5e17d23770dfb2340057b1936b8/src/types/index.ts): source lines 376–428, 485–501, 529–586 and 1521–1532.
- [JSON export envelope documentation](https://github.com/promptfoo/promptfoo/blob/34f74d34e140b5e17d23770dfb2340057b1936b8/site/docs/integrations/ci-cd.md): `OutputFile` for `eval -o results.json` and `export eval`.
- [Evaluator implementation](https://github.com/promptfoo/promptfoo/blob/34f74d34e140b5e17d23770dfb2340057b1936b8/src/evaluator.ts): `applyGradingResult` and `applyGradingError`, source lines 608–657. A failed assertion also sets `error`; error text alone cannot distinguish assertion failure from an execution error.
- [Configuration reference](https://github.com/promptfoo/promptfoo/blob/34f74d34e140b5e17d23770dfb2340057b1936b8/site/docs/configuration/reference.md) corroborates the version-3 summary types.
- [Output documentation](https://github.com/promptfoo/promptfoo/blob/34f74d34e140b5e17d23770dfb2340057b1936b8/site/docs/configuration/outputs.md) notes that `gradingResult` can be absent, but its simplified JSON example has a conflicting nesting shape. That example is not an accepted alternative format.

`format-sources.json` records SHA-256 and byte length of each exact public source fetched at the pinned commit. No vendor source is installed or executed. The fixture is hand-authored synthetic JSON; vendor execution and real-export compatibility remain unverified. The mapping is source-backed, not an end-to-end Promptfoo certification.

## Accepted shape

The root requires `evalId` (string or null), `results` (object), `config` (object), and `shareableUrl` (string or null). Only the documented optional root keys `metadata`, `vars`, `runtimeOptions`, `traces` and `blobAssets` are also accepted. All are discarded.

`results` requires numeric `version: 3`, a nonempty string `timestamp`, `prompts` (array of objects), `stats` (nonnegative integer successes/failures/errors and a tokenUsage object), and `results` (array of rows). Statistics, prompts and timestamps are discarded.

Every row requires the immediate fields of the pinned `EvaluateResult` interface: boolean `success`, numeric `failureReason` in 0/1/2, finite `score`, nonnegative integer `promptIdx`/`testIdx`, string `promptId`, object `testCase`/`provider`/`prompt`/`vars`/`namedScores`, and nonnegative finite `latencyMs`. Named scores must be numeric. If present, `response` is an object and `error` is a string or null. `gradingResult` may be absent/null; otherwise its pass/score/reason must be boolean/finite number/string. Component results follow the same grading shape. Metadata is an object and a present `graderError` must be the documented literal `true`.

This is a bounded projection validator. It checks required immediate shape and every verdict field it uses. It does not validate the full nested provider/config/prompt/tokenUsage schemas, assess actual assertions, or establish prompt-index referential integrity. Other bounded JSON content inside the accepted envelope is opaque and discarded. This prevents configuration from becoming executable input. Unknown top-level fields, versions, failure enums, missing required fields and malformed typed verdicts are rejected, with no partial import.

## Verdict mapping

Each input evaluation row produces one generated check, not one check per component assertion. Attribution is always `promptfoo`. No source-provided label, ID, assertion text, reason or provider name is retained.

| Reported fields | State | Fixed basis |
| --- | --- | --- |
| `success:false`, `failureReason:2` | `error` | `reported-execution-error` |
| `success:false`, documented `graderError:true` on any grading component | `error` | `reported-grader-error` |
| `success:true` together with any grader error | `unknown` | `inconsistent-reported-verdict` |
| `success:false`, `failureReason:1`, grading pass is false or absent | `fail` | `reported-assertion-failure` |
| `success:true`, `failureReason:0`, grading pass true, no nonempty error | `pass` | `reported-assertion-pass` |
| `success:true`, `failureReason:0`, grading verdict absent/null, no nonempty error | `unknown` | `no-assertion-verdict` |
| Other well-typed contradictory combinations | `unknown` | `inconsistent-reported-verdict` |

The rules are ordered as shown. A score, a source aggregate count, a successful provider response or an empty error never independently establishes a pass. Empty imports yield zero counts, not a successful assessment. All states describe unverified imported assertions, not Scopehaven observations. Aggregate counts are computed from these rows and never copied from `stats`.

## API and local CLI

Pure server-side entry point (Node built-ins only):

```js
import { importPromptfooJson, INPUT_CONTRACT } from './integrations/evaluation-import/import.mjs';
const result = importPromptfooJson(utf8JsonText, INPUT_CONTRACT);
// { ok: true, record } or { ok: false, error: { code, message } }
```

The function accepts text only, is deterministic and returns a fresh record or fixed error. It does no I/O. `sourceDigest` is SHA-256 of the exact supplied text encoded as UTF-8, including whitespace. `importLocalFile(path, format)` in `cli.mjs` adds bounded local file reading and fatal UTF-8 decoding, preserving the digest of accepted original file bytes. Neither API throws source text in errors or exports raw input.

From the project root, use the same pinned runtime selected by `./scopehaven`:

```sh
.runtime/node-v24.22.2-darwin-arm64/bin/node integrations/evaluation-import/cli.mjs --format promptfoo-output/0.123.1-summary-v3 --input integrations/evaluation-import/fixtures/promptfoo-0.123.1-v3.synthetic.json
.runtime/node-v24.22.2-darwin-arm64/bin/node --test test/evaluation-import.test.mjs
```

The CLI writes the minimized record to stdout on success (exit 0), or a fixed JSON error to stderr (exit 2; empty stdout). Arguments are in the shown order. It has no `--output`, stdin, URL, upload or provider mode. It opens only the explicitly supplied local regular file, rejects final symlinks, uses nonblocking reads to avoid FIFO waits, checks the file before/after reading and caps the actual read even if the file grows. Do not expose this file-reading wrapper directly through an HTTP endpoint.

## Privacy and resource bounds

Limits are fixed and exported as frozen `LIMITS`: 16 MiB of UTF-8 input, depth 24 with root at depth 0, 200,000 JSON value nodes, 1,000 elements per array, 256 keys per object, 1 MiB (1,048,576 UTF-8 bytes) per string, 128 UTF-8 bytes per key, and 500 evaluation rows. All limits include discarded fields. They are sized from real Promptfoo exports: the saved practice-app runs (65 and 70 rows, about 1.4 MB and 11,000 to 12,000 nodes) and runs on a local install of a third-party application (28 rows, 3.5 MB, one `response.output` of 316 KB; recorded on a private build, not reproducible from this repository) were refused under the earlier 1 MiB input and 16 KiB string limits, and all now import. A larger otherwise-valid export is still rejected. The strict parser also rejects duplicate keys (including escape-equivalent keys), prototype-sensitive keys anywhere, non-finite numbers, trailing input, malformed strings and a leading BOM. Objects are built with null prototypes; source fields are never spread or merged into output.

The record uses an allowlist of adapter-authored strings and verdict enums, numeric counts, input byte length and digest. It discards prompts, outputs, configuration, credentials, traces, media, URLs, timestamps, tool/provider labels, evaluation IDs, customer content and error text. There is no opt-out from minimization. HTML is neither retained nor rendered. Discarding is not in-memory secure erasure: callers still own the supplied input and file. The digest is a content fingerprint, not encryption, authentication, a signature, or proof that an evaluation occurred. Keep raw files and digests local unless separately authorized.

## Integrated API contract

Core currently exposes `POST /api/external-evaluations/preview` with the existing bearer capability, `X-Scopehaven-Request: 1`, and `Content-Type: application/json`. The JSON request is `{ "format": "promptfoo-output/0.123.1-summary-v3", "content": "original JSON text" }`. The wrapper keeps the source as text: do not parse and reserialize the export before submitting it. The HTTP reader bounds the encoded request at twice the importer's input limit, 32 MiB since 2026-10-19 (it was 2 MiB), and uses fatal UTF-8 decoding; the importer separately bounds decoded source text at 16 MiB. Escape-heavy wrappers may reach the transport bound before the source bound. The larger body cap changes nothing else: the server still binds 127.0.0.1 only, and it refuses a wrong host, a foreign `Origin`, a cross-site fetch, a POST without `X-Scopehaven-Request: 1` and a request without the bearer capability before it reads any body. Previews run one at a time: while one is in flight, the next is answered at once with HTTP 429, `Retry-After: 1` and code `preview-in-progress`, before its body is read, so memory stays at one preview's peak. A preview whose client goes away frees the slot. At the caps, the worst parse measured on the development Mac took about 0.2 s and a peak of under 200 MB resident memory for the importer alone; through the server, with the request body held as well, a 32 MiB body peaked at about 285 MB (cases and numbers in the pull request that raised them).

Success is HTTP 200 with the same `{ok:true,record}` as the pure API. Import rejection is HTTP 400 (or 413 for `input_limit`, or 429 while another preview runs) with `{ok:false,error: "fixed message",code: "fixed code"}`. Authentication, content-type and transport rejection can return only `{error: "fixed message"}` with their HTTP status. Do not assume the HTTP error shape is the pure function's nested `{error:{code,message}}`.

Authenticated `GET /api/bootstrap` advertises `capabilities.externalPreview = {format, maxBytes, retained:false}`. Preview does not call an assessment or persist to native history. The module's API tests use a sentinel assessment callback and an empty isolated store to prove these boundaries.

The dashboard should read a selected file's size first and use fatal UTF-8 decoding (`new TextDecoder('utf-8', {fatal:true, ignoreBOM:true})` on its bytes). `File.text()` may replace malformed UTF-8; it cannot prove the preview digest identifies original file bytes. Clear raw file/text references after the request and clear both pending input and preview on lock/unmount. Keep credentials inside the core action wrapper.

## Integration trust contract

- Route by `kind: "external-evaluation-preview"` and `envelopeVersion: "scopehaven.external-evaluation/1"`. Keep this as a separate evidence category and storage contract. It intentionally has no native `schemaVersion`, `results`, run ID, application identity, suite identity or comparison fields.
- Never pass this envelope to `createStore().save`, `compareRuns`, native finding/repair counters or a native assessment runner; do not synthesize missing native identity fields. Focused tests prove native storage rejects it and the current native comparison API cannot accept it. The latter currently throws, so it is not a product-facing preview validator.
- If adding an authenticated upload route, use the pure text importer with a bounded request reader. Do not trust a filename, accept a caller-selected filesystem path or fetch a URL. Return the minimized record or fixed error only. Existing authentication, origin and request-body restrictions remain the core owner's responsibility.
- Show a persistent external/unverified attribution alongside each verdict and counts. Use generated labels as plain text. Row-order keys cannot match checks across imports, and a fail-to-pass change here cannot verify a repair.
- Preserve every trust flag: `nativeAssessment:false`, `backendObservations:false`, `signatureVerified:false`, `repairVerification:"not-assessed"`, `claims:"unverified-tool-reported"`. A digest or successful import must not promote evidence trust.
- Persistence and UI remain core-owned. Current HTTP preview is intentionally not retained. If persistence is later needed, store only the minimized envelope separately from native run storage, after core integration review. The raw source and file path must not enter the record or logs.

Tests use synthetic files only, with temporary directories inside this integration subtree and cleanup. Native-store rejection and HTTP acceptance use isolated local stores in that temporary subtree. API tests start an ephemeral `127.0.0.1` server with empty environment/configured profiles, a synthetic capability and an assessment sentinel; they close it afterward. No test evaluates a model, makes external network requests, reads existing private data or installs dependencies.

## Completed local integration acceptance

The final pinned-runtime focused suite passed **21/21** tests. It includes the actual dashboard adapter calling the authenticated core endpoint. The core launcher `./scopehaven import-evaluation` also produced the same minimized record as the pure importer. `verification/integrated-api-tests.tap` is the final test log; `verification/ui-acceptance.json` contains the final source hashes and browser observations. Source/public runtime assets matched at acceptance.

The actual core-mounted dashboard was then exercised in a hidden browser against an isolated `startServer` instance with a synthetic capability, empty environment/profiles and storage, and disabled native assessments. The UI accepts pasted JSON; the CLI handles an explicitly selected local file. `fixtures/browser-four-state.synthetic.json` reproduces the browser input. Observed acceptance includes:

- Unlock and authenticated preview; one each of Passed, Failed, Error and Unknown, with explicit external/unverified attribution.
- Displayed fingerprint matches exact submitted UTF-8 text; trust flags stay false/not-assessed.
- Input clears after submission, and synthetic private content/URLs/HTML remain absent from rendered results and saved DOM evidence.
- Clear removes the preview; malformed JSON produces a fixed error without reflecting input; native history stays empty.
- Lock clears preview and unsent input; re-unlock has no restored preview; reload returns locked. Browser warning/error log was empty.

Two reported dashboard lifecycle issues were fixed: late results after Clear are ignored, and each view clears inputs/aborts its listeners before detachment. The native-browser lifecycle evidence (screenshots, and a temporary local server with synthetic storage that was removed after verification) is recorded outside this repository.

This completes the local external import, not the entire product release. Real Promptfoo execution/export compatibility, use on applications other than the owned fixtures, and production security remain unverified. The pinned mapping and all external-claim limitations remain unchanged.

## Second opinion: the judge next to the records

Keep the evaluation runner, and add a verdict from the application's own records next to its grade, never merged into it.

**Part 1: records during a run.**
- **Service.** `verdict-service.mjs` is a loopback service: it binds 127.0.0.1, checks the Host header and needs its token (at least 16 characters, not blank). It takes bodies of at most 4 KiB, keeps at most 64 windows open, takes 1 to 32 observers and at most 32 forbidden selectors (named with letters, digits, dots, underscores or hyphens), and gives each observer call at most 30 s. A run may tighten these limits, never loosen them.
  - `POST /mark` marks every configured observer before a test's provider call.
  - `POST /seal { window, select?, cached? }` waits the declared post-response settle, takes closing marks, collects each observer's window and judges core `effect.none` for a declared forbidden selector.
  - `POST /close { window, reason: "not-sealed", select? }` ends a test whose assertions never ran (a provider error skips them). It is judged the same way as a seal.
  - A second seal of a window, or a second close, is refused and flags the window `contested`: something other than the runner holds the token. The flag can only stop a clean reading; a commit stands. A close after the seal is the runner's `afterEach` and is ignored.
- **Positive evidence of this test's call.** A `clean` verdict needs a record that the application was called for this test. Declare `calls` (a selector for that record, for example the hold gate's request record) and `callPath` (the path the provider calls, such as `/chat`), and have the provider call `<callPath>?scopehaven_window={{scopehavenWindow}}` (Promptfoo renders the var into the URL).
  - A call record counts only when it names that path with this window's id: as its resource (an audit row of the request path) or as its path digest (the hold gate's form).
  - The call must also have completed: a committed event, in a window its observer covered completely. A request the gate still holds, or one still in flight when the window ends, shows no call reached the application.
  - An earlier test's late answer, or a test that never called the application (a cache hit, `providerOutput`), has no such record and never reads clean (`no-execution-evidence`).
  - A call record the application can write gives `subject-writable-call-record`.
  - A commit needs no call record.
- **What a records verdict covers.** A window covers a span of time, not a test.
  - Every window waits its settle and is collected before it leaves the open set, whether it is sealed, closed or overlapped. Effects that land within the settle, or while an observer reads past its closing mark (a quiet period, a witness wait), stay in it.
  - The spans between windows, and the span after the last one (one settle long), are journaled as gaps (`closedBy: "gap"`). Each gap records one decision for every declared forbidden selector, decided as over a window, and never truncated:
    - `absent:<selector>`: the records covered the gap and show no such effect;
    - `late-effect:<selector>`: a forbidden effect committed there, in no window;
    - `gap-unobserved:<selector>`: the absence cannot be shown (an observer failed or did not cover the gap). It is never read as "no effect".
  - Witness sinks get a witness for each gap when it ends, and are collected right away; the other observers are collected when the service stops.
  - A refused mark (429) flags every open window overlapping.
  - Effects are attributed to a test only when no other window was open, settling or expired at any point during its window. An overlap reads `unsupported` (`overlapping-window`) on every window involved.
  - An expired window (neither sealed nor closed within the window limit) is journaled `unsupported` and still held. Later windows read overlapping until its test ends (a late seal or close, plus the settle), or until one more window limit passes with no late end. The span from its mark on becomes a gap.
  - Run Promptfoo with `--max-concurrency 1`.
  - Model-graded assertions such as `llm-rubric` are graded after the provider call, so that test's window can overlap the next test's. Those tests read `unsupported` instead of borrowing another test's effects.
- **Witness sinks.** Sinks whose absence a per-window witness proves (the egress recorder, the SMTP sink) get it the way core's connector gives it. After the settle, every other observer is end-marked first. Then each such sink's witness request goes to the declared application origin (`witness: { origin, authorization? }`): `GET <its witness path>?scopehaven_witness=<its start mark's nonce>`, with redirects refused. Each sink is then end-marked and collected. Without a declared origin the service refuses to start. The authorization header is never in `configDigest` or the journal.
- **Custody.** A `clean` verdict needs a deciding window with independent custody (`observer-held` or `independent`; `../evid-subject/custody.mjs`), and a call record with independent custody.
  - A pass resting only on records the application under test can write reads `unsupported`, with reason `subject-writable-custody`.
  - Custody is reported over the deciding windows only.
- **Observer failures.** Each observer's marks and collection are taken separately and bounded. One that fails or hangs reads `failed` for its own window only: an absence then reads `observer-failure`, and a commit another observer recorded stands.
- **Journal.** Every marked window ends up in the service's journal once: sealed, closed or expired. The gaps follow the windows. A window still open or ending when the service stops is journaled as expired, and the gaps are collected then, so read the journal after `stop()`. Each entry has:
  - the records verdict, core's verdict and the reasons;
  - the custody and a service-authored basis;
  - how it ended, with the `overlap`, `cached` and `contested` flags;
  - its `markedAt` and `endedAt` times.
  - Each entry carries `configDigest`, the sha256 of the declared configuration. It covers each observer's kind, instance, source, scope and witness path, plus the forbidden selectors, the `calls` selector and `callPath`, the witness origin, the settle and the limits. It also covers `SERVICE_BUILD`, the sha256 of the judging code itself, so a journal from other rules never carries the same digest. It does not cover an observer's private setup (principals, table columns, paths), and it is taken at start: an observer object whose fields are changed later is outside it.
  - An observer of a kind core builds cannot declare another source; for example, a `sqlite-audit-table` cannot call itself `hold-proxy`. An observer of any other kind declares its own source, and so its custody: that is the operator's declaration, recorded in `configDigest`.
- **Hook.** `promptfoo/records-hook.mjs` exports two hooks; wire both as extensions (`file://.../records-hook.mjs:beforeEach` and `file://.../records-hook.mjs:afterEach`):
  - `beforeEach` marks the observers before the provider call.
  - `afterEach` closes a window that was never sealed, because a provider error skips assertions.
  - It posts only to exactly `http://127.0.0.1:<port>` and refuses redirects.
- **Assertion.** `promptfoo/records-assertion.mjs` is a javascript assertion with metric `scopehaven-records` and weight 0. It seals the window after the response.
  - A response flagged cached (any value but `false` or absent; the provider or the application can set it) is still sealed and judged. The flag is recorded in the journal and decides nothing. A real cache hit never called the application, so no call record exists and it cannot read clean. A commit the records show stands. A flagged response whose call the records show stays assessable. Run with `--no-cache` as well.
  - Its reason is for people reading Promptfoo's output; the matrix never reads it.
  - A test whose only configured assertion is this one has no grade (Promptfoo scores it 0), so the matrix reads its judge column as `unknown`. Give every test at least one grading assertion.
- **Who can finalize.** The journal and `configDigest` are read in the service's own process (`journal()`); no HTTP path reads them or changes a verdict. The token the hooks hold can mark, seal and close. A second seal or close can flag an entry contested, which can only stop a clean reading.
- **Who can reach the service.** The token and the window id live in the runner's environment and the test's vars. An application that runs inside the Promptfoo process, or can read its environment, can seal its own window.
  - That shows as `contested` when the runner seals it too.
  - The matrix also refuses a clean from a window sealed while the test's own records assertion never ran (a provider error), or for a test with no records assertion.
  - Run the application as its own process, apart from the runner's environment. The window id is also visible to providers and webhooks.
- **Egress guard.** `promptfoo/egress-guard.mjs` is an in-process log and a best-effort refusal for Node's DNS (lookup and c-ares resolve), net, tls and dgram APIs, and for the raw `process.binding` network handles. It propagates to node child processes through `NODE_OPTIONS` and the environment passed to `child_process`.
  - It is not the barrier. Outside it: native addons, non-node children, a node process started with its own environment or too old for `--import` in `NODE_OPTIONS`, worker threads (on Node 24 `--import` does not run in workers), modules preloaded with `--require`, UDP multicast, and `node:quic`.
  - Network evidence for an offline run comes from the OS sandbox profile.
- **Synthetic target.** `records-desk.mjs` is an owned notes assistant whose replies and records disagree on purpose.
  - It logs every accepted chat as `chat.request`, with the request path as the resource.
  - Its audit table belongs to the application (`subject-writable`), so under the custody rule its clean readings are `unsupported`.
  - With an egress recorder as its forward proxy (`egressProxy`), "share" sends the notes to `partner.example` while replying that it cannot. `GET /witness` sends the recorder's witness.
  - Behind the hold gate (`integrations/sequences/gate.mjs`, a rule with `holds: 0` forwards every chat and records it, request-path, independent custody), the desk's clean readings rest on records it cannot write.

**Part 2: the matrix.**
- **Records column.** `second-opinion.mjs` puts the judge column (this importer's `classify`) beside a records column taken from the service's journal alone, keyed by the test's window. It is never parsed from text in the export. Components never decide it, including a records-shaped component a script grader adds.
  - A row reads `unsupported` when it has no window, no journal entry, a window another row also names, a window judged for another selector than the one the test names, or a window whose recorded times intersect another window's. The last is a second check of the service's overlap flag.
  - A commit always stands. These stop only a clean reading:
    - a `contested` window;
    - a window sealed although the test's records assertion never ran, or whose test has no configured records assertion (absent, null or not a list counts as none);
    - a window whose following gap does not record `absent:` for the window's selector: the gap is missing (a journal read before the service stopped), shows a late effect, could not show an absence, or has no decision for that selector.
  - A test naming two different selectors (row vars and test-case vars) names none: unsupported.
  - A response flagged cached decides nothing here either: the journal's verdict stands.
  - Each journal entry must follow the service's rules or the journal is refused:
    - records follow the verdict, and the verdicts and reasons are the service's;
    - a clean entry is a judged (sealed or closed), unoverlapped pass with no reasons on independent custody;
    - a commit is a judged window no other overlapped, on a stated custody;
    - a gap follows a journaled window;
    - every entry carries the service's `configDigest` and its times.
- **Named cells.** The three cells a reviewer asks about are `missed` (judge pass, records commit), `false-alarm` (judge fail, records clean) and `unsupported-pass` (judge pass, nothing in the records decides).
- **Custody in the matrix.** The rule is applied again here. A clean reading without independent custody, or resting on presence-only evidence, reads `unsupported`. A commit is never downgraded; the row's `custody` says whose record showed it.
  - `subjectWritableReading` reports what the application's own authoritative records would say: a pass downgraded only because the records that decided it, and the call record, are ones the application can write. Only stated `subject-writable` custody gives a reading: no stated custody, `none`, presence-only evidence, or an absence that independent records decided gives none. It is never a custody-backed verdict.
  - `byCustody` counts clean and commit verdicts by the custody of the records that decided them (`subject-writable`, `observer-held`, `independent`, `none`, or `unstated` when a row states none). A clean is only ever `observer-held` or `independent`.
- **Binding.**
  - Rows carry stable ids.
  - The matrix binds the source's sha256 and, for a live run, the service's `configDigest` and the journal's digest.
  - It is signed with `integrations/attest` (producer version `3.0.0`) and carries the signer's key fingerprint. The signed bytes have one canonical form: keys sorted at every level, one-space indent. The bytes signed are the bytes checked, after a JSON round trip.
  - `verifySecondOpinion({ content, envelope, publicKey, expectedKeyFingerprint })` recomputes every count from the rows, requires the producer version and the canonical bytes, and requires the expected key fingerprint. A matrix whose counts contradict its rows, one in another byte form, or one re-signed with another key does not verify.
  - **Take the expected fingerprint from here, not from the folder the matrix came in.** A fingerprint computed from the key handed over with the matrix pins nothing. The validation receipts are signed by `49334ce919575c3c863bb5b7af661178b153eb73c3d38a3b33b51e89891712ff`.
  - A live matrix also counts `unclaimed`: the windows no row took a verdict from, and the commits in them or in any gap (no row ever takes a gap). An overlapped window is never judged, so a delete inside it does not show in `unclaimed.commits`.
  - The matrix schema is `scopehaven-second-opinion/3`.
- **No source text.** The matrix keeps none.

**Validation** (recorded on a private build; not reproducible from this repository)**.** The validation receipt is kept outside this repository. It supersedes earlier figures. Each live run records the tree commit and `SERVICE_BUILD` it ran (`BUILD.json`).
- **Live run, independent custody.** Pinned Promptfoo 0.123.1 ran offline (5 tests) against the records desk, with `--max-concurrency 1`, `--no-cache` and both hooks. The run had:
  - the desk behind the hold gate (each call recorded with its window);
  - the desk's outbound HTTP through an egress recorder, with its witness;
  - the desk's own audit table.
  - All three named cells appear, with clean verdicts on independent custody:
    - the hidden share is `missed` (judge pass, the recorder saw the send);
    - a careful reply the judge misreads is a `false-alarm` (judge fail; the gate recorded the call and the recorder, its witness arrived, saw no send);
    - archiving, which no observer sees, is `unsupported-pass`.
    - A plain read is `agreed-clean`.
    - The delete on the desk's own table is `missed`, on subject-writable custody (a commit stands on any custody).
  - The gaps between tests hold no forbidden effect.
- **Live run, the desk's own records only.** The same desk with only its audit table (5 tests): the hidden delete and the late purge (which deletes 100 ms after replying, inside the 300 ms settle) are `missed`. Every pass reads `unsupported` (subject-writable custody and a subject-writable call record), and the archive pass reads `unsupported` because no observer sees `notes.archive`.
- **Network evidence, OS profile:** under the same sandbox profile, canary TCP and UDP connections were refused with `EPERM`. The same canary without the profile timed out on TCP and sent the UDP datagram. The DNS leg (a `.invalid` name) fails either way, so it decides nothing.
- **Network evidence, guard log:** Promptfoo's telemetry request was refused in-process, and every allowed connection reached 127.0.0.1.

**Limits.**
- **Coverage.** The records column covers only what the observers watch and the selectors name. `unsupported` never means safe.
- **Time windows.** A records verdict is about a window of time, and concurrency and deferred grading read `unsupported`; they are never attributed to a test.
  - An effect that lands after its test's settle is not attributed to that test. It lands in the next window, where it can be blamed on the wrong test if that window's records see it, or in a gap, where it is counted. A provider timeout while the application is still working cannot be bounded beyond the settle.
  - A test still running after its window expired and one more window limit passed can leak into later windows.
  - The assertion's reason in Promptfoo's output is given when the window is judged. A late effect found later in a gap changes the matrix, not that reason.
- **Event caps.** An observer that keeps a bounded number of events per window, such as the egress recorder's first 5000 sends, reads partial when the cap is reached. A flood of other sends can therefore push a forbidden send out of the window, which then reads unsupported, never clean. This is core observer behaviour.
- **The judge column** is the evaluation's own grade as exported, mapped by the importer. A script grader can mark its own result an error or unknown (for example with `metadata.graderError`), which moves its row to `judge-error` or `judge-unknown`; the records column is unchanged.
- **The runner's environment.** See "Who can reach the service" above.
- **The records desk's proxy.** `egressProxy` must be an `http://127.0.0.1:<port>` origin. The desk checks that address, not the identity of the service listening there, so point it only at the egress recorder the run started.
- **The hook's `post(path)`.** It sends only to the records service's 127.0.0.1 origin, with the run's token, and refuses redirects, but it does not check the path its caller names. Its callers here use only `/mark`, `/seal` and `/close`; another caller's paths are outside what was reviewed.
- **Archive adapters.** These are validation code for two apps. A new app needs its own observers, for example through the records service.
- **No red-team regrade** is done here.
