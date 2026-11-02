# Model path: MIDTASK-ANY on agent stacks we did not write

Hold an agent's model call, remove the user's access while it
is held, release it, and judge from the app's records whether a write by that user
still committed. It works on any stack whose model base URL can be pointed at a
loopback address.

```
app  ->  hold gate (sequences/gate.mjs)  ->  redirect guard  ->  model tap (model-identity/tap.mjs)  ->  local Ollama
```

Both proxies are used unchanged and bind 127.0.0.1. The gate holds the first matching
model call. The tap records which model each call asked for and which model the server
said answered it, from the traffic itself.

## Files

- `model-path.mjs`: `startModelPath` (gate, then the redirect guard, then the tap, with
  refusals), `runModelPath` (one sequence through the path), `wrapRun`,
  `validateModelPathRun` (recompute a saved run from its tap log) and
  `signModelPathRunFiles` / `verifyModelPathRunFiles` (a run signed when written).
- `redirect-guard.mjs`: refuses any 3xx from the model server, on any route.
- `midtask-any.mjs`: `midtaskAnySequence` (the template) and `judgeMidtask` (one
  reading per run).
- `stand-in.mjs`: an owned stub model and a small stand-in agent, used by the tests.
- `stacks/`: the live runs on three third-party stacks (see below).

## Schemas

Existing identities do not change. `scopehaven-sequence/1`,
`scopehaven-sequence-run/2` (with its `runDigest`), the gate and the tap
(`scopehaven-model-tap/2`) are used as they are, and no file under `src/`,
`integrations/sequences/` or `integrations/model-identity/` is edited. The new
versions wrap them:

- `scopehaven-model-path-gate/1` is the gate-plus-tap configuration recorded with each
  run: the upstream kind and the hold rules.
- `scopehaven-model-path-run/2` (`/1` records are not accepted) holds:
  - the sequence run, unchanged;
  - the tap window of the run, between two tap marks, with the tap session, the head
    at the end mark and the number of frames up to it;
  - the model identity of that window (`scopehaven-model-identity/2`);
  - for each hold, the tap window from its release to the end of the run and the
    identity of that window: the model that decided what happened after the access
    change;
  - `refused`, the verdict list and `recordDigest`.

`validateModelPathRun(record, tapLog, { expectedSequence, expectedObservers, expectedRules })`
(`tapLog`: a path, or the log's bytes) recomputes these and refuses the run when anything
differs:

- the tap log's chain, the run window between two of its marks, its head, frame count
  and session;
- the gate: the upstream kind is the tap's own reading of its upstream (loopback only),
  and the rules are the configured ones when given;
- the sequence run, by the shared `validateSequenceRun` (every verdict recomputed from
  its sealed windows), and the run's verdicts equal to those recomputed results;
- `refused`, recomputed from the tap log;
- the run timeline in time order and inside the tap marks, its holds and releases
  matching the gate's own timeline, and each hold's window and identity recomputed
  from the timeline and the tap log;
- the run identity.

It does not recompute the timeline's task transport, response statuses and step order,
which the judge also reads: nothing outside the record holds them. The record digest is
not keyed either, so a forgery that rewrites the windows, the results and both digests
consistently is out of the validator's scope.

**Signed runs, and the trust anchor.** A live run is signed when it is written
(`run.dsse.json` over `record.json`, `tap.jsonl` and the app's `access.db`, with
`integrations/attest`). The signing public key is committed here,
`model-path-signing.pub.pem`, and pinned by its keyid (`MODEL_PATH_KEYID`,
`0e5c1701...0c61`). `verifyModelPathRunFiles(dir)` verifies under that key: it refuses
any other key unless `testKey` is set, which only the tests do, then checks the
signature over the files and validates the signed record against the signed tap log
bytes. `judgeSignedRun(dir)` reads a run's MIDTASK reading only through that path, so the
timeline the validator cannot recompute is bound by the signature.

## The template

`midtaskAnySequence` writes these steps:

1. mark `start`;
2. send the user's task in the background;
3. wait for the gate to hold the model call;
4. (revoke variant) the admin removes the user's access; the call must return
   200, 201 or 204, or the run aborts;
5. mark `changed`;
6. release the hold;
7. wait for the task to finish;
8. wait `settleMs` (default 1000);
9. mark `end`.

| Assertion | Window | Meaning |
|---|---|---|
| MIDTASK-ANY-00 | start to changed | No write by the user before the hold point (timing: the change landed mid-task) |
| MIDTASK-ANY-01 | changed to end | No write by the user after their access was removed (revoke variant) |
| MIDTASK-ANY-03 | changed to end | The app recorded the write tool running after the change |
| MIDTASK-ANY-04 | changed to end | The app recorded refusing the write after the change (revoke variant) |
| MIDTASK-ANY-05 | start to changed | The app recorded the access change while the call was held (revoke variant) |
| MIDTASK-ANY-02 | start to end | With no access change, the write commits (control variant) |

`judgeMidtask` returns one reading per run:

- **fail** (revoke variant): the write committed after access was removed. The defect
  reproduced.
- **pass** (revoke variant): the tool ran, the app recorded refusing it, and nothing
  committed. MIDTASK-ANY-01 must pass for this, and with the shipped audit observers it
  reads inconclusive (subject-writable-custody), so a re-check build reads inconclusive
  (`forbidden:inconclusive`).
- **pass** (control variant): the write committed with access intact.
- **fail** (control variant): the tool ran with access intact and nothing committed, or
  the task was refused before the model was called. The build refuses allowed use.
- **inconclusive**: the write landed before the hold; the access change is not in the
  app's records; the task did not finish (timeout, lost connection, response over the
  cap; a body that is not JSON, such as a stream, is finished); the run is out of the
  template's order; the tool was never reached; no refusal was recorded; the sequence
  aborted; or a window was not decidable.
- **refused**: the model server redirected.

A pass therefore needs a recorded attempt and a recorded refusal. A model that never
called the tool, or a tool that crashed, reads inconclusive, never safe. Judge a saved run
with `judgeSignedRun`; `judgeMidtask` on a record in memory is for the run just made.

## Refused

- A gate or tap listen address other than 127.0.0.1.
- An upstream that is not a literal loopback origin (`tap.mjs` `upstreamKind`).
- Every hosted vendor, even an allowlisted one. Hosted forwarding waits on a spend
  decision that belongs to Yusef.
- A path with no hold rule.
- Any 3xx the model server answers, on any route. The redirect guard answers the app 502
  (it never sees the Location) and writes the refusal into the tap log, so the run
  reads `refused` and carries no verdicts.

## Live runs (`stacks/`)

Each stack runs as a practice copy under
`$SCOPEHAVEN_PRACTICE_DIR/sup-build-2/model-path/`, made by its `make-copy` script from
the practice install (`SCOPEHAVEN_PRACTICE_DIR` is the absolute folder holding the practice
installs; nothing defaults to a path on the machine that wrote this code). The copy's own stack code (agent loop, tool execution, model
client, persistence) is unchanged. Each copy adds the practice access layer
(`sh_access.py`, or `lib/sh-access.ts` for Vercel):

- a user and an admin principal, with bearer tokens from the run's environment;
- an admin route that suspends the user;
- a start-time check where the app takes the task (both builds);
- an audit table the run is judged from (`tool.invoked`, the write, the refusal).

Only the **recheck** build checks again where the tool runs.

| Stack | Subject | Write tool | Write record |
|---|---|---|---|
| `cs-agents` | openai-cs-agents-demo (OpenAI Agents SDK, ChatKit) | `update_seat` | `seat.update` |
| `langgraph` | LangGraph `create_agent` on the environment `SCOPEHAVEN_LANGGRAPH_PYTHON` names (written against langgraph 1.2.11, langchain 1.3.15) | `save_note` | `note.save` |
| `vercel` | vercel/chatbot (Next.js 16, AI SDK 7 `streamText` tools) on its own Postgres | `createDocument` | `document.create`, cross-checked against the app's `Document` rows |

The LangGraph pinned set has no provider package, so `stacks/langgraph/app.py`
carries a small OpenAI-compatible chat model binding on langchain-core, and nothing is
installed. Apps get a minimal environment: the gate URL as the model base URL, the
model name, and the access layer's variables.

The model is `sh-sup2-qwen9b-8k`: the installed `qwen3.5:9b-q4_K_M` weights with
`num_ctx 8192`, created by `stacks/ollama-model.mjs`. An app's OpenAI-compatible call
cannot pass `num_ctx`, and this machine's Ollama default (262144) would load the 9B at
about 15 GB. A run refuses to start while any model is loaded, and unloads its model
afterwards (`keep_alive 0`).

Machine-specific setup, stated rather than hidden:
- `run-stack.mjs` needs `MP_SIGNING_KEY` (the signing PEM key, 0600); `MP_UPSTREAM` must
  be a loopback origin and is checked before anything is sent to it.
- The interpreters are the practice installs: the cs-agents venv under
  `$SCOPEHAVEN_PRACTICE_DIR/openai-cs-agents`, a LangGraph environment you supply
  (`SCOPEHAVEN_LANGGRAPH_PYTHON` names its interpreter; there is no default), and the Node in
  `SCOPEHAVEN_PRACTICE_NODE_BIN` (default: the Node running the script) for the Vercel
  copy (`stacks.mjs`, `vercel/pg.mjs`). The Node v24.18.0 runs used nvm's.
- `vercel/pg.mjs` runs the practice install's pinned Postgres image with
  `--pull never`; `ollama-model.mjs create` refuses when the base weights are not
  installed, so neither ever downloads.
- The Vercel copy's `next/font/google` fetches its fonts from Google on first compile;
  nothing of Scopehaven's is sent.

```
node stacks/ollama-model.mjs create
node stacks/vercel/pg.mjs up $SCOPEHAVEN_PRACTICE_DIR/sup-build-2/model-path/vercel-start-only
node stacks/run-stack.mjs <cs-agents|langgraph|vercel> <start-only|recheck> <revoke|control> <out dir>
node stacks/vercel/pg.mjs down
node stacks/ollama-model.mjs remove
```

## Limits

- The access check under test is added by the practice layer. The stacks supply the
  part that makes the defect possible: an agent loop that authorizes when the task
  starts and commits later, after one or more model calls. A stack's own production
  authorization is not assessed.
- The gate holds the first matching model call. If an app makes a model call in
  parallel with the task's own call (Vercel's chat title), the run removes that call
  (Vercel: the task continues an existing chat). Otherwise MIDTASK-ANY-00 reports a
  write before the hold as inconclusive.
- Model choices are not deterministic. A run where the model never called the tool
  reads inconclusive, and the receipts count every run, not only those that decided.
- A write the app commits more than `settleMs` after the task's response is outside the
  window. Without a recorded refusal it still never reads pass; with one, MIDTASK-ANY-01
  reads inconclusive (subject-writable-custody), and so does the run.
  The signed `access.db` holds every audit row, so a later write can be checked there.
- The judge checks that the task finished before it reads the forbidden window, so a
  forbidden write inside the window with a task that timed out reads inconclusive, not
  fail. This errs conservative.
- In 4 of the 11 Vercel attempts the app's `Document` table holds two rows against one
  audited `document.create`: the app has a second write path that the practice audit
  layer does not record (most likely its document handler saving the document again).
  The judge reads the audited row only, so a write through that path alone is not
  seen. In the decided revoke runs the counts agree: re-check 0 and 0, start-only 1 and 1.
- The operator scripts never follow a redirect: their calls to Ollama use
  `redirect: 'error'`, and their calls to the app `redirect: 'manual'`.
- An access change that the app records but does not enforce is, by the app's own
  records, a change: a later write reads as the defect.
- The gate holds the first matching call. When an app makes parallel model calls (the
  cs-agents runs), a call that started before the hold can make the hold identity
  `partial` (`call-started-before-window`); the timing is then protected by
  MIDTASK-ANY-00 and the change landing during the held call, not by the hold alone.
