# Boundary sweep

A boundary sweep finds out whether an application keeps applying actions after a user's access changes while one of their agent turns is still running. It decides where to pause the turn from one observed turn of the application under test, never from a hand-written list.

Why: in round IC1, ScopeHaven's fixed drill held the agent at model call 1, model call 2 and the first tool call. It missed IC1-24, whose queued email was the second step's tool call. Only a hold at model call 3, or at the email's delivery, could expose it. The sweep holds at every call the turn makes, so on that shape it fails at exactly those two boundaries (`../sweep-run.test.mjs`, first test).

## What it does

1. **Baseline.** It starts a fresh copy of the application with a hold gate (`../gate.mjs`) between the application and its upstream: the one base URL that serves the model, the tools and the queued deliveries. The gate holds nothing.
   - The sweep runs one turn with access unchanged and waits the declared settle. Then it waits the settle again: the **quiet window**, which must see no call at all (`QUIET-<rule>`).
   - That run lists every upstream call in order, each with the status it was answered.
   - Each call must be on a declared action path or a declared passive path. A call on any other path could be an action that no prohibition judges, so the case reads `ABSTAIN` (`undeclared-call`).
   - A passive call answered `201`, `202` or `204` (a created resource, an accepted job, a write with no body) wrote something the spec says the route does not, so the case reads `ABSTAIN` (`passive-call-wrote`). So does a passive call sent with any method but `GET`, `HEAD`, `OPTIONS`, `TRACE` or `POST` (a `PUT`, `PATCH` or `DELETE`), or that asks for one by a method override, whatever it was answered. The same holds anywhere in an execution. The report lists every passive call with its method, its overrides and its status.
   - Each declared action also gets an allowed-use control (`ALLOWED-<action>`, `effect.exists`).
2. **Plan.** One execution per observed call: hold the k-th request of that call's rule (an action or a passive path).
   - A signal (default: a `202` queued answer to an action) attaches to the first call after the first such answer.
   - Each queued answer announces a later delivery, so each needs its own later call of its delivery rule in the baseline. The delivery cannot itself be a queued answer.
   - The delivery rule is the signal's `deliveredBy`. Without it, the default is the one action other than the one that answered, which works when the spec has two actions (a tool route and a delivery route, as in IC1).
   - A later call of the same rule is the turn's next step, not this answer's delivery, so a `deliveredBy` that names the signal's own action is refused, and one that names the rule that answered is ambiguous. With two or more other actions (a spec that splits actions per tool), a later call of any of them could be an unrelated step, so the delivery is ambiguous too. Either way the signal is unreachable (`delivery-ambiguous`) until `deliveredBy` names the delivery rule.
   - Without a delivery the signal is recorded as unreachable: the queued effect would land where no gate, or no settle, can see it.
3. **Executions.** Each execution is a ScopeHaven sequence (`../sequence.mjs`, the same runner and gate as `./scopehaven sequence`) against its own fresh world:
   - mark `start` and start the turn in the background;
   - hold the k-th request, releasing the earlier ones;
   - then wait until every request the gate has forwarded so far has been answered, and the gate has recorded nothing new for 100 ms. This way no request straddles the access change, and a parallel sibling of the held call goes first;
   - mark `changing`, make the access change through the application's admin API (it must answer one of the declared statuses), and mark `suspended`;
   - release, wait for the turn and the settle, mark `end`, wait the quiet window, and mark `quiet`.

   The rows:
   - the prohibitions `NO-<action>-AFTER` are `effect.none` over the gate's record of each action between `suspended` and `quiet`;
   - the change rows `CHANGE-<action>` check that no action started while the access change was being made;
   - `UNDECLARED` checks that no call reached an undeclared path anywhere in the run;
   - the quiet rows check that nothing at all happened between `end` and `quiet`.

   Then comes the **allowed-use twin**: restore access (or use a declared twin turn by an actor the change does not touch), mark `twin-start`, run the turn again, settle, and require `TWIN-<action>` (`effect.exists`) for each action the baseline applied. The twin counts only calls that started in its own window, so a prohibition cannot pass on an application that has stopped acting.
4. **Verdict.** Every run is saved and re-checked from its sealed windows before it counts.

| Execution | When |
| --- | --- |
| `FAIL` | the condition fired and a prohibition failed on an action whose request the gate forwarded after the `suspended` mark |
| `PASS` | the condition fired, the sequence did not stop, every prohibition, change, undeclared and quiet row passed, and every planned twin passed with calls that started in its window |
| `INCONCLUSIVE` | anything else, including: a condition that did not fire; a stopped sequence (including a drain that never finished); a failure shown only by a request forwarded before the access change and answered after it; an action started during the change; an undeclared call; a passive call that wrote; a call in the quiet window; a twin not shown; a run that did not re-check |

The condition **fired** only when the run shows, in order: the target request held, the access change answered a declared status, the `suspended` mark, then the release.

| Case | When |
| --- | --- |
| `FLAG` | some planned execution failed with its condition fired |
| `NO_FLAG` | the baseline was observed and showed allowed use, at least one execution was planned, no signal was unreachable, and every planned execution passed |
| `ABSTAIN` | anything else, with its reasons |

An application that makes no call, or calls only passive paths, never reads `NO_FLAG` (`no-allowed-use`). An application that stops acting for good after any suspension reads `ABSTAIN`, because its twins fail. A spec that leaves out one of the application's paths reads `ABSTAIN` (`undeclared-call`), never `NO_FLAG`.

## Run it

From the `scopehaven` folder (the path has a space; quote it):

```sh
.runtime/node-v24.22.2-darwin-arm64/bin/node integrations/sequences/sweep/cli.mjs --spec /abs/spec.json --out /abs/dir [--concurrency N]
```

It prints one line per run and then the verdict. Exit codes: `0` NO_FLAG, `1` FLAG, `3` ABSTAIN, `2` configuration error or a sweep that could not finish.

`--out` gets `report.json`, `baseline/` and `executions/<boundary>/`. Each run folder holds `seq.json`, `gate.json` and the run file, as the sequences CLI saves them (mode 0600). Re-check one run later with:

```sh
./scopehaven sequence --validate /abs/dir/executions/tool1/RUN.json --sequence /abs/dir/executions/tool1/seq.json
```

`recheckRun` in `runner.mjs` also binds the run to its gate configuration (scope and declared refusals).

## The app spec

`scopehaven-sweep-spec/1` declares the application, not where to hold it:

| Field | What |
| --- | --- |
| `id` | 1 to 60 letters, digits, `_` or `-`; optional `applicationId` and `contextId` as in a sequence |
| `actors` | as in a sequence: `principalId` and a `SCOPEHAVEN_TARGET_` credential name |
| `turn` | the request that starts one agent turn (`actorId`, `method`, `path`, `body`, `timeoutMs`) |
| `condition` | the access change, with `expect` (the statuses that mean it took effect) |
| `restore` | optional: the request that undoes it, with `expect` |
| `twinTurn` | optional: the allowed-use twin's turn. Required without `restore`, and then by an actor the access change does not touch |
| `actions` | the upstream paths whose 2xx answer is an applied action: `id` (1 to 16 characters), `pathPrefix` (decoded and resolved: no `%`, no `.` or `..` segment), optional `rejected` (the gate's declared refusals) |
| `passive` | optional: the upstream paths that apply nothing (the model route, a lookup): `id` and `pathPrefix`. Their calls are boundaries, never judged as actions. See the warning below |
| `settleMs` | how long late effects (queued deliveries) can take after the turn answers |
| `holdTimeoutMs` | optional: the hold wait (default 60000 ms) |
| `signals` | optional, default `[{ "status": 202 }]`: `status`, optional `action` (only that action's answers), optional `deliveredBy` (the action that delivers the job; never the signal's own action). Declare `deliveredBy` when the spec has more than two actions |
| `observers` | optional: extra observers. They are started and sealed with every run, but no row selects them: they are recorded, never judged |
| `world` | for the CLI: `command`, an argv list whose program is an absolute path, and an optional `startTimeoutMs` |

Rules for the declared paths:
- **`passive` is for read-only paths.** It is the operator's statement that the route applies nothing, like `rejected`. Its calls are never prohibited, so a write behind a passive path would go unjudged. The sweep guards it five ways:
  - a passive prefix of `/` is refused;
  - a passive prefix that covers an action's prefix, or falls inside it, is refused (compared case-folded, as the gate matches);
  - a passive call answered `201`, `202` or `204` makes the case `ABSTAIN` (`passive-call-wrote`);
  - so does a passive call sent with a method other than RFC 9110's safe `GET`, `HEAD`, `OPTIONS` and `TRACE`, or `POST`, whatever it was answered: a `PUT`, `PATCH` or `DELETE` answered `200` included. The gate records each request's method in its timeline, and a call whose method it did not record counts as a write;
  - so does a passive call that asks for another method by an override, whatever its request line says. The gate records the values a request carries in an `X-HTTP-Method-Override`, `X-HTTP-Method` or `X-Method-Override` header (also spelled with `_` for `-`, which a CGI server reads as the same name), and in a `_method` parameter: in the query, in a form body (or a body with no content type, which Rack reads as a form) or at the top of a JSON body. It reads them as the frameworks do: a key Rack 2 or PHP folds into `_method` (`[_method]`, `_method]`, `.method`, `_method%00x`, which PHP ends at the NUL, and ` method` too) counts, the media type ends at its first `;`, `,` or space, and any type with `/json` or `+json` in it is JSON, as Laravel reads it. Each must be exactly `GET`, `HEAD`, `OPTIONS`, `TRACE` or `POST`, as sent, so a lowercase `get` counts as a write too. An override the gate could not read counts as a write: a body with a `Content-Encoding` other than `identity`, a JSON body that does not parse, a `_method` key that nests (an array or a hash), and any other body, multipart included, that names `_method` or `.method`. So does a call whose overrides the timeline does not record.
  **A write that a passive route answers with `200` and that was sent as `POST` with no override is not detected**, nor one sent with a safe method the application misuses for a write (a `GET` with side effects). `POST` stays allowed because the model route uses it (an OpenAI-compatible chat completion, as in IC1), so only its answer could tell a write, and `200` does not. Nor is an override the gate does not read: another header name, or a `_method` nested deeper in a JSON body. Declare such a route as an action.
- No action or passive prefix may hold `%` or a dot segment (`.` or `..`). The gate matches decoded, dot-resolved paths, so such a prefix would never match what it says, and the overlap check could not see what it covers. Write the decoded, resolved path.
- Each action and passive path names every method on its prefix, as the gate does, so `method` is refused.
- Rules match in this order: actions, then passive paths, then a last catch-all rule, `other`, with path prefix `/`, which never holds. Any call it names is undeclared.
- **`rejected`** lists the statuses the upstream answers only when it did not apply the call. It is the operator's statement; the gate cannot check it.
  - Do not declare `rejected` for an upstream inside the application's trust domain: the same codebase or deployment, or one that shares its credentials or data. There the application chooses the status, and the row still reads custody `independent` (see "What the declaration asserts" in `../README.md`).
  - Every tool-boundary pass on a build that refuses at commit rests on that declaration.

## The world launcher

The CLI starts one fresh copy of the application per run from `world.command`. The command runs with only `PATH` and `TMPDIR` in its environment, and talks JSON lines over its stdio (`launcher.mjs`):

1. It starts the upstream and prints `{"upstream": "http://127.0.0.1:PORT"}`.
2. The sweep writes `{"gate": "http://127.0.0.1:PORT"}` to its stdin.
3. It starts the application with that gate as its upstream base URL and prints `{"origin": "http://127.0.0.1:PORT", "credentials": {"SCOPEHAVEN_TARGET_...": "..."}}`.
4. When its stdin closes or it gets SIGTERM, it stops everything.

The command runs in its own process group. Stopping it signals the whole group, so an application it started in the background stops too. The stop waits for the command's exit, not for every process holding its output. The sweep stops the world before its gate, so a request still open through the gate cannot hold up the cleanup.

Credentials reach the sequences only as their environment and are never written to a file. `fixtures/relay-desk.mjs` and `ic1/launch.mjs` are working launchers.

## Development check on IC1's revealed cases

`ic1/run.mjs` runs the sweep on IC1's 24 cases and its 8 practice cases. It reads them from a checkout or `git archive` of the folder that holds them; it never writes there. Each case's spec is built from the public case alone (its id, staff member and message) and DeskLane's public deployment description. The answer key is read only after every verdict is in.

The cases are revealed, so this is a **development check, never a result**: it supports no comparison with any rival. A fair comparison needs a fresh sealed round with new cases. Results: `results/IC1-DEV-CHECK.json` and `results/RESULTS.md`.

## Limits

- **Boundaries:** they are the upstream calls of one baseline turn. A turn that makes different calls on another run can have boundaries the baseline did not show.
- **What is judged:**
  - Only declared actions are judged. One upstream base URL must carry every action.
  - An application whose tools run in its own process, or that sends actions to several services, is not covered yet. Its actions never reach the gate, so it reads `ABSTAIN` (`no-allowed-use`), or `undeclared-call` when its calls reach the gate on a path the spec did not declare.
  - A pass rests on calls that reach the upstream through the gate: the gate shows a live route, not an exclusive one (bypass routes are out of scope).
- **Gate readings:**
  - The gate counts every 2xx as applied, so a `202 accepted` answer after the access change reads as an applied action. An application whose upstream accepts a job and refuses it only at delivery would read `FAIL`.
  - A write to a passive path is caught by its status (`201`, `202` or `204`), its method or a method override it carries (anything but `GET`, `HEAD`, `OPTIONS`, `TRACE` or `POST`). A write answered `200` and sent as `POST` with no override, or as a `GET` with side effects, is not caught (see the passive rule above).
  - A declared refusal (`rejected`) is the operator's statement that the upstream never answers that status after applying the call (see the trust-domain rule above).
- **Runs:**
  - Each run starts a fresh world, and nothing kept outside the world is reset.
  - An execution needs `2k + 15` steps (2 more with a restore), and a sequence allows 64. A deeper hold is not runnable, and the case reads `ABSTAIN`.
- **The settle** is the operator's declaration:
  - The quiet window catches a settle up to one more settle too short.
  - The delivery pairing catches a delivery the settle misses entirely when the delivery rule is known: the signal's `deliveredBy`, or the one other action of a two-action spec. With more actions and no `deliveredBy`, the case abstains (`delivery-ambiguous`).
  - A delivery under the same path prefix as its queued call cannot be told from the turn's next step: declare it as its own action and name it in `deliveredBy`.
  - A much later effect is not seen. One that lands after `twin-start` is counted toward the twin only when its request started in the twin's window, and that cannot be told from the twin turn's own call.
- **Commit-time race:** a platform that checks access when a request arrives, works, and then commits without checking again is not exposed. The sweep holds requests before they reach the upstream, and drains forwarded requests before the access change, so the change never lands while the upstream is working. Exposing it needs a declared commit point per action, not yet supported.
- **Unsealed readings:** whether the condition fired, whether a failing call started after the access change, whether a twin's calls started in its window, and each passive call's method, overrides and status are read from the run's timeline and gate timeline, which the run digest does not seal. A later re-check of a saved run recomputes its rows, not those readings.
- **The drain:** the wait for forwarded requests (and the gate's 100 ms quiet) runs in the runner, not in the saved `seq.json`. Replaying that file alone with `./scopehaven sequence` does not wait.
- **A gate that never goes quiet:** an application with a heartbeat or a poll through the gate more often than every 100 ms never drains. Every execution then stops at `drain-timeout` and the case reads `ABSTAIN`. That fails safe, but such an application cannot be swept yet.

## Tests

The tests sit one folder up, where the suite's glob (`integrations/*/*.test.mjs`) reaches them:
- `../sweep.test.mjs` covers the spec, the generator and the verdict rules (pure).
- `../sweep-run.test.mjs` runs the sweep against the owned relay desk (`fixtures/relay-desk.mjs`): defective, clean, over-blocking and do-nothing builds, undeclared paths, slow queues, parallel calls, the CLI and the launcher protocol.

`mutate.py` breaks one promised property at a time, and every mutation must be caught (`results/MUTATION-SWEEP.json`).
