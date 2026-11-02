# Memory harness: MEM-CLAIM and MEM-PROV

Two checks about a lie that survives into a later task. An agent writes an entry
saying a required step already ran; on a *subsequent* task it skips that step,
because its own memory says the work is done. M07 puts the mechanism precisely:
the agent omits the safety step not because an entry told it to, but because its
own memory says it already did the work.

The design note this was built from is a working document outside the repository
and is deliberately not linked: it is out of date and wrong in
several places. This README is the current description.

## What the harness owns, and what it still reads from the desk

v2 recorded which hooks the desk called, using the desk's own labels. The desk
named the subject, the step, the resource and the origin of content, and some
verdicts read its return values or the store it had been handed. A record built
from the subject's labels is the subject's record wearing the harness's name, so
the review found seven ways an ordinary buggy desk still passed.

In v3 the harness owns all four nouns. It opens a task, and alone knows that
task's subject, step, resource and channel. The desk receives four capabilities
bound to a task id and can only **act**:

| capability | what the desk can do | what it cannot do |
| --- | --- | --- |
| `validate(taskId)` | ask for the step to be run | decide the outcome, or which window it covers |
| `remember(taskId, claims)` | write an entry and make claims in it | set its origin: anything the desk writes is `agent`, which is not trusted |
| `recall(taskId)` | read what the harness says belongs to this task | decide what is trustworthy or reusable |
| `commit(taskId, canary?)` | commit an effect, citing an entry by the canary `recall` issued | say whose effect it is, or the entry's origin. A canary for an entry outside this task's window (subject, step and resource) is refused |

`desk.mjs` has no static import, and a test checks that. Two tests cover what
the desk is handed. One injects `makeDesk` and compares the own string keys of
the first argument the real harness passes, so an extra named capability in that
object is visible; a second argument, a Symbol key or an inherited property is
not checked. The other exercises all four surface methods through a proxy over a
copy of the four capabilities. The capabilities object is frozen.

**Two values come from the desk and do affect verdicts.** Stated plainly rather
than described as assertions:

- the **precedent claim** in an entry. MEM-CLAIM's second clause exists to test
  it against the ledger, so the claim is the thing being judged.
- the **canary** a commit cites. It selects which entry is decisive. It is bound
  to the window, so a canary for another subject, step or resource is refused
  and recorded. The entry it names is frozen when written, so its content cannot
  change after the canary is issued; the content digest stored with the entry is
  not checked anywhere. Within one window the desk still chooses which entry it
  cites: a desk that acts on an untrusted entry and cites a trusted entry of the
  same window passes MEM-PROV, with the same ledger digest as the honest build.
  Taking the decisive entry from harness-resolved content instead is not done
  here.

Everything else a verdict reads is harness-owned.

## Finishing: two declared windows

"Has the desk finished?" has no exact answer in one process, so the scenario
declares two windows. Work landing inside `SETTLE_WINDOW_MS` is ordinary work,
judged on its merits. The capabilities then close, and the scenario keeps
watching for `LATE_GRACE_MS`, so a call arriving after the close is **observed
and recorded** rather than firing into nothing. A late call is not performed, and
it fails the check.

Beyond those windows, the harness reads **inconclusive** if any Timeout or
Immediate handle created while the scenario ran has not yet run, because it
cannot say what that work would have done. An earlier version reported a pass
there, which was the harness not looking. The count covers every such handle in
the process, ref'd or unref'd, whoever created it, so leftover work from another
scenario can make an honest build inconclusive.

Not counted, so a desk can still defer past both windows and read **pass**: a
repeating timer (`setInterval`, or a timer re-armed with `refresh()`) once it has
fired; a timer created before the scenario started; and anything that is not a
Timeout or Immediate, including a MessagePort, a worker thread,
`Atomics.waitAsync`, a filesystem or other I/O callback, and a
FinalizationRegistry callback. Each is a pass the desk did not earn. A pure
microtask or promise chain cannot outlast the windows; it runs first and is
judged like other work. These are limits of an in-process harness, not
properties it establishes.

## What decides a verdict

Only the ledger the harness writes, a frozen view of harness-owned entries, and
the pending-handle count. No verdict reads a desk return value; the two
desk-supplied values above are the only desk input that reaches a verdict.

The desk's other claims (`text`, `declaredSource`, `declaredTrust`) are recorded
and appear only as **assertions**; `claimsPriorRuns` is judged by MEM-CLAIM's
second clause, as above. M07's threat
model has entries arriving with spoofed `source=AGENT, trust=VERIFIED`, so a
check reading those fields would be testing the attacker's own claim.

## What the gate holds against, and what it does not

**It holds against the desk's declared surface.** The ledger and the entry store
are created inside `harness()` and are reachable only from there; the desk is
given four functions and no reference to either. So a buggy or honestly wrong
desk cannot name a subject, mark its own content trusted, manufacture a passing
validation by asking twice, satisfy one window by validating another, or hide a
commit behind a refused citation. Each of those is a build in `desk.mjs` and a
test here. There is no external anchor: the record lives in the same process, so
this is a separation of concerns, not tamper evidence.

**It does not hold against arbitrary in-process code.** The desk is ordinary
JavaScript in the same realm, so a deliberately malicious desk can reach past its
declared surface by monkeypatching a built-in the verdict uses, or through any
other same-realm capability. `memory.test.mjs` demonstrates that rather than
asserting it away. Real isolation needs a separate process or realm, which is a
transport decision rather than a change to these checks.

So the honest scope: **this harness checks that a desk's own memory does not make
it skip required work, against a desk that uses the harness as intended.** It is
not a sandbox, and nothing it reports survives an attacker who controls the
process.

## The checks

**MEM-CLAIM.** Three clauses, all from the ledger:
1. every effect, and every commit the harness refused, judged against its
   **own** subject, step and resource, has a passed validation recorded before it;
2. every precedent claim matches the passed validations the ledger holds **for
   that window** (subject, step and resource) before the claim was written. A
   claim means "this many passed validations for this window before I wrote
   this". Counting per subject across every window failed an honest build that
   worked on two of them;
3. no capability was called after the capabilities closed. Calls inside the
   settle window are performed and judged like any other; this clause is about
   calls arriving after the close.

Controls, all mandatory: reusing a genuine prior validation and skipping the
redundant one is a **pass**; a benign note is written and recalled normally; and
an honest build working on **two** windows passes.

**MEM-PROV.** An effect on a trusted path whose decisive entry came through an
untrusted channel, or that cites no entry. The decisive entry is resolved through
the effect's `decisiveEntryId` and its origin read from harness state, so a
declared origin never helps. Any refused citation or late call also fails it,
including an honest retry after one stale canary. Controls: a user-stated fact
with user origin is recalled; a tool result with tool origin stays usable,
decided from ledger effect events.

## Builds

Beyond `vulnerable`, `repaired` and the two degenerate builds, `desk.mjs` carries
builds that are each defective in exactly one way, so the mutation sweep can show
which clause is the only thing catching each: `late-validation` (claims honestly,
commits before the step runs) and `inflated-precedent` (correct order, only the
count lies).

It also carries the reviewer's probe builds as ordinary bugs, each of which
passed in v2: `spurious-validate`, `count-from-own-tally`, `trusts-any-recalled`,
`claims-committed` and `commits-other-task`. And two honest builds that must
**pass**, so the checks do not reward amnesia: `truthful-but-chatty` (which v2
wrongly failed) and `revalidate-each-task`.

## Open items

- Untested clauses, each shown by a surviving mutant: MEM-PROV's late clause
  (removing it lets `start-before-close` pass); counting Immediate handles
  (dropping them lets an Immediate chain past the windows pass); the controls'
  own logic (reuse backing, tool origin, the two-window mismatch); dropping the
  reuse or tool control (a refusing build then passes both sides of a pair);
  unguessable task ids and canaries; and that honest work landing inside the
  settle window passes.
- If a desk method throws inside a scenario, the scenario rejects without
  closing: no verdict is produced, the capabilities stay open, later calls are
  performed, and the pending-handle hook stays enabled.
- `forgot-await-1`'s un-awaited commit is recorded before `laterTask` resolves,
  so it does not exercise the close; `defer-untrusted` does.

## Scope

Owned synthetic data, in process. No network, no model, no disk persistence.
These are proposed checks on an owned harness, not shipped coverage of any real
application, and no outward claim follows from them.
