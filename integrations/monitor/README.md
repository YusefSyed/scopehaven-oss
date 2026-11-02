# Trace checker (`integrations/monitor`)

This is not monitoring in the sense `scopehaven/SECURITY.md` uses: monitoring there requires an
operating scheduler and verified delivery, and neither is built here. It checks the observations
it is handed when it is called; nothing runs it on a schedule or delivers its alerts anywhere.

The guards in `../guards` are preventive: they run inside an application, immediately
before an effect commits, and refuse it. This is the detective half, scoped to what it checks:
observations of traffic that already happened, against five fixed rules, each the observable
form of one guard denial or verdict. It raises a local alert when one of those five patterns
matches. It does not see every violation the guards prevent, only those five patterns, and only
in the observations a caller hands it.

Those observations come from a saved synthetic-fixture run (`observationsFromRun`), a trace file
(the CLI, below), or a caller's own `read()` polled by `pollSource`. No live source ships here:
nothing in this repository feeds `pollSource` from a running application (see Sources).

It holds no transport. No URL, no socket, no credential, no network import. A caller reads
a local source and pushes what it read; a test reads both modules' own source and asserts
they contain nothing that could reach off the machine. "Live" means a caller polls.

## The five rules

| Rule | Severity | Mirrors | Check |
|---|---|---|---|
| `commit-after-access-change` | critical | the access guard's `grants-changed` | MIDTASK-01 |
| `commit-by-inactive-principal` | critical | the access guard's `principal-inactive` | MIDTASK-01 |
| `claim-contradicts-record` | high | the claim guard's `unsupported` verdict | TRUTH-01 |
| `claim-unverifiable` | medium | the claim guard's `unverifiable` verdict | EFFECT-01 |
| `access-change-unjudged` | high | the access guard's `access-unreadable` | MIDTASK-01 |

Each `mirrors` value is a name the guards actually declare. The claim guard's vocabulary is
**derived at import time by driving the guard**, not copied: `deriveGuardVocabulary()` runs
it over a declared matrix of inputs in which **each probe states the verdict and reason it
must produce**, and reports any mismatch in `guardDrift`. It does not throw: a derivation
that throws at import time takes the whole suite down for a mismatch a test should be
reporting. An earlier version mirrored `unsupported-claim`, a string that existed nowhere in
the guards, and its own mirror test passed because the test read the same invented list.
The version after that collected whatever came back, so a renamed reason left this module
emitting the old string with nothing to say so.

`access-change-unjudged` is the coverage rule. It fires when access changed around a
request **and** the two access rules could not speak to it: the ledger was unreadable,
something committed with no commit-time authority observed, or an effect could not be
attributed to this request because another request's window showed the same row. It stays
silent when the record is readable and shows no commit, because that is a guard doing its
job, and a monitor that alerts every time a control works gets turned off. It does not
claim that a violation happened: it says the question was not answered here.

## What a verdict rests on

Every rule reads the **record**: ledger rows the application added, and plan status
transitions. What the application *said* about itself (a `completed` flag, a reply, an
executed-tool event) is only ever compared against that record, never substituted for it.
A tool event is kept on the observation as `toolsReported`, for corroboration in the alert,
and is never the trigger.

There are three, and each is named everywhere it matters. The ledger snapshots are the application's own record of its own state, so the absence of an effect from them is its statement, not an observation of the world: `answeredByAbsence` counts the verdicts that rested on one and `absencesWithNoClaim` counts the readable empty ledgers that answered nothing. Which effect names a window can answer for at all is also the source's statement, which is why a source that states none is answered by absence for nothing. And the authority an
effect committed under comes from the application's **own resume event**, because a saved
run carries no other commit-time observation of it. Every access alert carries
`authoritySource`, the limitations say so, and a request with no such event has
`atCommit: null` rather than an invented value copied from the request's start.

## Counters, and why they are separate

`report()` carries:

- `coverageGaps`: what this run could not judge. `unreadableLedger`,
  `effectsWithoutAuthority`, `unattributed`, `unattributableGaps`,
  `commitsWithNoCommitTimeView`, `guardDrift`, and whatever the source reported it dropped or
  failed to read. **Above zero means the run did not check
  everything it observed**, whatever the alert count says.
- `unjudgedAuthority`: commits whose commit-time authority was never observed. The two
  access rules are **silent** about those commits. Nothing judged them: there is no
  commit-time view to compare against. Reported separately and *not* part of
  `coverageGaps`, because a saved run records commit-time authority only for requests the
  application paused, so on honest traffic this is most commits.
- `commitsWithNoCommitTimeView`: the subset that matters, and it **is** part of
  `coverageGaps`. A commit on an operation the application can pause, with no resume event
  recorded. Which operations those are is the caller's declaration, below; it is not a
  constant in this folder. **An application that emits no
  resume event is not detected by the grants rule at all**, and this number is how that
  shows up.
- `unattributed`: identified rows that appear in more than one request's window. A source
  diffing global snapshots would otherwise charge one commit to every request in flight,
  which made a correctly refused request raise three alerts on its twin's row. This is a gap
  in *this run*, so it is part of `coverageGaps` and the coverage rule fires for it.
- `unattributableByShape`: effects with nothing to identify them, neither a row id nor a
  readable row (a cyclic structure or a throwing getter). An id-less row this can **place**,
  by its position in a ledger whose windows fit one order, is attributed normally, so
  this is now the residue rather than every id-less effect: sending all of them here
  hid a lone stale commit on an id-less ledger at `coverageGaps` 0. They are charged to
  no request and reported on their own, and the part of them that falls in a request where
  **access changed** is counted in `unattributableGaps` and is in `coverageGaps`.
- `guardDrift`: any probe whose verdict or reason no longer matches what the claim guard
  returns. Counted in `coverageGaps` rather than raised as an alert, because it is not about
  the traffic: it says this module may no longer be naming what the guard names.
- `ruleErrors`, `duplicateObservations`, `source` (`dropped`, `readErrors`, `invalid`,
  `batches`, `ticks`, `reported`). When `source.reported` is false, nothing is known about
  what the source dropped. A duplicated line is one finding per rule with the repeat
  counted; the fingerprint includes the committed rows, so two distinct stale commits in one
  request are two findings.

## Sources

`trace.mjs` holds them; the monitor itself reads nothing.

- `observationsFromRun(run)` : recorded traffic from a saved synthetic-fixture run. The
  returned array carries `dropped`, the attempts whose evidence could not be read.
- `pollSource({ monitor, read, ticks, intervalMs })` : polled traffic. `read()` is the
  caller's own local source, and none ships: nothing in this repository reads a SQLite file,
  an audit file or a running application for the monitor, and the tests call `pollSource` with
  a `read()` that returns synthetic observations. An observer over a loopback SQLite ledger or
  an audit file is the kind of source that would plug in here; it is not built. A `read()` that
  throws is counted, not swallowed, and one malformed observation is counted without ending the
  poll.

A snapshot has to **be** a snapshot: a non-object, or an object carrying none of the
declared ledgers, is a window that was never seen rather than an application without those
ledgers. Reading it as the latter made a truncated trace come out clean and invent three
success-claim alerts on top of it.

### A ledger without row ids makes honest claims unverifiable

Say this plainly, because it changes what a clean report means for such an application.
When a ledger's rows carry **no id** and a reply names one (an `actionId`, a refund id),
this source cannot tie the claim to a row. It does not go silent and it does not call the
claim a contradiction: it raises **`claim-unverifiable`** at medium. On an application whose
refunds are keyed `refund_id` or `uuid` rather than `id`, every honest id-naming success
claim reads that way, so a run can be full of medium unverifiable alerts with nothing wrong.

A claim that names an **id** is the case this covers, whatever else the ledger holds: a
request for row *r-9* cannot be confirmed or denied by the presence of *r-1*, so a failure or
pending claim about it is unverifiable rather than supported. A claim that names only an
**effect** is answered by its absence, but only under two conditions that this source can
state: the name is one this source actually produces, and the ledger that would carry it was
readable on **both** sides of the window. An earlier version answered by absence for any name at all,
including an adopter's `refund.issued`, a differently-cased `Refund.Commit` and a ledger only
one snapshot carried, and every one of those verdicts rested on the application's own snapshot
saying nothing was there. `answeredByAbsence` in the report counts how often a run leaned on
one. Without those conditions, reading an absence as an answer raised two mediums on the
repaired build the moment suite 2.3.0 added an honest refusal, and silenced claims the ledger
never covered.

A row charged to no request is also not an absence. After a collision the claim rules used to
read an empty ledger, so two honest refunds raised two highs; a claimed name or id sitting in
`unattributed` makes the claim unverifiable instead.

Silence would be worse than an unverifiable alert where the ledger truly cannot answer: it
would assert a match this source cannot make. The way to get a quiet report on such an
application is to give the source a reading of the ledger that carries the row id, not to
lower the rule. Where the row has no id, its **position** keys it,
under the conditions in "Placing a row without an id" below; a row this cannot read at all,
and a row in a ledger whose windows do not fit one order, are unattributable.

Mutating an older row is not tolerated on an id-less ledger, whatever keys the new rows: a
window that both changes row 1 and appends row 2 cannot be diffed by content or by length, so
it reads unreadable and the request goes unjudged rather than being charged a guess.

**Which operations can be paused** is a caller's declaration, not this module's guess. Both
`observationFromAttempt` and `createMonitor` take `interleavableOperations`; the observation's
own `interleavable` flag wins when the source set one, and **when nothing is declared
anywhere, every operation counts as pausable**.

That default has a price, and it is better to know it than to be surprised by it: declaring
nothing makes `coverageGaps` **25 of the 26 windows that commit** on the clean synthetic run,
and 37 of 39 on the vulnerable one, because none of those commits carries a commit-time view. Declaring `['refund-task']`, or declaring `[]` if
nothing in the application can be interleaved, takes it to 0. The conservative default is
there because hard-coding the fixture's one operation name meant an adopter whose
`approve-payout` committed with no resume event read `coverageGaps` 0, which is the same hole
for every application that is not this fixture.

**Placing a row without an id.** An id-less row is keyed by the ledger **store**, the ledger
and its **position** in that append-only ledger. Content is *not* in the key. What content
decides is two other things: whether a key exists at all, since a row nothing can fingerprint
gets none, and whether the windows fit one shared order, because that check compares
fingerprints. So a row that **mutates** between two windows, a changed `status` or
`updatedAt`, breaks the order, and that ledger's id-less rows are then charged to no request
and counted as a coverage gap. At position *N* within an order that does hold, it is the same
row in every window. Keying on content meant a row that mutated between two
windows looked like two rows and was charged to a request that had not committed it, so
nothing here identifies a row by what it holds. No source is exempt from the collision check.
An earlier version let a source declare itself per-request and skipped the check for it, and
the one source that declared it was wrong: the fixture snapshots the whole shared state.

The **store is the source's statement about where it read**, never the application's. An
earlier version took it from the trace, and that let the subject decide how its own rows were compared: a
"refund processed" lie was excused by its twin's row, and a trace naming two stores silenced
it outright. `observationFromAttempt(attempt, { ledgerStore })` is where it comes from, and
`observationsFromRun` names `run-check:<index>` because a saved run builds a fresh fixture per
check. A source that names nothing leaves rows comparable, so two windows showing one row
collide and are charged to neither. That is the conservative direction: unplaced, not placed
on the request that refused the work.

**That holds where a source builds the observation, and the CLI builds none.**
`observationFromAttempt` and `observationsFromRun` set the store, the authority (from the app's
resume event) and `interleavable` themselves. A trace file read by `cli.mjs` is observations that
are already built, so every field on every line, the `store` on each committed effect,
`authority`, `interleavable`, `answerableEffects`, `ledgerReadable` and the rest, is the trace's
own word, and the CLI trusts it. A trace written by the application under test can therefore
choose how its own rows are compared, which is the trace-supplied store above, one level up: on the CLI
path the store is whatever wrote the file says it is.

That key rests on one assumption, stated here because it used to be silent: **every window of
a ledger sees one shared append-only order**. It is now checked rather than assumed. The
windows of a store have to fit together, sorted by length each a prefix of the next, and where
they do not, a position places nothing, and those rows are charged to
no request and counted in `unattributed` and `coverageGaps`. Two shapes break the assumption
and used to pass silently, each charging a correctly refused request with another request's
row and reporting no gap:

- **One ledger behind two application instances.** Keyed by instance, the same row looked
  like two rows, one per window. The key is the store now, and a ledger reached through more
  than one store that the source did not name is unplaceable.
- **Per-user filtered views**, where an admin sees every row and a member sees only its own.
  The same row sits at different positions in the two windows, and no key can fix that.

`observationFromAttempt(attempt, { ledgerStore })` is how a SOURCE says which store a window was read from, and no source reads a store from the evidence it is given: an earlier version did, which let the application decide how its own rows were compared. (The CLI is handed observations, not evidence, so it takes the store from the trace line; see above.) There is no instance-id fallback; a window with no store named leaves its rows comparable, so two windows showing one row collide. A row carrying an id is no exception, and an unnamed store does not separate it from a named one: two instances
over one store name the same string and their rows line up; two genuinely separate ledgers
name different strings and are believed, because then it is a statement someone made rather
than a silence read as one.

**What filing and an already-held row do not claim.** A reply that says the work ALREADY
happened is not claiming it failed, whatever it says about the request that asked again:
"Duplicate request rejected: refund r-1 was already processed." asserts the refund, and
raising a failure contradiction against the committed row was a cost of reading an
already-held id strictly. What this module can say about an effect that landed in an EARLIER
window depends on what the claim names, because this source reads one window's delta. A claim
naming its id reaches that commit through `knownResources` and is judged against it. A
**filing** claim whose row was already held before this window depends on what the reply says:
a **pending** reply is `claim-unverifiable` while the commit it becomes has not landed here, a
**failure** reply is contradicted by the row, and a **success** reply is consistent with it.
But where that commit lands in **this** window the reply is contradicted outright, whatever
else is unplaced or held. Weighing the unplaced and already-held cases first would read
a lie as a medium where a high is owed. A claim naming no id is answered by this window
holding no such row, which is an absence and is counted in `answeredByAbsence`. Describing
all of this as one blanket silence is false for filings, and "this window's commits say
nothing" is false when the commit lands here. It is the
kind of limit that has to be measured per case rather than stated once. **The cost of getting
that lie right:** an honest retry about a filing that was already held, whose commit has *not*
landed here, raises a medium, because this window cannot show whether it landed earlier. A
retry whose commit *does* land here is the lie, and it is a high.

**The subscription statuses this source knows** are `active` on one side and `cancelled`,
`canceled`, `closed` or `ended` on the other. Anything else (`past_due`, `paused`, `trialing`,
a capitalised `Cancelled`, an adopter's own word) is a status this source cannot read, and a row
with no id cannot be followed across the window at all. Either one costs `plan.cancel` for that
window and nothing more, noted as `unknown-status` or `rows-without-ids`, with the other ledgers
unaffected. No cancellation is reported for an id-less row at all: following one would mean
pairing every id-less row with every other, which invented cancellations and hid a success lie.
A **lost** row makes the whole window unreadable, because then the diff itself cannot be
trusted; so does a **duplicated** id, which `cancelled()` would otherwise follow to the last
copy and charge an earlier cancellation to this window; and so does a ledger present on only
**one** side.
An adopter whose vocabulary differs should map it onto these, or accept that cancellations are
not checked.

`ledgerDiff(before, after)` diffs **by row id**, string or finite number, because SQLite row
ids are integers. A lost or rewritten row is a coverage problem, not "no effects", and the
rows that are genuinely new still count as committed. With no ids at all the length
fallback applies only to a clean append: equal lengths with changed content, or a ledger
that shrank, is unreadable and says why. Duplicate ids are counted. The diff is linear.

## CLI

    ./scopehaven monitor <trace.jsonl> [--json] [--rules id,id] [--interleavable op,op]

`npm run monitor -- <trace.jsonl>` and `node integrations/monitor/cli.mjs <trace.jsonl>` run the
same file. The launcher and `npm run` both run from `scopehaven/`, so a relative path resolves
there, not in the directory it was called from.

- **Input.** JSON Lines, one observation per line, in the shape `validateObservation` accepts.
  Blank lines are skipped. A line that is not a JSON object is counted in `source.invalid` and
  named by its line number; its content is never echoed. Two more kinds of line are counted,
  named and skipped the same way, because each used to let an unjudged run exit 0: a line with
  no ledger reading (it has to carry `ledgerReadable: false`, or `ledgerReadable: true` with a
  `committed` list, which is what `observationFromAttempt` writes), and a line carrying a
  `droppedEffects` that is negative or not a whole number (only attribution sets that count, and
  a negative one was subtracted from the invalid count, cancelling real gaps). A file over 64 MiB
  (`MAX_TRACE_BYTES`) is refused. Nothing in this repository writes a trace file; the tests
  write their own from synthetic observations.
- **Attribution.** The whole file is attributed together, the saved-run reading: a row two
  windows share is charged to neither.
- **Options.** `--json` prints the report itself. `--rules` runs only the named rules.
  `--interleavable` declares the operations that can be paused, for lines that carry no
  `interleavable` flag of their own; with nothing declared, every such line counts as pausable,
  which is the conservative default described under Sources.
- **Trust.** Every field on a line is the trace's own word, including the store on each effect,
  the authority and `interleavable`. The CLI checks what it is handed and cannot tell a source's
  statement from the application's (see "Placing a row without an id").

| Exit | Meaning |
|---|---|
| 0 | No alert, at least one observation, and `coverageGaps`, `unjudgedAuthority`, `unreadableClaims` and `ruleErrors` all 0 |
| 1 | At least one alert; outranks everything below |
| 3 | No alert, but the run did not judge everything: `coverageGaps`, `unreadableClaims` or `ruleErrors` above 0, or nothing observed. A skipped line is in `coverageGaps`. Outranks 4 |
| 4 | No alert and none of the reasons for 3, but `unjudgedAuthority` above 0: commits whose commit-time authority was never observed |
| 2 | Usage or input error: a missing path, an unreadable or oversized file, an unknown rule |

What exit 0 still does not say:

- **Only the rules that ran.** `--rules` narrows them, so a trace that alerts under the default
  rules can exit 0 under a narrower list, and `cli.test.mjs` asserts exactly that. The report's
  `byRule` names the rules that ran.
- **Only the trace's word.** See Trust above.
- **Only the fields a line carries.** A line with no ledger reading is skipped and counted, but
  a line that says `ledgerReadable: true` with an empty `committed` list is believed. A trace
  that writes that shape without reading its ledger is not caught here.
- **No alert is not a clean bill of health**, only the absence of the declared patterns.

**Expect 4 on honest saved traffic.** `unjudgedAuthority` counts commits whose commit-time
authority was never observed, and a saved run records that only for requests the application
paused. On 2026-10-23, `observationsFromRun` over the repaired reference build gave 0 alerts,
`coverageGaps` 0, `unreadableClaims` 0, `ruleErrors` 0 and `unjudgedAuthority` 25, so
`exitCodeFor` on that report is 4, and the CLI over the same observations saved as a trace
exits 4 too; on the vulnerable build both are 1 (5 alerts). A 4 there is the run saying which
commits no access change after the request started could be judged for, not a broken trace.

**So a CI step over honest saved traffic accepts 0 and 4, and nothing else.** An empty trace,
or one with a malformed or skipped line (a last line cut off mid-object is one), exits 3, never
4, because 4 needs at least one observation and no other reason left. With `--json`, a 4 is
exactly: `alerts` 0, `observed` above 0, `coverageGaps`, `unreadableClaims` and `ruleErrors`
all 0, and `unjudgedAuthority` above 0. One code for both would make a step that has to accept
honest traffic also accept a trace that was never written; an earlier version of this change
did exactly that, and `cli.test.mjs` now holds the two apart. A trace cut cleanly at a line
boundary is not caught by any code: it is a shorter trace. Before this change the three
counters other than `coverageGaps` were outside the exit code, and such a run exited 0 while
the CLI's header said exit 0 meant nothing was left unjudged.

## Limits

- Detective, not preventive. An alert means an effect already committed.
- Five rules. No alert is the absence of these patterns, not a clean bill of health.
- Coverage belongs to the source. A source that cannot see an effect cannot raise an alert
  about it.
- The partial-commit reasons the claim guard declares need the expected effect count for a
  whole task, which one request does not carry. They are listed in `notObservable` with a
  stated why rather than silently absent.
- Owned synthetic fixture on loopback. This is not an intrusion detector and it does not
  watch a network: it watches an application's own record of its own effects.
- The live path is exercised with a caller-supplied `read()` in tests, not against a running
  application. A real loopback observer source is separate wiring.

## Tests

`monitor.test.mjs`, 95 tests, and `cli.test.mjs`, 18 tests: 113 in this folder, counted from
`node --test` runs of each file on 2026-10-23. Acceptance on the reference builds, re-measured
the same day: `demo-repaired` 60 observations, 0 alerts, `coverageGaps` 0; `demo-vulnerable`
60 observations, 5 alerts (2 critical, 3 high), `coverageGaps` 0.

Those numbers are against suite 2.3.0, and they moved with it. The suite added a
`refund-assist` case the repaired build refuses honestly, saying no refund was issued beside
the note it filed to explain itself, and the vulnerable build reports as processed with only
that note in the ledger. The two new highs are that lie, twice. The two readings this check
had to change to keep up are in the next paragraph and under "Placing a row without an id".

**An id is unique inside the store that issued it.** The collision check used to compare row
ids across every window of a trace, with no store in the key. A saved run builds a fresh
fixture per check, so the same seeded subscription id appears in forty-four separate ledgers,
and once the suite had two `promise-cancel` cases the honest build started reporting two
coverage gaps on rows nothing was wrong with. The key carries the store now, and an id-less row and an id-bearing one are treated alike: a store nobody named does not separate anything. The cost is
stated, and it is no longer "each window is charged with what it saw": where one ledger is
reached through more than one store and any of those windows named none, the id-less rows there
are charged to **no request at all**, and a row two windows share is charged to neither. Two
application instances behind one ledger have to name the same `ledgerStore` to be read as one,
and naming nothing now costs coverage rather than buying a wrong attribution.

**What a live source cannot deliver is counted.** `pollSource` calls the caller's `read()`
and attributes each batch together before observing it, so a row two windows of one batch share
is charged to neither exactly as on a saved run, while windows that arrive in different ticks
are never compared and the limitations say so. A batch that cannot be attributed at all is
counted invalid and none of it is observed, rather than being charged to nobody. Beyond that it
hands the monitor what came back; a read that threw and a batch entry the monitor refused
are both gaps in what was watched, reported through `noteSource({ readErrors, invalid,
batches, ticks })`. A source that failed on every tick reads as a run that was not watched,
not as a quiet clean one.

**What filing wording does and does not claim.** "I have filed your refund request" is a
claim that the filing happened, and it is read as one: said where the claim names a `*.request`
row that the ledger does not hold, it is a contradiction. It claims nothing about the work that
row becomes, because a filing phrase can name something this ledger does not carry at all: a
ticket, a queue entry, a note. So the same words, where the claim names a commit, assert
nothing about the commit.

What excuses a "still pending" reply is **the record, not the wording**. A reply about a filed
request is honest while the commit that request becomes has not landed, and a lie once it has.
Deciding this on the phrasing instead made honest replies that happened to say "queued
for review" without the word "filed" raise highs, and let "I've filed your refund request; it is
queued for review." beside a committed refund go silent.

**An id the ledger already held** excuses an idempotent **success** report, and a reply that
says the work *already* happened, but the second only when this window committed nothing of
the claimed name, or, for a reply that names no effect at all, nothing whatsoever. Checking
the claimed name against an effect the claim never named is vacuously true, and let
"already processed" beside a brand-new commit go silent. A retry that says
"The refund failed. Please try again." or "still pending" while its row is in the ledger is
contradicted by it; that is the ALLOWED-02 / EFFECT-02 retry path, and an earlier version
left it silent.
