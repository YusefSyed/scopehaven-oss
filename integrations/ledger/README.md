# Evidence ledger (scopehaven-ledger/1)

A hash-chained log of signed Scopehaven runs that the workbench operator keeps across releases and signs with the operator's own key. Each signed run envelope (`integrations/attest`) becomes one entry. The operator signs checkpoints over a Merkle tree head, so a reader holding an earlier checkpoint can tell whether entries it covers were later reordered, dropped, inserted, backdated or rewritten. The design follows certificate-transparency logs (RFC 9162 hashing and proofs). It is tested only on the owned synthetic fixture.

**What a verified ledger shows:**
- The holder of the ledger key signed these entries, in this order.
- Every entry's envelope was signed by the evidence key.
- The run identities each entry records are the ones that envelope's signed statement gives.
- Each run appears once.
- The ledger's own metadata is the one its checkpoints signed.

**What only a reader with something of their own can tell:**
- **Rollback.** A log cut back to an earlier checkpoint, with the later checkpoints removed, verifies on its own. A reader who kept a later checkpoint detects it (walkthrough step 2).
- **Rewrites by the key holder.** The holder of the ledger key can rebuild the chain and re-sign every checkpoint. A reader who kept an earlier checkpoint detects a rewrite of anything it covered. Verdicts can also be compared with the signed run files themselves (walkthrough step 4), which binds them to the evidence key rather than the ledger key alone.

**What it does not show:**
- That the checks, the application or the results are correct.
- That the operator showed everyone the same history, unless witnesses you trust cosigned it. Checkpoints are signed only by the operator, and each one says `"witness": "none"` (both verifiers reject any that says otherwise). A dishonest operator could keep two histories and sign checkpoints for each. Two things detect that: comparing checkpoints with other holders (or keeping your own), and **witness cosignatures** (see Witnessing). A witness is a party other than the operator who countersigns only a history that grows. The witness code is here, but nobody outside the operator runs a witness yet, and who does is Yusef's decision.

| File | Role |
|---|---|
| `ledger.mjs` | Writer: init, append, checkpoint, and inclusion and consistency proofs. It is the only code that writes a ledger. It appends an envelope only after the attest verifier verifies it against its files. |
| `verify.mjs` | Node verifier. It imports nothing from `ledger.mjs`, recomputes every hash and tree head itself, and uses the attest verifier only for signatures. |
| `verify_ledger.py` | Independent verifier for auditors: Python 3.8+ standard library, plus `../attest/verify_envelope.py`. |
| `history.mjs` | Permission history: verdict changes per check, read only from a verified ledger. |
| `anchors.mjs` | The ledger as EVID-SUBJECT's operator-held anchor: `anchorFor` returns the `{ count, head }` that `verifyChain` in `integrations/evid-subject/custody.mjs` expects. |
| `cli.mjs` | `init`, `append`, `checkpoint`, `prove`, `verify`, `history`, plus `witness-request` and `add-cosignature` for witnessing. |
| `witness.mjs` | A witness (run by a party other than the operator): keeps the last checkpoint it cosigned per log and countersigns only a consistent extension, in the C2SP cosignature/v1 format. It imports the reader's checks from `verify.mjs`, nothing from `ledger.mjs`. |

## Layout

```
ledger.json         {"ledger":"scopehaven-ledger/1","log":<uuid>,"createdAt":<time>}
entries.jsonl       one canonical JSON entry per line
checkpoints.jsonl   one canonical DSSE envelope per line: a signed Merkle tree head
envelopes/          a copy of every signed run envelope, named <sha256>.json
pending.json        only while a signed append is being written (see Recovery)
cosignatures.jsonl  optional: witness cosignatures, one {treeSize, rootHash, cosignature} per line (see Witnessing)
```

Each entry records:
- `index`;
- `prev`, the previous entry's leaf hash;
- `recordedAt`;
- the envelope's digest and signer;
- for each run, the identity the signed statement gives, and its per-check `verdicts` taken from the run file, with their `verdictDigest`. For a run export the identity is the run id, suite, policy, fixture and evaluator hashes, application, build and evidence origin, and the verdicts are its `results`. For a payments-pack run (`scopehaven-payments-run/1`) the identity is its run id, times, target, application, build and pack digest, and the verdicts are its `rows`, read only from a run that passes attest's payments checks (the rules of the pack's own reader). An envelope signed before payments runs had identities names none, so its payments run is in no entry;
- for each run, its custody `anchors`: one `{ source, custody, count, head }` per observer chain, where `count` and `head` come from EVID-SUBJECT's `anchorOf`. It is `[]` when none are given.

Each checkpoint signs the log id, the ledger's creation time, the tree size, root and head, and its own time.

Leaf hash = SHA-256(0x00 ‖ entry line), node hash = SHA-256(0x01 ‖ left ‖ right), as in RFC 9162.

## What the verifiers check

Both verifiers apply the rules below. The tests give both the same tamper cases and edge inputs and require the same outcome and reason code from each. They include three sets of edge probes: `ledger-probes.test.mjs` (K01 to K25), `ledger-parity.test.mjs` (R00 to R10, Q01 to Q21) and `ledger-parity3.test.mjs` (E00 to E28, P01 to P14, and a two-run envelope with its run files). `ledger-payments.test.mjs` adds payments runs: alone and beside a run export, refused ones, and a ledger recorded by an earlier build (`fixtures/ledger-main-0de64259`), which still verifies. On all of them both verifiers give the same verdict, reason and exit code; agreement on inputs nobody has tried yet is a claim the tests can only sample.

| Check | Reason when it fails |
|---|---|
| Each line is canonical JSON with the entry shape: known statuses, a run id per run, anchor sources matching one ASCII pattern | `entry-shape`, `entry-not-canonical` |
| Entry `i` is on line `i` | `index-mismatch` (raw reorder, drop or insert) |
| `prev` is the previous entry's leaf hash | `chain-broken` (renumbered reorder, drop, or a rewritten entry) |
| Times never go back: not before the ledger or the previous entry, not before the evidence was signed, not after a checkpoint that covers the entry | `time-regression` (backdating) |
| Verdict digests match the verdicts | `verdict-digest-mismatch` |
| Each envelope appears once and each run id appears once (twice within one entry is `entry-shape`) | `envelope-duplicate`, `run-replayed` |
| Each envelope is present, matches its digest, is signed by the evidence key, and states the run identities the entry records | `envelope-missing`, `envelope-mismatch`, `envelope-invalid`, `run-mismatch` |
| When run files are supplied, recorded verdicts equal the signed run file's: the `results` of a run export, which must be a list of objects with a string `id` and `status`, or the `rows` of a payments run that passes attest's payments checks | `verdict-mismatch` |
| At least one checkpoint exists: a canonical line, signed by the ledger key, for this log and this `ledger.json`, unwitnessed | `no-checkpoint`, `keyid-mismatch`, `checkpoint-signature`, `checkpoint-shape`, `ledger-mismatch` |
| No two checkpoints of one size disagree | `fork` |
| Checkpoints never go back in size or time | `checkpoint-regression` |
| Every checkpoint's root and head match the entries, not only the latest | `checkpoint-mismatch` |
| Inclusion and consistency proofs (RFC 9162 sections 2.1.3.2 and 2.1.4.2) | `inclusion-proof-invalid`, `consistency-proof-invalid` |
| With trusted witness keys only: cosignature lines are well formed; a trusted key's cosignature verifies; it names a tree size this ledger has, with the same root | `witness-policy`, `cosignature-shape`, `cosignature-invalid`, `witness-rollback`, `witness-fork` |

Both verifiers read JSON the same way:
- **Numbers** are read as JavaScript reads them. `1` and `1.0` are the same index. An integer up to 2^53 - 1 in size is an integer in both, so a 16-digit anchor count verifies in both; a larger one becomes the double JavaScript holds, so Python's integer-digit limit never applies.
- **Nesting** deeper than 256 levels is refused before parsing, with the reason for that file, so neither language's parser limits ever decide an outcome.
- **Invalid UTF-8** in an input file is judged by the verifier, not reported as a file error. A byte-order mark is never stripped.
- **Shapes:** a run id that is a list or an object is `entry-shape` in both, never a crash.

After a pass, each verifier runs negative controls through its own code, and each must be rejected; otherwise the verdict is `self-check-failed`. The controls are:
- a tampered checkpoint payload;
- a wrong key;
- a rewritten entry;
- a tampered inclusion path;
- a stored envelope with a tampered signature;
- two reordered entries.

## An operator-held, unwitnessed anchor for EVID-SUBJECT

EVID-SUBJECT (`integrations/evid-subject`) checks an observer's evidence chain against an anchor kept outside the subject's reach. Without one, a subject that drops the last records and reseals the chain leaves records that verify among themselves, and only custody catches it.

The ledger can hold that anchor:
1. `append --anchors` records each chain's `{ count, head }` beside the run.
2. A signed checkpoint covers it.
3. `anchorFor(verified, { runId, source })` hands it back for `verifyChain`. The tests show a resealed truncation verifies against the subject's own anchor and gets `chain-head-mismatch` against the ledger's.

**Anchors are append-only per run.** A run id is recorded once, so its anchor can be neither superseded by a later entry nor replaced by replaying the run. Both verifiers reject a second entry for the same run id (`run-replayed`), and `anchorFor` refuses rather than choose if two anchors ever appear.

**Custody is not a free-form claim.** The caller names the observer `source` that kept the chain, and it must be a source EVID-SUBJECT knows. The writer derives custody from that source with `custodyOf`, and a declaration can only lower it: the app's own audit table stays `subject-writable`. Naming the source is still the caller's statement.

**This is an operator-held, unwitnessed anchor.** It is outside the application's reach only where the application cannot write the operator's ledger folder or read the operator's key. File modes alone don't ensure that: an application running as the same user can write a 0700 folder and read a 0600 key. Keep the ledger on a machine or account the application under test cannot reach. Until a party other than the operator holds checkpoints, the operator's own key is the only thing behind the anchor.

**Concurrent writers:** the lock keeps out other runs of this writer, not someone else who can write the folder. So the writer builds the new entry and its checkpoint only from the bytes it just verified, and compares both files with those bytes just before writing and again after. A line someone injects while the writer runs is refused before the write, or left outside the new checkpoint and reported: the ledger then either stops verifying or verifies with that line as an unsigned tail. A change made after the writer finishes is caught by the next verification, not by that append. The writer never signs such a line, and neither does recovery (below). This is tested for either file, and with a real-process race probe.

**Cadence:** the CLI's `append` signs a checkpoint over each new entry before writing anything. The `appendEnvelope` API does the same when given the private key; without it, it leaves an unsigned entry and returns its `lineSha256`. The gap that remains is between the observer recording a chain and someone appending its anchor, so append as each run finishes.

If `integrations/evid-subject` is absent, anchors are refused and the anchor tests are skipped.

## Witnessing

A **witness** keeps, for each log it follows, the last checkpoint it countersigned. It cosigns a new checkpoint only when the operator's key signed it and a consistency proof shows it extends what the witness already saw. So once a witness has cosigned a size, the operator cannot get it to cosign a different history at that size, or any smaller one. The design follows C2SP's [tlog-witness](https://c2sp.org/tlog-witness) and [tlog-cosignature](https://c2sp.org/tlog-cosignature):

- **What is signed.** Each ledger checkpoint maps to a C2SP checkpoint note: origin `scopehaven-ledger/<log id>`, the tree size, the base64 root. The witness signs `cosignature/v1`, a `time` line (its own clock, whole seconds) and that note, with Ed25519.
- **The cosignature** is a signed-note signature line: the signed-note marker character (U+2014), a space, the witness name, a space, then base64(key id || 8-byte big-endian time || signature). The key id is SHA-256(name, newline, 0x04, public key) truncated to 4 bytes. A witness key is published as a vkey, `<name>+<key id>+<base64(0x04 || public key)>`. A witness name follows the C2SP cosigner-name rule: a non-empty UTF-8 string of at most 255 bytes, with no Unicode spaces, no `+` and no control characters below U+0020 (so `witness.example/α` and `#w` are names). Use a separate key for each witness, never the ledger key: the signed message does not include the name, so one key under two names would count as two witnesses, and the verifiers refuse a policy that lists one key twice.
- **The exchange.**
  1. The operator runs `cli.mjs witness-request --ledger DIR [--old-size N]`, which gives the latest checkpoint and a consistency proof from the size the witness last cosigned.
  2. The witness runs `witness.mjs add-checkpoint` on that request. It answers like tlog-witness: 200 with a cosignature; 400 malformed (including an old size larger than the checkpoint); 403 not signed by the log key it trusts; 404 unknown log; 409 the old size is not the size it last cosigned (the answer says that size); 422 the consistency proof does not verify or the checkpoint is not a consistent extension. That includes a non-empty proof from size 0, a non-empty proof between equal sizes, and the same size with a different root. Only a 200 changes its state, and the check and the update happen in one locked step.
  3. The operator stores the cosignature with `cli.mjs add-cosignature`, which checks it names a tree this ledger has.
  Nothing is sent anywhere by this code: requests and cosignatures are files that move however the operator and the witness agree. It follows tlog-witness's add-checkpoint rules but not its HTTP interface. A cosignature is returned as the signature line without its final newline, so a transport adds the framing.
- **Verifying.** Give `verify` (either verifier) the witness keys you trust, one vkey per line, with `--witnesses FILE`, and how many must agree with `--quorum K` (default: all of them). In that file, spaces and tabs around a line are ignored, and blank lines and comments (`#` alone, or `#` then a space or tab) are skipped. Every other line must be a vkey. A vkey holds no space, so a name may start with `#`. A key disabled by writing `#` directly before it fails as a bad vkey instead of being skipped quietly: delete the line or write `# ` before it.
  - Cosignatures from keys you don't trust are counted and ignored. A key must match on both name and key id.
  - A trusted key's cosignature must verify (`cosignature-invalid`).
  - The cosignature must name a tree this ledger holds. A cosigned size larger than the ledger means the ledger was **rolled back** (`witness-rollback`); a different root at that size is a **fork** (`witness-fork`). Either is caught from the cosignatures in the folder, without the reader having kept any earlier checkpoint. An operator who rolls back can also delete cosignature lines. The ledger then still verifies, but with a smaller `witnessedSize` or `witness: "none"`. A reader who relies on witnessing must check that field, not only the verdict. Better still, get the latest cosignature from the witness directly.
  - The result's `witness` field stays `"none"` unless some checkpoint size has cosignatures from at least K trusted witnesses. Then it gives the largest such size and whether the latest checkpoint is witnessed; the `witnessing` field lists every cosigned size and its witnesses.
  - `witnessCoverage` says which case applies: `"no-policy"` when no witness keys were given (nothing about witnesses was checked, and there is no `witnessing` field); `"not-met"` when keys were given but no checkpoint size reached the quorum; `"met"` when one did. The quorum is a reporting threshold: below it the ledger can still verify, so a reader who requires witnessing must require `"met"`.
  - Through the API (`verifyLedger` in `verify.mjs`, `verify_ledger` in `verify_ledger.py`), a quorum that is omitted, `null` or `None` means all of the trusted keys, as `verify` without `--quorum` does.
- **What witnessing does not show.**
  - A witness only vouches for the checkpoints it was shown. Readers who trust disjoint sets of witnesses could each be shown a different, internally consistent history, because nothing here makes witnesses compare notes.
  - A cosignature's time is the witness's clock. The verifiers report it and do not reject future times.
  - Witnessing says nothing about whether the entries' results are correct.
  - The format follows the C2SP specs as published. It has been checked against those texts, not run against another implementation of them.

## Auditor walkthrough

The operator sends the ledger folder and the ledger public key (and the evidence key, if different). Confirm the key's `keyid` over a separate channel, as with attest.

1. **Verify the whole history.**
   ```sh
   python3 verify_ledger.py log --key "$PWD/ledger.pub.pem" --ledger "$PWD/received-ledger"
   ```
   Exit 0 means verified. The output lists every checkpoint (size, root, time), how many entries are covered, and any unsigned tail.
2. **Keep the latest checkpoint.** Save the last line of `checkpoints.jsonl`. Next quarter, ask for a consistency proof from that size to the new one, then check that the new history extends the one you saw:
   ```sh
   python3 verify_ledger.py consistency --key "$PWD/ledger.pub.pem" --older "$PWD/saved-checkpoint.json" --newer "$PWD/new-checkpoint.json" --proof "$PWD/proof.json"
   ```
   The operator makes the proof with `node integrations/ledger/cli.mjs prove --ledger DIR --from 4 --to 9`. A failure means history you had already seen was rewritten.
3. **Check one run without the whole log.** Ask for that entry's line, an inclusion proof (`prove --index N`) and a checkpoint, then run `python3 verify_ledger.py inclusion --key … --entry … --proof … --checkpoint …`.
4. **Check the verdicts against the evidence.** Ask for the run files too, and add `--run-files DIR`. Each run whose signed file is in the folder has its recorded verdicts compared with that file's results. The output reports how many runs were checked (`verdictsCheckedAgainstRunFiles` of `runs`); runs without a file stay vouched for by the ledger key only.
5. **Check the witnesses.** If the operator says witnesses cosigned the log, get their vkeys from the witnesses themselves, not from the operator, and add `--witnesses FILE [--quorum K]` to step 1. A rollback or a second history shown to those witnesses then fails verification, as long as their cosignatures are in the folder. Check that `witness` is not `"none"` and that `witnessedSize` is at least the size the witnesses report having cosigned: an operator could have removed cosignatures.
6. **Read the permission history** (with Node): `node integrations/ledger/cli.mjs history --ledger /ABSOLUTE/DIR --key /ABSOLUTE/ledger.pub.pem`.

   For each run of comparable identity, it lists when each check's verdict changed. Compare that with the release record. A suite, policy, fixture, evaluator, application or evidence-origin change starts a new segment, and nothing is compared across segments. Payments runs are compared only with payments runs of the same target and pack, in segments of their own, so they never cut a run export's history.

## Use

```sh
node integrations/ledger/cli.mjs init --ledger /ABSOLUTE/ledger          # an existing 0700 folder
node integrations/ledger/cli.mjs append --ledger /ABSOLUTE/ledger --key /ABSOLUTE/scopehaven-signing-key.pem --evidence-key /ABSOLUTE/pub.pem --envelope /ABSOLUTE/run.dsse.json --dir /ABSOLUTE/exports
node integrations/ledger/cli.mjs verify --ledger /ABSOLUTE/ledger --key /ABSOLUTE/pub.pem [--run-files /ABSOLUTE/runs]
```

Every command, in both CLIs, takes absolute paths only.

The writer refuses:
- to build on a ledger that doesn't verify. That includes a torn last line: restore the folder from your last verified copy;
- to extend or sign over entries no checkpoint covers;
- a run whose run file the verifiers could not read back (not UTF-8, nested deeper than 256, or `results` not a list of objects with a string `id` and `status`, or a payments run that fails attest's payments checks), or whose recorded results they would reject;
- an envelope that doesn't verify against its files;
- a duplicate envelope, a run id already in the ledger, or an envelope that names one run twice;
- a clock earlier than the ledger, the envelope, the previous entry or the last checkpoint;
- a checkpoint with nothing new;
- an `envelopes/` folder that is a symlink or not private;
- a second writer while `.lock` exists, or a new append while `pending.json` exists.

A writer removes `.lock` only while it still holds its own token. If `envelopes/` is swapped for a symlink or another folder during the write, it removes the copy it just created and refuses.

## Recovery

A signed append first signs an **intent**: a record of the head its checkpoint will have (size, root, head and time), under its own payload type (`application/vnd.scopehaven.ledger-intent+json`) and meaning text that says it is not a checkpoint. Both verifiers refuse it as a checkpoint, and its signature cannot be reused as one, because DSSE signs the payload type. The append then places `pending.json` (the entry line, the envelope and that intent) before it touches anything else. `pending.json` and the envelope copy are written whole under a temporary name, synced, then linked into place and the folder synced, so a crash leaves each either absent or whole, never torn. A stray dot-prefixed temporary file can remain; neither verifier reads it, and the next `append` or `checkpoint` removes it under the lock. The append removes `pending.json` only after the entry and checkpoint are appended and both files match what it wrote.

What `checkpoint` can finish, and what it cannot:
- **A crash or kill at any point after `pending.json` is in place** (before the envelope copy, between the two appends, or before `pending.json` is removed): `checkpoint` writes the envelope copy if it is missing or not whole, appends the pending entry line if `entries.jsonl` stops just before it, and signs and appends the checkpoint the intent fixes if it is missing. That is the only thing it signs: the size, root, head and time come from the intent, and Ed25519 signing is deterministic, so the line is byte for byte the one the append would have written. It does all this only when the intent is signed by the ledger key for this log and the result verifies with that checkpoint covering every entry. The tests kill a real CLI append at each of these points.
- **A crash before `pending.json` is in place** leaves nothing to finish: the ledger is as it was, and the append can simply be run again.
- **A crash in the middle of appending a line**, which leaves a torn last line, is not finished: the ledger stops verifying, and the folder has to be put back to just before that write (then `checkpoint` completes it).
- **Any line this write did not make** (a forgery, a rewritten copy of the operator's own uncovered line, or anything after it) is refused, and so is a tail with no `pending.json`. The refusal says what to do, judged from this folder alone:
  - **First, check held checkpoints.** The folder only shows what its own `checkpoints.jsonl` covers, and a checkpoint line can be lost (deleted by someone who can write the folder, or an older copy of the file restored) while you or an auditor still hold it. So every refusal that suggests removing lines or appending again first says to compare with the last checkpoint anyone holds. If that checkpoint covers more entries than this folder's, restore `checkpoints.jsonl` and `entries.jsonl` from a copy that verifies against it. Removing lines and appending again would sign a second history at a size someone already holds: a fork, which that holder's consistency check reports.
  - **Otherwise:** remove the lines no checkpoint in this folder covers, when the ledger verifies up to its last checkpoint; delete `pending.json` when the ledger verifies on its own and covers every entry (a stale or unreadable `pending.json` that nothing depends on).
  - **Restore the folder** when the ledger does not verify on its own.

The `checkpointLedger` API also signs a new checkpoint over a tail of unsigned API appends, but only when the caller names those lines by the `lineSha256` values the appends returned (`expectedTail`). The CLI's `append` always signs, so the CLI's `checkpoint` only finishes `pending.json`. Give it `--evidence-key` when the evidence key is not the ledger key.

What recovery cannot do: if someone deletes `pending.json`, the stopped write's own line is unexplained and stays unsigned until it is removed. That blocks the ledger; it never signs anything. A stale `pending.json` (or a stray temporary copy of one) holds only an intent, never a checkpoint, so an abandoned write leaves no second signed head by itself. One way remains to turn it into one: the key holder runs `checkpoint` on a copy of the folder that still holds the stale intent, after the real ledger has moved on at that size. Recovery then signs the checkpoint the intent fixes, and anyone holding the real head sees a fork. So when the advice says to delete `pending.json`, delete it rather than keep it, and run `checkpoint` only in the ledger's own folder.

## Limits

- No external witness runs yet, and no trusted timestamp. Witnessing works locally (see Witnessing), but no party other than the operator runs a witness, and OpenTimestamps anchoring is a separate step. Checkpoint times are the operator's clock, checked only for order.
- No key rotation. Changing either key part way through makes the ledger unverifiable under any single key, so a ledger lives as long as its keys.
- Single writer per folder, with a local lock file.
- **Size and cost:**
  - Up to 100,000 entries per log, and as many checkpoints, one per signed append.
  - Verification is linear in the entries. Measured with a checkpoint per entry, Node took about 0.15 to 0.36 ms per entry and Python 5.5 to 9.8 ms (1,000 to 8,000 entries, on a shared machine whose load varied), so a full 100,000-entry ledger would take tens of seconds in Node and 10 to 16 minutes in Python.
  - Before every signed append the writer verifies the whole existing ledger once, with Node, so an append costs about twice a Node verification of the ledger (measured at 2.84 s against 1.44 s at 8,000 entries).
- The history view compares the identity fields an entry carries. It doesn't apply every rule `compareRuns` does (for example HTTP actor signatures).
- Verdicts are recorded from the run file at append time. Without the run files, the ledger key alone vouches for them.
- A payments run file is read through attest's own parser. In Python, an integer longer than 309 digits is first written as the infinity Node reads it as, since no double holds 10^309 or more. That is a linear pass, so Python's integer-digit limit (at least 640 digits, 4300 by default in 3.11 and later and in some earlier security releases) never applies to a number.
- A ledger that holds payments entries needs this version or later for `verify --run-files` and `history`. An earlier verifier reports `verdict-mismatch` for those entries' run files, as if they were edited. An earlier `history` compares payments rows across packs and targets, and lets them cut a run export's segments. Verification without run files, and the writer, work as before in either version.
