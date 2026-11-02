# Signed evidence (scopehaven-attest/1)

Signs exported evidence files so someone else can check, without trusting Scopehaven or its operator's machine, that they are the exact files the key holder produced. The format is standard: a [DSSE](https://github.com/secure-systems-lab/dsse) envelope carrying an [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md), signed with a local Ed25519 key.

**What a valid signature shows:** the holder of this signing key produced these exact files, and the run identities in the statement are the ones inside the run files: for a run export its suite, policy, fixture, evaluator, application, build and evidence origin; for a payments-pack run its pack digest, target, application, build and times.

**What it does not show:** that the checks, the application or the results inside the files are correct. The signature's own statement says so, and both verifiers reject any statement that says otherwise.

| File | Role |
|---|---|
| `sign.mjs` | Builds the statement, signs it, then runs the verifier on the result; nothing is returned unless that passes |
| `verify.mjs` | Node verifier. Imports only Node built-ins: nothing from `sign.mjs` or `src/` |
| `verify_envelope.py` | Independent verifier for auditors: Python 3.8+ standard library only, with its own Ed25519 (RFC 8032) |
| `cli.mjs` | `keygen`, `sign`, `verify` and `countersign` commands |
| `verify-countersign.mjs` | Node verifier for ScopeHaven's countersignature and its RFC 3161 timestamp (own DER reader; Node built-ins and `verify.mjs` only) |
| `countersign.mjs` | The hash-only countersign request, the countersigning step and the RFC 3161 client |
| `scopehaven-keys.json` | ScopeHaven's published key set (`scopehaven-keys/1`), byte for byte the file served at `https://scopehaven.dev/.well-known/scopehaven-keys.json` |
| `test-tsa.mjs` | A test-only time-stamping authority made in memory for the tests; never trusted outside them |

## What gets checked

Both verifiers apply these rules. The tests check that they give the same verdict and reason code for every tamper case, and the same run identities for real exports.

- The envelope has exactly one signature, from the trusted key (its `keyid` is the SHA-256 of the public key), over the DSSE encoding of the payload type and payload. Base64 must be canonical. Ed25519 signatures with S >= L, and small-order keys or R points, are rejected.
- Only then is the payload parsed. It must be canonical JSON (no reordering, spacing or duplicate keys), an in-toto Statement v1 with this predicate type and the fixed meaning text.
- Every named file is present and matches its SHA-256. When files are listed one by one, a file the signature doesn't cover is rejected rather than ignored. With `--dir`, only the files the statement names are read; anything else in the folder is neither checked nor vouched for.
- Run identities are recomputed from the run files, never read from the statement. A run export whose results no longer match its own integrity hash is rejected, and the signer refuses to sign one. That hash has no key, so this catches careless edits only: someone who edits a result and recomputes the hash can still sign it. A signature says who signed, never that the results are true.
- **Payments-pack runs** (`scopehaven-payments-run/1`, from `./scopehaven payments run` or `payments export --format json`). Any JSON object (valid UTF-8, as every file the verifiers read as a run must be) that declares this schema is checked by the rules of the pack's own reader (`savedPaymentsRun` in `integrations/payments-pack/output.mjs`), written out in both verifiers: its run id; its `sha256` over everything but itself (`run-integrity-mismatch` when it differs); exactly a run's fields; the pack's scope text; rows with distinct ids whose status is the worst of their assertions, whose settlement findings are tags on a control and withheld on a boundary, and which pass only where the check request reached the app (a boundary only with no settlement finding); counts that are those statuses; a test-mode provider; and its start and finish times. A run that fails them is rejected (`payments-run-refused`), as the export refuses it, and gets no identity. The `sha256` has no key either: a run edited consistently and resealed passes. A comparison that `payments run --baseline` stores beside a run is outside its `sha256`, as in the pack, so it is covered by the file's digest only. The identity is the run's `id`, `schema`, `startedAt`, `finishedAt`, `targetId`, `applicationId`, `build` and `packSha256`, and `coreSha256`. Its `name`, `scope` and nested records (provider, authorization, counts, rows, settlement) are covered through `coreSha256` only. A file that is both a run export and a payments run is read as a run export.
- **Unnamed payments identities.** Envelopes signed before payments runs had identities name none (`runs: []`). Such an envelope still verifies when its run passes the checks above. The run's name is listed in `unclaimedRuns`, and a `note` says the signature covers its bytes but no run identity. An older envelope over a file that declares the schema and fails those checks, which the old signer signed as plain bytes, is now rejected. A statement must still name every run export's identity, and any payments identity it names must equal the recomputed one. Leaving one out needs the key and claims less, never something else.
- **Negative controls.** After an envelope passes, each verifier sends tampered copies through the same code: payload, signature, payload type, a fresh wrong key and one signed file. For the first run export and for the first payments run, named or not, it also sends that run's file with one edit only its digest covers (an added field for a run export, a changed `name` for a payments run, since its field-set rule would refuse an added field) and a statement naming its identity with one changed digest. Each must be rejected. If any is accepted, the verdict is `self-check-failed`, never `verified`. The Python verifier also checks the RFC 8032 test vector, since its Ed25519 is hand-written.

## Use

The operator signs. `./scopehaven export` signs each export by default: it writes `NAME.dsse.json` beside the file, with a key in `~/.config/scopehaven/signing` that the first export creates (`--signing-key-dir ABSOLUTE_DIR` uses another directory, `--unsigned` skips signing). Its output names the envelope, the key id, the public key and both verify commands. The signer verifies its own envelope before writing it, and a failed sign removes the export. A key or directory with a wrong mode or owner is refused (`signing-key-unsafe`), never repaired. `./scopehaven payments export` and `./scopehaven evidence-pack` sign the same way, and a payments run's JSON export is signed with its run identity. The GitHub Action and the scheduled drift runner export unsigned, and library callers of `exportRun()` sign only when asked.

Signing by hand after export is optional, for example to put several files in one envelope. Directories for keys and envelopes must already exist with mode 0700. Nothing is overwritten, and the private key is written 0600 and never printed.

```sh
node integrations/attest/cli.mjs keygen --dir /ABSOLUTE/keys
node src/export-cli.mjs --run RUN_ID --format json --out /ABSOLUTE/exports/run.json
node src/export-cli.mjs --run RUN_ID --format sarif --out /ABSOLUTE/exports/run.sarif
node integrations/attest/cli.mjs sign --key /ABSOLUTE/keys/scopehaven-signing-key.pem \
  --out /ABSOLUTE/exports/evidence.dsse.json /ABSOLUTE/exports/run.json /ABSOLUTE/exports/run.sarif
```

The two export lines also sign each file by default (`./scopehaven export` runs `src/export-cli.mjs`); add `--unsigned` to them to keep only the combined envelope.

Send the files, the envelope and `scopehaven-signing-key.pub.pem`. Confirm the `keyid` printed by `keygen` (or by the export) with the recipient over a separate channel.

The recipient verifies with either verifier:

```sh
python3 verify_envelope.py --key scopehaven-signing-key.pub.pem --envelope evidence.dsse.json --dir ./received
node integrations/attest/cli.mjs verify --key scopehaven-signing-key.pub.pem --envelope evidence.dsse.json --dir ./received
```

Exit codes: 0 verified, 1 rejected (the output names the reason), 2 usage or file error, 3 self-check failed (do not rely on that verifier).

## ScopeHaven countersignature (scopehaven-countersign/1)

The operator's envelope stays the first signature. ScopeHaven can add a second one, over hashes only, plus an RFC 3161 timestamp, so a reviewer gets a key that is not the operator's, a published key id, a time neither signer controls, and stated rotation and revocation. [docs/SIGNING-KEYS.md](../../docs/SIGNING-KEYS.md) has the published keys, the commands and the limits.

- `countersignRequest()` reads the envelope and builds the only thing sent: `request`, `licenceId`, `release`, `statementSha256` (the SHA-256 of the envelope's payload), `signerKeyid`, `signatureSha256` and a `nonce`.
- `countersignService()` takes exactly that body (any other field is refused). It signs an in-toto Statement v1 (`https://scopehaven.dev/attestation/countersignature/v1`) whose one subject, `evidence-statement`, is the statement's SHA-256 and whose predicate names the first signature, the request and a fixed meaning. It then has the TSA stamp the SHA-256 of that signature.
- `node cli.mjs countersign --envelope ABS/NAME.dsse.json --key ABS/SCOPEHAVEN_KEY --licence-id ID [--scopehaven-keys FILE] [--tsa-url URL]` writes `NAME.countersign.dsse.json` and `NAME.countersign.tsr` beside the envelope. It writes only after the result verifies, and it never overwrites a file.
- Both verifiers take `--scopehaven-keys KEYS.json --countersignature FILE --timestamp FILE` (all three or none). After the first envelope verifies, they check: the countersigning key is in the set (`countersign-key-unknown`); its signature; the statement's shape; that it names this envelope's statement (`countersign-subject-mismatch`) and first signature (`countersign-signer-mismatch`); and the timestamp. For the timestamp they check a granted SignedData over a TSTInfo with one signer, the signed attributes' content type and digest, the ESS signing-certificate hash, and the signature (RSA 2048+ or ECDSA P-256/P-384). The signer's certificate must be for time stamping only (critical extended key usage), valid at `genTime`, and issued by a pinned root valid then (`timestamp-untrusted`). The token must stamp the countersignature's SHA-256 (`timestamp-imprint-mismatch`). Finally, the key must have been in use at `genTime` and not revoked by then (`countersign-key-not-valid`, `countersign-key-revoked`). Other failures are `countersign-shape`, `countersign-signature-invalid`, `timestamp-invalid`, `countersign-time-inconsistent` (the countersigner's clock more than five minutes ahead of the TSA's), `keyset-invalid`, and `countersign-missing` or `timestamp-missing` when a file is absent.
- **Negative controls.** After a countersignature passes, each verifier sends nine tampered cases through the same code: the payload, the signature, an unpublished key, another statement, another first signature, a token over another digest, a token with one TSTInfo byte changed, no trusted root, and a key revoked at `genTime`. If any is accepted, the verdict is `self-check-failed`.

`countersign.test.mjs` runs both verifiers on every case and checks that they agree on the verdict, the reason and the exit code. The cases include the rehearsal's forgery: a run edited, its integrity hash recomputed, and the files re-signed with a new key. That forgery fails with the genuine countersignature kept (`countersign-subject-mismatch`), with the forger's own countersignature (`countersign-key-unknown`) and with none (`countersign-missing`). The test also checks Python copies with the imprint or revocation check removed (each must fail its own controls), the CLI over a loopback test TSA, and the published key set against its site copy. It also checks that the sample pack (`examples/sample-evidence-pack/pack/`, with a real freetsa.org token) verifies offline.

## Limits

- The operator signature's `signedAt` is the signer's local clock. Only a countersigned pack carries a trusted (RFC 3161) time.
- The operator's key has no rotation, revocation or transparency log. Trust in it comes from confirming its `keyid` out of band, or from a ScopeHaven countersignature that names it. ScopeHaven's own keys rotate and are revoked as [docs/SIGNING-KEYS.md](../../docs/SIGNING-KEYS.md) states. There is no transparency log.
- Countersigning is a local CLI that ScopeHaven runs with an interim key. There is no hosted endpoint and no licence check yet. A countersignature does not show that ScopeHaven ran the checks.
- The private key is protected by file permissions only. There is no passphrase, hardware key or keyless (Sigstore) signing yet.
- One signature per envelope: the countersignature is a separate envelope.
- Run identities are recomputed only for run exports from the store (JSON with `schemaVersion`, `id`, `suiteHash` and `integrity`) and payments-pack runs (JSON declaring `scopehaven-payments-run/1`). Other files, such as SARIF, HTML, comparisons (the payments comparison too) and sequence results, are covered by their digests only.
- A payments run's start and finish times must be ISO strings as the pack writes them (`toISOString`): a year from 2000 to 2999, milliseconds, `Z`, and a real date that prints back the same. The pack's reader takes anything `Date.parse` reads (another year, no milliseconds, February 29 of a common year, 24:00), and the verifiers refuse those, because Python cannot match `Date.parse`.
- An envelope that names a payments run identity needs a verifier from this change or later. An earlier one has no payments identity of its own to compare, and rejects it with `run-identity-mismatch` as if it were edited. The producer version and the `scopehaven-attest/1` format are unchanged, so nothing else in the envelope tells the two apart.
- The statement's `producer.release` names the build that signed, and a run's own `producer.release` names the build that ran it: `{ source, version, commit, manifestSha256 }`, from the install's `RELEASE-MANIFEST.json`, else the checkout's HEAD, else `unknown` (`src/producer.mjs`). Both verifiers print them apart as `builds.packing` and `builds.running`, since a pack can be made by another version than the run; a statement or run older than the field reads `null`. Each is what that install said of itself: an edited copy can say anything, and a checkout's HEAD says nothing of uncommitted edits. A statement that names a release needs a verifier from this change or later: an earlier one rejects it with `predicate-shape`. Oracle, refund and framework-mode runs have closed records, and a projected run is built from an existing run folder, so those name no build in their core and `running` reads `null` for them. A run's build is outside its evaluator identity, its contract view digest and comparisons, so two builds of different commits grade and compare alike.
- A file that is not valid UTF-8 is never read as a run, so it is covered by its digest only. The pack's own reader decodes lossily and may take it. Exports are always valid UTF-8.
- The Python CLI prints numbers as Python does (`1e+16` where Node prints `10000000000000000`), and prints a number beyond a double as `null`, as Node does. The run identities the verifiers compare are canonical bytes, and those agree.
- Human notes in a run export are covered by the signature like any other bytes. They never change computed results.
- The Python verifier refuses (`subject-unparseable`) valid JSON beyond its parser's limits: nesting deeper than roughly 500 levels, or integers over 4300 digits on Python 3.11 and later. Node accepts these. Exports from the store contain neither.
- Files are opened without following symlinks, and FIFOs or other non-regular files are refused.

`attest.test.mjs` signs real exports of the owned synthetic fixture and of the checked-in payments sample runs, in one envelope, and checks the tamper set against both verifiers. It also covers a verifier that accepts every signature, small-order key forgeries, number formats JavaScript and Python print differently, the CLI's file rules, and the Python digest port against `src/domain.mjs`. For payments runs it checks that both verifiers agree with the pack's reader on 44 payments run files: valid ones, edited ones and resealed ones. It checks that they recompute the same identity bytes the signer named, and that `payments export` and `evidence-pack` name the identity. It also checks that an envelope `payments export` signed by an earlier version (`fixtures/payments-main-848cb8a6`, a fresh owned-demo run, no identity named) still verifies. A copy of either verifier with its payments digest check removed must fail its own negative controls, and a run whose notes or stored comparison nest past a parser's limits must be refused with a reason, never a crash. A third test bisects for the depth where Node stops verifying and checks every depth within ten levels of it, through the library and the CLI.
