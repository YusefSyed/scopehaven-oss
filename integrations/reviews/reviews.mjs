// Reviewer sign-off: a person's agreement or dispute with one finding,
// recorded beside the verdict and never inside it.
//
// A review (scopehaven-review/1) is { reviewer, at, runId, findingId, decision: agree |
// dispute, reason }. It is kept in a review store next to the run store's notes: outside
// the run core and its integrity hash, like human notes, and never read by the runner, the
// comparison or the gate. Each review is signed with integrations/attest when it is
// recorded, and the store keeps the signed bytes and the envelope; reading it back
// verifies every signature against the reviewer key it was given.
//
// What reviews change: nothing that is computed. Verdicts, comparison labels and gate exit
// codes are byte-identical with or without reviews. They add counts beside the results
// (reviewed, agreed, disputed) and, in a gate summary, a "reviewer disputes" line for each
// failed check a reviewer disputes, with the exit code left as computed. The counts name
// the run they belong to, and are attached only to a gate summary or SARIF log of that run,
// or to a comparison that holds it (with its role, baseline or candidate).
import { constants } from 'node:fs';
import { mkdir, open, link, unlink, readdir, readFile, lstat } from 'node:fs/promises';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { signFiles } from '../attest/sign.mjs';
import { verifyEnvelope } from '../attest/verify.mjs';

export const REVIEW_SCHEMA = 'scopehaven-review/1';
export const REVIEW_VERSION = '1.0.0';
export const DECISIONS = Object.freeze(['agree', 'dispute']);
export const REVIEW_LIMITS = Object.freeze({ reason: 1000, reviewer: 120, perRun: 2000 });
const ID = /^[A-Za-z0-9_.:-]{1,120}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
// Line breaks and control characters would let a name or reason forge lines in a text summary;
// format characters (Cf: bidirectional overrides and isolates, zero-width spaces, the BOM) would
// let it reorder or hide what a reader sees.
const CONTROL = /[\u0000-\u001f\u007f-\u009f\u2028\u2029\p{Cf}]/u;
export class ReviewError extends Error { constructor(code) { super(`Invalid review: ${code}.`); this.name = 'ReviewError'; this.code = code; } }
const fail = code => { throw new ReviewError(code); };

// A review of one finding in one saved run. A dispute needs a reason.
export function validateReview(review, run) {
  if (!review || typeof review !== 'object' || Array.isArray(review)) fail('shape');
  const keys = Object.keys(review).sort().join(',');
  if (keys !== ['at', 'decision', 'findingId', 'reason', 'reviewer', 'runId', 'schema'].sort().join(',')) fail('fields');
  if (review.schema !== REVIEW_SCHEMA) fail('schema');
  if (typeof review.reviewer !== 'string' || !review.reviewer.trim() || review.reviewer.length > REVIEW_LIMITS.reviewer || CONTROL.test(review.reviewer)) fail('reviewer');
  if (typeof review.at !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/.test(review.at)) fail('at');
  if (!DECISIONS.includes(review.decision)) fail('decision');
  if (typeof review.reason !== 'string' || review.reason.length > REVIEW_LIMITS.reason || CONTROL.test(review.reason) || (review.decision === 'dispute' && !review.reason.trim())) fail('reason');
  if (run) {
    if (review.runId !== run.id) fail('run');
    if (!ID.test(review.findingId) || !run.results.some(r => r.id === review.findingId)) fail('finding');
  }
  return review;
}
export const makeReview = ({ reviewer, runId, findingId, decision, reason = '', at = new Date().toISOString() }) => ({ schema: REVIEW_SCHEMA, reviewer, at, runId, findingId, decision, reason });

// The review store: <dataDir>/reviews/<runId>/<n>.review.json (the signed review bytes) and
// <n>.dsse.json (its envelope). The sequence number is claimed by publishing exclusively, so
// two reviews recorded at once never share one, and files are never rewritten.
// Publish a file exclusively: written to a temporary name, then linked into place, so an
// existing file is never replaced (the link fails with EEXIST).
export async function publishExclusive(path, content) {
  const temporary = `${path}.${randomUUID()}.tmp`;
  const handle = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { await handle.writeFile(content); await handle.sync(); } finally { await handle.close(); }
  try { await link(temporary, path); } finally { await unlink(temporary).catch(() => {}); }
}
const NUMBERED = /^(\d{5})\.(?:review|dsse)\.json$/;
export function createReviewStore(dataDir) {
  const dir = runId => { if (!UUID.test(runId ?? '')) fail('run-id'); return join(dataDir, 'reviews', runId); };
  const exclusive = publishExclusive;
  return {
    // Record a signed review of a saved run (the run as the run store returns it).
    async record(run, review, { privateKey, now }) {
      validateReview(review, run);
      const where = dir(run.id);
      await mkdir(where, { recursive: true, mode: 0o700 });
      const content = Buffer.from(`${JSON.stringify(review, null, 1)}\n`);
      const files = await readdir(where);
      if (files.filter(f => f.endsWith('.review.json')).length >= REVIEW_LIMITS.perRun) fail('too-many');
      // The next number is one past the highest in use (a review or an envelope), so a gap or a planted file never blocks recording.
      let next = Math.max(0, ...files.map(f => NUMBERED.exec(f)?.[1]).filter(Boolean).map(Number)) + 1;
      for (let attempt = 0; ; attempt++, next++) {
        if (next > 99999) fail('too-many');
        const name = `${String(next).padStart(5, '0')}.review.json`;
        const { envelope } = signFiles([{ name, content }], { privateKey, version: REVIEW_VERSION, now });
        // The envelope is published first: whoever publishes it owns the number. A collision on either file moves to the next number.
        try { await exclusive(join(where, name.replace(/\.review\.json$/, '.dsse.json')), envelope); await exclusive(join(where, name), content); }
        catch (error) { if (error?.code === 'EEXIST' && attempt < 32) continue; throw error; }
        return { name, review };
      }
    },
    // Every review of a run, in the order recorded, each verified against the reviewer key (a
    // public key PEM: the attest verifier refuses a private one). A review whose signature or
    // bytes do not verify, or that has no envelope, is returned as unverified, never counted.
    async read(runId, { publicKey }) {
      const where = dir(runId);
      let files;
      try { if ((await lstat(where)).isSymbolicLink()) fail('store-symlink'); files = (await readdir(where)).filter(f => f.endsWith('.review.json')).sort(); }
      catch (error) { if (error?.code === 'ENOENT') return []; throw error; }
      const out = [];
      for (const name of files) {
        const content = await readFile(join(where, name)), envelope = await readFile(join(where, name.replace(/\.review\.json$/, '.dsse.json')), 'utf8').catch(() => null);
        const check = envelope ? verifyEnvelope({ envelope, publicKey, files: new Map([[name, content]]) }) : { verified: false };
        let review = null;
        try { review = validateReview(JSON.parse(content.toString())); } catch {}
        out.push({ name, verified: check.verified === true && review !== null && review.runId === runId, review });
      }
      return out;
    },
  };
}

// Counts beside the results. The latest verified review of a finding decides its state.
export function reviewSummary(run, entries) {
  const latest = new Map();
  for (const e of entries) if (e.verified && e.review.runId === run.id && run.results.some(r => r.id === e.review.findingId)) latest.set(e.review.findingId, e.review);
  const status = new Map(run.results.map(r => [r.id, r.status]));
  const disputes = [...latest.values()].filter(r => r.decision === 'dispute').map(r => ({ findingId: r.findingId, status: status.get(r.findingId), reviewer: r.reviewer, at: r.at, reason: r.reason }));
  return {
    runId: run.id, reviewed: latest.size, agreed: [...latest.values()].filter(r => r.decision === 'agree').length, disputed: disputes.length,
    unverified: entries.filter(e => !e.verified).length,
    // Verified reviews of a check this run does not have: shown, never counted.
    outsideRun: entries.filter(e => e.verified && e.review.runId === run.id && !run.results.some(r => r.id === e.review.findingId)).length, disputes,
    scope: 'Reviews are human readings recorded beside the results; they never change a verdict, a comparison label or a gate exit code.',
  };
}

// A gate summary with the reviews beside it: the computed fields are copied as they are, and
// a failed check a reviewer disputes is listed as "reviewer disputes".
export function annotateGateSummary(summary, reviews) {
  if (!summary?.current?.runId || summary.current.runId !== reviews.runId) fail('run-mismatch');
  const failedDisputes = reviews.disputes.filter(d => d.status === 'fail');
  return { ...structuredClone(summary), reviews: { runId: reviews.runId, reviewed: reviews.reviewed, agreed: reviews.agreed, disputed: reviews.disputed, unverified: reviews.unverified,
    lines: failedDisputes.map(d => `${d.findingId}: reviewer disputes (${d.reviewer}, ${d.at}): ${d.reason}`.slice(0, 600)), scope: reviews.scope } };
}
// An export with the review counts beside its results: a SARIF log of the reviewed run, or a
// comparison document that holds it, naming its role. Anything else is refused.
export function annotateExport(document, reviews) {
  const counts = { runId: reviews.runId, reviewed: reviews.reviewed, agreed: reviews.agreed, disputed: reviews.disputed, unverified: reviews.unverified, scope: reviews.scope };
  const copy = structuredClone(document);
  if (Array.isArray(copy.runs)) {
    if (!copy.runs[0]?.properties?.runId || copy.runs[0].properties.runId !== reviews.runId) fail('run-mismatch');
    copy.runs[0].properties.reviews = counts;
  } else if (copy.document === 'scopehaven-comparison/1') {
    const role = copy.baseline?.runId === reviews.runId ? 'baseline' : copy.candidate?.runId === reviews.runId ? 'candidate' : null;
    if (!role) fail('run-mismatch');
    copy.reviews = { ...counts, role };
  } else fail('document');
  return copy;
}
