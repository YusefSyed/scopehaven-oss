// Read-only collection of saved trials for a pass^k column.
// Pages the core store's history, keeps the runs whose trialIdentity matches the
// primary's (never the primary itself) and loads each through store.get, which
// checks the record against its own sha256 seal (consistency, not authentication;
// checksFromRun then validates each run's evidence). Every read or integrity error
// propagates; no run of the primary's identity is ever skipped. It never saves,
// deletes, reruns or retries anything, and pooling only works on what the store
// still holds: a run deleted from it goes unnoticed.
import { PassKError, PASS_K_MAX, trialIdentity } from './passk.mjs';

const PAGE_LIMIT = 100;
const MAX_PAGES = 1000;
const byCodeUnit = (a, b) => a < b ? -1 : a > b ? 1 : 0;
// A saved run whose model identity names no single observed model has no trial identity, so it
// matches nothing (as a run of another model would not); one such run never blocks collection.
const identityOf = summary => {
  try { return trialIdentity(summary); } catch (error) { if (error instanceof PassKError && error.code === 'trial-identity-differs') return null; throw error; }
};

/**
 * Every saved run of the primary's trial identity, oldest first (createdAt, then id;
 * checksFromRun refuses any createdAt that is not in toISOString form). More than `max`
 * refuses (too-many-trials). A primary whose model identity binds no single model
 * refuses (trial-identity-differs).
 */
export async function collectSavedTrials({ store, primary, max = PASS_K_MAX - 1 } = {}) {
  if (!store || typeof store.historyPage !== 'function' || typeof store.get !== 'function' || primary === null || typeof primary !== 'object' || typeof primary.id !== 'string'
    || !Number.isSafeInteger(max) || max < 0 || max > PASS_K_MAX - 1) throw new PassKError('invalid');
  const identity = trialIdentity(primary), ids = [];
  let before = null, pages = 0;
  do {
    if (++pages > MAX_PAGES) throw new PassKError('invalid');
    const page = await store.historyPage({ limit: PAGE_LIMIT, ...(before === null ? {} : { before }) });
    if (!page || !Array.isArray(page.runs) || (page.nextCursor !== null && typeof page.nextCursor !== 'string')) throw new PassKError('invalid');
    for (const summary of page.runs) {
      if (summary.id === primary.id || identityOf(summary) !== identity) continue;
      ids.push(summary.id);
      if (ids.length > max) throw new PassKError('too-many-trials');
    }
    before = page.nextCursor;
  } while (before !== null);
  const runs = [];
  for (const id of ids) {
    const run = await store.get(id);
    // The full run must still carry the identity its summary had.
    if (trialIdentity(run) !== identity) throw new PassKError('trial-identity-differs');
    runs.push(run);
  }
  return runs.sort((a, b) => byCodeUnit(a.createdAt, b.createdAt) || byCodeUnit(a.id, b.id));
}
