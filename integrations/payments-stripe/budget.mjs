// The request budget for a stage-2 invocation (its spend cap and limits): one budget per invocation, shared by every
// request that goes to Stripe test mode (the read-back's reads and the forwarder's writes). take() waits for the next slot, at most
// perSecond requests a second, and refuses once max requests were taken or once the budget stopped. note(status) stops the budget on
// the first 429 (Stripe's rate limit or lock_timeout): every later take() refuses, so the invocation stops instead of retrying.
// Nothing here makes a request; it only counts, paces and refuses.
export const BUDGET_LIMITS = Object.freeze({ max: Object.freeze([1, 2500]), perSecond: Object.freeze([1, 10]) });

export class BudgetStopped extends Error {}

export function createRequestBudget({ max = 2500, perSecond = 10, now = () => Date.now(), sleep = ms => new Promise(r => setTimeout(r, ms)) } = {}) {
  const inRange = (v, [lo, hi]) => Number.isSafeInteger(v) && v >= lo && v <= hi;
  if (!inRange(max, BUDGET_LIMITS.max) || !inRange(perSecond, BUDGET_LIMITS.perSecond)) throw new Error('max is 1 to 2500 requests and perSecond 1 to 10.');
  const gap = Math.ceil(1000 / perSecond);
  let used = 0, nextAt = 0, stopped = null;
  const statuses = new Map();
  const stop = reason => { if (!stopped) stopped = reason; };
  return {
    async take() {
      if (stopped) throw new BudgetStopped(`budget stopped: ${stopped}`);
      if (used >= max) { stop('request-cap'); throw new BudgetStopped('budget stopped: request-cap'); }
      // The slot is claimed before the wait, so concurrent callers queue one gap apart.
      used++;
      const at = Math.max(now(), nextAt);
      nextAt = at + gap;
      const wait = at - now();
      if (wait > 0) await sleep(wait);
      if (stopped) throw new BudgetStopped(`budget stopped: ${stopped}`);
    },
    note(status) {
      statuses.set(status ?? 'none', (statuses.get(status ?? 'none') ?? 0) + 1);
      if (status === 429) stop('rate-limited-429');
    },
    stop,
    state: () => ({ used, max, perSecond, stopped, statuses: Object.fromEntries([...statuses].map(([k, v]) => [String(k), v])) }),
  };
}
