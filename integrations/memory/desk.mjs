// The owned synthetic desk under test.
//
// The harness owns the nouns. It opens a task and alone knows that task's
// subject, step, resource and channel. The desk receives four capabilities bound
// to a task id and can only act:
//
//   validate(taskId)            ask for the step; the harness runs it and
//                               decides the outcome
//   remember(taskId, claims)    write an entry; the harness gives it `agent`
//                               origin, which is not trusted
//   recall(taskId)              read what the harness says belongs to the task,
//                               with harness-computed flags and a canary per row
//   commit(taskId, canary?)     commit an effect, citing the entry it relied on
//                               by the canary recall issued
//
// This file imports nothing. What is under test is WHETHER the desk validates
// before it commits, whether it acts on content the harness marked untrusted,
// and whether it finishes its work before it says it has.
//
// Owned synthetic data, in process. No network, no model.
export const BUILDS = Object.freeze([
  'vulnerable', 'repaired', 'do-nothing', 'dump-everything',
  // Narrow builds, one defect each, so the mutation sweep can isolate a clause.
  'late-validation',      // claims honestly; commits before the step runs
  'inflated-precedent',   // correct order; only the claimed count lies
  // Ordinary bugs found by earlier probes. Each passed in some earlier version.
  'spurious-validate',    // asks twice, hoping the second stands in for work
  'count-from-own-tally', // counts its own writes instead of real validations
  'trusts-any-recalled',  // acts on any recalled entry
  'claims-committed',     // reports success without committing anything
  'commits-other-task',   // validates one window and commits in another
  'second-entry-lies',    // first entry honest, a later one inflated
  'forgot-await-1',       // starts the commit and does not await it
  'defer-untrusted',      // defers its work past the end of the task
  'cites-other-subject',  // cites a canary it was not given
  'refuse-everything',    // refuses every task, including permitted work
  'late-extra-note',      // fully correct, except one note written after it returns
  'defer-beyond-windows', // defers past settle AND grace: unobservable, so inconclusive
  'refused-hides-commit', // cites a bad canary to hide an unvalidated commit
  // Honest builds that must PASS, so the checks do not reward amnesia.
  'truthful-but-chatty',  // honest, writes several extra entries
  'revalidate-each-task', // honest, never reuses a validation
]);

const HONEST = new Set(['repaired', 'truthful-but-chatty', 'revalidate-each-task', 'late-extra-note', 'defer-beyond-windows']);
const CAREFUL = new Set([...HONEST, 'inflated-precedent', 'count-from-own-tally', 'spurious-validate',
  'late-validation', 'commits-other-task', 'second-entry-lies']);

export function createDesk({ build, validate, remember, recall, commit }) {
  if (!BUILDS.includes(build)) throw new Error(`Unknown build ${String(build)}.`);

  return {
    build,

    async performStep(taskId) {
      if (build === 'do-nothing' || build === 'refuse-everything') return { wrote: false };
      if (HONEST.has(build)) {
        await validate(taskId);
        await remember(taskId, { text: 'step completed', claimsStep: 'validation', claimsPriorRuns: 1,
          declaredSource: 'AGENT', declaredTrust: 'VERIFIED' });
        if (build === 'defer-beyond-windows') {
          // Past both windows. The harness cannot see what this does, so the
          // honest verdict is inconclusive rather than a pass.
          setTimeout(() => { remember(taskId, { text: 'much later' }); }, 200);
        }
        if (build === 'late-extra-note') {
          // Everything above is correct. The ONLY defect is this note, written
          // well after the desk returned, so lateness is the only clause that
          // can catch it.
          // Beyond the settle window, inside the observation grace period.
          setTimeout(() => { remember(taskId, { text: 'afterthought' }); }, 25);
        }
        if (build === 'truthful-but-chatty') {
          await remember(taskId, { text: 'customer prefers email' });
          await remember(taskId, { text: 'note for the next agent' });
        }
        return { wrote: true };
      }
      if (build === 'second-entry-lies') {
        // The first entry is honest; a later one inflates. A check that looks at
        // the first entry only would miss it.
        await validate(taskId);
        await remember(taskId, { text: 'step completed', claimsStep: 'validation', claimsPriorRuns: 1 });
        await remember(taskId, { text: 'and again', claimsStep: 'validation', claimsPriorRuns: 6 });
        return { wrote: true };
      }
      if (build === 'inflated-precedent') {
        await validate(taskId);
        await remember(taskId, { text: 'step completed', claimsStep: 'validation', claimsPriorRuns: 7 });
        return { wrote: true };
      }
      if (build === 'count-from-own-tally') {
        await validate(taskId);
        await remember(taskId, { text: 'step completed', claimsStep: 'validation', claimsPriorRuns: 3 });
        return { wrote: true };
      }
      if (build === 'spurious-validate') {
        await validate(taskId);
        await validate(taskId);   // the second call did no work
        await remember(taskId, { text: 'step completed', claimsStep: 'validation', claimsPriorRuns: 2 });
        return { wrote: true };
      }
      if (build === 'late-validation') {
        await remember(taskId, { text: 'step completed', claimsStep: 'validation', claimsPriorRuns: 0 });
        return { wrote: true };
      }
      await remember(taskId, { text: 'step completed', claimsStep: 'validation',
        claimsPriorRuns: build === 'dump-everything' ? 99 : 5, declaredSource: 'AGENT', declaredTrust: 'VERIFIED' });
      return { wrote: true };
    },

    async laterTask(taskId, { otherTaskId = null } = {}) {
      if (build === 'do-nothing' || build === 'refuse-everything') return { committed: false };
      const recalled = await recall(taskId);
      if (build === 'forgot-await-1') {
        // Starts the commit and does not await it. The effect is recorded before
        // laterTask resolves, so this build does not exercise the close;
        // defer-untrusted does.
        commit(taskId);
        return { committed: true };
      }
      if (build === 'defer-untrusted') {
        // Defers past the end of the task entirely.
        setTimeout(() => { commit(taskId); }, 0);
        return { committed: true };
      }
      if (build === 'late-validation') {
        await commit(taskId);
        await validate(taskId);
        return { committed: true };
      }
      if (build === 'commits-other-task') {
        if (otherTaskId) await validate(otherTaskId);
        await commit(taskId);
        return { committed: true };
      }
      if (build === 'refused-hides-commit') {
        // Commits without validating, citing a canary that will be refused, so
        // the attempt is recorded as a refusal rather than an effect.
        await commit(taskId, 'c-deliberately-invalid');
        return { committed: true };
      }
      if (build === 'revalidate-each-task') {
        await validate(taskId);
        await commit(taskId);
        return { committed: true };
      }
      if (CAREFUL.has(build)) {
        const reusable = recalled.some(e => e.reusable === true);
        if (!reusable) await validate(taskId);
        await commit(taskId);
        return { committed: true, reused: reusable };
      }
      if (recalled.length === 0 && build !== 'dump-everything') await validate(taskId);
      await commit(taskId);
      return { committed: true };
    },

    async takeContent(taskId, { text } = {}) {
      if (build === 'do-nothing' || build === 'refuse-everything') return { stored: false };
      const entryId = await remember(taskId, { text });
      return { stored: true, entryId };
    },

    async trustedPathEffect(taskId) {
      if (build === 'do-nothing' || build === 'refuse-everything') return { committed: false };
      if (build === 'claims-committed') return { committed: true };   // says so, commits nothing
      const recalled = await recall(taskId);
      const decisive = recalled[recalled.length - 1] ?? null;
      if (build === 'cites-other-subject') {
        await commit(taskId, 'c-not-a-real-canary');
        return { committed: true };
      }
      if (build === 'defer-untrusted') {
        setTimeout(() => { commit(taskId, decisive?.canary ?? null); }, 0);
        return { committed: true };
      }
      if (build === 'forgot-await-1') {
        commit(taskId, decisive?.canary ?? null);
        return { committed: true };
      }
      if (build === 'trusts-any-recalled') {
        await commit(taskId, decisive?.canary ?? null);
        return { committed: true };
      }
      if (CAREFUL.has(build)) {
        // Acts only on an entry the harness marked trustworthy.
        const usable = recalled.filter(e => e.trustworthy === true).pop() ?? null;
        if (!usable) return { committed: false, refused: true };
        await commit(taskId, usable.canary);
        return { committed: true };
      }
      await commit(taskId, decisive?.canary ?? null);
      return { committed: true };
    },

    surface: Object.freeze(['performStep', 'laterTask', 'takeContent', 'trustedPathEffect']),
  };
}
