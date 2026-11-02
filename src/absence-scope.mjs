// The stated scope of an absence pass decided by an egress recorder or an SMTP sink.
// Presentation only: it reads a saved run's sealed rows and never feeds a verdict, status, count, comparison,
// gate outcome, note or any suite, policy, fixture, evaluator or profile hash. It is outside the HTTP evaluator hash,
// so a wording edit never changes run identity, and the validator never reads it. The HTML report, SARIF, the
// comparison export and the regression gate's JSON summary print it per row; the compact summary, which never reads traces,
// prints the run's limitation (src/http-scope-text.mjs ROUTED_ABSENCE_LIMITATION) instead.
//
// What such a pass rests on: the declared route was live (this window's witness reached the sink through it) and
// carried no matching send. Routing is declared, not shown exclusive: a send that never reaches the sink (a direct
// connection, another address, port or socket, a client or child process that ignores the route) is in no window.
// And it is bounded in time: a matching send recorded from the check's start mark through the run's final mark
// withholds or fails it; one made after the final mark is outside every window, so the pass says nothing about it.
//
// On a confined run (./scopehaven assess --confine, src/confinement-record.mjs) a clause whose deciding windows
// all came from confined sinks reads tier "confined": the kernel refused the launched process tree every outbound connection
// except to the declared sinks' ports and the recorded allowlist, within the limits the record states. Every other clause reads
// tier "declared", as above.
import { decidingWindows } from './custody.mjs';
import { confinementOf, confinedInstanceIds } from './confinement-record.mjs';

// The sealed window sources whose absence rests on a declared route (src/http-effects.mjs OBSERVER_OUTPUT).
export const ROUTED_SOURCES = Object.freeze({ 'http-egress': 'egress recorder', 'smtp-capture': 'SMTP sink' });
export const ROUTING_SCOPE = 'routing declared, not shown exclusive';
export const ABSENCE_SCOPE_RULE = 'An absence pass an egress recorder or SMTP sink decided shows that the declared route was live (the window\'s witness reached the sink through it) and carried no matching send. Routing is declared, not shown exclusive: it does not show that the application made no such call by another way out (a direct connection, another address, port or socket, or a client or child process that ignores the route). For that, run the application where the sink is its only way out. The pass is also bounded in time: it covers sends recorded from the check\'s start through the run\'s final mark, and says nothing about a send made later.';
// The confined tier's label (allow: the number of allowlisted loopback ports) and rule.
export const confinedRoutingScope = (allow = 0) => `routing confined: the kernel refused the launched process tree every outbound connection except to the declared sinks' ports${allow ? ` and ${allow} allowlisted loopback port${allow === 1 ? '' : 's'}` : ''} (see the confinement record's limits)`;
export const CONFINED_SCOPE_RULE = 'On a confined run, an absence pass an egress recorder or SMTP sink decided shows that the declared route was live (the window\'s witness reached the sink through it) and carried no matching send, and that ScopeHaven started the application under macOS sandbox-exec with every outbound connection refused except to the declared sinks\' ports and any allowlisted port listed in the run\'s confinement record, for the launched process and every process it started: a send by a direct connection, another port or socket, or a client or child process that ignores the route was refused, not merely unseen. The record\'s limits bound this: the rule admits every IPv4 address of this machine at an allowed port, so ScopeHaven also checked that it was the only listener on each sink port before, during and after the run; a process outside the launched tree that the application reaches by IPC, by a file or by an inbound connection is not confined; and a send through an allowlisted port reaches no sink. The pass is also bounded in time: it covers sends recorded from the check\'s start through the run\'s final mark, and says nothing about a send made later. A clause that a window outside the confinement decided keeps the declared scope: routing declared, not shown exclusive.';
// The rule and label a run's absence passes are stated under: confined when the run carries a valid confinement record.
export const absenceScopeRule = run => (confinementOf(run) ? CONFINED_SCOPE_RULE : ABSENCE_SCOPE_RULE);
export const routingScopeOf = run => { const c = confinementOf(run); return c ? confinedRoutingScope(c.allow.length) : ROUTING_SCOPE; };

const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const absenceKind = (kind, expected) => kind === 'effect.none' || kind === 'effect.only' || (kind === 'effect.count' && expected === 0);
const ms = value => Number.isSafeInteger(value) && value >= 0 ? value : null;

// The time bound of a run's absence passes, from its sealed timing and settlement records and its declared observers.
// deciding: the instance ids of the windows that decided one clause.
function timeBound(run, deciding) {
  const horizon = ms(run?.timing?.effectHorizonMs);
  const declared = Array.isArray(run?.observers) ? run.observers : [];
  const settles = [...new Set(deciding.map(id => declared.find(o => plain(o) && `${o.type}-${o.id}` === id)?.settleMs).map(ms).filter(v => v !== null))];
  const finalSettle = ms(run?.settlement?.settleMs);
  const own = horizon !== null ? `the declared effect horizon of ${horizon} ms after this check's response` : settles.length ? `the declared settle of ${settles.join(' or ')} ms after this check's response, then its witness` : 'its declared settle after this check\'s response, then its witness';
  return `Time bound: no matching send was recorded from this check's start through the run's final mark (this check's window was held ${own}; the final mark came at least ${finalSettle !== null ? `${finalSettle} ms, ` : ''}the largest declared settle, after the last check, and later when the recorders drained first). A send made after the final mark is outside every window, so this pass says nothing about it.`;
}

// One passing row's absence clauses that an egress recorder or SMTP sink decided, in row order:
// [{ assertion, kind, observers: [instance id], via: [label], tier: 'confined' | 'declared', routing, timeBound, note }]. An effect.only pass is listed when
// a complete authoritative egress or SMTP window was among the windows it judged. A row that did not pass lists nothing: its
// clause may have passed while the row was withheld for another reason. Anything malformed lists nothing.
export function absenceScopeEntries(row, run = null) {
  if (row?.status !== 'pass') return [];
  const data = Array.isArray(row?.trace) && plain(row.trace[1]?.data) ? row.trace[1].data : null;
  const sealed = Array.isArray(data?.windows) ? data.windows.filter(w => plain(w) && Object.hasOwn(ROUTED_SOURCES, w.source)) : [];
  if (!sealed.length) return [];
  const confinement = confinementOf(run), confined = confinedInstanceIds(run);
  const clauses = [...(Array.isArray(data.effects) ? data.effects : []).map((e, i) => ({ e, kind: e?.kind, assertion: `Observed effect ${i + 1} (${e?.kind})` })),
    ...(Array.isArray(data.claims) ? data.claims : []).map((c, i) => ({ e: c, kind: c?.clause, assertion: `Observed claim ${i + 1} (${c?.reading})` }))];
  return clauses.flatMap(({ e, kind, assertion }) => {
    if (!plain(e) || e.verdict !== 'pass' || !absenceKind(kind, e.expected)) return [];
    let deciding;
    try {
      deciding = kind === 'effect.only' ? sealed.filter(w => w.coverage === 'complete' && w.scope?.evidence === 'authoritative')
        : decidingWindows(sealed, { kind, select: e.select, verdict: 'pass', countBy: e.countBy });
    } catch { deciding = []; }
    if (!deciding.length) return [];
    const observers = [...new Set(deciding.map(w => String(w.instanceId)))], via = [...new Set(deciding.map(w => ROUTED_SOURCES[w.source]))];
    const bound = timeBound(run, observers), silent = kind === 'effect.only' ? 'no send outside the declared set' : 'no matching send';
    if (confinement && observers.every(id => confined.has(id))) {
      const allow = confinement.allow.length, routing = confinedRoutingScope(allow);
      return [{ assertion, kind, observers, via, tier: 'confined', routing, timeBound: bound,
        note: `${assertion} passed on the ${via.join(' and ')} (${observers.join(', ')}): ${routing}. The declared route was live and carried ${silent}; the confinement record's limits say what the kernel rule does not cover (a process outside the launched tree reached by IPC, a file or an inbound connection${allow ? `, and the allowlisted port${allow === 1 ? '' : 's'}` : ''}). ${bound}` }];
    }
    return [{ assertion, kind, observers, via, tier: 'declared', routing: ROUTING_SCOPE, timeBound: bound,
      note: `${assertion} passed on the ${via.join(' and ')} (${observers.join(', ')}): ${ROUTING_SCOPE}. The declared route was live and carried ${silent}; that does not show the application made no such call by another way out. ${bound}` }];
  });
}

// The rows of a run that carry such a pass, for summaries: [{ id, clauses }].
export const absenceScopeRows = run => (Array.isArray(run?.results) ? run.results : []).filter(plain)
  .map(row => ({ id: row.id, clauses: absenceScopeEntries(row, run).length })).filter(r => r.clauses > 0);
