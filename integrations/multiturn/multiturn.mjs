// Multi-turn, multi-identity task scripts judged from records.
//
// What existed: integrations/conversations runs multi-turn chats per proven identity, with
// values captured from one turn and used in later ones, but judges replies, GET state checks
// and surface snapshots; integrations/sequences judges declared effect observers (audit
// tables, database snapshots, sinks) over marked windows, but its request bodies are fixed.
// This module joins the two without changing either: a scenario (scopehaven-multiturn/1)
// is compiled into an ordinary sequence (scopehaven-sequence/1), and a capture-aware
// transport fills each turn's {{name}} placeholders from values earlier turns captured.
//
// A scenario: actors (as in a sequence), turns in order ({ actor, method, path, body?,
// capture?: { name: JSON pointer }, expect: [statuses] }), and assertions over turn
// windows: a window "turn-a..turn-b" covers turns a through b. A later turn may depend on
// state an earlier turn created ({{name}} in its path or body). Verdicts come only from
// the declared observers, through core's effect rules (the sequence runner's own
// decideAssertion). Every forbidden assertion names its paired allowed-use control
// (control: <id>), a positive check (effect.exists, or effect.count of at least 1); every
// identity an assertion can judge (its selector's actor, or every actor when it names none)
// has at least 3 turns. A capture that misses clears the name, so the next turn that needs
// it stops the run (inconclusive, never a pass or a fail), and a value can never carry over
// from an earlier capture.
import { validateSequence, runSequence, SEQUENCE_SCHEMA } from '../sequences/sequence.mjs';
import { sequenceTransport } from '../sequences/transport.mjs';
import { digest } from '../../src/domain.mjs';
import { CUSTODY_REASON } from '../../src/custody.mjs';

export const MULTITURN_SCHEMA = 'scopehaven-multiturn/1';
// 21 turns: each turn is three sequence steps, plus the first mark, within the sequence's 64.
export const MULTITURN_LIMITS = Object.freeze({ turns: 21, captures: 16, valueChars: 200 });
const NAME = /^[A-Za-z][A-Za-z0-9_]{0,31}$/;
const POINTER = /^(\/[^/~]*(~[01][^/~]*)*)*$/;
const PLACEHOLDER = /\{\{([A-Za-z][A-Za-z0-9_]{0,31})\}\}/g;
const bad = reason => { throw new Error(`Invalid multi-turn scenario: ${reason}.`); };
const usedNames = value => [...JSON.stringify(value ?? null).matchAll(PLACEHOLDER)].map(m => m[1]);
// Placeholders belong in values: a body key is never filled.
const keysOf = value => (Array.isArray(value) ? value.flatMap(keysOf) : value && typeof value === 'object' ? Object.entries(value).flatMap(([k, v]) => [k, ...keysOf(v)]) : []);
const POSITIVE = effect => effect?.kind === 'effect.exists' || (effect?.kind === 'effect.count' && Number.isInteger(effect.expected) && effect.expected >= 1);
// A control shows the same effect can happen, so its selector equals its forbidden row's in every
// field but the actor (source, operation, name, resource, outcome, traceId): a forbidden row narrowed
// so it can never match is never backed by a broader control.
const EFFECT_FIELDS = ['source', 'operation', 'name', 'resource', 'outcome', 'traceId'];
const SAME_EFFECT = (a, b) => JSON.stringify(EFFECT_FIELDS.map(k => a.effect?.select?.[k] ?? null)) === JSON.stringify(EFFECT_FIELDS.map(k => b.effect?.select?.[k] ?? null));

// Compile a scenario into a sequence. Marks: before-1, then after-k after turn k.
export function compileScenario(s) {
  if (!s || s.schema !== MULTITURN_SCHEMA || !/^[A-Za-z0-9_-]{1,80}$/.test(s.id ?? '')) bad('needs schema scopehaven-multiturn/1 and an id');
  if (!Array.isArray(s.turns) || !s.turns.length || s.turns.length > MULTITURN_LIMITS.turns) bad(`needs 1 to ${MULTITURN_LIMITS.turns} turns`);
  const captured = new Set();
  s.turns.forEach((t, i) => {
    if (!s.actors || typeof s.actors !== 'object' || !Object.hasOwn(s.actors, t.actor)) bad(`turn ${i + 1} names an unknown actor`);
    if (keysOf(t.body).some(k => usedNames(k).length)) bad(`turn ${i + 1} puts a placeholder in a body key`);
    for (const name of [...usedNames(t.path), ...usedNames(t.body)]) if (!captured.has(name)) bad(`turn ${i + 1} uses {{${name}}} before a turn captures it`);
    for (const [name, pointer] of Object.entries(t.capture ?? {})) { if (!NAME.test(name) || !POINTER.test(pointer)) bad(`turn ${i + 1} capture`); captured.add(name); }
    if (!Array.isArray(t.expect) || !t.expect.length || !t.expect.every(Number.isInteger)) bad(`turn ${i + 1} needs the statuses it expects`);
  });
  if (captured.size > MULTITURN_LIMITS.captures) bad('too many captures');
  // At least 3 turns for each identity an assertion can judge: its selector's actor, or every actor.
  const everyone = Object.values(s.actors).map(a => a.principalId);
  const judged = new Set((s.assertions ?? []).flatMap(a => (a.effect?.select?.actor ? [a.effect.select.actor] : everyone)));
  const principalOf = alias => s.actors[alias].principalId;
  for (const principal of judged) if (s.turns.filter(t => principalOf(t.actor) === principal).length < 3) bad(`${principal} has fewer than 3 turns`);
  // Every forbidden assertion is paired with an allowed-use control.
  const assertions = (s.assertions ?? []).map(a => {
    const m = /^turn-(\d+)\.\.turn-(\d+)$/.exec(a.window ?? '');
    if (!m || Number(m[1]) < 1 || Number(m[2]) > s.turns.length || Number(m[1]) > Number(m[2])) bad(`assertion ${a.id} needs a window turn-a..turn-b within the turns`);
    // The pairing stays in the run record (control), so a reader can see which control backs each forbidden row.
    const { window, ...rest } = a;
    return { ...rest, from: Number(m[1]) === 1 ? 'before-1' : `after-${Number(m[1]) - 1}`, to: `after-${m[2]}` };
  });
  if (!assertions.length) bad('needs assertions');
  // Each forbidden assertion names its own paired allowed-use control, which must be a positive check.
  for (const a of s.assertions.filter(x => x.severity !== 'control')) {
    const paired = s.assertions.find(x => x.id === a.control);
    if (!paired || paired.severity !== 'control' || !POSITIVE(paired.effect)) bad(`assertion ${a.id} needs a paired allowed-use control: control names a positive control assertion (effect.exists, or effect.count of at least 1)`);
    if (!SAME_EFFECT(a, paired)) bad(`assertion ${a.id}'s control must select the same effect as it does (every selector field but the actor)`);
  }
  if (s.assertions.some(x => x.severity === 'control' && x.control !== undefined)) bad('a control assertion names no control');
  const steps = [{ mark: 'before-1' }];
  s.turns.forEach((t, i) => {
    const id = `turn-${i + 1}`;
    steps.push({ request: { id, actorId: t.actor, method: t.method, path: t.path, ...(t.body === undefined ? {} : { body: t.body }), timeoutMs: t.timeoutMs ?? 5000 } });
    steps.push({ expectStatus: { request: id, in: t.expect } });
    steps.push({ mark: `after-${i + 1}` });
  });
  return validateSequence({ schema: SEQUENCE_SCHEMA, id: s.id, actors: s.actors, steps, assertions });
}

const pointerGet = (value, pointer) => {
  let at = value;
  for (const raw of pointer.split('/').slice(1)) { const key = raw.replace(/~1/g, '/').replace(/~0/g, '~'); if (at === null || typeof at !== 'object' || !Object.hasOwn(at, key)) return undefined; at = at[key]; }
  return at;
};
const fill = (value, captured) => {
  if (typeof value === 'string') return value.replace(PLACEHOLDER, (_, name) => captured.get(name));
  if (Array.isArray(value)) return value.map(v => fill(v, captured));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, fill(v, captured)]));
  return value;
};

// The transport for one run of a scenario: turn k is the k-th request the runner sends (the
// compiled sequence has no background requests). Placeholders are filled from the values
// earlier turns captured; a captured value must be a plain identifier of at most 200 chars.
export function captureTransport(scenario, { base = sequenceTransport } = {}) {
  const captured = new Map(), log = [];
  let k = 0;
  const transport = async (origin, check, options) => {
    const turn = scenario.turns[k++];
    const missing = [...usedNames(check.path), ...usedNames(check.body)].filter(name => !captured.has(name));
    if (missing.length) { log.push({ turn: k, missing }); return { status: null, error: 'capture-missing' }; }
    const filled = { ...check, path: fill(check.path, captured), ...(check.body === undefined ? {} : { body: fill(check.body, captured) }) };
    const observation = await base(origin, filled, options);
    for (const [name, pointer] of Object.entries(turn?.capture ?? {})) {
      const value = observation.jsonParsed ? pointerGet(observation.json, pointer) : undefined;
      // Only plain identifiers: a captured value can never add a path segment, a query or a placeholder.
      // A capture that misses clears the name: the next turn that needs it stops the run, never using an older value.
      if ((typeof value === 'string' || typeof value === 'number') && /^[A-Za-z0-9_.:-]{1,200}$/.test(String(value)) && !/^\.+$/.test(String(value))) captured.set(name, String(value));
      else { captured.delete(name); log.push({ turn: k, uncaptured: name }); }
    }
    return observation;
  };
  return { transport, captured, log };
}

// What must replay: the verdicts, and every window's events without the time they were
// observed (the sealed run digest also covers observation times, so it differs run to run).
export const replayDigest = run => digest({ sequenceId: run.sequenceId, sequenceHash: run.sequenceHash, aborted: run.aborted,
  results: run.results.map(r => ({ id: r.id, status: r.status, verdict: r.verdict })),
  windows: Object.fromEntries(Object.entries(run.windows).map(([key, list]) => [key, list.map(w => ({ source: w.source, instanceId: w.instanceId, coverage: w.coverage,
    events: w.events.map(e => ({ source: e.source, seq: e.seq, actor: e.actor, operation: e.operation, name: e.name, resource: e.resource, outcome: e.outcome })) }))])) });

// Why a pair does not hold, every reason that applies, most decisive first: the boundary broke; only
// records the target can write decided the forbidden row (custody), so it can never pass on them; the
// paired control did not pass; or the forbidden row was not decided for another reason.
function whyNot(forbidden, control) {
  const why = [];
  if (forbidden?.status === 'fail') why.push(['forbidden-failed', 'The forbidden row failed: an observer recorded the effect it forbids.']);
  // The custody upgrade names what could decide it: a request-path observer for the tool call or send that carries the effect, or none.
  else if (forbidden?.custodyReason === CUSTODY_REASON) why.push(['cannot-hold-custody', `Cannot hold: custody. Only records the target can write decided the forbidden row (subject-writable-custody). ${forbidden.custodyUpgrade ?? 'A request-path observer of the tool call or send that carries this effect is what can let it pass.'}`]);
  else if (forbidden?.status !== 'pass') why.push([`forbidden-${forbidden?.status ?? 'missing'}`, `The forbidden row reads ${forbidden?.status ?? 'missing'}${forbidden?.basis ? `: ${forbidden.basis}` : '.'}`]);
  if (control?.status !== 'pass') why.push(['control-not-passed', `The paired control reads ${control?.status ?? 'missing'}: without it, an absence could come from a target that does nothing.`]);
  return { why: why.map(([code]) => code), reasons: why.map(([, text]) => text) };
}

// Run a scenario once: the compiled sequence through the unchanged runner, with captures.
export async function runScenario(scenario, { origin, observers, env }) {
  const sequence = compileScenario(scenario);
  const { transport, log } = captureTransport(scenario);
  const run = await runSequence(sequence, { origin, observers, env, transport });
  // Each forbidden row with its control: the pair holds only when both pass, and a pair that does not hold says why.
  const row = id => run.results.find(r => r.id === id) ?? null;
  const pairs = sequence.assertions.filter(a => a.severity !== 'control').map(a => {
    const forbidden = row(a.id), control = row(a.control), holds = forbidden?.status === 'pass' && control?.status === 'pass';
    return { forbidden: a.id, status: forbidden?.status ?? null, custody: forbidden?.custody ?? null, control: a.control, controlStatus: control?.status ?? null, holds, ...(holds ? {} : whyNot(forbidden, control)) };
  });
  return { scenario: { schema: MULTITURN_SCHEMA, id: scenario.id, turns: scenario.turns.length }, run, pairs, replayDigest: replayDigest(run), captureLog: log };
}
