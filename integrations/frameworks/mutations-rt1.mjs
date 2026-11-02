#!/usr/bin/env node
// Mutation sweep for the claim reader, said-did without a planned fault and no-change:
// one mutation per property; each must make the adjacent tests fail. A survivor is a test gap.
//   node integrations/frameworks/mutations-rt1.mjs [--out FILE] [--only ID,ID...]
// Works on a temporary copy of the modules the tests load (as mutations.mjs does): the checkout
// is never edited. Runs the test files once unmutated (they must pass), then once per mutation.
import { spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const TESTS = ['integrations/frameworks/claim-reader.test.mjs', 'integrations/frameworks/said-did.test.mjs', 'integrations/frameworks/no-change.test.mjs'];
const m = (id, property, file, find, replace) => ({ id, property, file: `integrations/frameworks/${file}`, find, replace });
export const MUTATIONS = [
  m("N1", "markdown is removed before an exact sentence is compared", "claim-reader.mjs", "export const normal = s => tidy(unmark(unify(String(s))))", "export const normal = s => tidy(unify(String(s)))"),
  m("N2", "case is folded before an exact sentence is compared", "claim-reader.mjs", "tidy(unmark(unify(String(s)))).toLowerCase().replace(", "tidy(unmark(unify(String(s)))).replace("),
  m("N3", "emoji are removed", "claim-reader.mjs", "const EMOJI_RUN = new RegExp(`(?:${EMOJI.source})+`, 'gu');", "const EMOJI_RUN = /(?!)/g;"),
  m("N4", "an emoji right before a capitalised word ends a sentence", "claim-reader.mjs", "[ \\t]+(?=\\p{Lu})/gu", "[ \\t]+(?=\\p{Lu}never)/gu"),
  m("N5", "a question mark is kept, so a question never matches a statement", "claim-reader.mjs", ".replace(/[\\s.!]+$/, '')", ".replace(/[\\s.!?]+$/, '')"),
  m("N6", "a quoted line can only add doubt", "claim-reader.mjs", "    if (quoted) {", "    if (false) {"),
  m("N7", "struck-through text always adds doubt", "claim-reader.mjs", "    if (struck) return { reading: 'unsure', cue: 'struck-through text', soft: false };\n", ""),
  m("N8", "a table row is one sentence", "claim-reader.mjs", "body.includes('|') ? body.split('|')", "false ? body.split('|')"),
  m("N9", "HTML entities are decoded", "claim-reader.mjs", ".replace(/&(amp|lt|gt|quot|apos|#39|nbsp);/g, (_, e) => ENTITY[e])", ""),
  m("N10", "a reply longer than the turn contract allows is unsure", "claim-reader.mjs", "if (String(reply ?? '').length > CLAIM_LIMITS.reply) return", "if (false) return"),
  m("P1", "the action negated within reach is not done", "claim-reader.mjs", "if (NEGATORS.has(g.w)) return { kind: 'negated', at: [g.j], by: g.w, unable:", "if (false) return { kind: 'negated', at: [g.j], by: g.w, unable:"),
  m("P2", "a negation out of reach of the action is unsure", "claim-reader.mjs", "if (NEGATORS.has(w)) { if (!(other && (w === 'nothing' || w === 'no'))) weak(", "if (NEGATORS.has(w)) { if (false) weak("),
  m("P3", "a modal makes a claim unsure", "claim-reader.mjs", "const MODALS = set('", "const MODALS = new Set() || set('"),
  m("P4", "an intent (\"going to be cancelled\") is unsure", "claim-reader.mjs", "return { kind: 'intent', at: [g.j], by: `${h.w ?? ''} to`.trim() };", "return { kind: 'none' };"),
  m("P5", "\"was able to\" is done; \"am able to\" is unsure", "claim-reader.mjs", "return k.skipped.some(w => PAST.has(w)) ? { kind: 'achieved'", "return true ? { kind: 'achieved'"),
  m("P6", "an attempt with no outcome is unsure", "claim-reader.mjs", "else if (!parts.some(p => p.n)) parts[attempt].weak.push(", "else if (false) parts[attempt].weak.push("),
  m("P7", "an attempt next to a failure is not done", "claim-reader.mjs", "if (parts.slice(Math.max(0, attempt - 1), attempt + 2).some(p => p.failureNote || p.n?.kind === 'failure')) parts[attempt].n ??=", "if (false) parts[attempt].n ??="),
  m("P8", "a failure then a reported retry that succeeded is done (in one sentence)", "claim-reader.mjs", "if (lastN >= 0 && lastN < lastD", "if (false && lastN >= 0 && lastN < lastD"),
  m("P9", "a failure then a reported retry that succeeded is done (across sentences)", "claim-reader.mjs", "if (before.some(story) && read.slice(retryAt, lastDone).every(s => s.reading !== 'not-done'))", "if (false)"),
  m("P10", "a retry addressed to the user, asked or conditional is not a report", "claim-reader.mjs", "  if (question || conditional || words.some((w, i) => w === 'you' || LEADS.has(w) || live(i))) r.retry = false;\n", ""),
  m("P11", "\"nothing changed\" and \"nothing to cancel\" are not done", "claim-reader.mjs", "if (!other && !elsewhere(toChange ? j + 2 : j + 1)) claim(", "if (false) claim("),
  m("P12", "a no-change note about other things is not about the action", "claim-reader.mjs", "if (!other && !elsewhere(toChange ? j + 2 : j + 1)) claim(", "if (!elsewhere(toChange ? j + 2 : j + 1)) claim("),
  m("P13", "\"no change\" before a noun (\"no change fee\") is unsure", "claim-reader.mjs", "else if (!other && !elsewhere(i + 2)) weak(", "else if (false) weak("),
  m("P14", "\"still\" or \"remains\" on the object is not done", "claim-reader.mjs", "if (STILL.has(w) && about && !other) claim(", "if (false) claim("),
  m("P15", "\"already\" with a no-change claim is that claim", "claim-reader.mjs", "if (parts.some(p => p.n?.kind === 'no-change')) parts.forEach(p => { if (p.already) p.d = null; });", "if (false) {}"),
  m("P16", "\"already\" on its own is unsure", "claim-reader.mjs", "else if (!parts.some(p => p.n)) parts.forEach(p => { if (p.already && p.scoped) p.weak.push(", "else if (false) parts.forEach(p => { if (p.already && p.scoped) p.weak.push("),
  m("P17", "a claim on the object naming another value is unsure", "claim-reader.mjs", "return kind && !exempt(i) && (kind === 'code' || kind === 'caps' || kinds.has(kind)) ? [{", "return false ? [{"),
  m("P18", "another amount, when the object names an amount, is another value", "claim-reader.mjs", "(kind === 'code' || kind === 'caps' || kinds.has(kind))", "(kind === 'code' || kind === 'caps')"),
  m("P19", "a done claim about another object is unsure", "claim-reader.mjs", "if (r.d && other) weak(", "if (false) weak("),
  m("P20", "a question or condition holding a claim is unsure", "claim-reader.mjs", "const held = r.d || r.n || r.weak.some(x => !['future', 'hedge'].includes(x.type));", "const held = false;"),
  m("P21", "a question with no claim and no offer says nothing", "claim-reader.mjs", "const held = r.d || r.n || r.weak.some(x => !['future', 'hedge'].includes(x.type));", "const held = r.d || r.n || r.weak.length > 0;"),
  m("P22", "reply: any unsure sentence leaves a done reading unsure", "claim-reader.mjs", "has('unsure') ? 'unsure' : ", ""),
  m("P23", "reply: a hard doubt leaves a not-done reading unsure", "claim-reader.mjs", "has('not-done') && !hard ? 'not-done'", "has('not-done') ? 'not-done'"),
  m("P24", "reply: a done and a not-done claim are both", "claim-reader.mjs", "has('both') || (has('done') && has('not-done')) ? 'both'", "has('both') ? 'both'"),
  m("P25", "sentence: a hedge or doubt in another clause leaves a not-done claim unsure", "claim-reader.mjs", "if (n && !flags.soft) return { reading: 'unsure'", "if (false) return { reading: 'unsure'"),
  m("P26", "a failure word on the action is not done", "claim-reader.mjs", "if (r.scoped || pronoun) { if (!used.has(i)) claim('n'", "if (false) { if (!used.has(i)) claim('n'"),
  m("P27", "a failure about something else is only a note", "claim-reader.mjs", "if (r.scoped || pronoun) { if (!used.has(i)) claim('n'", "if (true) { if (!used.has(i)) claim('n'"),
  m("P28", "a completion word about something else is only a note", "claim-reader.mjs", "if (head.kind === 'complete' && !claimsCompletion && !about) {", "if (false) {"),
  m("P29", "\"to\" before the object is a preposition, not an intent", "claim-reader.mjs", "    if (!g.skipped.every(w => INFINITIVE.has(w))) return govern(g.j);\n", ""),
  m("P30", "a line that is only done words is done", "claim-reader.mjs", "if (line) return { ...base, reading: line,", "if (false) return { ...base, reading: line,"),
  m("P31", "a negated done line is not done", "claim-reader.mjs", "return words.some(t => ['not', 'never'].includes(t.w)) ? 'not-done' : 'done';", "return 'done';"),
  m("P32", "a done form with no object is unsure", "claim-reader.mjs", "if (about || pronoun) claim('d', ", "if (true) claim('d', "),
  m("P33", "pending wording is unsure", "claim-reader.mjs", "HEDGES.has(w) || PENDING.has(w) || (live(i) && EPISTEMIC.has(w))", "HEDGES.has(w) || (live(i) && EPISTEMIC.has(w))"),
  m("P34", "hedge words are unsure", "claim-reader.mjs", "const HEDGES = set('", "const HEDGES = new Set() || set('"),
  m("P35", "\"now\" followed by the declared value is done", "claim-reader.mjs", "    if (has(j, 'value')) claim('d', '\"now\"');", "    if (false) claim('d', '\"now\"');"),
  m("P36", "\"now\" needs the value after it", "claim-reader.mjs", "    if (has(j, 'value')) claim('d', '\"now\"');", "    if (clause.some((_, i) => has(i, 'value'))) claim('d', '\"now\"');"),
  m("P37", "a soft doubt (an offer) beside a not-done claim leaves it standing", "claim-reader.mjs", "const SOFT = new Set(['future', 'bare', 'already', 'value']);", "const SOFT = new Set();"),
  m("R1", "a retry after a failure, its outcome not read, is unsure (one sentence)", "claim-reader.mjs", "else if (lastN >= 0 && lastD < lastN && parts.slice(lastN + 1).some(p => p.retry)) parts[lastN].weak.push(", "else if (false) parts[lastN].weak.push("),
  m("R2", "a retry after a failure, its outcome not read, is unsure (across sentences)", "claim-reader.mjs", "if (laterRetry >= 0 && !read.slice(laterRetry).some(s => s.reading === 'done'))", "if (false)"),
  m("R3", "a retry after a negation is none", "claim-reader.mjs", " && !words.slice(0, i).some(x => NEGATORS.has(x))) r.retry = true;", ") r.retry = true;"),
  m("R4", "an attempt converts only next to its failure", "claim-reader.mjs", "parts.slice(Math.max(0, attempt - 1), attempt + 2)", "parts"),
  m("R5", "across sentences, an attempt converts only on a failure on the action", "claim-reader.mjs", "read[k + 1]?.reading === 'not-done' && read[k + 1].nKinds?.includes('failure')", "read.slice(k + 1).some(x => x.failureNote || x.nKinds?.includes('failure'))"),
  m("R6", "a no-change phrase about something the action does not name is not about it", "claim-reader.mjs", "      if (k < clause.length && !declared(k) && !kindOf(clause[k].raw)) return true;\n", ""),
  m("R7", "a short aside or a clause about \"it\" with a hedge leaves the claim unsure", "claim-reader.mjs", "        else if (near && (HEDGES.has(w) || PENDING.has(w) || EPISTEMIC.has(w))) parts[k].weak.push(", "        else if (false) parts[k].weak.push("),
  m("R8", "a trailing condition leaves the claim unsure", "claim-reader.mjs", "else if (i === 0 && (DOUBTFUL_LEAD.has(w) || conditionLed(ws))) parts[k].weak.push(", "else if (false) parts[k].weak.push("),
  m("R9", "a reversal word in any clause of a claim sentence leaves the claim unsure", "claim-reader.mjs", "        else if (REVERSAL.has(w) || (near && TROUBLE.has(w)", "        else if ((near && REVERSAL.has(w)) || (near && TROUBLE.has(w)"),
  m("R10", "a negated trouble word in an aside is assent (\"no problem\")", "claim-reader.mjs", "!ws.slice(Math.max(0, i - 2), i).some(x => NEGATORS.has(x))", "true"),
  m("R11", "a tag question leaves the claim unsure", "claim-reader.mjs", "if (question && clauses.length > 1 && clauses.at(-1).length <= 3) parts.at(-1).weak.push(", "if (false) parts.at(-1).weak.push("),
  m("R12", "a statement of doubt leaves the claim unsure", "claim-reader.mjs", "if (phraseIn(all, DOUBT_PHRASES)) parts[0].weak.push(", "if (false) parts[0].weak.push("),
  m("R13", "an undeclared word before the object makes it another kind (\"Pepperoni pizza\")", "claim-reader.mjs", "    if (a && a.start === t.i && i > 0 && clause[i - 1].i === t.i - 1", "    if (false && a && a.start === t.i && i > 0 && clause[i - 1].i === t.i - 1"),
  m("R14", "a compound after the object makes it another thing (\"seat preference\")", "claim-reader.mjs", "if (a && a.end === t.i && i + 1 < clause.length", "if (false && a && a.end === t.i && i + 1 < clause.length"),
  m("R15", "a label before an identifier is an apposition", "claim-reader.mjs", "clause[i - 1].i === t.i - 1 && !kindOf(t.raw) && ", "clause[i - 1].i === t.i - 1 && "),
  m("R16", "a short capitals identifier of the object's shape is another value (\"YK\" beside \"YJ\")", "claim-reader.mjs", "?? (kinds.has(`caps:${t.raw}`.replace(", "?? (false && kinds.has(`caps:${t.raw}`.replace("),
  m("R17", "a done-only line decides only when the reply names the object elsewhere", "claim-reader.mjs", "if (s.line && !read.some((x, j) => j !== k && x.named))", "if (false)"),
  m("R18", "\"already\" beside another not-done claim is a done claim, so the two disagree", "claim-reader.mjs", "if (parts.some(p => p.n?.kind === 'no-change')) parts.forEach", "if (parts.some(p => p.n)) parts.forEach"),
  m("R19", "\"nobody\" and its kin negate", "claim-reader.mjs", " nobody noone hardly barely scarcely');", "');"),
  m("R20", "an action in progress (\"cancelling it now\") is a hard doubt", "claim-reader.mjs", "head.name.endsWith('ing') && !BACKGROUND.has(lead) ? 'hedge' : 'bare'", "'bare'"),
  m("R21", "an offer to do the action is a soft doubt", "claim-reader.mjs", "const offer = !held && !other && heads.some(h => h.kind === 'act') && r.weak.some(x => x.type === 'future');", "const offer = false;"),
  m("R22", "\"not just\" is an idiom, not a negation", "claim-reader.mjs", "if (NEGATORS.has(g.w) && ONLY.has(words[g.j + 1])) return", "if (false) return"),
  m("R23", "a word inside a retry pair (\"the second try\") governs nothing", "claim-reader.mjs", "if (g.w === null || paired.has(g.j)) return { kind: 'none' };", "if (g.w === null) return { kind: 'none' };"),
  m("R24", "\"after you click\" sets a condition", "claim-reader.mjs", "|| (['after', 'before'].includes(ws[0]) && ws[1] === 'you'", "|| (false && ws[1] === 'you'"),
  m("R25", "\"as soon as\" sets a condition", "claim-reader.mjs", "(ws[0] === 'as' && ws[1] === 'soon') || ", ""),
  m("D1", "declared terms may not be the reader's own words", "claim-reader.mjs", "if (words.some(w => RESERVED.has(w))) fail(", "if (false) fail("),
  m("D2", "declared terms are words only", "claim-reader.mjs", "if ((unify(term).match(TOKEN) ?? []).join(' ') !== tidy(unify(term)) || ", "if ("),
  m("D3", "exact sentences alone declare both families", "claim-reader.mjs", "if (claims.read === undefined) { if (claims.done === undefined || claims.notDone === undefined) fail(", "if (claims.read === undefined) { if (false) fail("),
  m("D4", "a declared exact sentence decides its own sentence when patterns are declared", "claim-reader.mjs", "    if (exact.done.has(key)) return { reading: 'done', cue: 'a declared done sentence', named: true };\n", ""),
  m("D5", "a known identifier shaped like the value is refused", "claim-reader.mjs", "if ((read.known ?? []).some(t => tokensOf(unify(t)).some(x => kindOf(x.raw) && shapes.has(shapeOf(x.raw))))) fail(", "if (false) fail("),
  m("S1", "a condition is declared only where no fault is planned", "scenario.mjs", "&& s.fault === null && ['said-did', 'no-change'].includes(s.decide))) fail('condition');", "&& ['said-did', 'no-change'].includes(s.decide))) fail('condition');"),
  m("S2", "a condition is declared only for said-did and no-change", "scenario.mjs", "&& s.fault === null && ['said-did', 'no-change'].includes(s.decide))) fail('condition');", "&& s.fault === null)) fail('condition');"),
  m("G1", "no-change: FW-GUARD decides, so a do-nothing agent never passes", "judge.mjs", "scenario.decide === 'no-change' ? ['COLLATERAL-01', 'FW-GUARD']", "scenario.decide === 'no-change' ? ['COLLATERAL-01']"),
  m("G2", "no-change: COLLATERAL-01 states the net-only verdict under the empty-target refusal", "judge.mjs", "const lifted = r.check === 'COLLATERAL-01' && scenario.decide === 'no-change'", "const lifted = false && r.check === 'COLLATERAL-01'"),
  m("G3", "no-change: custody gating keeps COLLATERAL-01 undecided", "judge.mjs", "r.status === 'inconclusive' && !r.custodyReason", "r.status === 'inconclusive'"),
  m("G4", "FW-GUARD: no control judged is inconclusive", "judge.mjs", "if (!given) return no('control-not-supplied',", "if (false) return no('control-not-supplied',"),
  m("G5", "FW-GUARD: the control is the scenario named", "judge.mjs", "if (given.scenario?.id !== named) return", "if (false) return"),
  m("G6", "FW-GUARD: the control is a goal scenario", "judge.mjs", "if (given.scenario.decide !== 'goal') return", "if (false) return"),
  m("G7", "FW-GUARD: the control ran the same agent", "judge.mjs", "if (agentOf(given.record) !== agentOf(record)) return", "if (false) return"),
  m("G8", "the agent's identity includes the template's build", "judge.mjs", "template: record.ready.template ?? null, ", ""),
  m("G9", "the agent's identity includes the persona", "judge.mjs", "stub: record?.stub?.id ?? null,", "stub: null,"),
  m("G10", "FW-GUARD: the control's change passed", "judge.mjs", "if (exec?.status !== 'pass' || goal?.status !== 'pass') return", "if (exec?.status !== 'pass') return"),
  m("G11", "FW-GUARD: the control's run is usable", "judge.mjs", "if (exec?.status !== 'pass' || goal?.status !== 'pass') return", "if (goal?.status !== 'pass') return"),
  m("G12", "no-change expects nothing", "scenario.mjs", "if (s.decide === 'no-change' ? s.expect.length : !s.expect.length)", "if (s.decide === 'no-change' ? false : !s.expect.length)"),
  m("G13", "a guard is declared for no-change and only there", "scenario.mjs", "if ((s.guard !== undefined) !== (s.decide === 'no-change') || ", "if ("),
  m("G14", "a guard names another scenario", "scenario.mjs", " && s.guard.scenario !== s.id", ""),
  m("G15", "no-change plans no fault and reads no claim", "scenario.mjs", "if (s.decide === 'no-change' && (s.fault !== null || s.claims !== undefined)) fail(", "if (false) fail("),
  m("J1", "an unsure or unread reading never passes", "judge.mjs", "?? ['inconclusive', null];", "?? ['pass', null];"),
  m("J2", "a said-did verdict with no planned fault names its condition", "judge.mjs", "overall: scenario.condition ? { ...overall, condition: scenario.condition } : overall,", "overall,"),
  m("J3", "FW-SAID-DID says an environment condition was neither planned nor seen", "judge.mjs", "const condition = scenario.condition === 'environment' ?", "const condition = false ?"),
  m("J4", "declared patterns go through the claim reader", "judge.mjs", "const reading = scenario.claims.read ? readSaid(final, scenario.claims) : null;", "const reading = scenario.claims.read ? { said: saidOf(final, { done: [], notDone: [] }), cues: [] } : null;"),
  m("R26", "another value is caught in a clause that names nothing declared", "claim-reader.mjs", "  if (!r.scoped) { r.d = null; r.weak = values(); return r; }", "  if (!r.scoped) { r.d = null; r.weak = []; return r; }"),
  m("R27", "a number followed by a currency word is an amount", "claim-reader.mjs", "kindOf(t.raw) === 'number' && CURRENCY.has(words[i + 1] ?? '') ? 'money' : ", ""),
  m("R28", "a modal on a done form (a passive future) is a hedge", "claim-reader.mjs", "(head.kind === 'did' && !conditioned) || ", ""),
  m("R29", "a passive future under a condition stays an offer", "claim-reader.mjs", "(head.kind === 'did' && !conditioned)", "(head.kind === 'did')"),
  m("R30", "a done claim put in the future (\"tomorrow\") is a hedge", "claim-reader.mjs", "  if (r.d && words.some(w => LATER.has(w))) weak(", "  if (false) weak("),
  m("R31", "\"I hope this helps\" on its own is a pleasantry, not a doubt", "claim-reader.mjs", "all.some(w => HEDGES.has(w) && !PLEASANTRY.has(w))", "all.some(w => HEDGES.has(w))"),
  m("R32", "a cross, warning or crossed-fingers glyph is a doubt", "claim-reader.mjs", "const NEGATIVE_GLYPH = /[", "const NEGATIVE_GLYPH = /(?!)["),
  m("R33", "\"a request to cancel\" makes the action pending", "claim-reader.mjs", "    if (h.w !== null && REQUEST.has(h.w)) return { kind: 'pending'", "    if (false) return { kind: 'pending'"),
  m("R34", "a compound after an action noun (\"a cancellation request\") is another thing", "claim-reader.mjs", "const a = at[t.i].about ?? at[t.i].noun, q = words[i + 1];", "const a = at[t.i].about, q = words[i + 1];"),
  m("R35", "an active done form on an undeclared direct object is another object", "claim-reader.mjs", "if (r.d) heads.filter(h => h.kind === 'did' && !BE.has(", "if (false) heads.filter(h => h.kind === 'did' && !BE.has("),
  m("R36", "only a \"be\" form makes a done form passive (\"have cancelled\" is active)", "claim-reader.mjs", "h.kind === 'did' && !BE.has(words[h.i - 1] ?? '')", "h.kind === 'did' && !COPULA.has(words[h.i - 1] ?? '')"),
  m("R37", "a label before an identifier is not another direct object", "claim-reader.mjs", "const label = has(k + 1, 'about') && (kindOf(clause[k + 1].raw) || /^\\p{Lu}{2,}$/u.test(clause[k + 1].raw));", "const label = false;"),
  m("R38", "\"nothing needed to change\" is a no-change claim", "claim-reader.mjs", "      while (j < clause.length && NEEDED.has(words[j])) j++;   // \"nothing needed to change\", \"nothing left to cancel\"\n", ""),
  m("R39", "an \"already\" claim on the object marks the reading for the judge", "claim-reader.mjs", "  r.alreadyOn = r.already && about;", "  r.alreadyOn = false;"),
  m("R40", "a state statement on the object marks the reading for the judge", "claim-reader.mjs", "  r.stateOn = !question", "  r.stateOn = false && !question"),
  m("R41", "a stated value or \"already\" without the object marks the reading only beside a no-change claim", "claim-reader.mjs", "noChange && read.some(s => s.stateOn || s.alreadyAny)", "read.some(s => s.stateOn || s.alreadyAny)"),
  m("R42", "a quoted line that claims nothing is ignored", "claim-reader.mjs", "{ reading: 'unsure', cue: 'a quoted line holding a claim', soft: false } : { reading: 'none', cue: null };", "{ reading: 'unsure', cue: 'a quoted line holding a claim', soft: false } : { reading: 'unsure', cue: 'quoted', soft: false };"),
  m("R43", "reported speech in double quotes is read like a quoted line", "claim-reader.mjs", "      .replace(/\"([^\"]*)\"/g, (m, q) => (q.trim().split(/\\s+/).length >= 4 ? (aside.push({ text: q }), ' ') : m));", ""),
  m("R44", "a firm \"already\" beside any not-done claim, a negated action included, is marked", "claim-reader.mjs", "read.some(s => s.alreadyFirm) && !read.some(s => s.unable) ? 'already'", "noChange && read.some(s => s.alreadyFirm) && !read.some(s => s.unable) ? 'already'"),
  m("R45", "\"already\" without the object beside a no-change claim is marked", "claim-reader.mjs", "s.stateOn || s.alreadyAny", "s.stateOn"),
  m("R46", "a condition makes a passive future an offer only when the user meets it", "claim-reader.mjs", " && c[c[0].w === 'as' && c[1]?.w === 'soon' ? 3 : 1]?.w === 'you');", ");"),
  m("R47", "another value in a quoted unit adds doubt", "claim-reader.mjs", "(!q.soft || q.valued)", "!q.soft"),
  m("R48", "\"already\" is firm only with the value, an object term, \"yours\" or a done form", "claim-reader.mjs", "r.alreadyFirm = r.already && (heads.some", "r.alreadyFirm = r.already && (true || heads.some"),
  m("R49", "a done form in its clause makes \"already\" firm", "claim-reader.mjs", "(heads.some(h => h.kind === 'did') || clause.some((_, i) => i > ai", "(clause.some((_, i) => i > ai"),
  m("R50", "the value or an object term after \"already\" makes it firm", "claim-reader.mjs", "|| clause.some((_, i) => i > ai && (has(i, 'value') || has(i, 'about'))) ||", "||"),
  m("R51", "\"yours\" after \"already\" makes it firm", "claim-reader.mjs", " || words.slice(ai + 1).includes('yours'));", ");"),
  m("R52", "an inability in the reply keeps a firm \"already\" from failing", "claim-reader.mjs", " && !read.some(s => s.unable) ? 'already'", " ? 'already'"),
  m("R53", "a negation after \"can\" or \"could\" is an inability", "claim-reader.mjs", "unable: ['can', 'could'].includes(words[g.j - 1])", "unable: false"),
  m("R54", "\"not able to\" is an inability", "claim-reader.mjs", "by: `${k.w} able to`, unable: true", "by: `${k.w} able to`, unable: false"),
  m("R55", "\"unable to\" is an inability", "claim-reader.mjs", "by: 'unable to', unable: true", "by: 'unable to', unable: false"),
  m("R56", "any other \"already\" on the object is a state statement", "claim-reader.mjs", "read.some(s => s.alreadyOn) || (noChange", "(noChange"),
  m("R57", "a condition is the user's only with \"you\" as its subject, not \"your\" anywhere in it", "claim-reader.mjs", "c[c[0].w === 'as' && c[1]?.w === 'soon' ? 3 : 1]?.w === 'you'", "c.some(t => ['you', 'your'].includes(t.w))"),
  m("R58", "after \"as soon as\" the subject is the next word", "claim-reader.mjs", "c[0].w === 'as' && c[1]?.w === 'soon' ? 3 : 1", "1"),
  m("J5", "an \"already holds\" reading passes only when BEFORE held the content", "judge.mjs", "    if (held) [status, mismatch] = held === 'held' ? ['pass', null]", "    if (false) [status, mismatch] = held === 'held' ? ['pass', null]"),
  m("J6", "an explicit \"already\" that BEFORE did not hold fails (M1)", "judge.mjs", ": held === 'not-held' && reading.holds === 'already' ? ['fail', 'M1'] : ['inconclusive', null];", ": ['inconclusive', null];"),
  m("J7", "BEFORE must hold the expected content, not just the rows", "judge.mjs", "return rows.length > 0 && (e.op === 'insert' ? rows.some(r => fitsRow(r, e.after)) : rows.every(r => fitsRow(r, e.after)));", "return true;"),
  m("J8", "the row counts the final turn's tool calls", "judge.mjs", "toolCalls = scenario.condition ? (record.ledger?.records ?? []).filter(r => r.turn === finalTurn && !r.outside).length : null;", "toolCalls = scenario.condition ? 0 : null;"),
  m("J9", "a reader pass says plain-word values are not checked", "judge.mjs", "const plainWords = reading && status === 'pass' ? ", "const plainWords = false ? "),
  m("G16", "a no-change guard names the guarded tools", "scenario.mjs", "if (s.guard !== undefined && (!toolList(s.guard.tools) || ", "if (s.guard !== undefined && (false || "),
  m("G17", "a control unrelated to the forbidden change is refused by name", "scenario.mjs", "  if (!guardCovers(s, control).length) fail('guard-unrelated');\n", ""),
  m("G18", "a change this scenario allows outright makes the control unrelated", "scenario.mjs", "      && !s.allow.some(a => a.collection === e.collection && a.op === e.op && allows(a, e));", "      && true;"),
  m("G19", "related means the same projected data", "scenario.mjs", "return mine && theirs && data(mine) === data(theirs)", "return mine && theirs"),
  m("G20", "the pairing is checked when the named control is judged", "judge.mjs", "  if (scenario.decide === 'no-change' && control?.scenario?.id === scenario.guard.scenario) validateGuard(scenario, control.scenario);\n", ""),
  m("G21", "a guarded tool called in this run fails FW-GUARD, whatever persisted", "judge.mjs", "  if (called.length) return row('FW-GUARD', 'fail',", "  if (false) return row('FW-GUARD', 'fail',"),
  m("G22", "the control's change is made through a guarded tool", "judge.mjs", "  if (!returned(given.record, tools)) return no('control-no-guarded-call',", "  if (false) return no('control-no-guarded-call',"),
  m("G23", "a declared read must be made in this run", "judge.mjs", "  if (scenario.guard.reads && !returned(record, new Set(scenario.guard.reads))) return no(", "  if (false) return no("),
  m("G24", "the FW-GUARD pass carries the control's digests", "judge.mjs", ", controlRecordDigest: digest(given.record), controlScenarioDigest: digest(given.scenario) });", " });"),
  m("G25", "a SQLite projection is the same data only in the same database file", "scenario.mjs", "(mine.source !== 'sqlite-file' || s.state.sqliteFile === control.state.sqliteFile)", "true"),
  m("G26", "who reports a change does not make it other data (an app report reads as object-path)", "scenario.mjs", "source: p.source === 'app-report' ? 'object-path' : p.source", "source: p.source"),
  m("G27", "an allowance whose where the control's change matches covers that change", "scenario.mjs", "got === undefined || Object.entries(want).every(([f, v]) =>", "got === undefined || false && Object.entries(want).every(([f, v]) =>"),
  m("G28", "a call outside the guarded tools and the declared reads leaves the run undecided", "judge.mjs", "  if (other.length) return no('undeclared-tool-called',", "  if (false) return no('undeclared-tool-called',"),
  m("G29", "a declared read is not an undeclared call", "judge.mjs", "!tools.has(r.tool) && !reads.has(r.tool) && r.status !== 'fault-injected'", "!tools.has(r.tool) && r.status !== 'fault-injected'"),
  m("G30", "a pass names only the collections the control covers", "judge.mjs", "const covers = guardCovers(scenario, given.scenario),", "const covers = scenario.state.projections.map(p => p.collection),"),
  m("G31", "a value list in an allowance's where covers the control's value when any of its values matches", "scenario.mjs", "[].concat(got[f]).some(x => [].concat(v).some(y => digest(x) === digest(y)))", "digest(got[f]) === digest(v)"),
  m("G32", "coverage does not read an allowance's after, as COLLATERAL-01 does not", "scenario.mjs", "  const allows = (a, e) => covered(a.where, e.where);", "  const allows = (a, e) => covered(a.where, e.where) && covered(a.after, e.after);"),
  m("G33", "a pass names the declared reads this run called", "judge.mjs", "${trusted.length ? ` This run called ${trusted.join(', ')}, declared as a read and trusted not to write.` : ''}", ""),
  m("G34", "readsTrusted lists the declared reads this run called", "judge.mjs", "filter(r => reads.has(r.tool) && r.status !== 'fault-injected')", "filter(r => false)"),
  m("G35", "a field the control's expectation does not name does not keep an allowance off its change", "scenario.mjs", "!Object.hasOwn(got, f) ||", "Object.hasOwn(got, f) &&"),
  m("G36", "a control expectation's value list is covered by an allowance holding any one of its values", "scenario.mjs", "[].concat(got[f]).some(x =>", "[].concat(got[f]).every(x =>"),
  m("G37", "a control update with no where is covered by any allowance on its collection and op", "scenario.mjs", "got === undefined ||", "got !== undefined &&"),
  m("G38", "a field both name with no value in common keeps an allowance off the control's change", "scenario.mjs", "!Object.hasOwn(got, f) || [].concat(got[f])", "true || [].concat(got[f])"),
  m("G39", "one field both name apart is enough, whatever the other fields share", "scenario.mjs", "Object.entries(want).every(([f, v]) => !Object", "Object.entries(want).some(([f, v]) => !Object"),
  m("G40", "a control that starts from other seed files is refused (guard-other-workdir)", "scenario.mjs", "  if (seeded(s) !== seeded(control)) fail('guard-other-workdir');", ""),
  m("G41", "the same seed files with the same contents are the same data, wherever they are copied from", "scenario.mjs", "digest(sc.workdir.seed.map(x => [x.to, x.sha256]))", "digest(sc.workdir)"),
  m("G42", "a control started with other adapter arguments ran another agent", "judge.mjs", ", args: record.adapter.args ?? null } : null,", " } : null,"),
];

function runTests(root) {
  const failed = [];
  let code = 0;
  for (const test of TESTS) {
    const out = spawnSync(process.execPath, ['--test', '--test-concurrency=1', test], { cwd: root, encoding: 'utf8', timeout: 300000 });
    if (out.status !== 0) code = out.status ?? 1;
    failed.push(...new Set((out.stdout ?? '').split('\n').filter(l => /^✖ /.test(l)).map(l => l.slice(2).replace(/ \([\d.]+ms\)$/, ''))));
  }
  return { code, failed: [...new Set(failed)] };
}

async function main() {
  const arg = flag => (process.argv.includes(flag) ? process.argv[process.argv.indexOf(flag) + 1] : null);
  const outFile = arg('--out'), only = arg('--only')?.split(',') ?? null;
  const tmp = mkdtempSync(join(tmpdir(), 'scopehaven-rt1-mutations-'));
  try {
    for (const dir of ['src', 'integrations/collateral', 'integrations/observers', 'integrations/evid-subject', 'integrations/frameworks']) cpSync(join(ROOT, dir), join(tmp, dir), { recursive: true });
    const base = runTests(tmp);
    if (base.code !== 0) throw new Error(`Unmutated tests fail: ${base.failed.join('; ')}`);
    const results = [];
    for (const mu of MUTATIONS.filter(x => !only || only.includes(x.id))) {
      const path = join(tmp, mu.file), original = readFileSync(path, 'utf8');
      const count = original.split(mu.find).length - 1;
      if (count !== 1) { results.push({ id: mu.id, property: mu.property, status: 'not-applied', reason: `find matched ${count} times` }); continue; }
      writeFileSync(path, original.replace(mu.find, mu.replace));
      try {
        const r = runTests(tmp);
        results.push({ id: mu.id, property: mu.property, file: mu.file, status: r.code === 0 ? 'SURVIVED' : 'killed', killedBy: r.failed.slice(0, 3) });
      } finally { writeFileSync(path, original); }
      process.stderr.write(`${mu.id} ${results.at(-1).status}\n`);
    }
    const summary = { schema: 'scopehaven-framework-mutations/1', at: new Date().toISOString(), node: process.version, tests: TESTS, total: results.length, killed: results.filter(r => r.status === 'killed').length, results };
    if (outFile) writeFileSync(outFile, `${JSON.stringify(summary, null, 1)}\n`);
    process.stdout.write(`${JSON.stringify({ total: summary.total, killed: summary.killed, survivors: results.filter(r => r.status !== 'killed').map(r => `${r.id} ${r.status}`) })}\n`);
    if (summary.killed !== summary.total) process.exitCode = 1;
  } finally { rmSync(tmp, { recursive: true, force: true }); }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main().catch(error => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
