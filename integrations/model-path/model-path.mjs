// Model path: hold an agent's model call, change the user's
// access while it is held, release it, and judge from the app's records, on any
// agent stack whose model base URL can be pointed at a loopback address.
//
// Topology: app -> hold gate (integrations/sequences/gate.mjs) -> model tap
// (integrations/model-identity/tap.mjs) -> model server. Both proxies are unchanged
// and bind 127.0.0.1 only. The gate pauses the call at the boundary between "the
// model chose the next step" and "the tool ran"; the tap records which model each
// call asked for and which model the server says answered it, so the run's model
// identity comes from traffic, never from the app's configuration.
//
// A run (scopehaven-model-path-run/1) wraps the sequence run unchanged
// (scopehaven-sequence-run/2, with its own digest) and adds, for each hold, the tap
// window from the release to the end of the run and the model identity of that
// window, plus the run-level identity. Existing sequence and tap identities are not
// touched: this is a new record around them.
//
// Refused: a listen address other than 127.0.0.1; an upstream that is not a literal
// loopback origin (tap.mjs upstreamKind); every hosted vendor, even an allowlisted one,
// until hosted forwarding is approved (a spend decision that is Yusef's); and any 3xx the
// model server answers, on any route: the redirect guard between the gate and the tap
// answers the app 502 and writes the refusal into the tap log, so the run reads refused.
//
// Validation (validateModelPathRun) recomputes everything the judge reads: the sequence
// run by the shared validator (verdicts from its sealed windows), the verdicts and the
// refusal from that and the tap log, each hold's window and identity from the run timeline
// and the tap log, and the gate and tap fields from the log's own frames. The record
// digest is not keyed, so a consistent forgery of the whole record is out of its scope;
// a run signed when it was written (signModelPathRunFiles, integrations/attest) closes that
// for anyone without the signing key (verifyModelPathRunFiles).
import { readFileSync, existsSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { digest } from '../../src/domain.mjs';
import { createHoldGate } from '../sequences/gate.mjs';
import { runSequence, validateSequence } from '../sequences/sequence.mjs';
import { validateSequenceRun } from '../sequences/run-validator.mjs';
import { sequenceTransport } from '../sequences/transport.mjs';
import { createModelTap, TapLog, upstreamKind, chainHash, CHAIN_START, TAP_SCHEMA } from '../model-identity/tap.mjs';
import { modelIdentity } from '../model-identity/identity.mjs';
import { signFiles } from '../attest/sign.mjs';
import { verifyEnvelope, subjectNames, trustedKey, keyIdOf } from '../attest/verify.mjs';
import { createRedirectGuard, REDIRECT_REFUSED } from './redirect-guard.mjs';

export const MODEL_PATH_RUN_SCHEMA = 'scopehaven-model-path-run/2';
export const MODEL_PATH_GATE_SCHEMA = 'scopehaven-model-path-gate/1';
export class ModelPathError extends Error { constructor(code, detail) { super(`Model path refused: ${detail}.`); this.name = 'ModelPathError'; this.code = code; } }

// Start the gate in front of the redirect guard in front of the tap in front of the model server.
//   upstream     model server origin: http://127.0.0.1:<port> (local Ollama or another loopback server)
//   rules        hold-gate rules ([{ id, method?, pathPrefix, holds? }])
//   tapLogPath   absolute path for the append-only tap log (created, never overwritten), or null for memory only
//   listenHost   must be 127.0.0.1
export async function startModelPath({ upstream, rules, tapLogPath = null, listenHost = '127.0.0.1', ollamaTags } = {}) {
  if (listenHost !== '127.0.0.1') throw new ModelPathError('listen-not-loopback', 'the gate and tap listen on 127.0.0.1 only');
  const kind = upstreamKind(upstream);
  if (!kind) throw new ModelPathError('upstream-not-allowed', 'the model upstream must be a literal loopback origin or an allowlisted hosted vendor');
  if (kind === 'hosted') throw new ModelPathError('hosted-not-approved', 'a hosted model upstream waits on an approval this build does not have; use a loopback model server');
  if (!Array.isArray(rules) || !rules.length) throw new ModelPathError('no-rules', 'declare at least one gate rule for the model call');
  const log = new TapLog({ path: tapLogPath });
  const tap = createModelTap({ upstream, log, ...(ollamaTags === undefined ? {} : { ollamaTags }) });
  await tap.start();
  const guard = createRedirectGuard({ upstream: tap.url, log });
  try { await guard.start(); } catch (error) { await tap.stop(); log.close(); throw error; }
  const gate = createHoldGate({ upstream: guard.url, rules, instanceId: 'model-path-gate' });
  try { await gate.start(); } catch (error) { await guard.stop(); await tap.stop(); log.close(); throw error; }
  return {
    schema: MODEL_PATH_GATE_SCHEMA, upstreamKind: kind, rules: rules.map(r => ({ ...r })),
    get url() { return gate.url; }, gate, guard, tap, log,
    async stop() { await gate.stop(); await guard.stop(); await tap.stop(); log.close(); },
  };
}

// The sequence transport with every rule unchanged except the response cap: an agent's
// reply streams token by token and passes the 64 KiB default; a reply cut off there would
// disconnect the app mid-task.
export const MODEL_PATH_RESPONSE_BYTES = 4 * 1024 * 1024;
export const modelPathTransport = (origin, check, options) => sequenceTransport(origin, check, { ...options, maxResponseBytes: MODEL_PATH_RESPONSE_BYTES });

// Run one sequence through a started model path and wrap the result.
export async function runModelPath({ sequence, origin, observers = [], path, env = process.env, transport = modelPathTransport }) {
  validateSequence(sequence);
  const before = await path.tap.mark();
  const run = await runSequence(sequence, { origin, observers, gate: path.gate, env, transport });
  const after = await path.tap.mark();
  return wrapRun({ run, frames: path.log.frames, before: before.seq, after: after.seq, upstreamKind: path.upstreamKind, rules: path.rules });
}

// The last tap frame at or before wall time t (ns, as a string).
const seqAt = (frames, t) => frames.filter(f => Number.isInteger(f.seq) && typeof f.t === 'string' && BigInt(f.t) <= BigInt(t)).at(-1)?.seq ?? 0;
// A redirect in the run window: a model route answered 3xx (the tap's gap) or any route the guard refused.
export const redirectsIn = (frames, from, to) => frames.filter(f => Number.isInteger(f.seq) && f.seq > from && f.seq <= to
  && ((f.kind === 'result' && f.gap === 'redirect') || (f.kind === 'gap' && f.reason === REDIRECT_REFUSED))).length;
// Each release in the run timeline: the tap window from the release to the end of the run, and its identity.
const holdsFrom = (timeline, frames, from, to) => timeline.filter(e => e.step === 'released').map(e => {
  const start = Math.max(from, seqAt(frames, e.t));
  return { hold: e.hold, releasedAt: e.t, tapWindow: { from: start, to }, identity: modelIdentity(frames, { from: start, to }) };
});
const project = results => results.map(r => ({ id: r.id, severity: r.severity, status: r.status, verdict: r.verdict }));

export function wrapRun({ run, frames, before, after, upstreamKind: kind, rules }) {
  const refused = redirectsIn(frames, before, after) > 0 ? 'upstream-redirect' : null;
  const record = {
    schema: MODEL_PATH_RUN_SCHEMA, gate: { schema: MODEL_PATH_GATE_SCHEMA, upstreamKind: kind, rules },
    refused, sequenceRun: run,
    tap: { schema: TAP_SCHEMA, session: frames.find(f => f.kind === 'open')?.session ?? null, window: { from: before, to: after },
      head: frames.find(f => f.seq === after)?.h ?? CHAIN_START, frames: frames.filter(f => Number.isInteger(f.seq) && f.seq <= after).length },
    identity: modelIdentity(frames, { from: before, to: after }), holds: holdsFrom(run.timeline, frames, before, after),
    // A refused run carries no verdicts of its own: the sequence results stay as recorded, but the run reads refused.
    verdicts: refused ? null : project(run.results),
  };
  return { ...record, recordDigest: digest(record) };
}

const plain = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const NS = /^\d{1,30}$/;
// Recompute a saved run from its tap log (a file path, or the log's bytes). Options bind it to what
// the caller configured: expectedSequence and expectedObservers (as validateSequenceRun takes them)
// and expectedRules. What this recomputes: the sequence verdicts, the refusal, every hold's window
// and identity, the run identity, the tap window and the gate. What it does not: the timeline's
// task transport, response statuses and step order, which the judge also reads. Those are bound
// only by the run's signature, so read a run's MIDTASK reading only from a signed run directory
// verified under the pinned key (judgeSignedRun in midtask-any.mjs).
export function validateModelPathRun(record, tapLog, { expectedSequence, expectedObservers, expectedRules } = {}) {
  const need = (ok, code, detail) => { if (!ok) throw new ModelPathError(code, detail); };
  need(plain(record) && record.schema === MODEL_PATH_RUN_SCHEMA, 'schema', 'not a model-path run of this version');
  const { recordDigest, ...rest } = record;
  need(digest(rest) === recordDigest, 'digest', 'the record does not match its digest');
  // The tap log: every frame chained from the start, and the run window between two of its marks.
  const frames = (Buffer.isBuffer(tapLog) ? tapLog.toString('utf8') : readFileSync(tapLog, 'utf8')).split('\n').filter(Boolean).map(line => JSON.parse(line));
  let head = CHAIN_START;
  for (const f of frames) { const { h, ...body } = f; need(h === chainHash(head, body), 'tap-chain', 'the tap log chain is broken'); head = h; }
  const tap = record.tap, at = seq => frames.find(f => f.seq === seq), open = frames.find(f => f.kind === 'open');
  need(plain(tap) && tap.schema === TAP_SCHEMA && open && open.seq === 1 && tap.session === open.session, 'tap-session', 'the tap log is not this run\'s');
  const { from, to } = tap.window ?? {};
  need(Number.isInteger(from) && Number.isInteger(to) && from > 0 && from < to && [at(from), at(to)].every(f => f?.kind === 'models' && f.phase === 'mark'), 'tap-window', 'the run window is not bounded by two tap marks');
  need(tap.head === at(to).h && tap.frames === frames.filter(f => Number.isInteger(f.seq) && f.seq <= to).length, 'tap-head', 'the tap log does not reach the recorded head');
  // The gate: the upstream kind is the tap's own reading of its upstream, loopback only; the rules as configured.
  const gate = record.gate;
  need(plain(gate) && gate.schema === MODEL_PATH_GATE_SCHEMA && gate.upstreamKind === upstreamKind(open.upstream) && gate.upstreamKind === 'loopback', 'gate', 'the gate does not match the tap\'s upstream');
  need(Array.isArray(gate.rules) && gate.rules.length && gate.rules.every(r => plain(r) && typeof r.id === 'string') && (expectedRules === undefined || digest(expectedRules) === digest(gate.rules)), 'gate-rules', 'the gate rules are not the configured ones');
  // The sequence run, recomputed by the shared validator from its sealed windows.
  let results;
  try { ({ results } = validateSequenceRun(record.sequenceRun, { ...(expectedSequence === undefined ? {} : { expectedSequence }), ...(expectedObservers === undefined ? {} : { expectedObservers }) })); }
  catch (error) { throw new ModelPathError('sequence-run', `the sequence run does not recompute (${error.code ?? 'error'}${error.detail ? `: ${error.detail}` : ''})`); }
  // The refusal and the verdicts, recomputed.
  const refused = redirectsIn(frames, from, to) > 0 ? 'upstream-redirect' : null;
  need(record.refused === refused, 'refused', 'the refusal does not recompute from the tap log');
  need(digest(record.verdicts) === digest(refused ? null : project(results)), 'verdicts', 'the verdicts are not the sequence run\'s recomputed results');
  // The timeline: wall times in order, inside the tap marks, its holds and releases matching the gate's own timeline.
  const tl = record.sequenceRun.timeline, gt = record.sequenceRun.gateTimeline, ruleIds = new Set(gate.rules.map(r => r.id));
  need(Array.isArray(tl) && tl.length && tl.every(e => plain(e) && NS.test(e.t ?? '')) && tl.every((e, i) => i === 0 || BigInt(tl[i - 1].t) <= BigInt(e.t)), 'timeline', 'the run timeline is not in time order');
  need(BigInt(at(from).t) <= BigInt(tl[0].t) && BigInt(tl.at(-1).t) <= BigInt(at(to).t), 'timeline', 'the run timeline lies outside the tap window');
  need(Array.isArray(gt) && gt.every(e => plain(e) && NS.test(e.t ?? '') && (e.ruleId === undefined || e.ruleId === null || ruleIds.has(e.ruleId))), 'gate-timeline', 'the gate timeline names a rule the gate does not have');
  const gateEvents = type => gt.filter(e => e.type === type);
  const held = tl.filter(e => e.step === 'held'), released = tl.filter(e => e.step === 'released');
  need(held.every(e => ruleIds.has(e.rule)) && held.length === gateEvents('held').length && released.length === gateEvents('released').length, 'gate-timeline', 'the holds and releases do not match the gate\'s timeline');
  need(gateEvents('held').every((g, i) => BigInt(g.t) <= BigInt(held[i].t)) && gateEvents('released').every((g, i) => BigInt(g.t) <= BigInt(released[i].t) && BigInt(gateEvents('held')[i]?.t ?? g.t) <= BigInt(g.t)), 'gate-timeline', 'the gate held or released at another time');
  // Each hold's window and identity, recomputed from the timeline and the tap log; and the run identity.
  need(digest(record.holds) === digest(holdsFrom(tl, frames, from, to)), 'holds', 'the holds do not recompute from the timeline and the tap log');
  need(digest(modelIdentity(frames, tap.window)) === digest(record.identity), 'identity', 'the run identity does not recompute');
  return { results };
}

// A run directory as run-stack writes it: record.json, tap.jsonl and the app's audit store.
export const MODEL_PATH_SIGN_VERSION = '2.0.0';
const RUN_FILES = ['record.json', 'tap.jsonl', 'access.db'];
// Sign the run's files with the lane's key (integrations/attest), written once as run.dsse.json.
export function signModelPathRunFiles(dir, { privateKey, now }) {
  const files = RUN_FILES.filter(name => existsSync(join(dir, name))).map(name => ({ name, content: readFileSync(join(dir, name)) }));
  if (!files.some(f => f.name === 'record.json') || !files.some(f => f.name === 'tap.jsonl')) throw new ModelPathError('sign', 'a run needs record.json and tap.jsonl');
  const { envelope } = signFiles(files, { privateKey, version: MODEL_PATH_SIGN_VERSION, ...(now ? { now } : {}) });
  writeFileSync(join(dir, 'run.dsse.json'), envelope, { flag: 'wx', mode: 0o600 });
  return files.map(f => f.name);
}
// The trust anchor: the lane's model-path signing key, committed beside this module
// (model-path-signing.pub.pem) and pinned by its keyid. A run is verified under this key only; any
// other key is refused unless testKey is set, which only the tests do (they sign with fresh keys).
export const MODEL_PATH_KEYID = '0e5c170179dcf97b0c828ac1215a44fa7055875a53010d06cde2bb1dd75b0c61';
export const MODEL_PATH_PUBLIC_KEY = readFileSync(new URL('./model-path-signing.pub.pem', import.meta.url), 'utf8');
// Verify a signed run directory: the key, the signature over its files, then the record against the
// signed tap log bytes. Returns the verified record with the recomputed results.
export function verifyModelPathRunFiles(dir, { publicKey = MODEL_PATH_PUBLIC_KEY, testKey = false, ...options } = {}) {
  let key;
  try { key = trustedKey(publicKey); } catch (error) { throw new ModelPathError('untrusted-key', error.message); }
  const keyid = keyIdOf(key);
  if (keyid !== MODEL_PATH_KEYID && testKey !== true) throw new ModelPathError('untrusted-key', `runs are verified under the pinned model-path key ${MODEL_PATH_KEYID.slice(0, 16)}, not ${keyid.slice(0, 16)}`);
  const envelope = readFileSync(join(dir, 'run.dsse.json'));
  const names = subjectNames(envelope);
  if (!names.includes('record.json') || !names.includes('tap.jsonl') || names.some(n => !RUN_FILES.includes(n))) throw new ModelPathError('signature', 'the envelope does not cover this run\'s files');
  const files = new Map(names.map(name => [name, readFileSync(join(dir, name))]));
  const check = verifyEnvelope({ envelope, publicKey: key, files });
  if (!check.verified) throw new ModelPathError('signature', `the run's files are not the ones signed (${check.reason ?? check.verdict})`);
  const record = JSON.parse(files.get('record.json').toString('utf8'));
  return { signed: names, keyid, record, ...validateModelPathRun(record, files.get('tap.jsonl'), options) };
}
