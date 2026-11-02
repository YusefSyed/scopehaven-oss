import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { writeFileSync } from 'node:fs';
import { createStore } from './store.mjs';
import { createRegistry, loadProfiles } from './registry.mjs';
import { runGate } from '../integrations/regression-gate/gate.mjs';
import { assertRuntime } from './runtime.mjs';
import { needsAuthorization, windowRefusal } from './authorization.mjs';
import { authorizeConfigured } from './authorization-file.mjs';
import { ownedTapConfig } from './http-model-identity.mjs';
import { unpairedForwardedPasses, forwardedPairingGaps } from './forwarded-pairing.mjs';
import { channelReadings } from './channels.mjs';
import { identityCoverage, mirrorReport } from './two-identities.mjs';
import { identityControlPlan } from './contracts.mjs';

const args = process.argv.slice(2), options = {};
const unpairedKey = target => target?.targetContext === 'operator-remote' ? 'remoteUnpaired' : 'forwardedUnpaired';
// Framework mode (integrations/frameworks/assess.mjs): `assess --framework langgraph|mastra --template DIR ...` runs a frozen
// framework scenario and saves an ordinary run, instead of a registered target. Loaded only then.
const framework = args.includes('--framework') ? await import('../integrations/frameworks/assess.mjs') : null;
if (framework) process.exitCode = await framework.frameworkAssessMain(args, { defaultOut: fileURLToPath(new URL('../data/', import.meta.url)) });
else try {
  assertRuntime();
  for (let i = 0; i < args.length; i++) {
    const flag = args[i];
    if (['--list', '--check-config', '--self-test', '--single-identity'].includes(flag)) { if (options[flag]) throw new Error('Duplicate flag.'); options[flag] = true; }
    else if (['--target', '--config', '--out', '--refund-trust-out', '--confine', '--authorization'].includes(flag) && args[i + 1] && !args[i + 1].startsWith('--')) {
      if (options[flag]) throw new Error('Duplicate flag.'); options[flag] = args[++i];
    } else throw new Error('Unsupported or incomplete option.');
  }
  if (options['--single-identity'] && (options['--list'] || options['--check-config'])) throw new Error('--single-identity applies to an assess run only.');
  const profiles = await loadProfiles(options['--config'] || process.env.SCOPEHAVEN_TARGETS_FILE);
  const registry = createRegistry({ profiles });
  // --self-test (src/self-test.mjs): each check's planted violations through the pure evaluators, before anything is
  // authorized, started or sent. A broken check (a predicate that cannot fail or always fails) keeps the exit off 0.
  const selfTesting = options['--self-test'] ? await import('./self-test.mjs') : null;
  // Two identities by default (src/two-identities.mjs): a target that declares tenant-scoped resources ("tenantValues") with fewer
  // than two credentialed identities in distinct declared tenants is tested from one side of its tenant boundary only.
  const coverageOf = profile => identityCoverage(profile, identityControlPlan(profile));
  // Each target's mirror report, computed once (check-config prints it and warns from it). Mirrors are opt-in, so only a
  // target that declares a "mirrors" object is warned when none was generated.
  const plainMirrors = profile => profile?.mirrors !== null && typeof profile?.mirrors === 'object' && !Array.isArray(profile.mirrors);
  const reports = new Map(), reportOf = profile => { if (!reports.has(profile.id)) reports.set(profile.id, mirrorReport(profile, identityControlPlan(profile))); return reports.get(profile.id); };
  const singleIdentityText = id => `target ${id} declares tenant-scoped resources ("tenantValues") but fewer than two credentialed identities (actors with an "identityValue", a declared "tenantId" and an identity control) in distinct declared tenants, so its cross-tenant checks run from one side only: add an identity in another declared tenant, or pass --single-identity to run it anyway`;
  const broken = report => { const reasons = selfTesting.selfTestReasons(report); if (reasons.length) console.error(`Self-test: ${report.targetId} has broken checks (${reasons.join(', ')}): ${selfTesting.brokenChecks(report).join(', ')}`); return reasons.length > 0; };
  if (options['--list'] || options['--check-config']) {
    // registry.list() applies the audit-observer credential rule (withAuditCredentialReadiness), as the dashboard reads it.
    const targets = registry.list();
    // With --self-test, every HTTP contract target's report; with none to test, refused rather than a silent 0.
    const tested = selfTesting ? new Map(targets.filter(t => t.kind === 'http-contract').map(t => [t.id, selfTesting.selfTestFor(t, profiles.find(p => p.id === t.id))])) : null;
    if (tested && !tested.size) throw new selfTesting.SelfTestError(selfTesting.SELF_TEST_UNSUPPORTED);
    console.log(JSON.stringify({ configurationValid: true, dependencies: { node: process.versions.node, externalPackages: 0 }, connectionTested: false,
      // unpairedSelectors: absence selectors (effect.none, or effect.count expecting 0) that pin an actor, a resource or a trace id
      // and have no twin in the profile. They read inconclusive (selector-unpaired) unless every deciding observer declares the
      // resource for the selector's exact name in its vocabulary at run time and the window is closed for it (the payments
      // double declares its provider host's); this static report cannot see run-time vocabularies, so it lists those pins too.
      // unguardedAbsences: absences that pin nothing, in a boundary check that expects a success status and has no positive clause, whose actor has
      // no required allowed-use control with a positive effect; a do-nothing application would pass them, so they read inconclusive.
      // forwardedUnpaired and remoteUnpaired: in an operator-forwarded or operator-remote target, boundary
      // checks with no required control of the same method on the same route; their passes keep the gate from reading clean
      // (src/forwarded-pairing.mjs).
      // twoIdentities: for a target that declares tenantValues, its identities, whether it is single-identity, and each boundary
      // check's generated mirror under the second identity or the reason it has none (src/two-identities.mjs mirrorReport).
      targets: targets.map(t => { const gaps = forwardedPairingGaps(profiles.find(p => p.id === t.id)), p = profiles.find(q => q.id === t.id), two = t.kind === 'http-contract' && coverageOf(p).tenantScoped ? reportOf(p) : null; return { id: t.id, name: t.name, kind: t.kind, checks: t.checksTotal, available: t.available, ...(t.kind === 'http-contract' ? { credentialsReady: t.available } : {}), ...(t.readinessReason ? { readinessReason: t.readinessReason } : {}), missingCredentialRefs: t.missingCredentialRefs || [], ...(t.unpairedSelectors ? { unpairedSelectors: t.unpairedSelectors } : {}), ...(t.unguardedAbsences ? { unguardedAbsences: t.unguardedAbsences } : {}), ...(gaps.length ? { [unpairedKey(profiles.find(p => p.id === t.id))]: gaps } : {}), ...(tested?.has(t.id) ? { selfTest: tested.get(t.id) } : {}), ...(two ? { twoIdentities: two } : {}) }; }) }, null, 2));
    // The warning: check-config still exits 0 for a single-identity target; assess refuses it without --single-identity. --list
    // only lists the targets, so it does not warn.
    if (options['--check-config']) for (const t of targets.filter(t => t.kind === 'http-contract')) {
      const p = profiles.find(q => q.id === t.id), coverage = coverageOf(p);
      if (coverage.singleIdentity) console.error(`Warning: ${singleIdentityText(t.id)}.`);
      else if (coverage.tenantScoped && plainMirrors(p) && !reportOf(p).mirrored.length) console.error(`Warning: target ${t.id} declares tenant-scoped resources but no boundary check was mirrored under its second identity; see twoIdentities.notMirrored for each reason.`);
    }
    if (tested && [...tested.values()].filter(broken).length) process.exitCode = 1;
  } else {
    if (!registry.has(options['--target'])) throw new Error('Select a registered target using --target. Use --list to inspect target identifiers.');
    const directory = options['--out'] ? resolve(options['--out']) : fileURLToPath(new URL('../data/', import.meta.url));
    const entry = registry.list().find(t => t.id === options['--target']), kind = entry?.kind;
    const selfTest = selfTesting ? selfTesting.selfTestFor(entry, profiles.find(p => p.id === options['--target'])) : null;
    // Refused before anything is authorized, started or sent; --single-identity runs it, and the output says so.
    const singleIdentity = kind === 'http-contract' && coverageOf(profiles.find(p => p.id === options['--target'])).singleIdentity;
    if (singleIdentity && !options['--single-identity']) throw new Error(`Single identity refused: ${singleIdentityText(options['--target'])}.`);
    if (options['--single-identity'] && !singleIdentity) console.error('Note: --single-identity had no effect: the target is not a single-identity target.');
    const mirrorless = kind === 'http-contract' && !singleIdentity && (p => coverageOf(p).tenantScoped && plainMirrors(p) && !reportOf(p).mirrored.length)(profiles.find(p => p.id === options['--target']));
    if (mirrorless) console.error(`Warning: target ${options['--target']} declares tenant-scoped resources but no boundary check was mirrored under its second identity (see --check-config twoIdentities.notMirrored).`);
    // A configured target runs only under an authorization record that covers it now: checked before
    // anything starts or sends. Built-in fixture targets need none and keep their shape. The owned model tap's upstream
    // (SCOPEHAVEN_MODEL_TAP_UPSTREAM), which this process forwards the application's model calls to, must be covered too.
    const granted = needsAuthorization(entry) ? await authorizeConfigured(profiles.find(p => p.id === options['--target']), options['--authorization'] && resolve(options['--authorization']),
      { alsoContacts: [ownedTapConfig(process.env)?.upstream].filter(upstream => upstream !== undefined) }) : null;
    // The window is checked again before every request the run sends and when each observer call it makes starts: once it
    // ends, no further request is sent and no further observer call starts (one already running can finish its reads),
    // and the run is refused (exit 2, authorization-window-ended), never saved or stamped. It is
    // checked once more immediately before the run is saved, so a run that ended at or after validUntil is refused too.
    // A remote target's transport dials only what the record allows (src/remote-target.mjs).
    const authorization = granted?.stamp ?? null, runOptions = granted ? { beforeRequest: granted.window.check, remote: granted.remote } : undefined;
    // --confine (src/confine.mjs): ScopeHaven starts the application itself under sandbox-exec, with its declared
    // sinks (and a recorded allowlist) as its only ways out, and seals the confinement record into the run before it is saved.
    if (options['--confine'] && kind !== 'http-contract') throw new Error('--confine applies to an HTTP contract target from --config.');
    if(kind==='owned-refund-contract') {
      const result=await runGate({targetId:options['--target'],outputDirectory:directory,...(options['--refund-trust-out']?{refundTrustOutput:resolve(options['--refund-trust-out'])}:{})});
      console.log(JSON.stringify(result,null,2));process.exitCode=result.exitCode;
    } else {
    const store = createStore(directory); await store.ready;
    let result;
    if (options['--confine']) {
      const { readLaunchFile, startConfined } = await import('./confine.mjs');
      const { sealConfinement } = await import('./confinement-record.mjs');
      // A refused launch saves no run (nothing ever starts unconfined) and leaves a refusal receipt in the evidence directory, so
      // the attempt is on record beside any declared run made afterwards; its code goes to stderr too.
      try {
        const launch = await readLaunchFile(resolve(options['--confine']));
        const confined = await startConfined(profiles.find(p => p.id === options['--target']), launch);
        let assessed, record;
        try { assessed = await registry.run(options['--target'], runOptions); } catch (error) { throw windowRefusal(granted?.window, error); } finally { record = await confined.stop(); }
        // The window once more, after the application stopped and immediately before the run is sealed and saved.
        granted?.window.check();
        result = sealConfinement(assessed, record);
      } catch (error) {
        // Every failure under --confine leaves a receipt: a refusal (its code; an authorization window that ended during the
        // run is authorization-window-ended), or any other error (code "error"), such as a run the record could not be sealed
        // onto or a connector failure. A receipt that could not be written is said on stderr.
        const confinement = error?.name === 'ConfinementError', authorizationRefused = error?.name === 'AuthorizationError';
        const at = new Date().toISOString(), code = confinement || authorizationRefused ? error.code : 'error';
        const receipt = { schema: 'scopehaven-confine-refusal/1', at, target: options['--target'], code, message: String(error?.message ?? error), platform: `${process.platform} ${process.arch}`, node: process.versions.node,
          outcome: 'no run was saved; nothing started unconfined. A run made afterwards without --confine reads routing declared, not shown exclusive.' };
        try { writeFileSync(join(directory, `confine-refusal-${at.replace(/[:.]/g, '-')}.json`), `${JSON.stringify(receipt, null, 2)}\n`, { mode: 0o600, flag: 'wx' }); }
        catch (writeError) { console.error(`The refusal receipt could not be written to ${directory}: ${writeError.message}`); }
        if (confinement) error.message = `confined launch refused (${error.code}): ${error.message}`;
        else if (authorizationRefused) error.message = `${error.message} (confine receipt written)`;
        else if (error && typeof error === 'object') error.message = `confined run failed (receipt written): ${error.message}`;
        throw error;
      }
    } else {
      try { result = await registry.run(options['--target'], runOptions); } catch (error) { throw windowRefusal(granted?.window, error); }
      // The window once more, immediately before the run is saved and stamped.
      granted?.window.check();
    }
    const run = await store.save(authorization ? { ...result, authorization } : result), unpaired = unpairedForwardedPasses(run), withheld = channelReadings(run);
    console.log(JSON.stringify({ id: run.id, target: run.targetId, counts: run.counts, evidenceDirectory: directory,
      evidenceOrigin: run.evidenceOrigin, scope: run.scopeLabel || 'Owned synthetic fixture; no live model/customer assessment.', ...(run.authorization ? { authorization: run.authorization } : {}),
      ...(run.confinement ? { confinement: { tier: run.confinement.tier, mechanism: run.confinement.mechanism, profileSha256: run.confinement.profileDigest,
        sinks: run.confinement.sinks.map(s => `${s.observerId}:${s.port}`), allowlist: run.confinement.allow.length, kernelDenials: run.confinement.denials.collected ? run.confinement.denials.count : null } } : {}),
      ...(unpaired.length ? { [unpairedKey(run)]: unpaired } : {}), ...(selfTest ? { selfTest } : {}), ...(withheld.length ? { channelWithheld: withheld } : {}), ...(singleIdentity ? { singleIdentity: 'run with --single-identity: cross-tenant checks ran from one side only' } : {}) }, null, 2));
    // A forwarded run with a boundary pass no same-route control backs is not clean (src/forwarded-pairing.mjs), and
    // neither is a run with a check the self-test found broken, or an absence pass its declared channels do not support
    // (src/channels.mjs).
    const refused = selfTest ? broken(selfTest) : false;
    process.exitCode = run.counts.fail || run.counts.error || run.counts.inconclusive || unpaired.length || refused || withheld.length ? 1 : 0;
    }
  }
} catch (error) {
  console.error(`Scopehaven could not run: ${error?.name === 'AuthorizationError' ? `authorization refused (${error.code}): ` : error?.name === 'RemoteTargetError' ? `remote target refused (${error.code}): ` : error?.name === 'SelfTestError' ? `self-test refused (${error.code}): ` : ''}${error.message}`);
  console.error('Usage: npm run assess -- [--config targets.json] --target <id> [--out directory] [--authorization record.json] [--confine launch.json] [--self-test] [--single-identity] | --list | --check-config [--self-test] | --framework langgraph|mastra --template DIR ...');
  process.exitCode = 2;
}
