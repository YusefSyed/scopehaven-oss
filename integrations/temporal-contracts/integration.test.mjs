// Owned loopback only. These checks exercise one evaluator and the existing gate.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile, readFile, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { runRefundAssessment, currentRefundSuite } from './runner.mjs';
import { createResultSigner, writeFinalizedRun, publicKeyFingerprint } from './persistence.mjs';
import { finalizeRefundRun } from './evaluator.mjs';
import { summarizeGate, runGate, parseArgs } from '../regression-gate/gate.mjs';
import { createStore } from '../../src/store.mjs';
import { createRegistry } from '../../src/registry.mjs';
import { CHECKS } from './contract.mjs';
const row=(run,id)=>run.results.find(r=>r.id===id);
const copy=value=>JSON.parse(JSON.stringify(value));
async function workspace(t) { const root=await mkdtemp(join(tmpdir(),'scopehaven-refund-integrated-'));await chmod(root,0o700);t.after(()=>rm(root,{recursive:true,force:true}));return root; }
async function fresh(args) {
  const env={...process.env};delete env.SCOPEHAVEN_PG_LIVE;delete env.SCOPEHAVEN_MYSQL_LIVE;
  const child=spawn(process.execPath,[fileURLToPath(new URL('../regression-gate/cli.mjs',import.meta.url)),...args],{env,stdio:['ignore','pipe','pipe']});
  let out='',err='';child.stdout.on('data',c=>out+=c);child.stderr.on('data',c=>err+=c);
  const code=await new Promise((resolve,reject)=>{child.on('error',reject);child.on('close',resolve);});return {code,out:JSON.parse(out),err};
}

test('clean normal registered HTTP contract passes all mandatory checks, retry and independent identical instructions',async t=>{
  const registry=createRegistry();assert.equal(registry.has('refund-clean'),true);
  const run=await registry.run('refund-clean'),suite=await registry.currentSuite('refund-clean');
  assert.equal(run.counts.pass,CHECKS.length);assert.equal(summarizeGate({candidate:run,expectedSuite:suite}).exitCode,0);
  assert.equal(row(run,'retry-effects').effectIds.length,1);
  assert.ok(row(run,'retry-binding').attemptIds.length>=2,'multiple real sends retry a lost provider response');
  assert.notDeepEqual(row(run,'identical-a-effects').effectIds,row(run,'identical-b-effects').effectIds);
  for(const id of ['retry-completion','pre-cutoff-completion','active-control-completion','arrival-before-refusal','revoked-new-refusal','mutable-binding'])assert.equal(row(run,id).status,'pass',id);
  assert.equal(run.refundAdjudication.evidenceSummary.modelExercised,false);
  // Existing http-egress provenance retains independent operator-effect custody.
  for (const result of run.results) {
    assert.equal(result.custody, result.kind==='authority'?'subject-writable':'independent', result.id);
    if (result.kind==='authority') { assert.equal(result.severity,'control'); assert.ok(result.custodyLimit); }
  }
  const dir=await workspace(t),store=createStore(join(dir,'store'));await store.ready;
  await store.save(run);const loaded=await store.get(run.id);
  assert.equal(summarizeGate({candidate:loaded,expectedSuite:suite}).exitCode,2,'adjacent checksum cannot replace producer trust');
  await assert.rejects(store.save({...copy(run),id:'copied-run'}),/trusted evaluator finalization/);
});

for(const [variant,failedCheck] of [
  ['deny-all','active-control-completion'],['no-op','active-control-completion'],['never-completing','REFUND-COVERAGE'],
  ['duplicate-effect','retry-effects'],['shared-effect','identical-b-completion'],['false-success','active-control-completion'],
  ['accept-after-revoke','revoked-new-authority'],['changed-binding-dispatch','mutable-binding'],
])test(`same contract blocks ${variant} for its substantive fault`,async t=>{
  const id=`refund-${variant}`,run=await runRefundAssessment(id),suite=await currentRefundSuite(id);
  const summary=summarizeGate({candidate:run,expectedSuite:suite});assert.notEqual(summary.exitCode,0);
  assert.notEqual(row(run,failedCheck).status,'pass',JSON.stringify(run.counts));
  if(variant==='duplicate-effect')assert.equal(row(run,failedCheck).status,'fail');
  if(variant==='changed-binding-dispatch')assert.ok(row(run,'mutable-binding').reasons.includes('forbidden-or-mutated-dispatch'));
  if(variant==='never-completing')assert.ok(run.counts.inconclusive>0);
  const root=await workspace(t),signer=createResultSigner(),file=join(root,'results','finalized.json'),key=join(root,'trusted.pem');
  await writeFinalizedRun(file,signer.signRun(run));await writeFile(key,signer.publicKey,{mode:0o600});
  const restored=await fresh(['--target',id,'--saved-refund',file,'--refund-public-key',key,'--refund-key-fingerprint',signer.publicKeyFingerprint,'--expected-run',run.id]);
  assert.equal(restored.code,1,JSON.stringify(restored.out));assert.equal(restored.out.outcome,'assessment-failed');
});

test('exclusive signed persistence and fresh-process canonical gate accept clean and block raw, edits, wrong run and evaluator migration',async t=>{
  const root=await workspace(t),out=join(root,'gate-output'),key=join(root,'trusted-public.pem');
  const result=await runGate({targetId:'refund-clean',outputDirectory:out,refundTrustOutput:key});assert.equal(result.exitCode,0,JSON.stringify(result));
  const runId=result.current.runId,file=join(out,'signed-results',`${runId}.json`);
  const enrolledFingerprint=publicKeyFingerprint(await readFile(key,'utf8'));
  const args=['--target','refund-clean','--saved-refund',file,'--refund-public-key',key,'--refund-key-fingerprint',enrolledFingerprint,'--expected-run',runId];
  const pass=await fresh(args);assert.equal(pass.code,0,pass.err);assert.equal(pass.out.outcome,'clean');
  const wrong=await fresh([...args.slice(0,-1),'wrong-run']);assert.equal(wrong.code,2);
  const envelope=JSON.parse(await readFile(file,'utf8'));envelope.run.results[0].status='fail';
  const tampered=join(out,'signed-results','edited.json');await writeFile(tampered,JSON.stringify(envelope),{mode:0o600});
  const altered=await fresh(args.map(v=>v===file?tampered:v));assert.equal(altered.code,2);assert.ok(altered.out.reasons.includes('refund-signature-invalid'));
  assert.equal(summarizeGate({candidate:envelope.run,expectedSuite:await currentRefundSuite('refund-clean')}).exitCode,2);
  assert.throws(()=>parseArgs(['--target','refund-clean','--saved-refund',file,'--expected-run',runId]));
  assert.throws(()=>parseArgs([...args,'--require-model-identity']),/invalid-options/,'the strict model identity policy still requires a baseline');
  assert.throws(()=>parseArgs([...args,'--require-model-identity','--baseline',runId]),/invalid-options/,'saved refund verification cannot manufacture a baseline');
  const baseline=await runGate({targetId:'refund-clean',outputDirectory:join(root,'baseline-output'),baselineRunId:runId});
  assert.ok(baseline.reasons.includes('refund-fresh-baseline-required'));
});

test('fresh fixture/provider identities cannot reuse earlier effects or result authority',async()=>{
  const first=await runRefundAssessment('refund-clean'),second=await runRefundAssessment('refund-clean');
  assert.notEqual(first.id,second.id);assert.notDeepEqual(row(first,'retry-effects').effectIds,row(second,'retry-effects').effectIds);
  assert.notDeepEqual(first.refundAdjudication.evidenceSummary.instructions,second.refundAdjudication.evidenceSummary.instructions);
  assert.equal(second.counts.pass,CHECKS.length);
});

test('measured late completion fails with complete count evidence through canonical gate',async()=>{
  const {setTimeout:wait}=await import('node:timers/promises');
  const run=await runRefundAssessment('refund-clean',{beforeActiveControl:()=>wait(5100)}),suite=await currentRefundSuite('refund-clean');
  assert.equal(row(run,'active-control-effects').status,'pass');
  assert.equal(row(run,'active-control-completion').status,'fail');
  assert.ok(row(run,'active-control-completion').reasons.includes('terminal-success-after-deadline'));
  assert.equal(summarizeGate({candidate:run,expectedSuite:suite}).exitCode,1);
});

test('self-declared identity expectations cannot authorize a different observed login',async()=>{
  const run=await runRefundAssessment('refund-clean',{afterExecute:({httpEvidence})=>{
    for(const probe of httpEvidence.filter(p=>p.kind==='identity'&&p.auth==='own')){
      probe.principalId='other-observed-login';probe.expectedPrincipal='other-observed-login';
    }
  }});
  assert.equal(row(run,'REFUND-IDENTITY').status,'inconclusive');
  assert.notEqual(summarizeGate({candidate:run,expectedSuite:await currentRefundSuite('refund-clean')}).exitCode,0);
});

test('copied provider evidence and concurrent collectors cannot pass the integrated route',async()=>{
  await assert.rejects(runRefundAssessment('refund-clean',{afterExecute:({payments})=>{
    const collect=payments.collectPayments.bind(payments);payments.collectPayments=async(...args)=>copy(await collect(...args));
  }}),/refund-live-evidence-required/);
  assert.equal(summarizeGate({candidate:null,expectedSuite:await currentRefundSuite('refund-clean')}).exitCode,2);
  const {createTemporalCollector}=await import('./evidence.mjs');
  const raced=await runRefundAssessment('refund-clean',{afterExecute:async({fixture,payments,contract})=>{
    const contender=createTemporalCollector({fixture,payments,contract});
    await assert.rejects(contender.begin(),/already belongs|already registered/);
  }});
  assert.equal(raced.counts.pass,CHECKS.length,'rejected contender cannot steal healthy collection');
});

for(const fault of ['missing-timing','shortened-horizon','missing-cutoff'])test(`live closed source with ${fault} cannot pass the integrated gate`,async()=>{
  const {startRefundFixture}=await import('./fixtures/refund-app.mjs');
  const run=await runRefundAssessment('refund-clean',{fixtureFactory:async config=>{
    const actual=await startRefundFixture(config);
    return {...actual,snapshot:async options=>{
      const value=copy(await actual.snapshot(options));
      if(fault==='missing-timing')delete value.timing;
      if(fault==='shortened-horizon')value.horizon.deadlineMs--;
      if(fault==='missing-cutoff'){
        value.events=value.events.filter(e=>e.type!=='revoked').map((e,i)=>({...e,seq:i+1}));
        value.horizon.watermark=value.events.length;
        if(typeof value.coverage==='object')value.coverage.toSeq=value.events.length;
      }
      return value;
    }};
  }});
  assert.notEqual(summarizeGate({candidate:run,expectedSuite:await currentRefundSuite('refund-clean')}).exitCode,0);
  if(fault==='missing-cutoff'){assert.equal(row(run,'REFUND-CUTOFF').status,'pass','operator revoke log remains authoritative');assert.equal(row(run,'revoked-new-refusal').status,'fail','missing app order cannot support refusal consistency');}
  else assert.equal(row(run,'retry-effects').status,'inconclusive');
});

for(const fault of ['unregistered-witness','copied-mark','reused-mark','competing-legacy-collector'])test(`integrated ${fault} cannot recreate a false pass`,async()=>{
  const assessment=runRefundAssessment('refund-clean',{afterExecute:async({payments})=>{
    if(fault==='unregistered-witness')payments.dispatchWitness=async from=>{
      const {observeHttp}=await import('../../src/http-connector.mjs');
      await observeHttp(`http://127.0.0.1:${payments.port}`,{method:'GET',path:`/w/?scopehaven_witness=${encodeURIComponent(from.witnessNonce)}`});
    };
    if(fault==='copied-mark'){
      const mark=payments.mark.bind(payments);payments.mark=async()=>copy(await mark());
    }
    if(fault==='reused-mark'){
      const used=await payments.mark(),end=await payments.mark();
      await payments.collect(used,end);payments.mark=async()=>used;
    }
    if(fault==='competing-legacy-collector'){
      const collect=payments.collectPayments.bind(payments);payments.collectPayments=async(from,to)=>{
        const legacy=payments.collect(from,to);
        try{return await collect(from,to);}finally{await legacy;}
      };
    }
  }});
  if(fault!=='unregistered-witness'){
    await assert.rejects(assessment,/refund-live-evidence-required/);
    assert.equal(summarizeGate({candidate:null,expectedSuite:await currentRefundSuite('refund-clean')}).exitCode,2);
  } else {
    const run=await assessment;assert.equal(row(run,'retry-effects').status,'inconclusive');
    assert.notEqual(summarizeGate({candidate:run,expectedSuite:await currentRefundSuite('refund-clean')}).exitCode,0);
  }
});
