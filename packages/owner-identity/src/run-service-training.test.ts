import assert from 'node:assert/strict';
import test from 'node:test';
import { getRunCatalog, quoteRunSelection, startQueuedRun, type RunServiceDependencies } from './run-service.js';
import type { RunAdmissionRelease } from './task-release.js';

const training: RunAdmissionRelease = { releaseIdentity:'current', manifestHash:'a'.repeat(64), benchmarkVersion:'current',
  benchmarkHash:'b'.repeat(64), policyHash:'c'.repeat(64), mode:'training', taskIds:['S1','M1','H1'], weights:[1,2,3], priceUnits:'500000', precision:6 };
const ranked: RunAdmissionRelease = { ...training, mode:'ranked', taskIds:['S1','S2','S3','S4','M1','M2','M3','M4','H1','H2','H3','U1'],
  weights:[1,1,1,1,2,2,2,2,3,3,3,5], priceUnits:'1000000' };
const code = (value: string) => (error: unknown) => (error as { code?: string }).code === value;

test('current Training selection has exact proportional whole-request quotes and canonical order', () => {
  for (const [ids, units] of [[['S1'],83334n],[['M1'],166667n],[['H1'],250000n],[['M1','S1'],250000n],
    [['S1','H1'],333334n],[['M1','H1'],416667n],[['H1','M1','S1'],500000n]] as const) {
    const result=quoteRunSelection(training,[...ids]);
    assert.equal(result.priceUnits,units);
    assert.deepEqual(result.taskIds,training.taskIds.filter(id => (ids as readonly string[]).includes(id)));
  }
  assert.equal(quoteRunSelection({...training,priceUnits:'0'},['S1']).priceUnits,0n);
  assert.equal(quoteRunSelection(ranked,ranked.taskIds).priceUnits,1000000n);
});

test('all nine ineligible Training IDs, mixtures, duplicates and malformed descriptors fail closed', () => {
  for(const id of ranked.taskIds.filter(id=>!training.taskIds.includes(id))) {
    for(const ids of [[id],['S1',id]]) assert.throws(()=>quoteRunSelection(training,ids),code('INVALID_TASK_SELECTION'));
  }
  for(const ids of [[],['S1','S1'],['unknown']]) assert.throws(()=>quoteRunSelection(training,ids),code('INVALID_TASK_SELECTION'));
  for(const descriptor of [ {...training,weights:[1,2,12]}, {...training,weights:[1,3,2]},
    {...training,taskIds:['S1','M1','H2']}, {...training,taskIds:['S1','M1']}, {...training,weights:null} ]) {
    assert.throws(()=>quoteRunSelection(descriptor as RunAdmissionRelease,['S1']),code('RELEASE_INVALID'));
  }
  assert.throws(()=>quoteRunSelection(ranked,['S1']),code('INVALID_TASK_SELECTION'));
});

test('catalog publishes only validated aligned Training weights and rejects malformed provider metadata', async () => {
  let current=training;
  const deps={ db:{transaction:async(fn: (tx: unknown)=>unknown)=>fn({})}, admissionReleaseProvider:{
    getActiveAdmissionRelease:async(mode:string)=>mode==='training'?current:ranked,
    getPublicCatalog:()=>[],getValidatedRelease:async()=>null,
  }} as unknown as RunServiceDependencies;
  const catalog=await getRunCatalog(deps);
  assert.deepEqual(catalog.activeRelease?.openTaskIds,['S1','M1','H1']);
  assert.deepEqual(catalog.activeRelease?.openTaskWeights,[1,2,3]);
  assert.equal(catalog.activeRelease?.openWeightSum,6);
  current={...training,weights:[1,2,12] as unknown as RunAdmissionRelease['weights']};
  const invalid=await getRunCatalog(deps);
  assert.equal(invalid.activeRelease,null);assert.equal(invalid.intentCreationReady,false);
  assert.equal(invalid.intentCreationReason,'active_release_invalid');
});

test('start rejects changed weights, excluded selection and contradictory stored quote before debit transaction', async () => {
  const base={...training,pricing:{priceUnits:'500000',precision:6 as const},taskDeadlines:[{taskId:'S1',timeoutSeconds:60}],overallTimeoutSeconds:60};
  for(const variant of ['weights','selection','quote'] as const) {
    let transactions=0;
    const initial={owner_id:'10000000-0000-4000-8000-000000000001',agent_id:'10000000-0000-4000-8000-000000000002',
      release_identity:training.releaseIdentity,manifest_hash:training.manifestHash,mode:'training',task_ids:variant==='selection'?['S2']:['S1'],
      benchmark_version:training.benchmarkVersion,benchmark_hash:training.benchmarkHash,policy_hash:training.policyHash,status:'preparing',
      quote_price_units:variant==='quote'?'1':'83334',successor_preparation_policy_version:null,successor_preparation_timeout_seconds:null};
    const deps={db:{transaction:async(fn:(tx:unknown)=>unknown)=>{transactions++;assert.equal(transactions,1,'no debit transaction may be entered');return fn({execute:async()=>[initial]});}},
      admissionReleaseProvider:{getValidatedRelease:async()=>variant==='weights'?{...base,weights:[1,3,2]}:base},
      executionReadinessProvider:{isPreparedForRelease:async()=>({ready:true,environmentId:'fixture',evidenceHash:'d'.repeat(64)})}} as unknown as RunServiceDependencies;
    await assert.rejects(startQueuedRun(deps,{runId:'10000000-0000-4000-8000-000000000003',claimId:'10000000-0000-4000-8000-000000000004',operationId:'start_invalid_fixture'}),
      code(variant==='selection'?'RELEASE_INCOMPLETE':'RELEASE_INVALID'));
    assert.equal(transactions,1);
  }
});
