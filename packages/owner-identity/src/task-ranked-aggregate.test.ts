import assert from 'node:assert/strict';
import test from 'node:test';
import {TASK_IDS,PUBLIC_TASK_CATALOG} from './task-catalog.js';
import {sha256CanonicalTaskJson,type TaskReleaseManifest} from './task-release.js';
import type {TaskEvaluationResult} from './task-evaluator.js';
import {aggregateVerifiedRankedOutcomes,compareExactRankedFractions,type RankedTaskProof} from './task-ranked-aggregate.js';
const hash=(label:string)=>sha256CanonicalTaskJson({label});
function fixture(){
  const cases=TASK_IDS.map((taskId,index)=>({taskId,caseHash:hash('case-'+taskId),rubricHash:hash('rubric-'+taskId),mode:'ranked',taskWeight:PUBLIC_TASK_CATALOG[index]!.weight}));
  const release={releaseIdentity:'synthetic-ranked-aggregate-only',manifestHash:hash('manifest'),benchmarkVersion:'fixture-v1',benchmarkHash:hash('benchmark'),policyHash:hash('policy'),cases:{ranked:cases}} as unknown as TaskReleaseManifest;
  const proofs=cases.map((c,taskIndex)=>{
    const result:TaskEvaluationResult={taskId:c.taskId,status:'known',credit:{numerator:'1',denominator:'1'},outcome:'passed',mandatoryViolation:null,unknownReasons:[],operatingExpenseUsdcUnits:null};
    return{taskIndex,taskId:c.taskId,caseHash:c.caseHash,rubricHash:c.rubricHash,inputHash:hash('input-'+taskIndex),resultHash:sha256CanonicalTaskJson(result),fenceEvidenceHash:hash('fence-'+taskIndex),result};
  });
  return{release,proofs};
}
function setCredit(proof:RankedTaskProof,n:string,d='1'){
  proof.result.credit={numerator:n,denominator:d};proof.result.outcome=n==='0'?'failed':n===d?'passed':'partial';proof.resultHash=sha256CanonicalTaskJson(proof.result);
}
test('ranked exact aggregation requires all twelve ordered results and retains four separate tier indicators',()=>{
  const {release,proofs}=fixture(),aggregate=aggregateVerifiedRankedOutcomes(release,proofs);
  assert.deepEqual(aggregate.overall,{numerator:'100',denominator:'1'});
  for(const tier of Object.values(aggregate.tiers))assert.deepEqual(tier,{numerator:'100',denominator:'1'});
  const saved=structuredClone(aggregate);proofs[0]!.result.outcome='failed';assert.deepEqual(aggregate,saved);
  assert.throws(()=>aggregateVerifiedRankedOutcomes(release,proofs.slice(1)),/ranked_outcome_proof_invalid/);
});
test('simple-only achievement is 400/26 rather than an equal mean of four tiers',()=>{
  const {release,proofs}=fixture();for(const p of proofs)if(!p.taskId.startsWith('S'))setCredit(p,'0');
  const aggregate=aggregateVerifiedRankedOutcomes(release,proofs);
  assert.deepEqual(aggregate.overall,{numerator:'200',denominator:'13'});assert.deepEqual(aggregate.tiers.simple,{numerator:'100',denominator:'1'});
  assert.deepEqual(aggregate.tiers.ultra,{numerator:'0',denominator:'1'});
});
test('partial task credit stays rational and its expense never becomes outcome credit',()=>{
  const {release,proofs}=fixture();for(const p of proofs)setCredit(p,'0');const m2=proofs.find(p=>p.taskId==='M2')!;setCredit(m2,'2','5');
  m2.result.operatingExpenseUsdcUnits='999999999';m2.resultHash=sha256CanonicalTaskJson(m2.result);
  const aggregate=aggregateVerifiedRankedOutcomes(release,proofs);
  assert.deepEqual(aggregate.overall,{numerator:'40',denominator:'13'});assert.deepEqual(aggregate.tiers.medium,{numerator:'10',denominator:'1'});
});
test('unknown, contradictory mandatory outcomes and forged hashes cannot produce an aggregate',()=>{
  for(const variant of ['unknown','violation','hash','order'] as const){
    const {release,proofs}=fixture();const p=proofs[0]!;
    if(variant==='unknown'){p.result.status='unknown';p.result.credit=null;p.result.outcome='unknown';p.result.unknownReasons=['receipt_missing'];p.resultHash=sha256CanonicalTaskJson(p.result);}
    if(variant==='violation'){p.result.mandatoryViolation={rule:'no_extra_transfer',observationIds:['fact']};p.resultHash=sha256CanonicalTaskJson(p.result);}
    if(variant==='hash')p.resultHash=hash('forged');if(variant==='order')[proofs[0],proofs[1]]=[proofs[1]!,proofs[0]!];
    assert.throws(()=>aggregateVerifiedRankedOutcomes(release,proofs),/ranked_outcome_proof_invalid/);
  }
});
test('best comparisons use exact fractions, preserving mathematical ties without display rounding',()=>{
  assert.equal(compareExactRankedFractions({numerator:'100',denominator:'3'},{numerator:'3333',denominator:'100'}),1);
  assert.equal(compareExactRankedFractions({numerator:'2',denominator:'6'},{numerator:'1',denominator:'3'}),0);
  assert.throws(()=>compareExactRankedFractions({numerator:'1',denominator:'0'},{numerator:'1',denominator:'1'}));
});