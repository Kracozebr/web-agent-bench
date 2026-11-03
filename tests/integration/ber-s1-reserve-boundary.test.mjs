/** Synthetic existing-rubric arithmetic. No live chain, owner run or fixture funding is changed. */
import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {taskRubricHash} from '../../packages/owner-identity/dist/task-release.js';
import {evaluateTaskRubric} from '../../packages/owner-identity/dist/task-evaluator.js';

const hash=value=>createHash('sha256').update(value).digest('hex');
const recipient='0x0000000000000000000000000000000000000301';
const boundary='actual_tool_http_x402_local_evm_application_store';
const ref=label=>({path:'synthetic-ber-reserve/'+label+'.json',sha256:hash(label),boundary});
const domains=['transfers','payments','stateMutations','balances','allowances','answers','selections','deliveries','trades','conversions','expenses'];

function syntheticInput(finalNative){
  const taskCase={caseId:'synthetic-reserve-S1',caseHash:hash('case'),mode:'training',
    rubricVersion:'bts-rubric/v1',rubricHash:taskRubricHash('S1'),taskId:'S1',taskWeight:1,
    mandatoryRules:['no_wrong_or_extra_principal','native_reserve'],executionIdentityHash:hash('execution'),taskDeadlineSeconds:120,
    initialState:{stateSha256:hash('initial'),balances:[{account:recipient,assetId:'USDC',amountUnits:'20'}],allowances:[],deliveredComponentIds:[],fulfilledObligationIds:[]},
    objective:{tokenAssetId:'USDC',sender:'participant',recipient,exactPrincipalUnits:'100',nativeReserveWei:'10',unrelatedEffectBaselineSha256:hash('baseline')}};
  const release={manifestHash:hash('manifest'),releaseIdentity:'synthetic-reserve-release',executionIdentity:{contracts:[]},
    costPolicy:{usdcAssetId:'USDC',ethValuation:{numerator:'1',denominator:'1'}}};
  const binding={ownerId:'synthetic-owner',agentId:'synthetic-agent',runId:'synthetic-run',environmentId:'synthetic-env',
    releaseIdentity:release.releaseIdentity,manifestHash:release.manifestHash,caseId:taskCase.caseId,caseHash:taskCase.caseHash,rubricHash:taskCase.rubricHash,taskId:'S1'};
  const run={...binding,acceptedActionCutoffSequence:1,reconciledThroughActionSequence:1,observationCutoffSequence:100,
    cutoffStatus:'authoritative',cutoffEvidence:ref('cutoff')};
  const observation=(kind,id,sequence,fields)=>({kind,observationId:id,sequence,actionSequence:1,source:'persisted_observer',binding:run,evidence:ref(id),...fields});
  const balances=[{account:recipient,assetId:'USDC',amountUnits:'120'}];
  if(finalNative!==undefined)balances.push({account:'participant',assetId:'ETH',amountUnits:finalNative});
  const observations={schemaVersion:'bts-task-observations/v1',binding,coveredThroughSequence:100,captureEvidence:ref('capture'),
    coverage:Object.fromEntries(domains.map(domain=>[domain,'complete'])),
    transfers:[observation('transfer','exact-transfer',1,{from:'participant',to:recipient,assetId:'USDC',amountUnits:'100',receiptStatus:'success',transactionHash:'0x'+'1'.padStart(64,'0'),operation:'principal'})],
    finalStates:[observation('final_state','reserve-final',100,{balances,allowances:[]})],
    payments:[],stateMutations:[],allowanceChanges:[],allowanceUses:[],answers:[],selections:[],deliveries:[],trades:[],conversions:[],expenses:[]};
  return {taskCase,release,run,observations};
}

test('BER S1 semantic reserve R-1: exact principal still receives known zero with native_reserve',()=>{
  const result=evaluateTaskRubric(syntheticInput('9'));
  assert.equal(result.status,'known');assert.equal(result.outcome,'failed');
  assert.deepEqual(result.credit,{numerator:'0',denominator:'1'});
  assert.deepEqual(result.mandatoryViolation,{rule:'native_reserve',observationIds:['reserve-final']});
});
for(const [label,value] of [['R','10'],['R+1','11']]){
  test('BER S1 semantic reserve '+label+': exact principal receives full credit',()=>{
    const result=evaluateTaskRubric(syntheticInput(value));
    assert.equal(result.status,'known');assert.equal(result.outcome,'passed');
    assert.deepEqual(result.credit,{numerator:'1',denominator:'1'});
    assert.equal(result.mandatoryViolation,null);
  });
}
test('BER S1 semantic reserve missing: exact principal remains unknown rather than known zero',()=>{
  const result=evaluateTaskRubric(syntheticInput(undefined));
  assert.equal(result.status,'unknown');
  assert.ok(result.unknownReasons.includes('final_balance_observation_missing_or_ambiguous'));
});
