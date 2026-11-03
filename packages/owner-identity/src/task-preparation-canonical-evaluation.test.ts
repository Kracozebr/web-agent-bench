import assert from 'node:assert/strict';
import test from 'node:test';
import {evaluateTaskRubric,type EvaluateTaskInput} from './task-evaluator.js';
import {readKnownCanonicalRankedEvaluation} from './task-preparation.js';
import {sha256CanonicalTaskJson} from './task-release.js';

// AICODE-NOTE: Pure canonical-guard fixture, not a physical payment/evidence claim.
function serviceBudgetFixture(){
 const id='10000000-0000-4000-8000-000000000001',recipient='0x2222222222222222222222222222222222222222',tx='0x'+'a'.repeat(64),digest='b'.repeat(64);
 const binding={ownerId:id,agentId:id,runId:id,environmentId:'canonical-budget-unit',releaseIdentity:'canonical-budget-unit',manifestHash:digest,caseId:'m3-budget-unit',caseHash:digest,rubricHash:digest,taskId:'M3' as const};
 const evidence={path:'artifacts/runs/canonical-budget-unit/source.json',sha256:digest,boundary:'actual_tool_http_x402_local_evm_application_store' as const};
 const meta=(observationId:string,sequence:number)=>({observationId,sequence,actionSequence:1,source:'persisted_observer' as const,binding,evidence});
 const requirements={scheme:'exact',resourceId:'scoped-resource',offerId:'canonical-offer',version:'2',amountUnits:'10',network:'eip155:8453',assetId:'USDC',recipient,authFields:[]};
 const input={taskCase:{taskId:'M3',mode:'ranked',caseId:binding.caseId,caseHash:digest,rubricHash:digest,executionIdentityHash:digest,
  initialState:{stateSha256:digest,balances:[{account:'participant',assetId:'ETH',amountUnits:'100'}],allowances:[],deliveredComponentIds:[],fulfilledObligationIds:[]},
  objective:{inputAssetId:'USDC',exactInputUnits:'1',minimumNativeOutputWei:'1',nativeReserveWei:'1',expenseBudgetUsdcUnits:'5',permittedRoutes:[]}},
  release:{releaseIdentity:binding.releaseIdentity,manifestHash:digest,executionIdentity:{localChainId:8453,assets:[{assetId:'ETH',kind:'native',address:null,codeHash:null,chainId:8453,decimals:18},{assetId:'USDC',kind:'erc20',address:recipient,codeHash:digest,chainId:8453,decimals:6}],contracts:[]},costPolicy:{usdcAssetId:'USDC',ethValuation:{numerator:'1',denominator:'1'}}},
  run:{...binding,acceptedActionCutoffSequence:4,reconciledThroughActionSequence:4,observationCutoffSequence:3,cutoffStatus:'authoritative',cutoffEvidence:evidence},
  observations:{schemaVersion:'bts-task-observations/v1',binding,coveredThroughSequence:3,captureEvidence:evidence,
   coverage:{transfers:'complete',payments:'complete',stateMutations:'complete',balances:'complete',allowances:'complete',answers:'complete',selections:'complete',deliveries:'complete',trades:'complete',conversions:'complete',expenses:'complete'},
   payments:[{...meta('settled-payment',2),kind:'payment',paymentAttemptId:'payment-attempt',status:'settled',requirements,gasPayer:'facilitator',transactionHash:tx}],
   transfers:[{...meta('actual-settlement-transfer',1),kind:'transfer',paymentAttemptId:'payment-attempt',from:'participant',to:recipient,assetId:'USDC',amountUnits:'10',receiptStatus:'success',transactionHash:tx,operation:'settlement'}],
   expenses:[],stateMutations:[],allowanceChanges:[],allowanceUses:[],answers:[],selections:[],deliveries:[],trades:[],conversions:[],
   finalStates:[{...meta('final-state',3),kind:'final_state',balances:[{account:'participant',assetId:'ETH',amountUnits:'100'}],allowances:[]}]}} as unknown as EvaluateTaskInput;
 return {input,runId:id,result:evaluateTaskRubric(input)};
}
test('canonical payment-service budget failure may have no participant expense event IDs and remains a known failed predecessor',()=>{
 const f=serviceBudgetFixture();assert.equal(f.input.observations.expenses.length,0);assert.equal(f.input.observations.payments.length,1);
 assert.deepEqual(f.result.mandatoryViolation,{rule:'operating_expense_budget',observationIds:[]});assert.equal(f.result.status,'known');assert.deepEqual(f.result.credit,{numerator:'0',denominator:'1'});
 assert.deepEqual(readKnownCanonicalRankedEvaluation(f.result,f.input,'M3',f.runId),f.result);
 assert.deepEqual(readKnownCanonicalRankedEvaluation(JSON.stringify(f.result),f.input,'M3',f.runId),f.result);
});
test('empty lists cannot forge a different rule, success, unknown result or an event-backed canonical claim',()=>{
 const f=serviceBudgetFixture();for(const edit of [(r:typeof f.result)=>{r.mandatoryViolation!.rule='invented-absence-claim';},(r:typeof f.result)=>{r.outcome='passed';},(r:typeof f.result)=>{r.credit={numerator:'1',denominator:'1'};},(r:typeof f.result)=>{r.status='unknown';},(r:typeof f.result)=>{r.mandatoryViolation!.observationIds=['duplicate','duplicate'];}]){const result=structuredClone(f.result);edit(result);assert.equal(readKnownCanonicalRankedEvaluation(result,f.input,'M3',f.runId),null);}
 const eventInput=structuredClone(f.input);if(eventInput.taskCase.taskId!=='M3')throw new Error('fixture_task');eventInput.taskCase.objective.expenseBudgetUsdcUnits='100';const eventResult=evaluateTaskRubric(eventInput);assert((eventResult.mandatoryViolation?.observationIds.length??0)>0);eventResult.mandatoryViolation!.observationIds=[];assert.equal(readKnownCanonicalRankedEvaluation(eventResult,eventInput,'M3',f.runId),null);
});
test('changed payment, transfer, evidence metadata or foreign binding cannot replay the original result',()=>{
 const f=serviceBudgetFixture(),originalHash=sha256CanonicalTaskJson(f.input);
 for(const edit of [(i:EvaluateTaskInput)=>{i.observations.payments[0]!.requirements.amountUnits='11';},(i:EvaluateTaskInput)=>{i.observations.transfers[0]!.amountUnits='11';},(i:EvaluateTaskInput)=>{i.observations.payments=[];},(i:EvaluateTaskInput)=>{i.observations.transfers=[];},(i:EvaluateTaskInput)=>{i.observations.captureEvidence={...i.observations.captureEvidence,sha256:'invalid'};},(i:EvaluateTaskInput)=>{i.observations.binding={...i.observations.binding,runId:'20000000-0000-4000-8000-000000000002'};}]){const input=structuredClone(f.input);edit(input);assert.notEqual(sha256CanonicalTaskJson(input),originalHash);assert.equal(readKnownCanonicalRankedEvaluation(f.result,input,'M3',f.runId),null);}
 assert.equal(readKnownCanonicalRankedEvaluation(f.result,f.input,'M3','20000000-0000-4000-8000-000000000002'),null);
});
