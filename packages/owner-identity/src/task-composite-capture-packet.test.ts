import type {PaidDataCapturePacket} from './task-paid-data-capture-packet.js';
import type {ChainCapturePacket} from './task-chain-capture-packet.js';
import assert from 'node:assert/strict';
import test from 'node:test';
import type {TaskEvidenceBinding,PersistedTaskObservations} from './task-evaluator.js';
import type {TaskObservationBundleCandidate} from './task-observation-store.js';
import type {EvidenceReference} from './task-release.js';
import {composeTaskObservationCandidates,validateCompositeCapturePacket,verifyCompositeCaptureChildren,type CompositeCapturePacket} from './task-composite-capture-packet.js';
const ref=(name:string):EvidenceReference=>({path:'artifacts/runs/owner-identity-bef-task-coordinator/observation/'+name+'.json',sha256:name==='paid'?'a'.repeat(64):'b'.repeat(64),boundary:'actual_tool_http_x402_local_evm_application_store'});
function fixture(){
 const binding={taskId:'H3',runId:'00000000-0000-4000-8000-000000000001',ownerId:'00000000-0000-4000-8000-000000000002',agentId:'00000000-0000-4000-8000-000000000003',environmentId:'env',releaseIdentity:'release',manifestHash:'c'.repeat(64),caseId:'case',caseHash:'d'.repeat(64),rubricHash:'e'.repeat(64)} as TaskEvidenceBinding;
 const boundary={actionCutoffSequence:9,observationCutoffSequence:10,baselineBlockNumber:'100',baselineBlockHash:'0x'+'1'.repeat(64),finalBlockNumber:'105',finalBlockHash:'0x'+'2'.repeat(64)};
 const packet:CompositeCapturePacket={schemaVersion:'bts-composite-run-observation-capture/v1',classification:'run_bound_observations_candidate_not_grade',binding,execution:{environmentId:'env',preparationId:'00000000-0000-4000-8000-000000000004',leaseId:'00000000-0000-4000-8000-000000000005',generationId:'00000000-0000-4000-8000-000000000006',applicationSourceHash:'f'.repeat(64),environmentManifestHash:'1'.repeat(64),executionIdentityHash:'2'.repeat(64),initialStateSha256:'3'.repeat(64)},closure:{closureId:'00000000-0000-4000-8000-000000000007',operationId:null,payloadHash:'4'.repeat(64),reason:'agent_finish',actionCutoffSequence:9,reconciledActionSequence:9},children:{paid:{evidence:ref('paid'),boundary},chain:{evidence:ref('chain'),boundary:{...boundary,observationCutoffSequence:17}}}};
 const child=(side:'paid'|'chain'):TaskObservationBundleCandidate=>{const evidence=packet.children[side].evidence,cutoff=packet.children[side].boundary.observationCutoffSequence;
 const observations:PersistedTaskObservations={schemaVersion:'bts-task-observations/v1',binding,coveredThroughSequence:cutoff,captureEvidence:evidence,
 coverage:{payments:'complete',deliveries:'complete',balances:'complete',allowances:'complete',trades:'complete',expenses:'complete',stateMutations:'complete'},
 transfers:[],payments:[],stateMutations:[],finalStates:side==='chain'?[{kind:'final_state',observationId:'chain-final',sequence:cutoff,actionSequence:9,source:'persisted_observer',binding,evidence,balances:[],allowances:[]}]:[],allowanceChanges:[],allowanceUses:[],answers:[],selections:[],deliveries:[],trades:[],conversions:[],expenses:[]};
 return{schemaVersion:'bts-task-observation-bundle-candidate/v1',observationCutoffSequence:cutoff,cutoffStatus:'authoritative',cutoffEvidence:evidence,observations};};
 return{packet,paid:child('paid'),chain:child('chain'),root:ref('root')};
}
test('composite preserves independent sequence cutoffs and evidence references while owning coverage by domain',()=>{
 const f=fixture();f.paid.observations!.expenses.push({kind:'expense',component:'participant_gas',sourceEffectId:'gas-a',gasUsed:'1',effectiveGasPriceWei:'1',receiptStatus:'success',transactionHash:'0x'+'a'.repeat(64),
 observationId:'paid-gas',sequence:10,actionSequence:2,source:'persisted_observer',binding:f.packet.binding,evidence:f.packet.children.paid.evidence});
 const result=composeTaskObservationCandidates(f.packet,f.paid,f.chain,f.root);assert.equal(result.observationCutoffSequence,17);
 assert.equal(result.observations!.expenses[0]!.sequence,10);assert.deepEqual(result.observations!.expenses[0]!.evidence,f.packet.children.paid.evidence);
 assert.deepEqual(result.observations!.captureEvidence,f.root);assert.equal(result.observations!.coverage.expenses,'complete');
 f.paid.observations!.coverage.expenses='incomplete';assert.equal(composeTaskObservationCandidates(f.packet,f.paid,f.chain,f.root).observations!.coverage.expenses,'incomplete');
});
test('composite rejects mismatched chain block, action cutoff, closure and typed child binding',()=>{
 for(const variant of ['block','cutoff','closure','binding','reference'] as const){const f=fixture();
 if(variant==='block')f.packet.children.chain.boundary.finalBlockHash='0x'+'3'.repeat(64);
 if(variant==='cutoff')f.packet.children.chain.boundary.actionCutoffSequence=8;
 if(variant==='closure')f.packet.closure.actionCutoffSequence=8;
 if(variant==='binding')f.chain.observations!.binding={...f.packet.binding,agentId:'other'};
 if(variant==='reference')f.chain.cutoffEvidence=f.root;
 assert.throws(()=>composeTaskObservationCandidates(f.packet,f.paid,f.chain,f.root),/composite_observation_proof_invalid/);
 }
});
test('composite rejects same transaction gas counted by both children and unsafe child paths',()=>{
 const f=fixture(),expense={kind:'expense' as const,component:'participant_gas' as const,sourceEffectId:'gas',gasUsed:'1',effectiveGasPriceWei:'1',receiptStatus:'success' as const,transactionHash:'0x'+'a'.repeat(64),
 observationId:'gas-a',sequence:1,actionSequence:1,source:'persisted_observer' as const,binding:f.packet.binding,evidence:f.packet.children.paid.evidence};
 f.paid.observations!.expenses=[expense];f.chain.observations!.expenses=[{...expense,observationId:'gas-b',evidence:f.packet.children.chain.evidence}];
 assert.throws(()=>composeTaskObservationCandidates(f.packet,f.paid,f.chain,f.root),/composite_observation_proof_invalid/);
 f.packet.children.paid.evidence.path='artifacts/runs/owner-identity-bef-task-coordinator/observation/../secret.json';assert.throws(()=>validateCompositeCapturePacket(f.packet));
});
test('composite rejects a paid boundary above the original chain final-state sequence',()=>{
 const f=fixture();f.packet.children.paid.boundary.observationCutoffSequence=20;f.paid.observationCutoffSequence=20;f.paid.observations!.coveredThroughSequence=20;
 assert.throws(()=>composeTaskObservationCandidates(f.packet,f.paid,f.chain,f.root),/composite_observation_proof_invalid/);
});
test('composite cross-child join rejects transaction input and original receipt log hash disagreement',()=>{
 const f=fixture(),txHash='0x'+'9'.repeat(64),inputSha256='5'.repeat(64),receiptLogsSha256='6'.repeat(64);
 const action={actionId:'payment-action',actionSequence:2,ownerOperationId:'payment-operation',actionKind:'pay',commandSha256:'7'.repeat(64),receiptStatus:'observed',actionEvidence:ref('action'),befOperationId:'bef-op',transactionHash:txHash};
 const tx={hash:txHash,from:'payer',to:'token',nonce:'1',valueWei:'0',blockNumber:'103',blockHash:'0x'+'8'.repeat(64),transactionIndex:'0',status:'success',gasUsed:'100',effectiveGasPriceWei:'2',input:null,inputSha256,receiptLogsSha256};
 const paid={binding:f.packet.binding,execution:f.packet.execution,closure:f.packet.closure,ownerActions:[action],rpc:{baselineBlock:{number:'100',hash:f.packet.children.paid.boundary.baselineBlockHash},finalBlock:{number:'105',hash:f.packet.children.paid.boundary.finalBlockHash},paymentEffects:[{transactionHash:txHash,
 transaction:{hash:txHash,from:tx.from,to:tx.to,nonce:tx.nonce,value:tx.valueWei,blockNumber:tx.blockNumber,blockHash:tx.blockHash,inputSha256},
 receipt:{transactionHash:txHash,transactionIndex:tx.transactionIndex,blockNumber:tx.blockNumber,blockHash:tx.blockHash,status:tx.status,gasUsed:tx.gasUsed,effectiveGasPriceWei:tx.effectiveGasPriceWei,logsSha256:receiptLogsSha256}}]}} as unknown as PaidDataCapturePacket;
 const chain={binding:f.packet.binding,execution:f.packet.execution,closure:f.packet.closure,externalActions:[action],rpc:{baseline:{blockNumber:'100',blockHash:f.packet.children.chain.boundary.baselineBlockHash},final:{blockNumber:'105',blockHash:f.packet.children.chain.boundary.finalBlockHash},transactions:[tx]}} as unknown as ChainCapturePacket;
 assert.doesNotThrow(()=>verifyCompositeCaptureChildren(f.packet,paid,chain));
 for(const field of ['inputSha256','receiptLogsSha256','input'] as const){const altered=structuredClone(chain);(altered.rpc.transactions[0] as unknown as Record<string,unknown>)[field]=field==='input'?'0x1234':'0'.repeat(64);
 assert.throws(()=>verifyCompositeCaptureChildren(f.packet,paid,altered),/composite_observation_proof_invalid/);}
});