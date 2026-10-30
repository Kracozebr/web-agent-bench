import assert from 'node:assert/strict';
import test from 'node:test';
import { captureBefChainCensus, collectBefChainTaskObservationCandidate, matchesReleaseCodeHash, observedRuntimeCodeHash, neutralChainInspectionEvidenceMatches, rejectedChainActionEvidenceMatches, type BefChainObservationCollectorDependencies } from './bef-chain-observation-collector.js';
import { makeChainCaptureFixture, prependChainInspectionFixture, makeRejectedChainCaptureFixture } from './task-chain-capture-packet.fixture.js';
import { validateTaskChainCapturePacket } from './task-chain-capture-packet.js';
import { createHash } from 'node:crypto';
import { canonicalTaskJson } from './task-release.js';

test('actual pre-broadcast rejection producer shape survives the observer census and projects without effects',async()=>{
 const fixture=makeRejectedChainCaptureFixture('H2'),source=fixture.packet.bef.before as Record<string,unknown>;
 const generation=source.generation as Record<string,unknown>,proof=(source.rejectedChainOperations as Record<string,unknown>[])[0]!;
 const op=proof.operation as Record<string,unknown>,selected=proof.selectedExecution as Record<string,unknown>;
 assert.equal(rejectedChainActionEvidenceMatches(fixture.rejectedActionDocument),true);
 for(const key of ['transactionHash','participantToolResponse','recoverySource','paymentProtocol','receiptStatus','outcome','httpStatus','rawResponseSha256']){
  assert.equal(rejectedChainActionEvidenceMatches({...fixture.rejectedActionDocument,[key]:null}),false,key);
 }
 const operation={operation_id:op.operationId,env_id:op.environmentId,generation_id:op.generationId,participant_id:op.participantId,
  idempotency_key_sha256:op.idempotencyKeySha256,request_sha256:op.requestSha256,operation_kind:op.actionKind,status:op.status,
  receipt_status:op.receiptStatus,transaction_hash:op.transactionHash,response_sha256:op.responseSha256,started_at:op.startedAt,completed_at:op.completedAt};
 const execution={operation_id:selected.operationId,env_id:selected.environmentId,generation_id:selected.generationId,action_kind:selected.actionKind,
  selected_action_json:selected.selectedAction,prestate_json:null,transaction_intent_json:null,measurement_json:null,transaction_hash:null,
  outcome:'rejected',reason_code:'execution_observation_unknown',completed_at:selected.completedAt};
 const events=(proof.selectedEvents as Record<string,unknown>[]).map((event)=>({event_id:event.eventId,event_sequence:event.eventSequence,
  operation_id:event.operationId,env_id:op.environmentId,generation_id:op.generationId,event_kind:event.eventKind,transaction_hash:null,event_json:event.eventPayload}));
 async function capture(effect=false){
  const results:unknown[][]=[
   [{current_user:'bef_observer',session_user:'bef_observer',database_name:'bef',transaction_read_only:'on',transaction_isolation:'repeatable read',rolsuper:false,rolbypassrls:false,schema_create:false}],
   ['bef_environment','bef_generation','bef_operation','bef_selected_execution','bef_selected_execution_event','bef_transaction_cost'].map((table_name)=>({table_name,can_select:true,can_insert:false,can_update:false,can_delete:false,can_truncate:false})),
   [generation],[operation],[execution],events,effect?[{operation_id:op.operationId}]:[],[{payments:'0',deliveries:'0'}],
   [{operations:'1',selected_executions:'1',selected_events:'2',costs:effect?'1':'0'}],
  ];
  return captureBefChainCensus({environmentId:String(generation.env_id),withRepeatableRead:async(callback)=>callback(async()=>results.shift()!)},
   String(generation.env_id),String(generation.generation_id),true);
 }
 const captured=await capture();assert.deepEqual(captured.census,source);
 fixture.packet.bef.before=captured.census;fixture.packet.bef.after=structuredClone(captured.census);
 assert.doesNotThrow(()=>validateTaskChainCapturePacket(fixture.packet,fixture.taskCase));
 await assert.rejects(()=>capture(true));
});

test('read-only BEF census retains source GET rows and rejects any read cost/selected/event evidence before projection',async()=>{
 const fixture=prependChainInspectionFixture(makeChainCaptureFixture('M3'));
 const source=fixture.packet.bef.before as Record<string,unknown>,generation=source.generation as Record<string,unknown>;
 const readRows=(source.inspectionOperations as Record<string,unknown>[]).map((op)=>({operation_id:op.operationId,env_id:op.environmentId,
  generation_id:op.generationId,participant_id:op.participantId,idempotency_key_sha256:op.idempotencyKeySha256,request_sha256:op.requestSha256,
  operation_kind:op.actionKind,status:op.status,receipt_status:op.receiptStatus,transaction_hash:op.transactionHash,response_sha256:op.responseSha256,
  started_at:op.startedAt,completed_at:op.completedAt}));
 async function capture(effect:'none'|'cost'|'selected'|'event'){
  const effects=effect==='none'?[]:[{operation_id:readRows[0]!.operation_id}];
  const results:unknown[][]=[
   [{current_user:'bef_observer',session_user:'bef_observer',database_name:'bef',transaction_read_only:'on',transaction_isolation:'repeatable read',rolsuper:false,rolbypassrls:false,schema_create:false}],
   ['bef_environment','bef_generation','bef_operation','bef_selected_execution','bef_selected_execution_event','bef_transaction_cost'].map((table_name)=>({table_name,can_select:true,can_insert:false,can_update:false,can_delete:false,can_truncate:false})),
   [generation],readRows,effect==='selected'?effects:[],effect==='event'?effects:[],effect==='cost'?effects:[],[{payments:'0',deliveries:'0'}],
   [{operations:'2',selected_executions:effect==='selected'?'1':'0',selected_events:effect==='event'?'1':'0',costs:effect==='cost'?'1':'0'}],
  ];
  return captureBefChainCensus({environmentId:String(generation.env_id),withRepeatableRead:async(callback)=>callback(async()=>results.shift()!)},
   String(generation.env_id),String(generation.generation_id),true);
 }
 const captured=await capture('none');
 assert.deepEqual(captured.census.inspectionOperations,source.inspectionOperations);
 fixture.packet.bef.before={...source,inspectionOperations:captured.census.inspectionOperations};
 fixture.packet.bef.after=structuredClone(fixture.packet.bef.before);
 fixture.packet.bef.censusSha256=createHash('sha256').update(canonicalTaskJson(fixture.packet.bef.before)).digest('hex');
 assert.doesNotThrow(()=>validateTaskChainCapturePacket(fixture.packet,fixture.taskCase));
 for(const effect of ['cost','selected','event'] as const)await assert.rejects(()=>capture(effect));
});

test('neutral chain inspection requires a pinned free GET response and no claimed effects',()=>{
 const payment={scheme:'exact',network:'base',asset:'0x'+'1'.repeat(40),amount:'2500',payTo:'0x'+'2'.repeat(40),transferMethod:'transferWithAuthorization'};
 const offer={id:'offer-a',payment};
 const resource={resourceId:'resource-a',resourceSha256:'a'.repeat(64),contentType:'application/json',offers:[offer]};
 const operationId='01234567-89ab-4cde-8fab-0123456789ab';
 const row={receipt_status:'observed',transaction_hash:null};
 const documents=[
  {command:{kind:'inspect_catalog'} as const,response:{catalog:[resource],operationId,freeInspection:true,deliveryState:'not_delivered'}},
  {command:{kind:'inspect_offer',resourceId:'resource-a',offerId:'offer-a'} as const,
   response:{...resource,operationId,payment,freeInspection:true,deliveryState:'not_delivered'}},
 ];
 for(const {command,response} of documents){
  const doc={participantToolResponse:response,httpStatus:200,rawResponseSha256:'b'.repeat(64),requestStartedAt:'2026-10-30T00:00:00Z',
   requestFinishedAt:'2026-10-30T00:00:01Z',befOperationId:operationId,
   environmentId:'inspection-env',manifestSha256:'c'.repeat(64),applicationSourceSha256:'d'.repeat(64)};
  assert.equal(neutralChainInspectionEvidenceMatches(command,row,doc),true);
  const health={boundary:'benchmark-environment-api',envId:doc.environmentId,manifestSha256:doc.manifestSha256,
   applicationSourceSha256:doc.applicationSourceSha256,facilitatorAddress:'0x'+'2'.repeat(40),
   anvil:{clientVersion:'anvil/v0.3.1',chainId:'31337',executionNetwork:'base',hardFork:'cancun',forkBlockNumber:'291',forkBlockHash:'0x'+'e'.repeat(64)},
   sdkVersions:{core:'2.28.0',evm:'2.28.0',viem:'2.56.9'}};
  assert.equal(Object.keys(health).length,7);
  assert.equal(neutralChainInspectionEvidenceMatches(command,row,{...doc,environmentHealth:health}),true);
  for(const [key,value] of [['envId','wrong-env'],['manifestSha256','f'.repeat(64)],['applicationSourceSha256','f'.repeat(64)],
   ['boundary','other-boundary'],['facilitatorAddress','invalid-address'],['anvil',{...health.anvil,chainId:31337}],
   ['sdkVersions',{...health.sdkVersions,core:7}],['unknownField',true]] as const){
   assert.equal(neutralChainInspectionEvidenceMatches(command,row,{...doc,environmentHealth:{...health,[key]:value}}),false,key);
  }
  for(const key of ['transactionHash','outcome','receiptStatus','receiptGasUsed','receiptEffectiveGasPriceWei','paymentProtocol','recoverySource','reasonCode']){
   assert.equal(neutralChainInspectionEvidenceMatches(command,row,{...doc,[key]:null}),false,key);
  }
  assert.equal(neutralChainInspectionEvidenceMatches(command,{...row,receipt_status:'rejected_before_execution'},doc),false);
  assert.equal(neutralChainInspectionEvidenceMatches(command,row,{...doc,participantToolResponse:{...response,deliveryState:'delivered'}}),false);
  assert.equal(neutralChainInspectionEvidenceMatches(command,row,{...doc,participantToolResponse:{...response,transaction:{hash:'0x'+'f'.repeat(64)}}}),false);
  assert.equal(neutralChainInspectionEvidenceMatches(command,row,{...doc,befOperationId:'01234567-89ab-4cde-8fab-0123456789ac'}),false);
  assert.equal(neutralChainInspectionEvidenceMatches(command,row,{...doc,befOperationId:17}),false);
  assert.equal(neutralChainInspectionEvidenceMatches(command,row,{...doc,participantToolResponse:{...response,operationId:17}}),false);
  assert.equal(neutralChainInspectionEvidenceMatches(command,row,{...doc,httpStatus:201}),false);
  assert.equal(neutralChainInspectionEvidenceMatches(command,row,{...doc,rawResponseSha256:'invalid'}),false);
  const missing=structuredClone(doc) as Record<string,unknown>;delete missing.befOperationId;
  assert.equal(neutralChainInspectionEvidenceMatches(command,row,missing),false);
 }
});

test('retained public runtime code hashes match the naked hash pinned in the release',()=>{
 const publicCode='0x6000';
 assert.equal(observedRuntimeCodeHash(publicCode),'07ad118d6cc8642c86c03827f276d8b791a65e5c99a3845faf186be720a1455d');
 assert.equal(observedRuntimeCodeHash(publicCode).length,64);
});

test('fee-3000 pool code hash accepts only an exact prefixed or naked release hash',()=>{
 const releaseHash='71ff5f428af7891e7cbce51d4dadacef1e8eb0c1e454342413066bbd8a0d344c';
 assert.equal(matchesReleaseCodeHash(`0x${releaseHash}`,releaseHash),true);
 assert.equal(matchesReleaseCodeHash(`0X${releaseHash.toUpperCase()}`,releaseHash),true);
 assert.equal(matchesReleaseCodeHash(`${releaseHash}00`,releaseHash),false);
 assert.equal(matchesReleaseCodeHash(`0x${releaseHash.slice(1)}`,releaseHash),false);
 assert.equal(matchesReleaseCodeHash('not-a-hash',releaseHash),false);
 assert.equal(matchesReleaseCodeHash(`0x${releaseHash}`,`0x${releaseHash.slice(0,-1)}0`),false);
});

test('chain collector rejects malformed targets before opening a transaction',async()=>{
 let transactions=0;
 const deps={db:{transaction:async()=>{transactions++;throw new Error('unexpected_transaction')}}} as unknown as BefChainObservationCollectorDependencies;
 const result=await collectBefChainTaskObservationCandidate(deps,{runId:'not-a-uuid',taskIndex:0});
 assert.deepEqual(result,{status:'unavailable',reasonCode:'invalid_target'});
 assert.equal(transactions,0);
});

test('chain collector stops after its initial owner-row lookup when no run exists',async()=>{
 const statements:unknown[]=[];
 const fakeTx={execute:async(statement:unknown)=>{statements.push(statement);return [];}};
 let transactions=0;
 const deps={db:{transaction:async<T>(callback:(tx:unknown)=>Promise<T>)=>{transactions++;return callback(fakeTx);}}} as unknown as BefChainObservationCollectorDependencies;
 const result=await collectBefChainTaskObservationCandidate(deps,{runId:'123e4567-e89b-42d3-a456-426614174000',taskIndex:0});
 assert.deepEqual(result,{status:'unavailable',reasonCode:'owner_cutoff_unavailable'});
 assert.equal(transactions,1);
 assert.equal(statements.length,1);
 assert.ok(statements[0]&&typeof statements[0]==='object');
});
