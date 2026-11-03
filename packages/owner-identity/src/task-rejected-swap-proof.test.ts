import assert from 'node:assert/strict';
import test from 'node:test';
import {createHash} from 'node:crypto';
import {makeRejectedSwapFamilyFixture} from './task-rejected-swap-proof.fixture.js';
import {makeChainFamilyCaptureFixture} from './task-chain-family-capture-packet.fixture.js';
import {canonicalTaskJson} from './task-release.js';
import {rejectedSwapSource,validateRejectedRecipientCode,rereadRejectedRecipientCode} from './task-rejected-swap-proof.js';
import {projectTaskChainFamilyCapturePacket} from './task-chain-capture-packet.js';
import {classifyBefTaskActionResponse} from './bef-task-executor.js';
import {projectRejectedSwapReceiptProof} from './task-action-service.js';
import {rejectedSwapActionEvidenceMatches,captureBefChainCensus} from './bef-chain-observation-collector.js';
const hash=(v:unknown)=>createHash('sha256').update(canonicalTaskJson(v)).digest('hex');
function project(f:ReturnType<typeof makeRejectedSwapFamilyFixture>){return projectTaskChainFamilyCapturePacket(f.packet,f.context);}
function rebind(f:ReturnType<typeof makeRejectedSwapFamilyFixture>){f.packet.bef.after=structuredClone(f.packet.bef.before);f.packet.bef.censusSha256=hash(f.packet.bef.before);}
test('family non-EOA swap source is no-execution evidence, with independent historical code and unchanged remaining effects',()=>{
 const original=makeChainFamilyCaptureFixture(),base=projectTaskChainFamilyCapturePacket(original.packet,original.context);
 const effect=(row:unknown)=>{const {sequence,observationId,...rest}=row as Record<string,unknown>;return rest;};
 for(const mixed of [false,true]){const f=makeRejectedSwapFamilyFixture(mixed),facts=project(f);for(const key of ['trades','expenses','transfers','allowanceChanges','allowanceUses','conversions','stateMutations'] as const)assert.deepEqual(facts[key].map(effect),mixed?base[key].map(effect):[]);assert.equal(f.packet.rejectedChainActions!.length,1);assert.equal(rejectedSwapActionEvidenceMatches(f.document),true);}
});
for(const variant of ['no-code-read','code','code-hash','block','recipient','request','event-hash','extra-event','cost','payment','delivery','intent','measurement','tx','reason','foreign-operation','extra-guard-key','code-response-hash'] as const)test(`strict swap guard rejects ${variant} without inventing no-effect or changing grades`,()=>{
 const f=makeRejectedSwapFamilyFixture(),s=f.source as Record<string,any>;
 if(variant==='no-code-read')delete f.packet.rpc.rejectedRecipientCodes;
 if(variant==='code')f.packet.rpc.rejectedRecipientCodes![0]!.code='0x6001';
 if(variant==='code-hash')f.guard.codeKeccak256='0x'+'f'.repeat(64) as `0x${string}`;
 if(variant==='block')f.packet.rpc.rejectedRecipientCodes![0]!.blockHash='0x'+'f'.repeat(64);
 if(variant==='recipient')s.selectedEvents[1].eventPayload.recipientCodeObservation.recipient='0x00000000000000000000000000000000000000d2';
 if(variant==='request')s.operation.requestSha256='f'.repeat(64);
 if(variant==='event-hash')s.selectedEvents[1].eventJsonSha256='f'.repeat(64);
 if(variant==='extra-event')s.selectedEvents.push(structuredClone(s.selectedEvents[1]));
 if(variant==='cost')s.costsCount=1;
 if(variant==='payment')s.paymentsCount='1';
 if(variant==='delivery')s.deliveriesCount='1';
 if(variant==='intent')s.selectedExecution.transactionIntent={nonce:'1'};
 if(variant==='measurement')s.selectedExecution.measurement={outcome:'success'};
 if(variant==='tx')s.operation.transactionHash='0x'+'f'.repeat(64);
 if(variant==='reason')s.selectedExecution.reasonCode='recipient_code_observation_unavailable';
 if(variant==='foreign-operation')s.operation.operationId='70000000-0000-4000-8000-000000000099';
 if(variant==='extra-guard-key')s.selectedEvents[1].eventPayload.recipientCodeObservation.passed=true;
 if(variant==='code-response-hash')f.packet.rpc.responseHashes=[];
 // The source fixture is shared with the retained before-census, while guard is copied into its payload.
 if(variant==='code-hash')s.selectedEvents[1].eventPayload.recipientCodeObservation.codeKeccak256=f.guard.codeKeccak256;
 rebind(f);assert.throws(()=>project(f));
});
test('exact HTTP marker is provisional only; generic 400, missing/extra/mismatched marker and any original TX stay unknown',()=>{
 const f=makeRejectedSwapFamilyFixture(),input={status:400,headerOperationId:null,body:{error:'selected_recipient_must_be_eoa',operationId:f.marker.operationId,rejectionProof:f.marker},rawResponseSha256:'a'.repeat(64)};
 const result=classifyBefTaskActionResponse(input);assert.equal(result.status,'rejected_before_execution');assert.deepEqual(result.rejectionProof,f.marker);assert.equal(result.participantToolResponse,undefined);
 for(const body of [{error:'selected_recipient_must_be_eoa',operationId:f.marker.operationId},{...input.body,rejectionProof:{...f.marker,extra:true}},{...input.body,rejectionProof:{...f.marker,operationId:'70000000-0000-4000-8000-000000000099'}},{...input.body,transactionHash:'0x'+'f'.repeat(64)},{...input.body,error:'recipient_code_observation_unavailable'}])assert.equal(classifyBefTaskActionResponse({...input,body}).status,'unknown');
 assert.equal(classifyBefTaskActionResponse({...input,headerOperationId:'70000000-0000-4000-8000-000000000099'}).status,'unknown');
});
test('MCP serializer exposes only a durable null-TX rejected swap marker and never a raw code or measurement',()=>{
 const f=makeRejectedSwapFamilyFixture(),d=f.document,row={id:d.actionId,runId:d.runId,taskIndex:0,operationId:d.ownerOperationId,payloadHash:d.commandSha256,environmentId:d.environmentId,status:d.status,transactionHash:null,toolResponse:null};
 assert.deepEqual(projectRejectedSwapReceiptProof(d,row),f.marker);
 for(const change of [{status:'unknown'},{status:'observed'},{transactionHash:'0x'+'f'.repeat(64)},{toolResponse:{outcome:'success'}}])assert.equal(projectRejectedSwapReceiptProof(d,{...row,...change}),undefined);
 for(const change of [{runId:'70000000-0000-4000-8000-000000000099'},{actionKind:'transfer'},{rejectionProof:{...f.marker,code:'0x6000'}},{transactionHash:'0x'+'f'.repeat(64)},{participantToolResponse:{outcome:'success'}}])assert.equal(projectRejectedSwapReceiptProof({...d,...change},row),undefined);
 const recovered={...d,reasonCode:'platform_recovery_original_operation_terminal'};delete (recovered as Partial<typeof d>).httpStatus;delete (recovered as Partial<typeof d>).rawResponseSha256;delete (recovered as Partial<typeof d>).environmentHealth;delete (recovered as Partial<typeof d>).requestStartedAt;delete (recovered as Partial<typeof d>).requestFinishedAt;
 assert.equal(rejectedSwapActionEvidenceMatches(recovered),true);assert.deepEqual(projectRejectedSwapReceiptProof(recovered,row),f.marker);
});
test('independently validated source requires raw code keccak and immutable original command/operation bindings',()=>{
 const f=makeRejectedSwapFamilyFixture();assert.deepEqual(validateRejectedRecipientCode(f.guard),f.guard);
 const input={action:f.action,source:f.source,environmentId:f.packet.binding.environmentId,generationId:f.packet.execution.generationId,participantId:(f.packet.bef.before.generation as Record<string,unknown>).participant_id,environmentManifest:f.context.environmentManifest,environmentManifestSha256:f.packet.execution.environmentManifestHash,assets:f.packet.rpc.assets,contracts:f.packet.rpc.contracts,routes:f.packet.rpc.routes};assert.deepEqual(rejectedSwapSource(input),f.guard);
 for(const change of [{generationId:'70000000-0000-4000-8000-000000000099'},{participantId:'foreign'},{action:{...f.action,command:{...f.command,amountInUnits:'2'}}}])assert.throws(()=>rejectedSwapSource({...input,...change}));
});
test('historical readback uses only original header/code/header and rejects unavailable, changed and empty code',async()=>{
 const f=makeRejectedSwapFamilyFixture(),tag=`0x${BigInt(f.guard.blockNumber).toString(16)}`;
 for(const variant of ['valid','unavailable','empty','changed-code','changed-block','changed-after'] as const){
  const calls:Array<{method:string;params:readonly unknown[]}>=[];
  const request=async(method:string,params:readonly unknown[])=>{calls.push({method,params});if(variant==='unavailable')throw new Error('no provider details retained');if(method==='eth_getCode')return variant==='empty'?'0x':variant==='changed-code'?'0x6001':f.guard.code;return {number:tag,hash:variant==='changed-block'||variant==='changed-after'&&calls.length===3?'0x'+'f'.repeat(64):f.guard.blockHash};};
  if(variant==='valid'){assert.deepEqual(await rereadRejectedRecipientCode(f.guard,request),f.guard);assert.deepEqual(calls,[{method:'eth_getBlockByNumber',params:[tag,false]},{method:'eth_getCode',params:[f.guard.recipient,tag]},{method:'eth_getBlockByNumber',params:[tag,false]}]);}else await assert.rejects(()=>rereadRejectedRecipientCode(f.guard,request));
 }
});
test('an over-budget guard or missing guard fails before a raw code read, without truncation',async()=>{
 const f=makeRejectedSwapFamilyFixture();let calls=0;const request=async()=>{calls++;return null;};
 await assert.rejects(()=>rereadRejectedRecipientCode({...f.guard,code:'0x'+'60'.repeat(2*1024*1024)},request));assert.equal(calls,0);
 await assert.rejects(()=>rereadRejectedRecipientCode(null,request));assert.equal(calls,0);
});
test('actual family census retains the original deterministic swap denial and rejects any associated cost or infrastructure reason',async()=>{
 const f=makeRejectedSwapFamilyFixture(),source=f.source,op=source.operation,s=source.selectedExecution,generation=f.packet.bef.before.generation;
 const operation={operation_id:op.operationId,env_id:op.environmentId,generation_id:op.generationId,participant_id:op.participantId,idempotency_key_sha256:op.idempotencyKeySha256,request_sha256:op.requestSha256,operation_kind:op.actionKind,status:op.status,receipt_status:op.receiptStatus,transaction_hash:null,response_sha256:null,started_at:op.startedAt,completed_at:op.completedAt,rejected_payments_count:'0',rejected_deliveries_count:'0'};
 const selected={operation_id:s.operationId,env_id:s.environmentId,generation_id:s.generationId,action_kind:'swap',selected_action_json:s.selectedAction,prestate_json:null,transaction_intent_json:null,measurement_json:null,transaction_hash:null,outcome:'rejected',reason_code:s.reasonCode,completed_at:s.completedAt};
 const events=source.selectedEvents.map(e=>({event_id:e.eventId,event_sequence:e.eventSequence,operation_id:e.operationId,env_id:op.environmentId,generation_id:op.generationId,event_kind:e.eventKind,transaction_hash:null,event_json:e.eventPayload}));
 async function capture(variant:'valid'|'cost'|'infra'){
  const replies:unknown[][]=[[{current_user:'bef_observer',session_user:'bef_observer',database_name:'bef',transaction_read_only:'on',transaction_isolation:'repeatable read',rolsuper:false,rolbypassrls:false,schema_create:false}],['bef_environment','bef_generation','bef_operation','bef_selected_execution','bef_selected_execution_event','bef_transaction_cost'].map(table_name=>({table_name,can_select:true,can_insert:false,can_update:false,can_delete:false,can_truncate:false})),[generation],[operation],[{...selected,reason_code:variant==='infra'?'recipient_code_observation_unavailable':selected.reason_code}],events,variant==='cost'?[{operation_id:op.operationId}]:[],[{payments:'0',deliveries:'0'}],[{operations:'1',selected_executions:'1',selected_events:'2',costs:variant==='cost'?'1':'0'}]];
  return captureBefChainCensus({environmentId:op.environmentId,withRepeatableRead:async callback=>callback(async sql=>{if(sql.includes('event_json,created_at'))assert(sql.includes('coalesce(sum(octet_length(event_json::text)),0)'));return replies.shift()!;})},op.environmentId,op.generationId,false,true);
 }
 const actual=await capture('valid');assert.deepEqual(actual.census.rejectedChainOperations,[source]);assert.equal(actual.census.operations.length,0);await assert.rejects(()=>capture('cost'));await assert.rejects(()=>capture('infra'));
});
test('request binding preserves exact pinned pool-code spelling instead of replacing manifest bytes with normalized release hashes',()=>{
 const f=makeRejectedSwapFamilyFixture(),manifest=JSON.parse(Buffer.from(f.context.environmentManifest).toString('utf8'));manifest.contracts.pool3000.codeHash='0x'+manifest.contracts.pool3000.codeHash;
 const bytes=Buffer.from(JSON.stringify(manifest)),input={action:f.action,source:f.source,environmentId:f.packet.binding.environmentId,generationId:f.packet.execution.generationId,participantId:(f.packet.bef.before.generation as Record<string,unknown>).participant_id,environmentManifest:bytes,environmentManifestSha256:createHash('sha256').update(bytes).digest('hex'),assets:f.packet.rpc.assets,contracts:f.packet.rpc.contracts,routes:f.packet.rpc.routes};
 assert.throws(()=>rejectedSwapSource(input),'old naked-hash request bytes cannot be silently accepted under different pinned manifest spelling');
 const r=f.packet.rpc.routes[0]!,action={kind:'swap',route:'uniswap-v3-exactInputSingle',router:r.router,inputAssetId:'WETH',outputAssetId:'USDC',tokenIn:r.tokenIn,tokenOut:r.tokenOut,fee:3000,poolAddress:r.pool,poolCodeHash:manifest.contracts.pool3000.codeHash,amountInUnits:'1',amountOutMinimumUnits:'1',recipient:f.command.recipient,gasLimit:'300000'},request=hash({method:'POST',path:'/tools/swap',action});
 const source=f.source as Record<string,any>;source.operation.requestSha256=request;source.selectedEvents[0].eventPayload.requestSha256=request;source.selectedEvents[1].eventPayload.recipientCodeObservation.requestSha256=request;for(const event of source.selectedEvents)event.eventJsonSha256=hash(event.eventPayload);f.action.rejectionProof!.requestSha256=request;
 assert.equal(rejectedSwapSource(input).requestSha256,request);
 assert.throws(()=>rejectedSwapSource({...input,environmentManifest:f.context.environmentManifest}),'unmatched manifest bytes cannot replace the hashed original');
});
