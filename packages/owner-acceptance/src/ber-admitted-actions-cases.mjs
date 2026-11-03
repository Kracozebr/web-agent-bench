/** Controlled BER learning-mistake smoke. Real browser/backend/MCP/worker;
 * reference SDK actor only, never native Codex or full BER acceptance. */
import assert from 'node:assert/strict';
import {randomUUID,createHash} from 'node:crypto';
import {readFile,lstat} from 'node:fs/promises';
import {resolve,relative,isAbsolute} from 'node:path';
import pg from 'pg';
import {Client,StreamableHTTPClientTransport} from '@modelcontextprotocol/client';
import {createArcTracingFetch} from './arc-http-trace.mjs';
import {assertSecretFree} from './evidence.mjs';
import {monitorMatrixTerminal} from './ber-matrix-controller.mjs';
const pause=ms=>new Promise(done=>setTimeout(done,ms));
const need=(v,code)=>{if(!v)throw Object.assign(new Error(code),{code});};
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const SHA=/^[a-f0-9]{64}$/;
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const terms=['scheme','network','asset','amount','payTo','transferMethod'];
export function selectControlledS1PayOffer(body,conditions){
 need(conditions?.tokenAssetId==='USDC'&&/^0x[a-f0-9]{40}$/i.test(conditions.recipient??'')&&/^[1-9][0-9]*$/.test(conditions.exactPrincipalUnits??''),'ber_s1_conditions_invalid');
 const candidates=[];
 for(const resource of body?.catalog??[]){
  // Actual /catalog publishes offers but no root payment. Its first offer is
  // only a candidate: /offer must independently confirm the root terms below.
  const offer=resource?.offers?.[0],p=offer?.payment;
  if(typeof resource.resourceId!=='string'||!SHA.test(resource.resourceSha256??'')||typeof resource.contentType!=='string'||typeof offer?.id!=='string'||!p||!terms.every(k=>typeof p[k]==='string')||!['name','version','paymentFlow'].every(k=>p[k]===undefined||typeof p[k]==='string')||!/^0x[a-f0-9]{40}$/i.test(p.asset)||!/^0x[a-f0-9]{40}$/i.test(p.payTo)||!/^[1-9][0-9]*$/.test(p.amount))continue;
  // Choose a canonical public offer, not an invented/modified payment. The wrong
  // goal is deliberate; the independent observer/evaluator must establish effects.
  if(p.payTo.toLowerCase()===conditions.recipient.toLowerCase()&&p.amount===conditions.exactPrincipalUnits)continue;
  candidates.push({resourceId:resource.resourceId,resourceSha256:resource.resourceSha256,contentType:resource.contentType,offerId:offer.id,publicPayment:structuredClone(p)});
 }
 need(candidates.length>0,'ber_s1_no_scoped_nonobjective_canonical_offer');return candidates[0];
}
export function assertControlledS1OfferRead(selection,body){
 const first=body?.offers?.[0],root=body?.payment;
 need(body?.freeInspection===true&&body.deliveryState==='not_delivered'&&body.resourceId===selection.resourceId&&body.resourceSha256===selection.resourceSha256&&body.contentType===selection.contentType&&body.readHandle?.kind==='offer'&&UUID.test(body.operationId??'')&&body.readHandle.operationId===body.operationId&&first?.id===selection.offerId&&root&&first.payment,'ber_s1_actual_canonical_offer_identity_mismatch');
 for(const key of [...terms,'name','version','paymentFlow'])need(root[key]===selection.publicPayment[key]&&first.payment[key]===selection.publicPayment[key],'ber_s1_actual_canonical_offer_terms_mismatch');
 need(body.offers.filter(o=>o.id===selection.offerId).length===1,'ber_s1_actual_offer_identity_duplicated');
}
/** Acceptance-only seam: exactly one real finish call, never a replacement action. */
export async function finishBerControlledS1Task({input,mode,taskIds,runId,taskIndex,taskId,call}){
 const fault=input.berGenericSealFault;
 if(fault)need(input.berAdmittedS1PayOnly===true&&input.automaticWorkerEvaluation===true&&mode==='training'&&
  taskId==='S1'&&taskIndex===0&&JSON.stringify(taskIds)==='["S1"]'&&
  ['missing_child','corrupt_child','restart_blocked_seal'].includes(fault.variant)&&
  ['beforeFinish','afterFinish','close'].every(key=>typeof fault[key]==='function'),'BER_GENERIC_SEAL_FAULT_EXACT_ACTOR_REQUIRED');
 let primary;
 try{
  await fault?.beforeFinish({runId,taskIndex,taskId});
  const operationId=randomUUID(),finished=await call('runs.finish_task',{runId,taskIndex,operationId});
  need(UUID.test(finished.closureId??''),'ber_s1_finish_not_confirmed');
  await fault?.afterFinish({runId,taskIndex,taskId,operationId,closureId:finished.closureId});
  return{operationId,finished};
 }catch(error){primary=error;throw error;}
 finally{try{await fault?.close();}catch(cleanup){throw Object.assign(new AggregateError(primary?[primary,cleanup]:[cleanup],'BER_GENERIC_SEAL_FAULT_CLEANUP_FAILED'),{code:'BER_GENERIC_SEAL_FAULT_CLEANUP_FAILED',cleanupRef:cleanup.cleanupRef,berGenericFaultCapture:primary?.berGenericFaultCapture});}}
}
export async function performBerAdmittedS1PayOnly(context,task){
 const {input,output,runId,taskIndex,taskId,bearer}=context;
 need(input.berAdmittedS1PayOnly===true&&input.automaticWorkerEvaluation===true&&context.mode==='training'&&taskId==='S1'&&taskIndex===0&&JSON.stringify(output.taskIds)==='["S1"]','ber_s1_exact_controlled_boundary_required');
 const target=new URL(input.observerDatabaseUrl);need(target.username==='oid_observer'&&/^\/oid_acceptance_[a-f0-9]{32}$/.test(target.pathname),'ber_s1_disposable_observer_required');
 const proof={schemaVersion:'ber-controlled-s1-pay-actor/v1',boundary:'actual_participant_mcp_reference_sdk_not_native_model',runId,taskIndex,taskId,execution:structuredClone(task.execution),calls:[],http:[],nativeAgent:false,economicStrategy:'inspect_catalog_then_canonical_inspect_offer_then_pay_without_retrieve',fullScenarioAcceptance:false};
 output.berAdmittedS1Pay=proof;
 const tracing=createArcTracingFetch({onRecord:row=>{assertSecretFree(row,'ber-controlled-http');proof.http.push(row);}});
 const client=new Client({name:'ber-admitted-reference-sdk',version:'2.4.0'},{versionNegotiation:{mode:{pin:'2026-07-28'}}});
 const transport=new StreamableHTTPClientTransport(new URL('/api/agent/mcp',input.publicOrigin),{requestInit:{headers:{authorization:'Bearer '+bearer,origin:new URL(input.publicOrigin).origin}},fetch:tracing.fetch,onInsufficientScope:'throw'});
 let lastAt=0;
 const call=async(tool,args)=>{await pause(Math.max(0,2100-(Date.now()-lastAt)));lastAt=Date.now();const startedAt=new Date().toISOString(),result=await client.callTool({name:tool,arguments:args});const body=result.structuredContent??JSON.parse(result.content?.find(x=>x.type==='text')?.text??'{}');proof.calls.push({tool,args:structuredClone(args),startedAt,completedAt:new Date().toISOString(),isError:result.isError===true,body});assertSecretFree(proof,'ber-controlled-mcp');need(!result.isError&&!body.error,'ber_s1_mcp_'+(body.error?.code??'tool_error'));return body;};
 const action=async(command)=>{
  const operationId=randomUUID(),admitted=await call('runs.task_action',{runId,taskIndex,operationId,command});
  need(admitted.admitted===true&&UUID.test(admitted.actionId??''),'ber_s1_action_not_admitted');
  const fact={taskId,taskIndex,kind:command.kind,operationId,command:structuredClone(command),actionId:admitted.actionId,httpStatus:200,transport:'actual_mcp_reference_sdk'};output.participantActions.push(fact);
  const deadline=Date.now()+120000;
  while(Date.now()<deadline){const receipt=await call('runs.task_action_status',{runId,actionId:admitted.actionId});need(receipt.actionId===admitted.actionId&&receipt.runId===runId,'ber_s1_receipt_identity_mismatch');
   if(receipt.status==='observed'){fact.receiptStatus=receipt.status;fact.transactionHash=receipt.transactionHash??null;fact.evidence=receipt.evidencePath&&receipt.evidenceHash?{path:receipt.evidencePath,sha256:receipt.evidenceHash}:null;need(command.kind==='pay'?/^0x[a-f0-9]{64}$/i.test(fact.transactionHash??''):fact.transactionHash===null,'ber_s1_actual_effect_identity_missing');return receipt;}
   need(receipt.status==='pending','ber_s1_action_unknown_or_rejected_no_economic_retry');
  }
  throw Object.assign(new Error('ber_s1_action_timeout_original_identity_retained'),{code:'ber_s1_action_timeout_original_identity_retained'});
 };
 try{
  await client.connect(transport);
  const preflight=await call('identity.preflight',{agentId:output.agent.agentId,operationId:randomUUID()});need(preflight.status==='allowed'||preflight.allowed===true,'ber_s1_preflight_not_allowed');
  const current=await call('runs.current_task',{runId});need(current.task?.runId===runId&&current.task?.taskId==='S1'&&current.task?.taskIndex===0,'ber_s1_actual_issued_task_mismatch');
  const catalog=await action({kind:'inspect_catalog'}),selection=selectControlledS1PayOffer(catalog.toolResponse,task.conditions);
  const inspected=await action({kind:'inspect_offer',resourceId:selection.resourceId,offerId:selection.offerId});
  assertControlledS1OfferRead(selection,inspected.toolResponse);
  const paid=await action({kind:'pay',resourceId:selection.resourceId,offerId:selection.offerId,offerReadActionId:inspected.actionId});
  need(paid.toolResponse?.status==='payment_confirmed'&&paid.toolResponse?.payment?.receiptStatus==='success','ber_s1_payment_not_confirmed');
  proof.selection=selection;proof.payActionId=paid.actionId;proof.transactionHash=paid.transactionHash;proof.retrievalSubmitted=false;
  const {operationId,finished}=await finishBerControlledS1Task({input,mode:context.mode,taskIds:output.taskIds,runId,taskIndex,taskId,call});
  return {answer:undefined,berMcpFinishFact:{taskId,taskIndex,kind:'finish',operationId,httpStatus:200,closureId:finished.closureId,transport:'actual_mcp_reference_sdk'}};
 }finally{await client.close().catch(()=>{});}
}
async function readActualOwnerOutcome(input,runId){
 const url=new URL(input.observerDatabaseUrl);need(url.username==='oid_observer'&&/^\/oid_acceptance_[a-f0-9]{32}$/.test(url.pathname),'ber_s1_disposable_observer_required');
 const pool=new pg.Pool({connectionString:input.observerDatabaseUrl,max:1,options:'-c default_transaction_read_only=on -c statement_timeout=10000'}),c=await pool.connect();
 try{await c.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');const identity=(await c.query("SELECT current_user AS role,current_database() AS \"databaseName\",current_setting('transaction_read_only') AS mode")).rows[0];need(identity.role==='oid_observer'&&identity.mode==='on'&&identity.databaseName===url.pathname.slice(1),'ber_s1_actual_observer_identity_invalid');
  const query=async(text)=>JSON.parse(JSON.stringify((await c.query(text,[runId])).rows));
  const run=await query('SELECT * FROM oid_benchmark_run WHERE id=$1'),tasks=await query('SELECT * FROM oid_run_task WHERE run_id=$1 ORDER BY task_index'),actions=await query('SELECT * FROM oid_run_task_action WHERE run_id=$1 ORDER BY action_sequence'),receipts=await query('SELECT r.* FROM oid_run_task_action_receipt r JOIN oid_run_task_action a ON a.id=r.action_id WHERE a.run_id=$1 ORDER BY a.action_sequence'),evaluations=await query('SELECT * FROM oid_run_task_evaluation WHERE run_id=$1 ORDER BY task_index'),bundles=await query('SELECT * FROM oid_run_task_observation_bundle WHERE run_id=$1 ORDER BY task_index'),ledger=await query("SELECT * FROM oid_ledger_entry WHERE operation_id='rundeb_'||replace($1::text,'-','') OR operation_id='runacc_'||replace($1::text,'-','') ORDER BY created_at,id");
  await c.query('COMMIT');return {source:'postgresql_observer',observer:{role:identity.role,databaseName:identity.databaseName,readOnly:true},run,tasks,actions,receipts,evaluations,bundles,ledger};
 }catch(error){await c.query('ROLLBACK').catch(()=>{});throw error;}finally{c.release();await pool.end();}
}
export async function retainEvidenceClosure(repoRoot,value,seen=new Map(),manifestHash=value?.execution?.environmentManifestHash){
 if(Array.isArray(value)){for(const item of value)await retainEvidenceClosure(repoRoot,item,seen,manifestHash);return [...seen.values()];}
 if(!value||typeof value!=='object')return [...seen.values()];
 if(typeof value.path==='string'&&SHA.test(value.sha256??'')&&!seen.has(value.path)){
  const pinnedManifest=value.path==='infrastructure/benchmark-environment/manifest.json'&&/^[a-f0-9]{64}$/.test(manifestHash??'')&&value.sha256===manifestHash;
  need((value.path.startsWith('artifacts/runs/')||pinnedManifest)&&!value.path.includes('\\'),'ber_s1_evidence_namespace_invalid');const full=resolve(repoRoot,value.path),rel=relative(repoRoot,full);need(rel&&!isAbsolute(rel)&&!rel.startsWith('..'),'ber_s1_evidence_path_invalid');const stat=await lstat(full);need(stat.isFile()&&!stat.isSymbolicLink()&&stat.size<=32*1024*1024&&seen.size<1024,'ber_s1_evidence_closure_bound');const bytes=await readFile(full);need(hash(bytes)===value.sha256,'ber_s1_evidence_hash_mismatch');seen.set(value.path,{path:value.path,sha256:value.sha256,bytes:bytes.length});if(full.endsWith('.json'))await retainEvidenceClosure(repoRoot,JSON.parse(bytes),seen,manifestHash);
 }
 for(const child of Object.values(value))await retainEvidenceClosure(repoRoot,child,seen,manifestHash);return [...seen.values()];
}
export const BER_S1_BEF_READ_QUERIES=Object.freeze({
 identity:{sql:"SELECT current_user AS role,current_database() AS \"databaseName\",current_setting('transaction_read_only') AS mode",parameterKind:'identity'},
 payments:{sql:'SELECT payment_id::text,operation_id::text,env_id,generation_id::text,payer_address,asset_address,amount_units::text,facilitator_address,to_jsonb(bef_payment)->>\'payment_recipient\' AS payment_recipient,transaction_hash,receipt_status,token_delta_units::text,payer_balance_before::text,payer_balance_after::text FROM bef_payment WHERE env_id=$1 AND generation_id=$2::uuid AND transaction_hash=$3',parameterKind:'payment_scope'},
 costs:{sql:'SELECT operation_id::text,env_id,generation_id::text,transaction_hash,payer_address,payer_role,receipt_status,receipt_block_hash,receipt_block_number::text,gas_used::text,effective_gas_price_wei::text,gas_cost_wei::text FROM bef_transaction_cost WHERE env_id=$1 AND generation_id=$2::uuid AND transaction_hash=$3',parameterKind:'payment_scope'},
 deliveries:{sql:`SELECT d.delivery_id::text,d.operation_id::text,o.env_id,o.generation_id::text FROM bef_delivery d JOIN bef_operation o ON o.operation_id=d.operation_id WHERE o.env_id=$1 AND o.generation_id=$2::uuid AND d.operation_id=$3::uuid`,parameterKind:'delivery_scope'},
 generations:{sql:'SELECT generation_id::text,env_id,payer_address,status FROM bef_generation WHERE env_id=$1 AND generation_id=$2::uuid',parameterKind:'generation_scope'},
});
export async function captureBerS1PaidEffectReadOnly(capture,bundle){
 let phase='bef_scope';
 try{
 const proof=capture.berAdmittedS1Pay,tx=proof.transactionHash,env=bundle.binding.environmentId,generation=bundle.execution.generationId;
 need(env==='bef-env-a'&&UUID.test(generation)&&/^0x[a-f0-9]{64}$/i.test(tx??''),'ber_s1_actual_execution_scope_invalid');
 phase='bef_secret';let password=(await readFile('/run/secrets/bef_database_observer_password','utf8')).trim();need(password.length>=16&&!/[\r\n\u0000]/.test(password),'ber_s1_bef_observer_unavailable');
 const database=new URL('postgres://bef_observer@host.docker.internal:'+(process.env.BEF_DATABASE_HOST_PORT||'55432')+'/bef');database.password=password;
 const pool=new pg.Pool({connectionString:database.href,max:1,options:'-c default_transaction_read_only=on -c statement_timeout=10000'});password='';database.password='';phase='bef_connect';let c;try{c=await pool.connect();}catch(error){await pool.end().catch(()=>{});throw error;}
 let postgres;
 try{phase='bef_identity';await c.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');const identity=(await c.query(BER_S1_BEF_READ_QUERIES.identity.sql)).rows[0];need(identity.role==='bef_observer'&&identity.mode==='on','ber_s1_bef_observer_identity_invalid');
  const params=[env,generation,tx];phase='bef_payments';const payments=(await c.query(BER_S1_BEF_READ_QUERIES.payments.sql,params)).rows;
  phase='bef_costs';const costs=(await c.query(BER_S1_BEF_READ_QUERIES.costs.sql,params)).rows;
  need(payments.length===1&&costs.length===1,'ber_s1_exact_payment_and_cost_rows_missing');phase='bef_deliveries';const deliveries=(await c.query(BER_S1_BEF_READ_QUERIES.deliveries.sql,[env,generation,payments[0].operation_id])).rows;
  phase='bef_generations';const generations=(await c.query(BER_S1_BEF_READ_QUERIES.generations.sql,[env,generation])).rows;
  await c.query('COMMIT');postgres={source:'postgresql_observer',observer:{role:identity.role,databaseName:identity.databaseName,readOnly:true},payments,costs,deliveries,generations};
 }catch(error){await c.query('ROLLBACK').catch(()=>{});throw error;}finally{c.release();await pool.end();}
 const rpcRecords=[];let id=0;const rpc=async(method,params)=>{need(['eth_chainId','eth_getTransactionReceipt','eth_getTransactionByHash','eth_getBlockByNumber'].includes(method),'ber_s1_rpc_read_method_invalid');phase='rpc_'+method;const response=await fetch('http://host.docker.internal:'+(process.env.BEF_LOCAL_RPC_A_HOST_PORT||'18545'),{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:++id,method,params}),redirect:'error',signal:AbortSignal.timeout(20000)});need(response.ok,'ber_s1_rpc_http_failed');const raw=Buffer.from(await response.arrayBuffer());need(raw.length<=4*1024*1024,'ber_s1_rpc_response_bound');const body=JSON.parse(raw);need(body.id===id&&!body.error&&body.result!==undefined,'ber_s1_rpc_response_invalid');let projected=body.result;if(method==='eth_getTransactionByHash'&&projected){const input=projected.input;projected={...Object.fromEntries(['hash','from','to','value','nonce','blockHash','blockNumber','transactionIndex','type','chainId','gas','gasPrice','maxFeePerGas','maxPriorityFeePerGas'].filter(k=>projected[k]!==undefined).map(k=>[k,projected[k]])),inputSha256:hash(Buffer.from(input??''))};}if(method==='eth_getBlockByNumber'&&projected)projected={number:projected.number,hash:projected.hash,parentHash:projected.parentHash};rpcRecords.push({method,params,httpStatus:response.status,rawResponseSha256:hash(raw),result:projected});return body.result;};
 const chainId=await rpc('eth_chainId',[]),receipt=await rpc('eth_getTransactionReceipt',[tx]),transaction=await rpc('eth_getTransactionByHash',[tx]);need(BigInt(chainId)===BigInt(proof.execution.localChainId)&&receipt?.status==='0x1'&&receipt.transactionHash?.toLowerCase()===tx.toLowerCase()&&transaction?.hash?.toLowerCase()===tx.toLowerCase(),'ber_s1_rpc_payment_identity_unverified');
 const block=await rpc('eth_getBlockByNumber',[receipt.blockNumber,false]);need(block?.hash?.toLowerCase()===receipt.blockHash?.toLowerCase()&&transaction.blockHash?.toLowerCase()===receipt.blockHash.toLowerCase(),'ber_s1_rpc_payment_block_mismatch');
 phase='verify_asset';const payment=postgres.payments[0],cost=postgres.costs[0],asset=proof.execution.assets.find(a=>a.assetId==='USDC');
 need(postgres.generations.length===1&&postgres.generations[0].payer_address.toLowerCase()===payment.payer_address.toLowerCase()&&asset?.address?.toLowerCase()===payment.asset_address.toLowerCase(),'ber_s1_independent_payer_asset_mismatch');
 phase='verify_transfer_logs';const topic='0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',transfers=[];
 for(const log of receipt.logs??[])if(log.address?.toLowerCase()===payment.asset_address.toLowerCase()&&log.topics?.[0]?.toLowerCase()===topic){need(log.topics.length===3&&/^0x[0-9a-f]{64}$/i.test(log.data??'')&&!log.removed,'ber_s1_transfer_log_invalid');transfers.push({from:'0x'+log.topics[1].slice(-40).toLowerCase(),to:'0x'+log.topics[2].slice(-40).toLowerCase(),amountUnits:BigInt(log.data).toString(),transactionHash:log.transactionHash,logIndex:log.logIndex});}
 const matches=transfers.filter(t=>t.from===payment.payer_address.toLowerCase()&&t.to===proof.selection.publicPayment.payTo.toLowerCase()&&t.amountUnits===proof.selection.publicPayment.amount);
 need(matches.length===1&&payment.receipt_status==='success'&&payment.amount_units===matches[0].amountUnits&&payment.token_delta_units===matches[0].amountUnits&&BigInt(payment.payer_balance_before)-BigInt(payment.payer_balance_after)===BigInt(matches[0].amountUnits)&&postgres.deliveries.length===0,'ber_s1_actual_principal_or_delivery_unverified');
 const goal=capture.taskDisclosure.conditions;need(matches[0].to!==goal.recipient.toLowerCase()||matches[0].amountUnits!==goal.exactPrincipalUnits,'ber_s1_actual_payment_not_wrong_relative_to_goal');
 phase='verify_gas';need(cost.receipt_status==='success'&&cost.payer_role==='facilitator'&&cost.payer_address.toLowerCase()===transaction.from.toLowerCase()&&BigInt(cost.gas_used)===BigInt(receipt.gasUsed)&&BigInt(cost.effective_gas_price_wei)===BigInt(receipt.effectiveGasPrice)&&BigInt(cost.gas_cost_wei)===BigInt(receipt.gasUsed)*BigInt(receipt.effectiveGasPrice),'ber_s1_independent_gas_mismatch');
 return {source:'independent_readonly_bef_postgresql_and_rpc',postgres,rpc:rpcRecords,decodedTransfers:transfers,actualWrongPrincipal:matches[0],deliveryCount:0,classification:'actual_effect_evidence_not_native_performance'};
 }catch(error){const sqlState=/^[A-Z0-9]{5}$/.test(error?.code??'')?error.code:null;error.safeDiagnostic={phase,sqlState,errorKind:['Error','TypeError','SyntaxError','AssertionError'].includes(error?.name)?error.name:'Error'};throw error;}
}
// AICODE-NOTE: The paid actor closes its own SDK session. Terminal evidence is a
// separate read-only connection using that same callback credential, never a new run.
export async function observeBerS1PayRunTerminal({publicOrigin,runId,agentId,agentBearer,deadlineMs,record},unitDependencies){
 need(UUID.test(runId??'')&&UUID.test(agentId??'')&&typeof agentBearer==='string'&&agentBearer.length>0&&Number.isFinite(deadlineMs),'ber_s1_terminal_identity_invalid');
 const open=unitDependencies?.openSession??(async()=>{
  const client=new Client({name:'ber-admitted-reference-sdk',version:'2.4.0'},{versionNegotiation:{mode:{pin:'2026-07-28'}}});
  const signal=AbortSignal.timeout(Math.max(1,Math.ceil(deadlineMs-Date.now())));
  const boundedFetch=(url,init={})=>fetch(url,{...init,signal:init.signal?AbortSignal.any([signal,init.signal]):signal});
  const transport=new StreamableHTTPClientTransport(new URL('/api/agent/mcp',publicOrigin),{requestInit:{headers:{authorization:'Bearer '+agentBearer,origin:new URL(publicOrigin).origin}},fetch:boundedFetch,onInsufficientScope:'throw'});
  try{await client.connect(transport);}catch(error){await client.close().catch(()=>{});throw error;}
  return {callTool:(name,args)=>client.callTool({name,arguments:args}),close:()=>client.close()};
 });
 const session=await open();
 try{return await monitorMatrixTerminal({runId,deadlineMs,record,callTool:session.callTool,...(unitDependencies?.clock??{})});}
 finally{await session.close();}
}
export async function runBerAdmittedS1PaySmoke(input,unitDependencies){
 need(input.berAdmittedS1PayOnly===true&&input.automaticWorkerEvaluation===true&&!input.sequenceMode&&input.taskId==='S1'&&input.mode==='training'&&!input.bddProbes,'ber_s1_exact_smoke_profile_required');
 const {runGenuineS1OwnerCase}=unitDependencies??await import('./genuine-s1-cases.mjs');
 const terminalRecords=[];let terminalResult,completionIdentity;
 const capture=await runGenuineS1OwnerCase({...input,async onGenuineRunCompleted(context){
  need(!completionIdentity&&context.mode==='training'&&JSON.stringify(context.taskIds)==='["S1"]'&&UUID.test(context.runId??'')&&UUID.test(context.agentId??''),'ber_s1_completion_identity_mismatch');
  completionIdentity={runId:context.runId,agentId:context.agentId};
  terminalResult=await (unitDependencies?.observeTerminal??observeBerS1PayRunTerminal)({publicOrigin:input.publicOrigin,runId:context.runId,agentId:context.agentId,agentBearer:context.agentBearer,deadlineMs:Date.now()+30000,record:row=>terminalRecords.push(row)});
  need(terminalResult?.runId===context.runId&&terminalResult.terminal===true&&terminalResult.status==='completed','ber_s1_terminal_not_confirmed');
  if(typeof input.onGenuineRunCompleted==='function')await input.onGenuineRunCompleted(context);
 }});capture.classification='controlled_reference_s1_learning_mistake_real_mcp_worker_not_native_or_full_ber_acceptance';
 capture.berAdmittedS1PayQualification={schemaVersion:'ber-controlled-s1-pay-run-qualification/v1',terminalMcp:{records:terminalRecords,...(terminalResult?{result:terminalResult}:{status:'not_observed'})}};
 if(capture.runCompletion?.status==='verified'&&!(completionIdentity?.runId===capture.runId&&(!capture.agent?.agentId||completionIdentity.agentId===capture.agent.agentId)&&terminalResult?.runId===capture.runId&&terminalResult.terminal===true&&terminalResult.status==='completed')){
  capture.status='blocked';capture.blocker={stage:'ber_s1_explicit_mcp_terminal',reasonCode:'ber_s1_terminal_not_confirmed'};
 }
 if(capture.status==='blocked')return capture;
 try{
  const owner=await readActualOwnerOutcome(input,capture.runId);capture.berAdmittedS1Pay.ownerOutcome=owner;
  need(owner.run.length===1&&owner.run[0].status==='completed'&&owner.tasks.length===1&&owner.tasks[0].status==='failed'&&owner.evaluations.length===1&&owner.bundles.length===1,'ber_s1_known_terminal_owner_result_missing');
  need(owner.actions.length===3&&JSON.stringify(owner.actions.map(a=>a.action_kind))==='["inspect_catalog","inspect_offer","pay"]'&&owner.receipts.length===3&&owner.receipts.every(r=>r.receipt_status==='observed'),'ber_s1_original_action_census_mismatch');
  const parse=x=>typeof x==='string'?JSON.parse(x):x,result=parse(owner.evaluations[0].result_json),bundle=parse(owner.bundles[0].bundle_json);
  need(result.status==='known'&&result.taskId==='S1'&&result.outcome==='failed'&&result.credit?.numerator==='0'&&result.credit?.denominator==='1','ber_s1_actual_rubric_not_known_zero');
  const goal=capture.taskDisclosure.conditions,tx=capture.berAdmittedS1Pay.transactionHash;
  const wrong=(bundle.observations.transfers??[]).filter(t=>t.receiptStatus==='success'&&t.transactionHash?.toLowerCase()===tx?.toLowerCase()&&t.assetId==='USDC'&&(t.to.toLowerCase()!==goal.recipient.toLowerCase()||t.amountUnits!==goal.exactPrincipalUnits));
  need(wrong.length>0&&(bundle.observations.deliveries??[]).length===0,'ber_s1_independent_wrong_principal_or_absent_delivery_not_proved');
  capture.berAdmittedS1Pay.independentEffect=await captureBerS1PaidEffectReadOnly(capture,bundle);
  need(capture.runCompletion?.status==='verified'&&capture.runCompletion.debitEntryCount===1&&capture.runCompletion.runRefundCount===0,'ber_s1_exact_once_charge_not_verified');
  capture.berAdmittedS1Pay.evidenceClosure=await retainEvidenceClosure(input.repoRoot,bundle);
  need(capture.berAdmittedS1Pay.evidenceClosure.length>=3,'ber_s1_paid_chain_raw_evidence_missing');
  capture.berAdmittedS1Pay.result={status:'verified_controlled_smoke_only',knownCredit:result.credit,resultHash:owner.evaluations[0].result_hash,sealedBundleHash:owner.bundles[0].bundle_hash,nativeAgent:false,fullScenarioAcceptance:false};
 }catch(error){if(error?.safeDiagnostic)capture.berAdmittedS1Pay.postCheckFailure=error.safeDiagnostic;capture.status='blocked';capture.blocker={stage:'ber_s1_independent_owner_and_raw_effect_check',reasonCode:/^ber_[a-z0-9_]+$/.test(error?.code??'')?error.code:'ber_s1_independent_proof_failed'};}
 assertSecretFree(capture,'ber-controlled-s1-smoke');return capture;
}
