/** Read-only M3/M4/H2 collector. It returns an unsealed candidate and never dispatches actions. */
import { createHash } from 'node:crypto';
import { lstat, open, realpath } from 'node:fs/promises';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import { sql } from 'drizzle-orm';
import { keccak256 } from 'viem';
import { TaskActionCommandSchema, type TaskActionCommand } from './task-action-service.js';
import type { OwnerDatabase } from './db.js';
import { recoveredActionEvidenceIsOwnerBound, recoveredOwnerLineageJoinSql, recoveredOwnerLineageSelectSql,
 recoverySourceEvidenceMatchesFacts, type RecoveredOwnerLineageRow,
 type RecoverySourceFacts } from './bef-recovery-observation.js';
import type { RecoveryActionEvidence } from './beta-platform-recovery-source-evidence.js';
import type { PersistedTaskObservations, TaskEvidenceBinding } from './task-evaluator.js';
import { canonicalTaskJson, sha256CanonicalTaskJson, type EvidenceReference, type TaskCase, type TaskReleaseQuerySource } from './task-release.js';
import type { TaskObservationBundleCandidate } from './task-observation-store.js';
import { m1PreparationHealthMatches, parseM1PreparationEvidence } from './bef-m1-observation-collector.js';
import { projectTaskChainCapturePacket, type ChainCaptureExternalAction, type ChainCapturePacket, type ChainJson, type ChainTaskCase } from './task-chain-capture-packet.js';

const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HASH=/^[0-9a-f]{64}$/i, TX=/^0x[0-9a-f]{64}$/i, ADDRESS=/^0x[0-9a-f]{40}$/i;
const UINT=/^(?:0|[1-9][0-9]{0,77})$/, HEX_QUANTITY=/^0x(?:0|[1-9a-f][0-9a-f]*)$/i;
const ROOT='artifacts/runs/owner-identity-bef-task-coordinator/';
const ACTION_ROOT=ROOT+'action/', PREP_ROOT=ROOT+'preparation/', OBS_ROOT=ROOT+'observation/';
const BOUNDARY='actual_tool_http_x402_local_evm_application_store' as const;
const MAX_ACTIONS=256, MAX_BLOCKS=256, MAX_ROWS=2048, MAX_EVIDENCE_BYTES=256*1024, MAX_RPC_BYTES=4*1024*1024, MAX_PACKET_BYTES=8*1024*1024;
const TRANSFER='0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
const APPROVAL='0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925';
const SWAP='0xc42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67';
const DEPOSIT='0xe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c';
const WITHDRAWAL='0x7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65';
const CHAIN_KINDS=new Set(['approve','transfer','wrap','unwrap','swap']);
type J=Record<string,unknown>;
type OwnerTx=Parameters<Parameters<OwnerDatabase['transaction']>[0]>[0];
type ReadQuery=(statement:string,parameters?:readonly unknown[])=>Promise<unknown>;
type Census={generation:J;operations:J[];externalPaymentOperations:J[];selectedExecutions:J[];selectedEvents:J[];costs:J[];paymentsCount:string;deliveriesCount:string;counts:J};
type PreparationRow={preparation_id:string;claim_id:string;lease_id:string;environment_id:string;release_identity:string;manifest_hash:string;task_id:string;
 case_id:string;case_hash:string;initial_state_sha256:string;execution_identity_hash:string;environment_manifest_sha256:string;application_source_hash:string;
 created_at:Date|string;lease_state:string;observation_status:string;generation_id:string|null;participant_id:string|null;payer_address:string|null;
 baseline_state_sha256:string|null;fixture_evidence:unknown;baseline_evidence:unknown};
type ActionRow={id:string;run_id:string;task_index:number;owner_id:string;agent_id:string;task_id:string;environment_id:string;action_sequence:string|number;
 operation_id:string;payload_hash:string;action_kind:string;command_json:unknown;receipt_revision:number;receipt_status:string;evidence_hash:string|null;
 evidence_path:string|null;transaction_hash:string|null;history_revision:number|null;history_status:string|null;history_evidence_hash:string|null;
 history_evidence_path:string|null;history_transaction_hash:string|null}&RecoveredOwnerLineageRow;
type Loaded={row:ActionRow;sequence:number;command:Extract<TaskActionCommand,{kind:'approve'|'transfer'|'wrap'|'unwrap'|'swap'}>;
 evidence:EvidenceReference;recoveryEvidence:RecoveryActionEvidence;befOperationId:string;transactionHash:string;outcome:'success'|'reverted';selectedAction:J;approvalSpender:string|null};
type LoadedActions={chain:Loaded[];external:ChainCaptureExternalAction[]};
type PrepProof={fixture:EvidenceReference;baseline:EvidenceReference;blockNumber:bigint;blockHash:string};
type Checkpoint=ChainCapturePacket['rpc']['baseline'];
type CapturedTx=ChainCapturePacket['rpc']['transactions'][number];

export interface BefChainReadOnlyPostgresPort { environmentId:string; withRepeatableRead<T>(callback:(query:ReadQuery)=>Promise<T>):Promise<T> }
export interface BefChainReadOnlyRpcPort { environmentId:string; request(method:string,params:readonly unknown[]):Promise<unknown> }
export interface BefChainObservationEvidenceSink { write(packet:ChainCapturePacket):Promise<EvidenceReference> }
export interface BefChainObservationCollectorDependencies {
 db:OwnerDatabase;taskReleaseSource:TaskReleaseQuerySource;repositoryRoot:string;
 postgresByEnvironment:Readonly<Record<string,BefChainReadOnlyPostgresPort>>;
 rpcByEnvironment:Readonly<Record<string,BefChainReadOnlyRpcPort>>;evidenceSink:BefChainObservationEvidenceSink;
}
export type ChainObservationBoundary={actionCutoffSequence:number;observationCutoffSequence:number;baselineBlockNumber:string;baselineBlockHash:string;
 finalBlockNumber:string;finalBlockHash:string};
export type BefChainObservationUnavailableCode='invalid_target'|'unsupported_task'|'owner_cutoff_unavailable'|'owner_cutoff_mismatch'|
 'reconciliation_pending'|'action_evidence_unavailable'|'preparation_unavailable'|'release_binding_mismatch'|'source_not_configured'|
 'observer_role_invalid'|'observer_census_unavailable'|'observer_census_changed'|'rpc_identity_mismatch'|'rpc_observation_unavailable'|
 'rpc_interval_too_large'|'rpc_mapping_incomplete'|'baseline_mismatch'|'capture_evidence_unavailable';
export type BefChainObservationCollectionResult={status:'unavailable';reasonCode:BefChainObservationUnavailableCode}|{
 status:'candidate';candidate:TaskObservationBundleCandidate;evidence:EvidenceReference;classification:'run_bound_observations_candidate_not_grade';boundary:ChainObservationBoundary};

class Unavailable extends Error { constructor(readonly reasonCode:BefChainObservationUnavailableCode){super(reasonCode)} }
function fail(reason:BefChainObservationUnavailableCode):never{throw new Unavailable(reason)}
function unavailable(reasonCode:BefChainObservationUnavailableCode):BefChainObservationCollectionResult{return {status:'unavailable',reasonCode}}
function isRecord(value:unknown):value is J{return !!value&&typeof value==='object'&&!Array.isArray(value)&&(Object.getPrototypeOf(value)===Object.prototype||Object.getPrototypeOf(value)===null)}
function exactKeys(value:J,keys:readonly string[]):boolean{return Object.keys(value).sort().join('\0')===[...keys].sort().join('\0')}
function same(a:unknown,b:unknown):boolean{return canonicalTaskJson(a)===canonicalTaskJson(b)}
function addr(value:unknown):string|null{return typeof value==='string'&&ADDRESS.test(value)?value.toLowerCase():null}
function txHash(value:unknown):string|null{return typeof value==='string'&&TX.test(value)?value.toLowerCase():null}
function dec(value:unknown):bigint|null{return typeof value==='string'&&UINT.test(value)?BigInt(value):null}
function quantity(value:unknown):bigint|null{try{return typeof value==='string'&&HEX_QUANTITY.test(value)?BigInt(value):null}catch{return null}}
function seq(value:string|number|null|undefined):number|null{try{const n=BigInt(value as string|number);return n>=0n&&n<=BigInt(Number.MAX_SAFE_INTEGER)?Number(n):null}catch{return null}}
function sha(value:string|Uint8Array):string{return createHash('sha256').update(value).digest('hex')}
function safeValue(value:unknown):unknown{if(value instanceof Date)return value.toISOString();if(typeof value==='bigint')return value.toString();if(Array.isArray(value))return value.map(safeValue);if(isRecord(value))return Object.fromEntries(Object.entries(value).map(([k,v])=>[k,safeValue(v)]));return value}
function parseJson(value:unknown):unknown{if(typeof value!=='string')return value;try{return JSON.parse(value) as unknown}catch{return null}}
function rows<T extends J>(value:unknown):T[]{const parsed=parseJson(value);if(!Array.isArray(parsed)||parsed.some((x)=>!isRecord(x)))fail('observer_census_unavailable');return parsed as T[]}
function dbRows<T extends J>(value:unknown):T[]{if(Array.isArray(value))return rows(value);if(isRecord(value)&&Array.isArray(value.rows))return rows(value.rows);if(isRecord(value)&&Array.isArray(value.result))return rows(value.result);fail('owner_cutoff_unavailable')}
async function ownerRows<T extends J>(tx:OwnerTx,statement:ReturnType<typeof sql>):Promise<T[]>{return dbRows<T>(await tx.execute(statement))}

const SECRET_KEYS=new Set(['privatekey','privkey','seedphrase','mnemonic','secret','clientsecret','bearer','bearertoken','accesstoken','refreshtoken',
 'providertoken','paymenttoken','token','apitoken','apikey','authorization','walletmaterial','walletsecret','signature','signedpayload','password','credential','connectionstring','databaseurl','dsn']);
function hasSecret(value:unknown,path:string[]=[],seen=new Set<object>()):boolean{
 if(value===null||typeof value!=='object')return false;if(seen.has(value))return true;seen.add(value);
 const found=Array.isArray(value)?value.some((v,i)=>hasSecret(v,[...path,String(i)],seen)):Object.entries(value as J).some(([key,v])=>{
  const normalized=key.toLowerCase().replace(/[^a-z]/g,'');const publicToken=normalized==='token'&&path.at(-1)==='selectedAction'&&addr(v)!==null;
  return (SECRET_KEYS.has(normalized)&&!publicToken)||hasSecret(v,[...path,key],seen);
 });seen.delete(value);return found;
}
function evidenceRef(value:unknown,prefix:string):EvidenceReference|null{
 if(!isRecord(value)||!exactKeys(value,['path','sha256','boundary'])||value.boundary!==BOUNDARY||typeof value.path!=='string'||!value.path.startsWith(prefix)||
  value.path.length>512||!/^(?![A-Za-z]:)(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/-]{1,512}$/.test(value.path)||value.path.includes('\\')||!HASH.test(String(value.sha256)))return null;
 return {path:value.path,sha256:String(value.sha256).toLowerCase(),boundary:BOUNDARY};
}
async function readEvidence(rootPath:string,ref:EvidenceReference,prefix:string,reason:BefChainObservationUnavailableCode):Promise<Buffer>{
 if(!ref.path.startsWith(prefix)||ref.path.includes('\\')||ref.path.includes('\0')||isAbsolute(ref.path)||ref.path.split('/').some((p)=>!p||p==='.'||p==='..'))fail(reason);
 const root=await realpath(rootPath).catch(()=>fail(reason)),file=resolve(root,...ref.path.split('/'));
 const actual=await realpath(file).catch(()=>fail(reason)),rel=relative(root,actual),normalized=rel.split(sep).join('/');
 if(!rel||rel==='..'||rel.startsWith(`..${sep}`)||isAbsolute(rel)||!normalized.startsWith(prefix))fail(reason);
 const handle=await open(actual,'r').catch(()=>fail(reason));let bytes:Buffer;
 try{const before=await handle.stat({bigint:true}),linkBefore=await lstat(actual,{bigint:true});
  if(!before.isFile()||!linkBefore.isFile()||before.dev!==linkBefore.dev||before.ino!==linkBefore.ino||before.size<1n||before.size>BigInt(MAX_EVIDENCE_BYTES))fail(reason);
  const buffer=Buffer.alloc(MAX_EVIDENCE_BYTES+1);let total=0;while(total<buffer.length){const result=await handle.read(buffer,total,buffer.length-total,null);if(!result.bytesRead)break;total+=result.bytesRead;}
  const after=await handle.stat({bigint:true}),linkAfter=await lstat(actual,{bigint:true});
  if(total<1||total>MAX_EVIDENCE_BYTES||BigInt(total)!==before.size||before.dev!==after.dev||before.ino!==after.ino||before.size!==after.size||
   before.mtimeNs!==after.mtimeNs||before.ctimeNs!==after.ctimeNs||linkAfter.dev!==after.dev||linkAfter.ino!==after.ino)fail(reason);
  bytes=buffer.subarray(0,total);
 }catch(error){if(error instanceof Unavailable)throw error;fail(reason)}finally{await handle.close().catch(()=>undefined)}
 if(sha(bytes)!==ref.sha256)fail(reason);return bytes;
}
function publicPins(prep:PreparationRow,runId:string,index:number):string{
 const createdAt=prep.created_at instanceof Date?prep.created_at.toISOString():new Date(prep.created_at).toISOString();if(!Number.isFinite(Date.parse(createdAt)))fail('preparation_unavailable');
 return sha256CanonicalTaskJson({preparationId:prep.preparation_id,runId,taskIndex:index,claimId:prep.claim_id,leaseId:prep.lease_id,environmentId:prep.environment_id,
  releaseIdentity:prep.release_identity,manifestHash:prep.manifest_hash,taskId:prep.task_id,caseId:prep.case_id,caseHash:prep.case_hash,
  initialStateSha256:prep.initial_state_sha256,executionIdentityHash:prep.execution_identity_hash,environmentManifestSha256:prep.environment_manifest_sha256,
  applicationSourceHash:prep.application_source_hash,createdAt}).toLowerCase();
}
function stateProjection(state:ChainTaskCase['initialState']):J{
 const balances=[...state.balances].sort((a,b)=>`${a.account.toLowerCase()}|${a.assetId}`.localeCompare(`${b.account.toLowerCase()}|${b.assetId}`));
 const allowances=[...state.allowances].sort((a,b)=>`${a.owner.toLowerCase()}|${a.tokenAssetId}|${a.spender.toLowerCase()}`.localeCompare(`${b.owner.toLowerCase()}|${b.tokenAssetId}|${b.spender.toLowerCase()}`));
 return {balances,allowances,deliveredComponentIds:[...state.deliveredComponentIds].sort(),fulfilledObligationIds:[...state.fulfilledObligationIds].sort()};
}
async function loadPreparation(root:string,prep:PreparationRow,runId:string,index:number,taskCase:ChainTaskCase):Promise<PrepProof>{
 const fixture=evidenceRef(prep.fixture_evidence,PREP_ROOT),baseline=evidenceRef(prep.baseline_evidence,PREP_ROOT);
 if(!fixture||!baseline||fixture.path===baseline.path||fixture.sha256===baseline.sha256)fail('preparation_unavailable');
 const [fixtureBytes,baselineBytes]=await Promise.all([readEvidence(root,fixture,PREP_ROOT,'preparation_unavailable'),readEvidence(root,baseline,PREP_ROOT,'preparation_unavailable')]);
 const f=parseM1PreparationEvidence(fixtureBytes,'fixture') as J,b=parseM1PreparationEvidence(baselineBytes,'baseline') as J,pins=publicPins(prep,runId,index);
 for(const [doc,kind] of [[f,'fixture'],[b,'baseline']] as const)if(doc.schemaVersion!=='owner-bef-task-preparation-evidence/v1'||doc.kind!==kind||
  doc.preparationId!==prep.preparation_id||doc.environmentId!==prep.environment_id||doc.publicPinsSha256!==pins||!isRecord(doc.evidence))fail('preparation_unavailable');
 const fEvidence=f.evidence as J,bEvidence=b.evidence as J;
 if(!m1PreparationHealthMatches(fEvidence.environmentHealth,fEvidence.publicStatus,{environmentId:prep.environment_id,preparationId:prep.preparation_id,
   generationId:prep.generation_id,environmentManifestHash:prep.environment_manifest_sha256,applicationSourceHash:prep.application_source_hash}))fail('preparation_unavailable');
 const state=bEvidence.state;
 if(!isRecord(state)||state.sameBlock!==true||!isRecord(state.projection)||!Array.isArray(state.reads)||
  bEvidence.stateSha256!==taskCase.initialState.stateSha256.toLowerCase()||bEvidence.expectedStateSha256!==taskCase.initialState.stateSha256.toLowerCase()||
  prep.baseline_state_sha256?.toLowerCase()!==taskCase.initialState.stateSha256.toLowerCase()||!same(state.projection,stateProjection(taskCase.initialState))||
  sha256CanonicalTaskJson(state.projection).toLowerCase()!==taskCase.initialState.stateSha256.toLowerCase())fail('baseline_mismatch');
 const blockNumber=quantity(state.blockNumber),blockHash=txHash(state.blockHash);if(blockNumber===null||!blockHash)fail('preparation_unavailable');
 return {fixture,baseline,blockNumber,blockHash};
}

async function validateObserverSession(query:ReadQuery):Promise<J>{
  const session=dbRows<J>(await query(`SELECT current_user AS current_user,session_user AS session_user,current_database() AS database_name,
    current_setting('transaction_read_only') AS transaction_read_only,current_setting('transaction_isolation') AS transaction_isolation,
    r.rolsuper AS rolsuper,r.rolbypassrls AS rolbypassrls,has_schema_privilege(current_user,'public','CREATE') AS schema_create
    FROM pg_roles r WHERE r.rolname=current_user`));
  const tables=['bef_environment','bef_generation','bef_operation','bef_selected_execution','bef_selected_execution_event','bef_transaction_cost'];
  const grants=dbRows<J>(await query(`SELECT table_name,has_table_privilege(current_user,'public.'||table_name,'SELECT') AS can_select,
    has_table_privilege(current_user,'public.'||table_name,'INSERT') AS can_insert,has_table_privilege(current_user,'public.'||table_name,'UPDATE') AS can_update,
    has_table_privilege(current_user,'public.'||table_name,'DELETE') AS can_delete,has_table_privilege(current_user,'public.'||table_name,'TRUNCATE') AS can_truncate
    FROM unnest(ARRAY[${tables.map((t)=>`'${t}'`).join(',')}]) AS table_name`));
  const row=session[0];if(session.length!==1||row!.current_user!=='bef_observer'||row!.session_user!=='bef_observer'||row!.transaction_read_only!=='on'||
   row!.transaction_isolation!=='repeatable read'||row!.rolsuper!==false||row!.rolbypassrls!==false||row!.schema_create!==false||grants.length!==tables.length||
   grants.some((g)=>g.can_select!==true||g.can_insert!==false||g.can_update!==false||g.can_delete!==false||g.can_truncate!==false))fail('observer_role_invalid');
 return {currentUser:'bef_observer',sessionUser:'bef_observer',databaseName:row!.database_name,transactionReadOnly:'on',transactionIsolation:'repeatable read',superuser:false,bypassRls:false};
}
function normalizeAction(value:unknown,kind:string):J|null{
 const parsed=parseJson(value);if(!isRecord(parsed)||parsed.kind!==kind)return null;
 const keys:Record<string,string[]>={approve:['kind','tokenAssetId','amountUnits','gasLimit'],transfer:['kind','amountUnits','recipient','gasLimit'],
  wrap:['kind','amountWei','gasLimit'],unwrap:['kind','amountWei','gasLimit'],swap:['kind','inputAssetId','outputAssetId','feeTier','amountInUnits','amountOutMinimumUnits','recipient','gasLimit']};
 if(!keys[kind]||!exactKeys(parsed,keys[kind]!))return null;
 if(kind==='approve'&&(!['USDC','WETH'].includes(String(parsed.tokenAssetId))||!UINT.test(String(parsed.amountUnits))))return null;
 if(kind==='transfer'&&(!UINT.test(String(parsed.amountUnits))||!addr(parsed.recipient)))return null;
 if((kind==='wrap'||kind==='unwrap')&&!UINT.test(String(parsed.amountWei)))return null;
 if(kind==='swap'&&(!['USDC','WETH'].includes(String(parsed.inputAssetId))||!['USDC','WETH'].includes(String(parsed.outputAssetId))||
  parsed.inputAssetId===parsed.outputAssetId||![500,3000].includes(Number(parsed.feeTier))||!addr(parsed.recipient)||!UINT.test(String(parsed.amountInUnits))||
  !UINT.test(String(parsed.amountOutMinimumUnits))))return null;
 if(!UINT.test(String(parsed.gasLimit)))return null;
 if('recipient' in parsed)parsed.recipient=addr(parsed.recipient);
 return parsed;
}
function eventPayload(row:J,execution:J,operation:J):J|null{
 const raw=parseJson(row.event_json),kind=row.event_kind;if(!isRecord(raw)||hasSecret(raw))return null;
 if(kind==='selected_action_bound'){
  if(!exactKeys(raw,['actionKind','requestSha256','selectedAction'])||raw.actionKind!==execution.actionKind||raw.requestSha256!==operation.requestSha256||!same(raw.selectedAction,execution.selectedAction))return null;
  return {actionKind:raw.actionKind,requestSha256:String(raw.requestSha256).toLowerCase(),selectedAction:execution.selectedAction};
 }
 if(kind==='prestate_observed'){
  if(!isRecord(raw.prestate)||Object.keys(raw).some((k)=>!['prestate','idempotentReplay'].includes(k))||(raw.idempotentReplay!==undefined&&raw.idempotentReplay!==true))return null;
  return {prestate:raw.prestate,...(raw.idempotentReplay===true?{idempotentReplay:true}:{})};
 }
 if(kind==='original_tx_hash_bound'){
  if(!exactKeys(raw,['requestSha256','transactionHash','transactionIntent'])||raw.requestSha256!==operation.requestSha256||
   txHash(raw.transactionHash)!==operation.transactionHash||!same(raw.transactionIntent,execution.transactionIntent))return null;
  return {requestSha256:String(raw.requestSha256).toLowerCase(),transactionHash:txHash(raw.transactionHash),transactionIntent:execution.transactionIntent};
 }
 if(kind==='receipt_finalized'){
  if(!exactKeys(raw,['measurement','outcome'])||raw.outcome!==execution.outcome||!isRecord(raw.measurement)||
   sha256CanonicalTaskJson(raw.measurement).toLowerCase()!==String((execution.measurement as J).measurementSha256))return null;
  return {outcome:raw.outcome,measurementSha256:String((execution.measurement as J).measurementSha256)};
 }
 return null;
}
async function captureCensus(port:BefChainReadOnlyPostgresPort,envId:string,generationId:string):Promise<{session:J;census:Census}>{
 if(port.environmentId!==envId)fail('source_not_configured');
 try{return await port.withRepeatableRead(async(query)=>{
  const session=await validateObserverSession(query);
  const g=dbRows<J>(await query(`SELECT g.generation_id::text,g.env_id,g.participant_id,g.payer_address,trim(g.manifest_sha256) AS manifest_sha256,g.status,
    e.chain_id::text,trim(e.manifest_sha256) AS environment_manifest_sha256 FROM public.bef_generation g JOIN public.bef_environment e ON e.env_id=g.env_id
    WHERE g.env_id=$1 AND g.generation_id=$2::uuid`,[envId,generationId]));
  const rawOps=dbRows<J>(await query(`SELECT operation_id::text,env_id,generation_id::text,participant_id,trim(idempotency_key_sha256) AS idempotency_key_sha256,
    trim(request_sha256) AS request_sha256,operation_kind,status,receipt_status,transaction_hash,trim(response_sha256) AS response_sha256,started_at::text,completed_at::text
    FROM public.bef_operation WHERE env_id=$1 AND generation_id=$2::uuid ORDER BY started_at,operation_id LIMIT ${MAX_ROWS+1}`,[envId,generationId]));
  const rawSelected=dbRows<J>(await query(`SELECT operation_id::text,env_id,generation_id::text,action_kind,selected_action_json,prestate_json,
    transaction_intent_json,measurement_json,transaction_hash,outcome,reason_code,completed_at::text FROM public.bef_selected_execution
    WHERE env_id=$1 AND generation_id=$2::uuid ORDER BY created_at,operation_id LIMIT ${MAX_ROWS+1}`,[envId,generationId]));
  const rawEvents=dbRows<J>(await query(`SELECT event_sequence::text,event_id::text,operation_id::text,env_id,generation_id::text,event_kind,
    transaction_hash,event_json,created_at::text FROM public.bef_selected_execution_event WHERE env_id=$1 AND generation_id=$2::uuid
    ORDER BY event_sequence LIMIT ${MAX_ROWS+1}`,[envId,generationId]));
  const rawCosts=dbRows<J>(await query(`SELECT operation_id::text,env_id,generation_id::text,transaction_hash,payer_address,payer_role,receipt_status,
    transaction_from,receipt_from,receipt_block_number::text,receipt_block_hash,receipt_block_parent_hash,gas_used::text,effective_gas_price_wei::text,
    gas_cost_wei::text,modeled_gas_fee_usdc_units::text,manifest_sha256,selected_principal_asset,selected_principal_units::text,observed_principal_units::text
    FROM public.bef_transaction_cost WHERE env_id=$1 AND generation_id=$2::uuid ORDER BY transaction_hash LIMIT ${MAX_ROWS+1}`,[envId,generationId]));
  const ancillary=dbRows<J>(await query(`SELECT (SELECT count(*)::text FROM public.bef_payment WHERE env_id=$1 AND generation_id=$2::uuid) AS payments,
    (SELECT count(*)::text FROM public.bef_delivery d JOIN public.bef_operation o ON o.operation_id=d.operation_id WHERE o.env_id=$1 AND o.generation_id=$2::uuid) AS deliveries`,[envId,generationId]));
  const counts=dbRows<J>(await query(`SELECT (SELECT count(*)::text FROM public.bef_operation WHERE env_id=$1 AND generation_id=$2::uuid) AS operations,
    (SELECT count(*)::text FROM public.bef_selected_execution WHERE env_id=$1 AND generation_id=$2::uuid) AS selected_executions,
    (SELECT count(*)::text FROM public.bef_selected_execution_event WHERE env_id=$1 AND generation_id=$2::uuid) AS selected_events,
    (SELECT count(*)::text FROM public.bef_transaction_cost WHERE env_id=$1 AND generation_id=$2::uuid) AS costs`,[envId,generationId]));
  if(g.length!==1||ancillary.length!==1||counts.length!==1||[rawOps,rawSelected,rawEvents,rawCosts].some((x)=>x.length>MAX_ROWS))fail('observer_census_unavailable');
  const count=counts[0]!;if(String(count.operations)!==String(rawOps.length)||String(count.selected_executions)!==String(rawSelected.length)||
   String(count.selected_events)!==String(rawEvents.length)||String(count.costs)!==String(rawCosts.length))fail('observer_census_unavailable');
  const chainRows=rawOps.filter((row)=>CHAIN_KINDS.has(String(row.operation_kind)));
  const chainIds=new Set(chainRows.map((row)=>String(row.operation_id).toLowerCase()));
  const paymentOperations=rawOps.filter((row)=>(row.operation_kind==='pay'||row.operation_kind==='purchase')&&row.transaction_hash!==null).map((row)=>({
   operationId:String(row.operation_id).toLowerCase(),status:String(row.status),receiptStatus:String(row.receipt_status),transactionHash:txHash(row.transaction_hash)}));
  const selectedRows=rawSelected.filter((row)=>chainIds.has(String(row.operation_id).toLowerCase()));
  const eventRows=rawEvents.filter((row)=>chainIds.has(String(row.operation_id).toLowerCase()));
  const costRows=rawCosts.filter((row)=>chainIds.has(String(row.operation_id).toLowerCase()));
  const operations=chainRows.map((r)=>({operationId:String(r.operation_id).toLowerCase(),environmentId:r.env_id,generationId:String(r.generation_id).toLowerCase(),
   participantId:r.participant_id,idempotencyKeySha256:r.idempotency_key_sha256===null?null:String(r.idempotency_key_sha256).toLowerCase(),
   requestSha256:String(r.request_sha256).toLowerCase(),actionKind:r.operation_kind,status:r.status,receiptStatus:r.receipt_status,
   transactionHash:r.transaction_hash===null?null:txHash(r.transaction_hash),responseSha256:r.response_sha256===null?null:String(r.response_sha256).toLowerCase(),
   startedAt:r.started_at,completedAt:r.completed_at}));
  const opById=new Map(operations.map((op)=>[String(op.operationId),op]));
  const selectedExecutions=selectedRows.map((r)=>{
   const opId=String(r.operation_id).toLowerCase(),op=opById.get(opId),selected=normalizeAction(r.selected_action_json,String(r.action_kind));
   const prestate=parseJson(r.prestate_json),intent=parseJson(r.transaction_intent_json),rawMeasurement=parseJson(r.measurement_json);
   if(!op||!selected||!isRecord(prestate)||!isRecord(intent)||!isRecord(rawMeasurement))fail('observer_census_unavailable');
   const outcome=r.outcome;if(outcome!=='success'&&outcome!=='reverted')fail('observer_census_unavailable');
   const sourceReceipt=isRecord(rawMeasurement.receipt)?rawMeasurement.receipt:null;
   const sourceReceiptTxHash=sourceReceipt?txHash(sourceReceipt.transactionHash):null;
   const sourceGasUsed=sourceReceipt&&typeof sourceReceipt.gasUsed==='string'&&UINT.test(sourceReceipt.gasUsed)?sourceReceipt.gasUsed:null;
   const sourceEffectiveGasPrice=sourceReceipt&&typeof sourceReceipt.effectiveGasPrice==='string'&&UINT.test(sourceReceipt.effectiveGasPrice)
    ?sourceReceipt.effectiveGasPrice:null;
   if(!sourceReceipt||sourceReceiptTxHash!==txHash(r.transaction_hash)||sourceReceipt.status!==outcome||sourceGasUsed===null||
      sourceEffectiveGasPrice===null)fail('observer_census_unavailable');
   const sourceGasCostWei=(BigInt(sourceGasUsed)*BigInt(sourceEffectiveGasPrice)).toString();
   return {operationId:opId,environmentId:r.env_id,generationId:String(r.generation_id).toLowerCase(),actionKind:r.action_kind,selectedAction:selected,
    prestate,transactionIntent:intent,measurement:{measurementSha256:sha256CanonicalTaskJson(rawMeasurement).toLowerCase(),
     receipt:{transactionHash:sourceReceiptTxHash,status:sourceReceipt.status,gasUsed:sourceGasUsed,
      effectiveGasPriceWei:sourceEffectiveGasPrice,gasCostWei:sourceGasCostWei}},
    transactionHash:txHash(r.transaction_hash),outcome,reasonCode:r.reason_code,completedAt:r.completed_at};
  });
  const selectedByOp=new Map(selectedExecutions.map((r)=>[String(r.operationId),r]));
  const eventKinds=eventRows.map((r)=>{
   const operation=opById.get(String(r.operation_id).toLowerCase()),execution=selectedByOp.get(String(r.operation_id).toLowerCase());
   if(!operation||!execution||!UUID.test(String(r.event_id))||!UINT.test(String(r.event_sequence)))fail('observer_census_unavailable');
   const rawEvent=parseJson(r.event_json),payload=eventPayload(r,execution,operation);if(!payload||!isRecord(rawEvent))return fail('observer_census_unavailable');
   return {eventId:String(r.event_id).toLowerCase(),eventSequence:String(r.event_sequence),operationId:String(r.operation_id).toLowerCase(),
    eventKind:r.event_kind,eventJsonSha256:sha(canonicalTaskJson(rawEvent)).toLowerCase(),
    transactionHash:r.transaction_hash===null?null:txHash(r.transaction_hash),eventPayload:payload};
  });
  const costs=costRows.map((r)=>({operationId:String(r.operation_id).toLowerCase(),environmentId:r.env_id,generationId:String(r.generation_id).toLowerCase(),
   transactionHash:txHash(r.transaction_hash),payerAddress:addr(r.payer_address),payerRole:r.payer_role,receiptStatus:r.receipt_status,
   transactionFrom:addr(r.transaction_from),receiptFrom:addr(r.receipt_from),receiptBlockNumber:String(r.receipt_block_number),receiptBlockHash:txHash(r.receipt_block_hash),
   receiptBlockParentHash:txHash(r.receipt_block_parent_hash),gasUsed:String(r.gas_used),effectiveGasPriceWei:String(r.effective_gas_price_wei),gasCostWei:String(r.gas_cost_wei),
   modeledGasFeeUsdcUnits:String(r.modeled_gas_fee_usdc_units),manifestSha256:String(r.manifest_sha256).toLowerCase(),selectedPrincipalAsset:r.selected_principal_asset,
   selectedPrincipalUnits:r.selected_principal_units===null?null:String(r.selected_principal_units),observedPrincipalUnits:r.observed_principal_units===null?null:String(r.observed_principal_units)}));
  const census:Census={generation:{generation_id:String(g[0]!.generation_id).toLowerCase(),env_id:g[0]!.env_id,participant_id:g[0]!.participant_id,
   payer_address:addr(g[0]!.payer_address),manifest_sha256:String(g[0]!.manifest_sha256).toLowerCase(),status:g[0]!.status,chain_id:String(g[0]!.chain_id),
   environment_manifest_sha256:String(g[0]!.environment_manifest_sha256).toLowerCase()},operations,externalPaymentOperations:paymentOperations,
    selectedExecutions,selectedEvents:eventKinds,costs,paymentsCount:String(ancillary[0]!.payments),deliveriesCount:String(ancillary[0]!.deliveries),
    counts:{operations:String(operations.length),externalPaymentOperations:String(paymentOperations.length),selectedExecutions:String(selectedExecutions.length),
     selectedEvents:String(eventKinds.length),costs:String(costs.length)}};
  if(hasSecret(census)||Buffer.byteLength(canonicalTaskJson(census),'utf8')>MAX_PACKET_BYTES)fail('observer_census_unavailable');
  return {session,census};
 });}catch(error){if(error instanceof Unavailable)throw error;fail('observer_census_unavailable')}
}

function selectedMatchesCommand(selected:J,command:TaskActionCommand):boolean{
 if(selected.kind!==command.kind)return false;
 if(command.kind==='approve')return selected.tokenAssetId===(command.tokenAssetId??'WETH')&&selected.amountUnits===command.amountUnits&&selected.gasLimit===command.gasLimit;
 if(command.kind==='transfer')return selected.amountUnits===command.amountUnits&&String(selected.recipient).toLowerCase()===command.recipient.toLowerCase()&&selected.gasLimit===command.gasLimit;
 if(command.kind==='wrap'||command.kind==='unwrap')return selected.amountWei===command.amountWei&&selected.gasLimit===command.gasLimit;
 if(command.kind==='swap')return selected.inputAssetId===command.inputAssetId&&selected.outputAssetId===command.outputAssetId&&
  Number(selected.feeTier)===Number(command.feeTier??500)&&selected.amountInUnits===command.amountInUnits&&
  selected.amountOutMinimumUnits===command.amountOutMinimumUnits&&String(selected.recipient).toLowerCase()===command.recipient.toLowerCase()&&selected.gasLimit===command.gasLimit;
 return false;
}
function permittedRoutesFor(taskCase:ChainTaskCase){return taskCase.taskId==='H2'?taskCase.objective.permittedConversions:taskCase.objective.permittedRoutes;}
function selectionFromCommand(command:TaskActionCommand):J{
 if(command.kind==='approve')return {kind:command.kind,tokenAssetId:command.tokenAssetId??'WETH',amountUnits:command.amountUnits,gasLimit:command.gasLimit};
 if(command.kind==='transfer')return {kind:command.kind,amountUnits:command.amountUnits,recipient:command.recipient.toLowerCase(),gasLimit:command.gasLimit};
 if(command.kind==='wrap'||command.kind==='unwrap')return {kind:command.kind,amountWei:command.amountWei,gasLimit:command.gasLimit};
 if(command.kind==='swap')return {kind:command.kind,inputAssetId:command.inputAssetId,outputAssetId:command.outputAssetId,feeTier:command.feeTier??500,
  amountInUnits:command.amountInUnits,amountOutMinimumUnits:command.amountOutMinimumUnits,recipient:command.recipient.toLowerCase(),gasLimit:command.gasLimit};
 return {};
}
export function sameActionEnvelope(raw:J,selected:J,command:TaskActionCommand,taskCase:ChainTaskCase,assets:Array<{assetId:string;address:string|null}>,contracts:Array<{contractId:string;address:string;codeHash:string}>):boolean{
 if(!selectedMatchesCommand(selected,command)||raw.kind!==command.kind)return false;
 if(command.kind==='approve'){
  const token=assets.find((a)=>a.assetId===(command.tokenAssetId??'WETH'))?.address;
   const allowed=permittedRoutesFor(taskCase).map((r)=>contracts.find((c)=>c.contractId===r.routerContractId)?.address);
   if(taskCase.taskId==='U1')allowed.push(...taskCase.objective.temporarySpenderScope.filter((scope)=>scope.owner==='participant'&&
    scope.tokenAssetId===(command.tokenAssetId??'WETH')).map((scope)=>scope.spender));
  return exactKeys(raw,['kind','tokenAssetId','token','spender','amountUnits','gasLimit'])&&raw.tokenAssetId===(command.tokenAssetId??'WETH')&&
   addr(raw.token)===token?.toLowerCase()&&allowed.some((value)=>addr(value)===addr(raw.spender))&&raw.amountUnits===command.amountUnits&&raw.gasLimit===command.gasLimit;
 }
 if(command.kind==='transfer'){
  return exactKeys(raw,['kind','token','amountUnits','recipient','gasLimit'])&&addr(raw.token)===assets.find((a)=>a.assetId==='USDC')?.address?.toLowerCase()&&
   raw.amountUnits===command.amountUnits&&addr(raw.recipient)===command.recipient.toLowerCase()&&raw.gasLimit===command.gasLimit;
 }
 if(command.kind==='wrap'||command.kind==='unwrap')return exactKeys(raw,['kind','amountWei','gasLimit'])&&raw.amountWei===command.amountWei&&raw.gasLimit===command.gasLimit;
 if(command.kind!=='swap')return false;
  const route=permittedRoutesFor(taskCase).find((r)=>r.tokenInAssetId===command.inputAssetId&&
   r.tokenOutAssetId===command.outputAssetId&&r.feeTier===(command.feeTier??500));
 if(!route)return false;
 const router=contracts.find((c)=>c.contractId===route.routerContractId)?.address,pool=contracts.find((c)=>c.contractId===route.poolContractId)?.address;
 const tokenIn=assets.find((a)=>a.assetId===route.tokenInAssetId)?.address,tokenOut=assets.find((a)=>a.assetId===route.tokenOutAssetId)?.address;
 const legacy=route.feeTier===500&&command.inputAssetId==='WETH'&&command.outputAssetId==='USDC';
 const keys=legacy?['kind','route','router','tokenIn','tokenOut','fee','amountInWei','amountOutMinimumUsdcUnits','recipient','gasLimit']:
  route.feeTier===3000?['kind','route','router','inputAssetId','outputAssetId','tokenIn','tokenOut','fee','poolAddress','poolCodeHash','amountInUnits','amountOutMinimumUnits','recipient','gasLimit']:
   ['kind','route','router','inputAssetId','outputAssetId','tokenIn','tokenOut','fee','amountInUnits','amountOutMinimumUnits','recipient','gasLimit'];
 const rawAmount=legacy?raw.amountInWei:raw.amountInUnits,rawMinimum=legacy?raw.amountOutMinimumUsdcUnits:raw.amountOutMinimumUnits;
 return raw.route==='uniswap-v3-exactInputSingle'&&addr(raw.router)===router?.toLowerCase()&&
  exactKeys(raw,keys)&&(!legacy?(raw.inputAssetId===command.inputAssetId&&raw.outputAssetId===command.outputAssetId):true)&&
  addr(raw.tokenIn)===tokenIn?.toLowerCase()&&addr(raw.tokenOut)===tokenOut?.toLowerCase()&&Number(raw.fee)===route.feeTier&&
  (route.feeTier!==3000||(addr(raw.poolAddress)===pool?.toLowerCase()&&matchesReleaseCodeHash(raw.poolCodeHash,contracts.find((c)=>c.contractId===route.poolContractId)?.codeHash)))&&
  rawAmount===command.amountInUnits&&rawMinimum===command.amountOutMinimumUnits&&addr(raw.recipient)===command.recipient.toLowerCase()&&raw.gasLimit===command.gasLimit;
}
async function loadActions(root:string,runId:string,index:number,run:J,prep:PreparationRow,cutoff:number,rowsIn:ActionRow[],taskCase:ChainTaskCase,
 assets:Array<{assetId:string;address:string|null}>,contracts:Array<{contractId:string;address:string;codeHash:string}>):Promise<LoadedActions>{
 if(cutoff>MAX_ACTIONS||rowsIn.length!==cutoff)fail('owner_cutoff_mismatch');const chain:Loaded[]=[],external:ChainCaptureExternalAction[]=[],ownerOps=new Set<string>();
 const allowed=['schema','actionId','runId','taskIndex','actionSequence','ownerOperationId','actionKind','commandSha256','environmentId','generationId','manifestSha256',
  'applicationSourceSha256','idempotencyKey','status','reasonCode','requestStartedAt','requestFinishedAt','httpStatus','recoverySource','befOperationId','transactionHash','outcome',
  'receiptStatus','rawResponseSha256','participantToolResponse','receiptGasUsed','receiptEffectiveGasPriceWei','paymentProtocol','environmentHealth'];
 for(let i=0;i<rowsIn.length;i++){
  const row=rowsIn[i]!,actionSequence=seq(row.action_sequence),ref=row.evidence_path&&row.evidence_hash?evidenceRef({path:row.evidence_path,sha256:row.evidence_hash,boundary:BOUNDARY},ACTION_ROOT):null;
  if(actionSequence!==i+1||!UUID.test(row.id)||row.id!==row.id.toLowerCase()||row.run_id!==runId||row.task_index!==index||row.owner_id!==run.owner_id||
   row.agent_id!==run.agent_id||row.task_id!==taskCase.taskId||row.environment_id!==prep.environment_id||!HASH.test(row.payload_hash)||!ref||
   row.receipt_revision!==row.history_revision||row.receipt_status!==row.history_status||row.history_evidence_hash!==row.evidence_hash||
   row.history_evidence_path!==row.evidence_path||(row.history_transaction_hash?.toLowerCase()??null)!==(row.transaction_hash?.toLowerCase()??null)||
   !['observed','rejected_before_execution'].includes(row.receipt_status)||ownerOps.has(String(row.operation_id)))fail('action_evidence_unavailable');
  ownerOps.add(String(row.operation_id));
  const parsed=TaskActionCommandSchema.safeParse(row.command_json);if(!parsed.success||parsed.data.kind!==row.action_kind||
   sha256CanonicalTaskJson({runId,taskIndex:index,command:parsed.data}).toLowerCase()!==row.payload_hash.toLowerCase())fail('action_evidence_unavailable');
  const chainAction=CHAIN_KINDS.has(parsed.data.kind);
  const externalAction=['inspect_catalog','inspect_offer','purchase','pay','retrieve'].includes(parsed.data.kind);
  if((chainAction&&row.receipt_status!=='observed')||(!chainAction&&(!externalAction||!['H3','U1'].includes(taskCase.taskId))))fail('action_evidence_unavailable');
  const bytes=await readEvidence(root,ref,ACTION_ROOT,'action_evidence_unavailable');let doc:unknown;
  try{doc=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes)) as unknown}catch{fail('action_evidence_unavailable')}
  const evidence=isRecord(doc)?doc:null,recoverySourceBacked=evidence?.recoverySource!==undefined;
  if(externalAction&&recoverySourceBacked)fail('action_evidence_unavailable');
  if(!isRecord(doc)||Object.keys(doc).some((key)=>!allowed.includes(key))||doc.schema!=='bef-task-action-observation-v1'||doc.actionId!==row.id||
   doc.runId!==runId||doc.taskIndex!==index||doc.actionSequence!==String(actionSequence)||doc.ownerOperationId!==row.operation_id||doc.actionKind!==row.action_kind||
   doc.commandSha256!==row.payload_hash.toLowerCase()||doc.environmentId!==prep.environment_id||doc.generationId!==prep.generation_id||
   doc.manifestSha256!==prep.environment_manifest_sha256.toLowerCase()||doc.applicationSourceSha256!==prep.application_source_hash.toLowerCase()||
   doc.idempotencyKey!==`task-action-${row.id}`||doc.status!==row.receipt_status||
   (row.receipt_status==='observed'&&(!isRecord(doc.participantToolResponse)||
    (recoverySourceBacked ? (!recoveredActionEvidenceIsOwnerBound(doc,row,{actionId:row.id,runId,ownerId:run.owner_id,
        agentId:run.agent_id,taskIndex:index,environmentId:prep.environment_id,operationId:row.operation_id,payloadHash:row.payload_hash,
        evidenceHash:row.evidence_hash??''})) : (doc.httpStatus!==200||!HASH.test(String(doc.rawResponseSha256))))))||
   (row.receipt_status==='rejected_before_execution'&&((doc.participantToolResponse!==undefined&&doc.participantToolResponse!==null)||
    (doc.transactionHash!==undefined&&doc.transactionHash!==null)||row.transaction_hash!==null)))
   fail('action_evidence_unavailable');
  const scrub=structuredClone(doc);if(isRecord(scrub.participantToolResponse)){delete scrub.participantToolResponse.content;delete scrub.participantToolResponse.contentBytes;}
  if(hasSecret(scrub))fail('action_evidence_unavailable');
  if(externalAction){
   const command=parsed.data;
   const response=isRecord(doc.participantToolResponse)?doc.participantToolResponse:null;
   const protocol=isRecord(doc.paymentProtocol)?doc.paymentProtocol:null;
   const befId=typeof doc.befOperationId==='string'&&UUID.test(doc.befOperationId)?doc.befOperationId.toLowerCase():null;
   const evidenceHash=txHash(doc.transactionHash),ownerHash=txHash(row.transaction_hash);
   if(command.kind==='pay'&&row.receipt_status==='observed'){
    const payment=response&&isRecord(response.payment)?response.payment:null;
    if(!response||!protocol||!befId||protocol.schema!=='bef-x402-split-payment-observation-v1'||protocol.befOperationId!==befId||
     response.operationId!==befId||response.status!=='payment_confirmed'||response.deliveryHandle!==befId||
     !payment||txHash(payment.transactionHash)!==evidenceHash||!ownerHash||ownerHash!==evidenceHash)fail('action_evidence_unavailable');
   }else if(command.kind==='pay'&&(ownerHash!==null||evidenceHash!==null))fail('action_evidence_unavailable');
   if(command.kind==='purchase'&&((ownerHash===null)!==(evidenceHash===null)||
    (ownerHash!==null&&(ownerHash!==evidenceHash||!befId))))fail('action_evidence_unavailable');
   if(!['pay','purchase'].includes(command.kind)&&(ownerHash!==null||evidenceHash!==null))fail('action_evidence_unavailable');
   if(row.receipt_status==='observed'&&(['inspect_catalog','inspect_offer'].includes(command.kind)&&(!response||protocol!==null)))fail('action_evidence_unavailable');
   external.push({actionId:row.id,actionSequence,ownerOperationId:String(row.operation_id),actionKind:command.kind as ChainCaptureExternalAction['actionKind'],
    commandSha256:row.payload_hash.toLowerCase(),receiptStatus:row.receipt_status as ChainCaptureExternalAction['receiptStatus'],actionEvidence:ref,
    befOperationId:befId,transactionHash:ownerHash});
   continue;
  }
  if(!isRecord(doc.participantToolResponse)||!isRecord(doc.participantToolResponse.selectedAction)||!isRecord(doc.participantToolResponse.transaction)||
   !isRecord(doc.participantToolResponse.receipt)||!UUID.test(String(doc.befOperationId))||!TX.test(String(doc.transactionHash))||
   (doc.outcome!=='success'&&doc.outcome!=='reverted')||doc.receiptStatus!==doc.outcome||(!recoverySourceBacked&&doc.httpStatus!==200))fail('action_evidence_unavailable');
  const command=parsed.data as Loaded['command'],selected=selectionFromCommand(command);
  if(!sameActionEnvelope(doc.participantToolResponse.selectedAction as J,selected,command,taskCase,assets,contracts))fail('action_evidence_unavailable');
  const response=doc.participantToolResponse as J,transaction=response.transaction as J,receipt=response.receipt as J;
  if(response.operationId!==doc.befOperationId||response.outcome!==doc.outcome||txHash(transaction.hash)!==txHash(doc.transactionHash)||
   txHash(receipt.transactionHash)!==txHash(doc.transactionHash)||receipt.status!==doc.receiptStatus||String(receipt.gasUsed)!==String(doc.receiptGasUsed)||
   String(receipt.effectiveGasPrice)!==String(doc.receiptEffectiveGasPriceWei))fail('action_evidence_unavailable');
  const ownerHash=txHash(row.transaction_hash),evidenceHash=txHash(doc.transactionHash);if(!ownerHash||ownerHash!==evidenceHash)fail('action_evidence_unavailable');
  const approvalSpender=command.kind==='approve'?addr(doc.participantToolResponse.selectedAction.spender):null;
  if(command.kind==='approve'&&!approvalSpender)fail('action_evidence_unavailable');
  chain.push({row,sequence:actionSequence,command,evidence:ref,recoveryEvidence:doc as unknown as RecoveryActionEvidence,befOperationId:String(doc.befOperationId).toLowerCase(),transactionHash:ownerHash,
   outcome:doc.outcome as 'success'|'reverted',selectedAction:selected,approvalSpender});
 }
 return {chain,external};
}

class RpcRecorder{
 readonly responseHashes:Array<{method:string;paramsSha256:string;resultSha256:string}>=[];
 constructor(private readonly port:BefChainReadOnlyRpcPort){}
 async request(method:string,params:readonly unknown[]):Promise<unknown>{
  if(!['eth_chainId','eth_blockNumber','eth_getBlockByNumber','eth_getBalance','eth_call','eth_getCode','eth_getTransactionCount','eth_getTransactionByHash','eth_getTransactionReceipt'].includes(method))fail('rpc_observation_unavailable');
  let result:unknown;try{result=await this.port.request(method,params)}catch{fail('rpc_observation_unavailable')}
  if(Buffer.byteLength(canonicalTaskJson(result),'utf8')>MAX_RPC_BYTES||hasSecret(result))fail('rpc_observation_unavailable');
  this.responseHashes.push({method,paramsSha256:sha256CanonicalTaskJson(params).toLowerCase(),resultSha256:sha256CanonicalTaskJson(result).toLowerCase()});return result;
 }
}
function header(value:unknown,expected?:bigint):{number:bigint;hash:string;parentHash:string}{
 if(!isRecord(value))fail('rpc_observation_unavailable');const number=quantity(value.number),hash=txHash(value.hash),parentHash=txHash(value.parentHash);
 if(number===null||!hash||!parentHash||(expected!==undefined&&number!==expected))fail('rpc_observation_unavailable');return {number,hash,parentHash};
}
function normalizeRpcTransaction(value:unknown):J|null{
 if(!isRecord(value))return null;const hash=txHash(value.hash),from=addr(value.from),to=value.to===null?null:addr(value.to),nonce=quantity(value.nonce),gas=quantity(value.gas),
  valueWei=quantity(value.value),blockNumber=quantity(value.blockNumber),blockHash=txHash(value.blockHash),txIndex=quantity(value.transactionIndex),chainId=quantity(value.chainId);
 const input=typeof value.input==='string'&&/^0x(?:[0-9a-f]{2})*$/i.test(value.input)?value.input.toLowerCase():null;
 if(!hash||!from||(value.to!==null&&!to)||nonce===null||gas===null||valueWei===null||blockNumber===null||!blockHash||txIndex===null||chainId===null||!input)return null;
 return {hash,from,to,nonce:nonce.toString(),input,valueWei:valueWei.toString(),gasLimit:gas.toString(),blockNumber:blockNumber.toString(),blockHash,
  transactionIndex:txIndex.toString(),chainId:chainId.toString()};
}
function normalizeLog(value:unknown,receipt:J):ChainJson|null{
 if(!isRecord(value)||!Array.isArray(value.topics))return null;
 const addressValue=addr(value.address),block=quantity(value.blockNumber),txIndex=quantity(value.transactionIndex),logIndex=quantity(value.logIndex),
  blockHash=txHash(value.blockHash),transactionHash=txHash(value.transactionHash);
 if(!addressValue||block===null||txIndex===null||logIndex===null||!blockHash||!transactionHash||typeof value.data!=='string'||
  !/^0x(?:[0-9a-f]{2})*$/i.test(value.data)||value.removed!==false||value.blockNumber!==receipt.blockNumber||value.blockHash!==receipt.blockHash||
  value.transactionHash!==receipt.transactionHash||value.transactionIndex!==receipt.transactionIndex||value.blockHash!==receipt.blockHash||
  value.topics.some((x)=>typeof x!=='string'||!/^0x[0-9a-f]{64}$/i.test(x)))return null;
 return {address:addressValue,topics:value.topics.map((x)=>String(x).toLowerCase()),data:value.data.toLowerCase(),blockNumber:block.toString(),blockHash,
  transactionHash,transactionIndex:txIndex.toString(),logIndex:logIndex.toString(),removed:false,
  rpcBlockNumber:value.blockNumber,rpcTransactionIndex:value.transactionIndex,rpcLogIndex:value.logIndex};
}
function normalizeReceipt(value:unknown,transaction:J):{status:'success'|'reverted';gasUsed:string;effectiveGasPriceWei:string;gasCostWei:string;receiptLogsSha256:string;logs:ChainJson[]}|null{
 if(!isRecord(value)||!Array.isArray(value.logs))return null;
 const hash=txHash(value.transactionHash),from=addr(value.from),to=value.to===null?null:addr(value.to),block=quantity(value.blockNumber),blockHash=txHash(value.blockHash),index=quantity(value.transactionIndex),
  gas=quantity(value.gasUsed),price=quantity(value.effectiveGasPrice);
 if(!hash||hash!==transaction.hash||!from||from!==transaction.from||(value.to!==null&&!to)||to!==transaction.to||block===null||block.toString()!==transaction.blockNumber||
  !blockHash||blockHash!==transaction.blockHash||index===null||index.toString()!==transaction.transactionIndex||gas===null||price===null||
  (value.status!=='0x1'&&value.status!=='0x0'))return null;
 const logs=value.logs.map((entry)=>normalizeLog(entry,value));if(logs.some((item)=>!item))return null;
 return {status:value.status==='0x1'?'success':'reverted',gasUsed:gas.toString(),effectiveGasPriceWei:price.toString(),gasCostWei:(gas*price).toString(),
  receiptLogsSha256:sha256CanonicalTaskJson(value.logs).toLowerCase(),logs:logs as ChainJson[]};
}
function codeWord(address:string):string{return address.slice(2).toLowerCase().padStart(64,'0')}
function callData(selector:string,...addresses:string[]):string{return selector+addresses.map(codeWord).join('')}
function parseWord(value:unknown):bigint|null{return typeof value==='string'&&/^0x[0-9a-f]{64}$/i.test(value)?BigInt(value):null}
export function matchesReleaseCodeHash(observed:unknown,expected:unknown):boolean{
 const normalize=(value:unknown):string|null=>typeof value==='string'&&/^(?:0x)?[0-9a-f]{64}$/i.test(value)?value.replace(/^0x/i,'').toLowerCase():null;
 const observedHash=normalize(observed),expectedHash=normalize(expected);
 return observedHash!==null&&expectedHash!==null&&observedHash===expectedHash;
}
function account(value:string,participant:string):{label:string;address:string}{const address=value==='participant'?participant:addr(value)??'';if(!address)fail('release_binding_mismatch');return {label:value==='participant'?'participant':address,address}}
// AICODE-NOTE: Release-pinned code hashes are naked 32-byte hex, so strip Keccak's 0x prefix before identity comparison.
export function observedRuntimeCodeHash(code:string):string{return keccak256(code as `0x${string}`).slice(2).toLowerCase()}
async function verifyCode(rpc:RpcRecorder,identity:{assets:Array<{kind:string;address:string|null;codeHash:string|null}>;contracts:Array<{address:string;codeHash:string}>},
 baseline:bigint,final:bigint):Promise<Array<{address:string;expectedCodeHash:string;observedCodeHash:string}>>{
 const expected=new Map<string,string>();for(const asset of identity.assets)if(asset.address&&asset.codeHash)expected.set(asset.address.toLowerCase(),asset.codeHash.toLowerCase());
 for(const contract of identity.contracts)expected.set(contract.address.toLowerCase(),contract.codeHash.toLowerCase());
 const hashes:Array<{address:string;expectedCodeHash:string;observedCodeHash:string}>=[];
 for(const [address,codeHash] of expected){for(const block of [baseline,final]){
   const code=await rpc.request('eth_getCode',[address,`0x${block.toString(16)}`]);if(typeof code!=='string'||!/^0x(?:[0-9a-f]{2})+$/i.test(code))fail('rpc_identity_mismatch');
   const observed=observedRuntimeCodeHash(code);if(observed!==codeHash)fail('rpc_identity_mismatch');
   if(block===baseline)hashes.push({address,expectedCodeHash:codeHash,observedCodeHash:observed});
  }}
 return hashes;
}
async function readCheckpoint(rpc:RpcRecorder,block:bigint,identity:{assets:Array<{assetId:string;kind:string;address:string|null}>;contracts:Array<{contractId:string;address:string}>},
 participant:string,taskCase:ChainTaskCase):Promise<Checkpoint>{
 const headerValue=header(await rpc.request('eth_getBlockByNumber',[`0x${block.toString(16)}`,false]),block);
 const balances=new Map<string,{account:string;assetId:string;amountUnits:string}>();
 const assets=new Map(identity.assets.map((asset)=>[asset.assetId,asset]));
 const balanceSeeds=[...taskCase.initialState.balances];
 for(const asset of identity.assets)if(asset.kind==='native'&&!balanceSeeds.some((row)=>row.account==='participant'&&row.assetId===asset.assetId))balanceSeeds.push({account:'participant',assetId:asset.assetId,amountUnits:'0'} as typeof balanceSeeds[number]);
 for(const seed of balanceSeeds){const asset=assets.get(seed.assetId);if(!asset)fail('release_binding_mismatch');const who=account(seed.account,participant);
  let amount:bigint|null;if(asset.kind==='native')amount=quantity(await rpc.request('eth_getBalance',[who.address,`0x${block.toString(16)}`]));
  else{if(!asset.address)fail('release_binding_mismatch');amount=parseWord(await rpc.request('eth_call',[{to:asset.address,data:callData('0x70a08231',who.address)},`0x${block.toString(16)}`]));}
  if(amount===null)fail('rpc_observation_unavailable');const key=`${who.label}|${seed.assetId}`;if(balances.has(key))fail('release_binding_mismatch');
  balances.set(key,{account:who.label,assetId:seed.assetId,amountUnits:amount.toString()});
 }
  const allowanceSeeds=[...taskCase.initialState.allowances];
  if(taskCase.taskId==='U1')for(const scope of taskCase.objective.temporarySpenderScope){
   if(scope.owner==='participant'&&!allowanceSeeds.some((a)=>a.owner===scope.owner&&a.tokenAssetId===scope.tokenAssetId&&a.spender.toLowerCase()===scope.spender.toLowerCase()))
    allowanceSeeds.push({owner:scope.owner,tokenAssetId:scope.tokenAssetId,spender:scope.spender,amountUnits:'0'} as typeof allowanceSeeds[number]);
  }
  const routes=permittedRoutesFor(taskCase);
 for(const route of routes){const spender=identity.contracts.find((x)=>x.contractId===route.routerContractId)?.address;
  if(!spender)fail('release_binding_mismatch');if(!allowanceSeeds.some((a)=>a.owner==='participant'&&a.tokenAssetId===route.tokenInAssetId&&a.spender.toLowerCase()===spender.toLowerCase()))
   allowanceSeeds.push({owner:'participant',tokenAssetId:route.tokenInAssetId,spender,amountUnits:'0'} as typeof allowanceSeeds[number]);}
 const allowances=new Map<string,{owner:string;tokenAssetId:string;spender:string;amountUnits:string}>();
 for(const seed of allowanceSeeds){const asset=assets.get(seed.tokenAssetId);if(!asset?.address)fail('release_binding_mismatch');const who=account(seed.owner,participant),spender=addr(seed.spender);if(!spender)fail('release_binding_mismatch');
  const data=await rpc.request('eth_call',[{to:asset.address,data:callData('0xdd62ed3e',who.address,spender)},`0x${block.toString(16)}`]);const amount=parseWord(data);
  if(amount===null)fail('rpc_observation_unavailable');const key=`${who.label}|${seed.tokenAssetId}|${spender}`;if(allowances.has(key))fail('release_binding_mismatch');
  allowances.set(key,{owner:who.label,tokenAssetId:seed.tokenAssetId,spender,amountUnits:amount.toString()});
 }
 const nonce=quantity(await rpc.request('eth_getTransactionCount',[participant,`0x${block.toString(16)}`]));if(nonce===null)fail('rpc_observation_unavailable');
 return {blockNumber:block.toString(),blockHash:headerValue.hash,parentHash:headerValue.parentHash,balances:[...balances.values()],allowances:[...allowances.values()],participantTransactionCount:nonce.toString()};
}

function routeIdentities(taskCase:ChainTaskCase,assets:Array<{assetId:string;kind:'native'|'erc20';address:string|null;codeHash:string|null}>,
 contracts:Array<{contractId:string;address:string;codeHash:string}>):ChainCapturePacket['rpc']['routes']{
  const permitted=permittedRoutesFor(taskCase);
 return permitted.map((route)=>{
  const router=contracts.find((x)=>x.contractId===route.routerContractId),pool=contracts.find((x)=>x.contractId===route.poolContractId);
  const tokenIn=assets.find((x)=>x.assetId===route.tokenInAssetId),tokenOut=assets.find((x)=>x.assetId===route.tokenOutAssetId);
  if(!router||!pool||!tokenIn?.address||!tokenOut?.address)fail('release_binding_mismatch');
  return {routeId:route.routeId,tokenInAssetId:route.tokenInAssetId,tokenOutAssetId:route.tokenOutAssetId,router:router.address.toLowerCase(),pool:pool.address.toLowerCase(),
   tokenIn:tokenIn.address.toLowerCase(),tokenOut:tokenOut.address.toLowerCase(),feeTier:route.feeTier};
 });
}
function encodeWord(value:bigint):string{return value.toString(16).padStart(64,'0')}
function encodeAddress(value:string):string{return value.slice(2).toLowerCase().padStart(64,'0')}
function actionRoute(taskCase:ChainTaskCase,command:Extract<TaskActionCommand,{kind:'swap'}>,routes:ChainCapturePacket['rpc']['routes']){
 return routes.find((route)=>route.tokenInAssetId===command.inputAssetId&&route.tokenOutAssetId===command.outputAssetId&&route.feeTier===(command.feeTier??500));
}
function transactionMatchesCommand(tx:CapturedTx,command:Loaded['command'],taskCase:ChainTaskCase,routes:ChainCapturePacket['rpc']['routes'],
 assets:ChainCapturePacket['rpc']['assets'],approvalSpender:string|null):boolean{
 if(tx.from!==tx.from.toLowerCase()||tx.gasLimit!==command.gasLimit)return false;
 if(command.kind==='approve'){
  const assetId=command.tokenAssetId??'WETH',asset=assets.find((a)=>a.assetId===assetId);const route=routes.find((r)=>r.tokenInAssetId===assetId);
   const spender=addr(approvalSpender)??route?.router,amount=dec(command.amountUnits);if(!asset?.address||!spender||amount===null)return false;
   const routeAllowed=routes.some((candidate)=>candidate.tokenInAssetId===assetId&&candidate.router.toLowerCase()===spender.toLowerCase());
   const scopeAllowed=taskCase.taskId==='U1'&&taskCase.objective.temporarySpenderScope.some((scope)=>scope.owner==='participant'&&
    scope.tokenAssetId===assetId&&scope.spender.toLowerCase()===spender.toLowerCase());
   return (routeAllowed||scopeAllowed)&&tx.to===asset.address.toLowerCase()&&tx.valueWei==='0'&&
    tx.input===`0x095ea7b3${encodeAddress(spender)}${encodeWord(amount)}`;
 }
 if(command.kind==='transfer'){
  const asset=assets.find((a)=>a.assetId==='USDC'),amount=dec(command.amountUnits);if(!asset?.address||amount===null)return false;
  return tx.to===asset.address.toLowerCase()&&tx.valueWei==='0'&&tx.input===`0xa9059cbb${encodeAddress(command.recipient)}${encodeWord(amount)}`;
 }
 if(command.kind==='wrap'||command.kind==='unwrap'){
  const weth=assets.find((a)=>a.assetId==='WETH'),amount=dec(command.amountWei);if(!weth?.address||amount===null)return false;
  return tx.to===weth.address.toLowerCase()&&tx.input===(command.kind==='wrap'?'0xd0e30db0':`0x2e1a7d4d${encodeWord(amount)}`)&&
   tx.valueWei===(command.kind==='wrap'?amount.toString():'0');
 }
 if(command.kind==='swap'){
  const route=actionRoute(taskCase,command,routes),amount=dec(command.amountInUnits),minimum=dec(command.amountOutMinimumUnits);
  if(!route||amount===null||minimum===null)return false;
  const expected=`0x04e45aaf${encodeAddress(route.tokenIn)}${encodeAddress(route.tokenOut)}${encodeWord(BigInt(route.feeTier))}${encodeAddress(command.recipient)}${encodeWord(amount)}${encodeWord(minimum)}${encodeWord(0n)}`;
  return tx.to===route.router&&tx.valueWei==='0'&&tx.input===expected;
 }
 return false;
}
function normalizeCheckpointState(value:Checkpoint,expected:ChainTaskCase['initialState'],participant:string):boolean{
 const expectedBalances=expected.balances.map((x)=>({account:x.account==='participant'?'participant':addr(x.account),assetId:x.assetId,amountUnits:x.amountUnits}));
 const expectedAllowances=expected.allowances.map((x)=>({owner:x.owner==='participant'?'participant':addr(x.owner),tokenAssetId:x.tokenAssetId,spender:addr(x.spender),amountUnits:x.amountUnits}));
 for(const row of expectedBalances){const found=value.balances.find((x)=>x.account===row.account&&x.assetId===row.assetId);if(!found||found.amountUnits!==row.amountUnits)return false;}
 for(const row of expectedAllowances){const found=value.allowances.find((x)=>x.owner===row.owner&&x.tokenAssetId===row.tokenAssetId&&x.spender===row.spender);if(!found||found.amountUnits!==row.amountUnits)return false;}
 void participant;return true;
}
function eventWord(log:ChainJson,index:number):bigint|null{
 const data=log.data; if(typeof data!=='string'||!/^0x[0-9a-f]{64,}$/i.test(data))return null;const start=2+index*64;
 const part=data.slice(start,start+64);return part.length===64?BigInt('0x'+part):null;
}
function eventTopics(log:ChainJson):string[]{return Array.isArray(log.topics)?log.topics.map(String):[]}
function relevantLogs(transactions:CapturedTx[],assets:ChainCapturePacket['rpc']['assets']):{
 transferLogs:ChainJson[];approvalLogs:ChainJson[];swapLogs:ChainJson[];wethLogs:ChainJson[]}{
 const known=new Set(assets.filter((a)=>a.address).map((a)=>a.address!.toLowerCase()));const weth=assets.find((a)=>a.assetId==='WETH')?.address?.toLowerCase();
 const transferLogs:ChainJson[]=[],approvalLogs:ChainJson[]=[],swapLogs:ChainJson[]=[],wethLogs:ChainJson[]=[];
 for(const tx of transactions)for(const raw of tx.logs){const topic=eventTopics(raw)[0]?.toLowerCase(),address=String(raw.address).toLowerCase();
  if(topic===TRANSFER&&(known.has(address)||eventTopics(raw).slice(1).some((x)=>x.toLowerCase().endsWith(tx.from.slice(2)))))transferLogs.push(raw);
  if(topic===APPROVAL&&known.has(address))approvalLogs.push(raw);
  if(topic===SWAP)swapLogs.push(raw);
  if(topic===DEPOSIT||topic===WITHDRAWAL){if(address===weth)wethLogs.push(raw);else wethLogs.push(raw);}
 }
 const order=(a:ChainJson,b:ChainJson)=>BigInt(String(a.blockNumber))<BigInt(String(b.blockNumber))?-1:BigInt(String(a.blockNumber))>BigInt(String(b.blockNumber))?1:
  BigInt(String(a.transactionIndex))<BigInt(String(b.transactionIndex))?-1:BigInt(String(a.transactionIndex))>BigInt(String(b.transactionIndex))?1:
  BigInt(String(a.logIndex))<BigInt(String(b.logIndex))?-1:BigInt(String(a.logIndex))>BigInt(String(b.logIndex))?1:0;
 return {transferLogs:transferLogs.sort(order),approvalLogs:approvalLogs.sort(order),swapLogs:swapLogs.sort(order),wethLogs:wethLogs.sort(order)};
}

async function collectLocked(deps:BefChainObservationCollectorDependencies,target:{runId:string;taskIndex:number},tx:OwnerTx):Promise<BefChainObservationCollectionResult>{
 const owners=await ownerRows<J>(tx,sql`SELECT owner_id::text,agent_id::text FROM oid_benchmark_run WHERE id=${target.runId}`),owner=owners[0];
 if(!owner)return unavailable('owner_cutoff_unavailable');
 await tx.execute(sql`SELECT id FROM oid_owner WHERE id=${owner.owner_id} FOR NO KEY UPDATE`);
 await tx.execute(sql`SELECT id FROM oid_agent WHERE id=${owner.agent_id} AND owner_id=${owner.owner_id} FOR NO KEY UPDATE`);
 const runRows=await ownerRows<J>(tx,sql`SELECT r.owner_id::text,r.agent_id::text,r.mode,r.task_ids,r.release_identity,r.manifest_hash,t.task_id,t.closure_status,
   t.closure_id::text,t.closure_operation_id::text,t.closure_payload_hash,t.closure_reason,t.action_cutoff_sequence::text AS action_cutoff_sequence,
   t.reconciled_action_sequence::text AS reconciled_action_sequence FROM oid_benchmark_run r JOIN oid_run_task t ON t.run_id=r.id
   WHERE r.id=${target.runId} AND r.owner_id=${owner.owner_id} AND r.agent_id=${owner.agent_id} AND t.task_index=${target.taskIndex} FOR UPDATE OF r,t`);
 const run=runRows[0];if(!run||!['M3','M4','H2','H3','U1'].includes(String(run.task_id))||!Array.isArray(run.task_ids)||run.task_ids[target.taskIndex]!==run.task_id)
  return unavailable(run?'unsupported_task':'owner_cutoff_unavailable');
 if(run.closure_status!=='closed'||!run.closure_id||run.action_cutoff_sequence===null)return unavailable('owner_cutoff_unavailable');
 const cutoff=seq(run.action_cutoff_sequence as string|number),reconciled=seq(run.reconciled_action_sequence as string|number);
 if(cutoff===null||reconciled===null||reconciled<cutoff)return unavailable('reconciliation_pending');
 const closureRows=await ownerRows<J>(tx,sql`SELECT id::text,operation_id::text,payload_hash,reason,action_cutoff_sequence::text AS action_cutoff_sequence,owner_id::text,agent_id::text
   FROM oid_run_task_closure WHERE id=${run.closure_id} AND run_id=${target.runId} AND task_index=${target.taskIndex} FOR KEY SHARE`),closure=closureRows[0];
 if(!closure||closure.owner_id!==run.owner_id||closure.agent_id!==run.agent_id||seq(closure.action_cutoff_sequence as string|number)!==cutoff||
  closure.operation_id!==run.closure_operation_id||closure.payload_hash!==run.closure_payload_hash||closure.reason!==run.closure_reason||
  !['agent_finish','task_deadline','run_deadline'].includes(String(closure.reason)))return unavailable('owner_cutoff_mismatch');
 const prepRows=await ownerRows<PreparationRow>(tx,sql`SELECT i.preparation_id::text,i.claim_id::text,i.lease_id::text,i.environment_id,i.release_identity,i.manifest_hash,
  i.task_id,i.case_id,i.case_hash,i.initial_state_sha256,i.execution_identity_hash,i.environment_manifest_sha256,i.application_source_hash,i.created_at,
  l.state AS lease_state,o.status AS observation_status,o.generation_id::text,o.participant_id,o.payer_address,o.baseline_state_sha256,o.fixture_evidence,o.baseline_evidence
  FROM oid_task_preparation_intent i JOIN oid_task_environment_lease l ON l.preparation_id=i.preparation_id AND l.lease_id=i.lease_id
  JOIN LATERAL(SELECT status,generation_id,participant_id,payer_address,baseline_state_sha256,fixture_evidence,baseline_evidence FROM oid_task_preparation_observation
   WHERE preparation_id=i.preparation_id ORDER BY revision DESC LIMIT 1) o ON true
  WHERE i.run_id=${target.runId} AND i.task_index=${target.taskIndex} FOR UPDATE OF i,l`),prep=prepRows[0];
 if(!prep||prep.lease_state!=='leased'||prep.observation_status!=='ready'||!prep.generation_id||!prep.participant_id||!addr(prep.payer_address)||
  prep.task_id!==run.task_id||prep.release_identity!==run.release_identity||prep.manifest_hash!==run.manifest_hash||prep.baseline_state_sha256!==prep.initial_state_sha256)
  return unavailable('preparation_unavailable');
 const bindingRows=await ownerRows<J>(tx,sql`SELECT env_id,generation_id::text,manifest_hash,application_source_hash,participant_id,payer_address FROM oid_task_execution_binding
  WHERE run_id=${target.runId} AND task_index=${target.taskIndex} FOR KEY SHARE`),execution=bindingRows[0];
 if(!execution||execution.env_id!==prep.environment_id||execution.generation_id!==prep.generation_id||execution.manifest_hash!==prep.environment_manifest_sha256||
  execution.application_source_hash!==prep.application_source_hash||execution.participant_id!==prep.participant_id||String(execution.payer_address).toLowerCase()!==String(prep.payer_address).toLowerCase())
  return unavailable('preparation_unavailable');
 const release=await deps.taskReleaseSource.getValidatedReleaseRecord(String(run.release_identity),String(run.manifest_hash),tx);
 if(!release||release.releaseIdentity!==run.release_identity||release.manifestHash!==run.manifest_hash||release.manifest.releaseIdentity!==run.release_identity||
  release.manifest.manifestHash!==run.manifest_hash)return unavailable('release_binding_mismatch');
 const rawCase=release.manifest.cases[String(run.mode) as 'training'|'ranked'].find((entry)=>entry.taskId===run.task_id);
 if(!rawCase||rawCase.taskId!==run.task_id||rawCase.caseId!==prep.case_id||rawCase.caseHash!==prep.case_hash||rawCase.executionIdentityHash!==prep.execution_identity_hash||
  rawCase.initialState.stateSha256!==prep.initial_state_sha256)return unavailable('release_binding_mismatch');
 const taskCase=rawCase as ChainTaskCase,taskId=taskCase.taskId;
 const evidenceBinding:TaskEvidenceBinding={ownerId:String(run.owner_id),agentId:String(run.agent_id),runId:target.runId,environmentId:prep.environment_id,
  releaseIdentity:String(run.release_identity),manifestHash:String(run.manifest_hash),caseId:taskCase.caseId,caseHash:taskCase.caseHash,rubricHash:taskCase.rubricHash,taskId};
 const identity=release.manifest.executionIdentity;
 if(identity.localChainId<1||identity.environmentManifestSha256.toLowerCase()!==prep.environment_manifest_sha256.toLowerCase())return unavailable('release_binding_mismatch');
 const assets=identity.assets.map((asset)=>({assetId:asset.assetId,kind:asset.kind,address:asset.address?.toLowerCase()??null,codeHash:asset.codeHash?.toLowerCase()??null}));
 const contracts=identity.contracts.map((contract)=>({contractId:contract.contractId,address:contract.address.toLowerCase(),codeHash:contract.codeHash.toLowerCase()}));
 const routes=routeIdentities(taskCase,assets,contracts),participant=addr(prep.payer_address)!;
 let prepProof:PrepProof;try{prepProof=await loadPreparation(deps.repositoryRoot,prep,target.runId,target.taskIndex,taskCase)}catch(error){if(error instanceof Unavailable)return unavailable(error.reasonCode);return unavailable('preparation_unavailable')}
 const actionRows=await ownerRows<ActionRow>(tx,sql`SELECT a.id::text,a.run_id::text,a.task_index,a.owner_id::text,a.agent_id::text,a.task_id,a.environment_id,a.action_sequence::text,
  a.operation_id,a.payload_hash,a.action_kind,a.command_json,r.receipt_revision,r.receipt_status,r.evidence_hash,r.evidence_path,r.transaction_hash,
  h.revision AS history_revision,h.receipt_status AS history_status,h.evidence_hash AS history_evidence_hash,h.evidence_path AS history_evidence_path,
  h.transaction_hash AS history_transaction_hash ${recoveredOwnerLineageSelectSql} FROM oid_run_task_action a JOIN oid_run_task_action_receipt r ON r.action_id=a.id
  ${recoveredOwnerLineageJoinSql}
  LEFT JOIN LATERAL(SELECT revision,receipt_status,evidence_hash,evidence_path,transaction_hash FROM oid_run_task_action_reconciliation WHERE action_id=a.id ORDER BY revision DESC LIMIT 1) h ON true
  WHERE a.run_id=${target.runId} AND a.task_index=${target.taskIndex} ORDER BY a.action_sequence FOR UPDATE OF a,r`);
 let loaded:LoadedActions;try{loaded=await loadActions(deps.repositoryRoot,target.runId,target.taskIndex,run,prep,cutoff,actionRows,taskCase,assets,contracts)}
 catch(error){if(error instanceof Unavailable)return unavailable(error.reasonCode);return unavailable('action_evidence_unavailable')}
 const actions=loaded.chain,externalActions=loaded.external;
 const pg=deps.postgresByEnvironment[prep.environment_id],rpcPort=deps.rpcByEnvironment[prep.environment_id];
 if(!pg||!rpcPort||rpcPort.environmentId!==prep.environment_id)return unavailable('source_not_configured');
 const before=await captureCensus(pg,prep.environment_id,prep.generation_id);const generation=before.census.generation;
 if(generation.env_id!==prep.environment_id||generation.generation_id!==prep.generation_id.toLowerCase()||generation.participant_id!==prep.participant_id||
  generation.payer_address!==participant||generation.chain_id!==String(identity.localChainId)||generation.status!=='active'||
  generation.manifest_sha256!==prep.environment_manifest_sha256.toLowerCase()||generation.environment_manifest_sha256!==prep.environment_manifest_sha256.toLowerCase()||
  (!['H3','U1'].includes(taskId)&&(before.census.paymentsCount!=='0'||before.census.deliveriesCount!=='0')))
  return unavailable('rpc_mapping_incomplete');
 if(before.census.operations.length!==actions.length||before.census.selectedExecutions.length!==actions.length||before.census.costs.length!==actions.length)
  return unavailable('rpc_mapping_incomplete');
 const actionByOp=new Map(actions.map((action)=>[action.befOperationId,action]));
 for(const operation of before.census.operations){const opId=String(operation.operationId),action=actionByOp.get(opId);
  if(!action||operation.environmentId!==prep.environment_id||operation.generationId!==prep.generation_id.toLowerCase()||operation.participantId!==prep.participant_id||
   operation.actionKind!==action.command.kind||operation.transactionHash!==action.transactionHash||operation.receiptStatus!==action.outcome||
   operation.status!==(action.outcome==='success'?'settled':'reverted')||operation.idempotencyKeySha256!==sha(`task-action-${action.row.id}`))return unavailable('rpc_mapping_incomplete');
 }
 const rpc=new RpcRecorder(rpcPort),chain=quantity(await rpc.request('eth_chainId',[]));
 if(chain===null||chain!==BigInt(identity.localChainId))return unavailable('rpc_identity_mismatch');
 const baselineHeader=header(await rpc.request('eth_getBlockByNumber',[`0x${prepProof.blockNumber.toString(16)}`,false]),prepProof.blockNumber);
 if(baselineHeader.hash!==prepProof.blockHash)return unavailable('baseline_mismatch');
 const head=quantity(await rpc.request('eth_blockNumber',[]));if(head===null||head<prepProof.blockNumber)return unavailable('rpc_observation_unavailable');
 const count=head-prepProof.blockNumber;if(count>BigInt(MAX_BLOCKS))return unavailable('rpc_interval_too_large');
 const baseline=await readCheckpoint(rpc,prepProof.blockNumber,identity,participant,taskCase),final=await readCheckpoint(rpc,head,identity,participant,taskCase);
 if(baseline.blockHash!==prepProof.blockHash||!normalizeCheckpointState(baseline,taskCase.initialState,participant))return unavailable('baseline_mismatch');
 const identityCodeHashes=await verifyCode(rpc,identity,prepProof.blockNumber,head);
  const externalTransactionHashes=new Set(externalActions.filter((action)=>['pay','purchase'].includes(action.actionKind)&&action.transactionHash!==null)
   .map((action)=>String(action.transactionHash).toLowerCase()));
  const blockMap:Array<{number:string;hash:string;parentHash:string;transactionCount:number;participantTransactions:string[];externalTransactions:string[];all:J[]}>=[];
 let parent=baseline.blockHash;
 for(let number=prepProof.blockNumber+1n;number<=head;number++){
  const raw=await rpc.request('eth_getBlockByNumber',[`0x${number.toString(16)}`,true]);if(!isRecord(raw)||!Array.isArray(raw.transactions))return unavailable('rpc_observation_unavailable');
  const pinned=header(raw,number);if(pinned.parentHash!==parent)return unavailable('rpc_mapping_incomplete');parent=pinned.hash;
   const participants:string[]=[],externalTransactions:string[]=[],all:J[]=[];
  for(const item of raw.transactions){const transaction=normalizeRpcTransaction(item);if(!transaction)return unavailable('rpc_mapping_incomplete');all.push(transaction);
    if(transaction.from===participant)participants.push(String(transaction.hash));
    else if(externalTransactionHashes.has(String(transaction.hash).toLowerCase()))externalTransactions.push(String(transaction.hash));}
   blockMap.push({number:number.toString(),hash:pinned.hash,parentHash:pinned.parentHash,transactionCount:raw.transactions.length,
    participantTransactions:participants,externalTransactions,all});
 }
 if(parent!==final.blockHash)return unavailable('rpc_mapping_incomplete');
 const blockParticipant=blockMap.flatMap((block)=>block.all.filter((value)=>value.from===participant));
 const nonceDelta=BigInt(final.participantTransactionCount)-BigInt(baseline.participantTransactionCount);
  if(nonceDelta<0n||nonceDelta!==BigInt(blockParticipant.length))return unavailable('rpc_mapping_incomplete');
 const sortedNonces=blockParticipant.map((item)=>BigInt(String(item.nonce))).sort((a,b)=>a<b?-1:a>b?1:0);
 if(sortedNonces.some((value,index)=>value!==BigInt(baseline.participantTransactionCount)+BigInt(index)))return unavailable('rpc_mapping_incomplete');
 const intervalTxByHash=new Map<string,J>();for(const raw of blockParticipant){const hash=String(raw.hash).toLowerCase();if(intervalTxByHash.has(hash))return unavailable('rpc_mapping_incomplete');intervalTxByHash.set(hash,raw);}
  const intervalAllTxByHash=new Map<string,J>();for(const raw of blockMap.flatMap((block)=>block.all)){
   const hash=String(raw.hash).toLowerCase();if(intervalAllTxByHash.has(hash))return unavailable('rpc_mapping_incomplete');intervalAllTxByHash.set(hash,raw);}
  const expectedParticipantHashes=new Set([...actions.map((action)=>action.transactionHash),...externalTransactionHashes].filter((hash)=>
   intervalAllTxByHash.get(hash)?.from===participant));
  if(expectedParticipantHashes.size!==blockParticipant.length||[...intervalTxByHash.keys()].some((hash)=>!expectedParticipantHashes.has(hash))||
   externalTransactionHashes.size!==externalActions.filter((action)=>['pay','purchase'].includes(action.actionKind)&&action.transactionHash!==null).length||
   [...externalTransactionHashes].some((hash)=>!intervalAllTxByHash.has(hash)))return unavailable('rpc_mapping_incomplete');
 const txByHash=new Map<string,CapturedTx>(),transactions:CapturedTx[]=[];
 const operationsById=new Map(before.census.operations.map((op)=>[String(op.operationId),op]));
 const selectedById=new Map(before.census.selectedExecutions.map((row)=>[String(row.operationId),row]));
 const costsById=new Map(before.census.costs.map((row)=>[String(row.operationId),row]));
 for(const action of actions){
  const op=operationsById.get(action.befOperationId),selected=selectedById.get(action.befOperationId),cost=costsById.get(action.befOperationId);
  if(!op||!selected||!cost||selected.actionKind!==action.command.kind||!same(selected.selectedAction,action.selectedAction)||
   selected.transactionHash!==action.transactionHash||selected.outcome!==action.outcome||op.transactionHash!==action.transactionHash)return unavailable('rpc_mapping_incomplete');
  if(action.recoveryEvidence.recoverySource){
   const generation=before.census.generation,measurement=isRecord(selected.measurement)?selected.measurement:null;
   const measuredReceipt=measurement&&isRecord(measurement.receipt)?measurement.receipt:null;
   const selectedEvents=before.census.selectedEvents.filter((event)=>String(event.operationId)===action.befOperationId&&event.eventKind==='selected_action_bound');
   const boundEvents=selectedEvents.flatMap((event)=>{
    const payload=isRecord(event.eventPayload)?event.eventPayload:null;
    if(!payload||typeof payload.actionKind!=='string'||typeof payload.requestSha256!=='string'||typeof event.eventJsonSha256!=='string')return [];
    return [{eventKind:String(event.eventKind),actionKind:payload.actionKind,requestSha256:payload.requestSha256,
     selectedAction:payload.selectedAction,eventJsonSha256:event.eventJsonSha256}];
   });
   const facts:RecoverySourceFacts|null=measurement&&typeof measurement.measurementSha256==='string'&&isRecord(selected.selectedAction)&&
    boundEvents.length===selectedEvents.length?{operation:{operationId:String(op.operationId),environmentId:String(op.environmentId),
     generationId:String(op.generationId),participantId:String(op.participantId),idempotencyKeySha256:String(op.idempotencyKeySha256),
     requestSha256:String(op.requestSha256),operationKind:String(op.actionKind),status:String(op.status),
     transactionHash:op.transactionHash===null?null:txHash(op.transactionHash),receiptStatus:String(op.receiptStatus),
     responseSha256:op.responseSha256===null?null:String(op.responseSha256)},
     generationManifestSha256:String(generation.manifest_sha256),environmentManifestSha256:String(generation.environment_manifest_sha256),
     selectedExecution:{actionKind:String(selected.actionKind),selectedAction:selected.selectedAction,
      outcome:typeof selected.outcome==='string'?selected.outcome:null,
      transactionHash:selected.transactionHash===null?null:txHash(selected.transactionHash),
      measurementSha256:measurement.measurementSha256},selectedActionBoundEvents:boundEvents}:null;
   const response=action.recoveryEvidence.participantToolResponse;
   if(!facts||!measuredReceipt||!recoverySourceEvidenceMatchesFacts(action.recoveryEvidence.recoverySource,facts)||!isRecord(response)||
      response.operationId!==action.befOperationId||response.outcome!==action.outcome||!isRecord(response.selectedAction)||
      !sameActionEnvelope(response.selectedAction as J,action.selectedAction,action.command,taskCase,assets,contracts)||
      !isRecord(response.transaction)||txHash(response.transaction.hash)!==action.transactionHash||!isRecord(response.receipt)||
      txHash(response.receipt.transactionHash)!==action.transactionHash||response.receipt.status!==action.outcome||
      txHash(measuredReceipt.transactionHash)!==action.transactionHash||measuredReceipt.status!==action.outcome||
      String(response.receipt.gasUsed)!==String(measuredReceipt.gasUsed)||
      String(response.receipt.effectiveGasPrice)!==String(measuredReceipt.effectiveGasPriceWei)||
      action.recoveryEvidence.receiptGasUsed!==String(measuredReceipt.gasUsed)||
      action.recoveryEvidence.receiptEffectiveGasPriceWei!==String(measuredReceipt.effectiveGasPriceWei)||
      String(response.receipt.gasUsed)!==action.recoveryEvidence.receiptGasUsed||
      String(response.receipt.effectiveGasPrice)!==action.recoveryEvidence.receiptEffectiveGasPriceWei)
    return unavailable('rpc_mapping_incomplete');
  }
  const principal=action.command.kind==='wrap'?{asset:'ETH',units:action.command.amountWei}:action.command.kind==='unwrap'?{asset:'WETH',units:action.command.amountWei}:
   action.command.kind==='swap'?{asset:action.command.inputAssetId,units:action.command.amountInUnits}:
   action.command.kind==='transfer'?{asset:'USDC',units:action.command.amountUnits}:{asset:null,units:'0'};
  const observed=action.outcome==='success'?principal.units:'0';
  if(cost.selectedPrincipalAsset!==principal.asset||cost.selectedPrincipalUnits!==principal.units||cost.observedPrincipalUnits!==observed)
   return unavailable('rpc_mapping_incomplete');
  const blockTx=intervalTxByHash.get(action.transactionHash);if(!blockTx)return unavailable('rpc_mapping_incomplete');
  const originalRaw=await rpc.request('eth_getTransactionByHash',[action.transactionHash]),original=normalizeRpcTransaction(originalRaw);
  if(!original||!same(original,blockTx))return unavailable('rpc_mapping_incomplete');
  const intent=selected.transactionIntent as J;
  if(!isRecord(intent)||txHash(intent.hash)!==action.transactionHash||intent.chainId!==identity.localChainId||addr(intent.from)!==participant||
   addr(intent.to)!==blockTx.to||String(intent.nonce)!==String(blockTx.nonce)||String(intent.input).toLowerCase()!==String(blockTx.input).toLowerCase()||
   String(intent.valueWei)!==String(blockTx.valueWei)||String(intent.gasLimit)!==String(blockTx.gasLimit)||
   (intent.blockHash!==null&&txHash(intent.blockHash)!==blockTx.blockHash)||(intent.blockNumber!==null&&String(intent.blockNumber)!==blockTx.blockNumber)||
   (intent.transactionIndex!==null&&String(intent.transactionIndex)!==blockTx.transactionIndex))return unavailable('rpc_mapping_incomplete');
   const block=blockMap.find((b)=>b.number===blockTx.blockNumber);if(!block||!transactionMatchesCommand(blockTx as unknown as CapturedTx,action.command,taskCase,
    routes,assets,action.approvalSpender))return unavailable('rpc_mapping_incomplete');
  const receiptRaw=await rpc.request('eth_getTransactionReceipt',[action.transactionHash]);
  const receipt=normalizeReceipt(receiptRaw as J,blockTx);if(!receipt||receipt.status!==action.outcome||receipt.status!==op.receiptStatus||selected.outcome!==receipt.status||
   cost.transactionHash!==action.transactionHash||cost.receiptStatus!==receipt.status||cost.payerRole!=='participant'||cost.payerAddress!==participant||
   cost.transactionFrom!==participant||cost.receiptFrom!==participant||cost.receiptBlockNumber!==blockTx.blockNumber||cost.receiptBlockHash!==blockTx.blockHash||
   cost.receiptBlockParentHash!==block.parentHash||cost.gasUsed!==receipt.gasUsed||cost.effectiveGasPriceWei!==receipt.effectiveGasPriceWei||cost.gasCostWei!==receipt.gasCostWei)
   return unavailable('rpc_mapping_incomplete');
   if(action.recoveryEvidence.recoverySource){
    const measurement=isRecord(selected.measurement)?selected.measurement:null;
    const measuredReceipt=measurement&&isRecord(measurement.receipt)?measurement.receipt:null;
    if(!measuredReceipt||txHash(measuredReceipt.transactionHash)!==action.transactionHash||measuredReceipt.status!==receipt.status||
       String(measuredReceipt.gasUsed)!==receipt.gasUsed||String(measuredReceipt.effectiveGasPriceWei)!==receipt.effectiveGasPriceWei||
       String(measuredReceipt.gasCostWei)!==receipt.gasCostWei)return unavailable('rpc_mapping_incomplete');
   }
  const captured:CapturedTx={hash:String(blockTx.hash),from:String(blockTx.from),to:blockTx.to===null?null:String(blockTx.to),nonce:String(blockTx.nonce),input:String(blockTx.input),
   inputSha256:createHash('sha256').update(String(blockTx.input),'utf8').digest('hex'),receiptLogsSha256:receipt.receiptLogsSha256,
   valueWei:String(blockTx.valueWei),gasLimit:String(blockTx.gasLimit),blockNumber:String(blockTx.blockNumber),blockHash:String(blockTx.blockHash),
   transactionIndex:String(blockTx.transactionIndex),chainId:String(blockTx.chainId),status:receipt.status,gasUsed:receipt.gasUsed,
   effectiveGasPriceWei:receipt.effectiveGasPriceWei,gasCostWei:receipt.gasCostWei,logs:receipt.logs};
  txByHash.set(captured.hash,captured);transactions.push(captured);
 }
  for(const action of externalActions.filter((item)=>['pay','purchase'].includes(item.actionKind)&&item.transactionHash!==null)){
   const hash=String(action.transactionHash).toLowerCase(),blockTx=intervalAllTxByHash.get(hash);if(!blockTx||txByHash.has(hash))return unavailable('rpc_mapping_incomplete');
   const originalRaw=await rpc.request('eth_getTransactionByHash',[hash]),original=normalizeRpcTransaction(originalRaw);
   if(!original||!same(original,blockTx))return unavailable('rpc_mapping_incomplete');
   const receiptRaw=await rpc.request('eth_getTransactionReceipt',[hash]),receipt=normalizeReceipt(receiptRaw as J,blockTx);
   const block=blockMap.find((candidate)=>candidate.number===String(blockTx.blockNumber));
   if(!receipt||!block||!isRecord(originalRaw)||typeof originalRaw.input!=='string'||!/^0x(?:[0-9a-f]{2})*$/i.test(originalRaw.input))return unavailable('rpc_mapping_incomplete');
   const captured:CapturedTx={hash:String(blockTx.hash),from:String(blockTx.from),to:blockTx.to===null?null:String(blockTx.to),nonce:String(blockTx.nonce),input:null,
    inputSha256:createHash('sha256').update(originalRaw.input,'utf8').digest('hex'),receiptLogsSha256:receipt.receiptLogsSha256,
    valueWei:String(blockTx.valueWei),gasLimit:String(blockTx.gasLimit),blockNumber:String(blockTx.blockNumber),blockHash:String(blockTx.blockHash),
    transactionIndex:String(blockTx.transactionIndex),chainId:String(blockTx.chainId),status:receipt.status,gasUsed:receipt.gasUsed,
    effectiveGasPriceWei:receipt.effectiveGasPriceWei,gasCostWei:receipt.gasCostWei,logs:receipt.logs};
   txByHash.set(hash,captured);transactions.push(captured);
  }
  const nonParticipantExternalCount=[...externalTransactionHashes].filter((hash)=>intervalAllTxByHash.get(hash)?.from!==participant).length;
  if(txByHash.size!==intervalTxByHash.size+nonParticipantExternalCount||transactions.length!==actions.length+externalTransactionHashes.size)
   return unavailable('rpc_mapping_incomplete');
 const baselineAgain=header(await rpc.request('eth_getBlockByNumber',[`0x${prepProof.blockNumber.toString(16)}`,false]),prepProof.blockNumber);
 const finalAgain=header(await rpc.request('eth_getBlockByNumber',[`0x${head.toString(16)}`,false]),head);
 if(baselineAgain.hash!==baseline.blockHash||finalAgain.hash!==final.blockHash)return unavailable('rpc_mapping_incomplete');
  const intervalBlocks=blockMap.map(({number,hash,parentHash,transactionCount,participantTransactions,externalTransactions})=>
   ({number,hash,parentHash,transactionCount,participantTransactions,externalTransactions}));
 const categorized=relevantLogs(transactions,assets);
 const after=await captureCensus(pg,prep.environment_id,prep.generation_id);
 if(!same(before.census,after.census)||after.census.generation.status!=='active')return unavailable('observer_census_changed');
 const packet:ChainCapturePacket={schemaVersion:'bts-chain-task-observation-capture/v1',classification:'run_bound_observations_candidate_not_grade',taskId,
  binding:evidenceBinding,closure:{closureId:String(closure.id),actionCutoffSequence:cutoff,reconciledActionSequence:reconciled},
  execution:{preparationId:prep.preparation_id,leaseId:prep.lease_id,generationId:prep.generation_id,environmentId:prep.environment_id,
   environmentManifestHash:prep.environment_manifest_sha256.toLowerCase(),applicationSourceHash:prep.application_source_hash.toLowerCase(),
   executionIdentityHash:prep.execution_identity_hash.toLowerCase(),initialStateSha256:prep.initial_state_sha256.toLowerCase()},
  preparation:{fixtureEvidence:prepProof.fixture,baselineEvidence:prepProof.baseline,baselineBlockNumber:baseline.blockNumber,baselineBlockHash:baseline.blockHash},
   ownerActions:actions.map((action)=>({actionId:action.row.id,actionSequence:action.sequence,ownerOperationId:action.row.operation_id,actionKind:action.command.kind,
    commandSha256:action.row.payload_hash.toLowerCase(),command:action.command as unknown as J,selectedAction:action.selectedAction,approvalSpender:action.approvalSpender,
    actionEvidence:action.evidence,befOperationId:action.befOperationId,transactionHash:action.transactionHash})),
   externalActions,
  bef:{session:before.session,before:before.census,after:after.census,censusSha256:sha256CanonicalTaskJson(before.census).toLowerCase()},
  rpc:{localChainId:String(identity.localChainId),participant,assets,contracts,routes,identityCodeHashes,baseline,final,intervalBlocks,transactions,
   transferLogs:categorized.transferLogs,approvalLogs:categorized.approvalLogs,swapLogs:categorized.swapLogs,wethLogs:categorized.wethLogs,
   responseHashes:rpc.responseHashes}};
 if(hasSecret(packet)||Buffer.byteLength(canonicalTaskJson(packet),'utf8')>MAX_PACKET_BYTES)return unavailable('capture_evidence_unavailable');
 let evidence:EvidenceReference;
 try{evidence=await deps.evidenceSink.write(packet)}catch{return unavailable('capture_evidence_unavailable')}
 if(!evidenceRef(evidence,OBS_ROOT))return unavailable('capture_evidence_unavailable');
 const ethValuation=release.manifest.costPolicy.ethValuation;
 const projected=projectTaskChainCapturePacket(packet,{binding:evidenceBinding,taskCase,evidence,ethValuation});
 const observationCutoffSequence=Math.max(0,...Object.values(projected).flatMap((list)=>Array.isArray(list)?list.map((item)=>
  isRecord(item)&&typeof item.sequence==='number'?item.sequence:0):[]));
 const observations:PersistedTaskObservations={schemaVersion:'bts-task-observations/v1',binding:evidenceBinding,coveredThroughSequence:observationCutoffSequence,
  captureEvidence:evidence,coverage:projected.coverage,transfers:projected.transfers,payments:[],stateMutations:[],finalStates:projected.finalStates,
  allowanceChanges:projected.allowanceChanges,allowanceUses:projected.allowanceUses,answers:[],selections:[],deliveries:[],trades:projected.trades,
  conversions:projected.conversions,expenses:projected.expenses};
 const candidate:TaskObservationBundleCandidate={schemaVersion:'bts-task-observation-bundle-candidate/v1',observationCutoffSequence,
  cutoffStatus:'authoritative',cutoffEvidence:evidence,observations};
 return {status:'candidate',candidate,evidence,classification:'run_bound_observations_candidate_not_grade',boundary:{actionCutoffSequence:cutoff,
  observationCutoffSequence,baselineBlockNumber:baseline.blockNumber,baselineBlockHash:baseline.blockHash,finalBlockNumber:final.blockNumber,finalBlockHash:final.blockHash}};
}

/** Captures one already-closed run task from locked owner rows, readonly observer census and local-chain RPC. */
export async function collectBefChainTaskObservationCandidate(deps:BefChainObservationCollectorDependencies,
 target:{runId:string;taskIndex:number}):Promise<BefChainObservationCollectionResult>{
 if(!UUID.test(target.runId)||!Number.isSafeInteger(target.taskIndex)||target.taskIndex<0||target.taskIndex>11)return unavailable('invalid_target');
 try{return await deps.db.transaction((tx)=>collectLocked(deps,target,tx));}
 catch(error){if(error instanceof Unavailable)return unavailable(error.reasonCode);return unavailable('rpc_observation_unavailable')}
}
