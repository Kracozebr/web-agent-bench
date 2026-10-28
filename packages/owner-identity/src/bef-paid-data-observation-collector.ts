import { createHash } from 'node:crypto';
import { lstat, open, realpath } from 'node:fs/promises';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import { sql } from 'drizzle-orm';
import type { OwnerDatabase } from './db.js';
import { decodeM1TransferLog, m1PreparationHealthMatches, parseM1PreparationEvidence } from './bef-m1-observation-collector.js';
import { readOnlyToolResponseMatches } from './bef-task-executor.js';
import { TaskActionCommandSchema, type TaskActionCommand } from './task-action-service.js';
import { canonicalTaskJson, sha256CanonicalTaskJson, type EvidenceReference, type TaskCase, type TaskReleaseQuerySource } from './task-release.js';
import { splitPayRequestSha256 } from './task-m1-capture-packet.js';
import { projectPaidDataCaptureCandidate, projectPaidDataObservationBundle, validatePaidDataCapturePacket, type PaidDataAction, type PaidDataCapturePacket,
  type PaidDataObservationCandidate } from './task-paid-data-capture-packet.js';
import type { TaskObservationBundleCandidate } from './task-observation-store.js';

const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HASH=/^[0-9a-f]{64}$/i,TX=/^0x[0-9a-f]{64}$/i,ADDRESS=/^0x[0-9a-f]{40}$/i,HEX=/^0x(?:0|[1-9a-f][0-9a-f]*)$/i;
const ROOT='artifacts/runs/owner-identity-bef-task-coordinator/',PREP=ROOT+'preparation/',ACTION=ROOT+'action/',OBS=ROOT+'observation/';
const BOUNDARY='actual_tool_http_x402_local_evm_application_store' as const;
const MAX_ACTIONS=256,MAX_ROWS=2048,MAX_MANIFEST=256*1024,MAX_RESOURCE=2*1024*1024,MAX_EVIDENCE=2*1024*1024,MAX_PACKET=8*1024*1024;
const TRANSFER_TOPIC='0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
const SECRET_KEYS=new Set(['privatekey','privkey','seedphrase','mnemonic','secret','clientsecret','bearer','bearertoken','accesstoken','refreshtoken',
  'providertoken','paymenttoken','token','apitoken','apikey','authorization','walletmaterial','walletsecret','signature','signedpayload',
  'paymentpayload','paymentauthorization','paymentauth','paymentproof','xpayment','xpaymentsignature','xpaymentpayload','xpaymentauthorization',
  'x402authorization','x402signature','x402payload','x402proof','password','dsn','databaseurl']);
const SECRET_VALUES=new Set(['input','data','calldata','rawtransaction','rawtx','v','r','s']);
type J=Record<string,unknown>;type R=Record<string,unknown>;type Tx=Parameters<Parameters<OwnerDatabase['transaction']>[0]>[0];
type Prep={preparation_id:string;claim_id:string;lease_id:string;environment_id:string;release_identity:string;manifest_hash:string;task_id:string;
  case_id:string;case_hash:string;initial_state_sha256:string;execution_identity_hash:string;environment_manifest_sha256:string;application_source_hash:string;
  created_at:Date|string;lease_state:string;observation_status:string;generation_id:string|null;participant_id:string|null;payer_address:string|null;
  baseline_state_sha256:string|null;fixture_evidence:unknown;baseline_evidence:unknown};
type ActionRow={id:string;run_id:string;task_index:number;owner_id:string;agent_id:string;task_id:string;environment_id:string;action_sequence:string|number;
  operation_id:string;payload_hash:string;action_kind:string;command_json:unknown;receipt_revision:number;receipt_status:string;evidence_hash:string|null;
  evidence_path:string|null;transaction_hash:string|null;history_revision:number|null;history_status:string|null;history_evidence_hash:string|null;
  history_evidence_path:string|null;history_transaction_hash:string|null};
type Census={generation:J;operations:J[];payments:J[];deliveries:J[];costs:J[];x402Observations:J[]};
type Query=(statement:string,parameters?:readonly unknown[])=>Promise<unknown>;
export interface BefPaidDataReadOnlyPostgresPort{environmentId:string;withRepeatableRead<T>(fn:(query:Query)=>Promise<T>):Promise<T>}
export interface BefPaidDataReadOnlyRpcPort{environmentId:string;request(method:string,params:readonly unknown[]):Promise<unknown>}
export interface BefPaidDataEvidenceSink{write(packet:PaidDataCapturePacket):Promise<EvidenceReference>}
export interface BefPaidDataObservationCollectorDependencies{db:OwnerDatabase;taskReleaseSource:TaskReleaseQuerySource;repositoryRoot:string;
  postgresByEnvironment:Readonly<Record<string,BefPaidDataReadOnlyPostgresPort>>;rpcByEnvironment:Readonly<Record<string,BefPaidDataReadOnlyRpcPort>>;
  evidenceSink:BefPaidDataEvidenceSink}
export type BefPaidDataUnavailableCode='invalid_target'|'unsupported_task'|'owner_cutoff_unavailable'|'owner_cutoff_mismatch'|'reconciliation_pending'|
  'action_evidence_unavailable'|'preparation_unavailable'|'release_binding_mismatch'|'source_not_configured'|'observer_role_invalid'|
  'observer_census_unavailable'|'observer_census_changed'|'rpc_identity_mismatch'|'rpc_observation_unavailable'|'rpc_mapping_incomplete'|'capture_evidence_unavailable';
export type BefPaidDataCollectionResult={status:'unavailable';reasonCode:BefPaidDataUnavailableCode}|
  {status:'candidate';candidate:TaskObservationBundleCandidate;paidDataCandidate:PaidDataObservationCandidate;boundary:import('./task-paid-data-capture-packet.js').ChainObservationBoundary;
    evidence:EvidenceReference;classification:'run_bound_observations_candidate_not_grade';packet:PaidDataCapturePacket};
class Unavailable extends Error{constructor(readonly reasonCode:BefPaidDataUnavailableCode){super(reasonCode)}}
function stop(code:BefPaidDataUnavailableCode):never{throw new Unavailable(code)}
function unavailable(reasonCode:BefPaidDataUnavailableCode):BefPaidDataCollectionResult{return {status:'unavailable',reasonCode}}
function rec(v:unknown):v is J{return !!v&&typeof v==='object'&&!Array.isArray(v)}
function getRows(v:unknown,code:BefPaidDataUnavailableCode):R[]{if(Array.isArray(v)&&v.every(rec))return v;if(rec(v)&&Array.isArray(v.rows)&&v.rows.every(rec))return v.rows;return stop(code)}
function parse(v:unknown,code:BefPaidDataUnavailableCode):unknown{if(typeof v!=='string')return v;try{return JSON.parse(v) as unknown}catch{return stop(code)}}
function sha(v:string|Uint8Array):string{return createHash('sha256').update(v).digest('hex')}
function hjson(v:unknown):string{return sha256CanonicalTaskJson(v).toLowerCase()}
function seq(v:unknown):number|null{try{const n=BigInt(v as string|number|bigint);return n>=0n&&n<=BigInt(Number.MAX_SAFE_INTEGER)?Number(n):null}catch{return null}}
function hash(v:unknown):string|null{return typeof v==='string'&&HASH.test(v)?v.toLowerCase():null}
function txHash(v:unknown):string|null{return typeof v==='string'&&TX.test(v)?v.toLowerCase():null}
function addr(v:unknown):string|null{return typeof v==='string'&&ADDRESS.test(v)?v.toLowerCase():null}
function qty(v:unknown):bigint|null{if(typeof v!=='string'||!HEX.test(v))return null;try{return BigInt(v)}catch{return null}}
function dec(v:unknown):bigint|null{if(typeof v!=='string'&&typeof v!=='number'&&typeof v!=='bigint')return null;try{const n=BigInt(v);return n>=0n?n:null}catch{return null}}
function valueSafe(v:unknown):unknown{if(v instanceof Date)return v.toISOString();if(typeof v==='bigint')return v.toString();if(Array.isArray(v))return v.map(valueSafe);
  if(rec(v))return Object.fromEntries(Object.entries(v).map(([k,x])=>[k,valueSafe(x)]));return v}
function project(row:R,keys:readonly string[]):J{const out:J={};for(const k of keys)out[k]=valueSafe(row[k]);return out}
function hasSecret(v:unknown,seen=new Set<object>()):boolean{
  if(!v||typeof v!=='object')return false;if(seen.has(v))return true;seen.add(v);
  const bad=Array.isArray(v)?v.some((x)=>hasSecret(x,seen)):Object.entries(v as J).some(([k,x])=>{
    const n=k.toLowerCase().replace(/[^a-z]/g,'');return SECRET_KEYS.has(n)||SECRET_VALUES.has(n)||hasSecret(x,seen)});
  seen.delete(v);return bad
}
function evidenceRef(v:unknown):EvidenceReference|null{
  if(!rec(v)||Object.keys(v).sort().join(',')!=='boundary,path,sha256'||v.boundary!==BOUNDARY||typeof v.path!=='string'||
    !HASH.test(String(v.sha256))||v.path.includes('\\')||v.path.includes('\0')||
    !/^artifacts\/runs\/owner-identity-bef-task-coordinator\/[A-Za-z0-9._/-]{1,450}$/.test(v.path)||
    v.path.split('/').some((p)=>!p||p==='.'||p==='..'))return null;
  return {path:v.path,sha256:String(v.sha256).toLowerCase(),boundary:BOUNDARY}
}
async function readFile(rootPath:string,path:string,prefix:string,max:number,code:BefPaidDataUnavailableCode,expected?:string):Promise<Buffer>{
  if(!path.startsWith(prefix)||isAbsolute(path)||path.includes('\\')||path.includes('\0')||path.split('/').some((p)=>!p||p==='.'||p==='..'))return stop(code);
  const root=await realpath(rootPath).catch(()=>stop(code)),actual=await realpath(resolve(root,...path.split('/'))).catch(()=>stop(code));
  const rel=relative(root,actual);if(!rel||rel==='..'||rel.startsWith('..'+sep)||isAbsolute(rel)||!rel.split(sep).join('/').startsWith(prefix))return stop(code);
  const handle=await open(actual,'r').catch(()=>stop(code));
  try{
    const before=await handle.stat({bigint:true}),lb=await lstat(actual,{bigint:true});
    if(!before.isFile()||!lb.isFile()||before.dev!==lb.dev||before.ino!==lb.ino||before.size<1n||before.size>BigInt(max))return stop(code);
    const b=Buffer.alloc(max+1);let n=0;while(n<b.length){const r=await handle.read(b,n,b.length-n,null);if(!r.bytesRead)break;n+=r.bytesRead}
    const after=await handle.stat({bigint:true}),la=await lstat(actual,{bigint:true});
    if(n<1||n>max||BigInt(n)!==before.size||before.dev!==after.dev||before.ino!==after.ino||before.size!==after.size||
      before.mtimeNs!==after.mtimeNs||before.ctimeNs!==after.ctimeNs||la.dev!==after.dev||la.ino!==after.ino)return stop(code);
    const bytes=b.subarray(0,n);if(expected&&sha(bytes)!==expected.toLowerCase())return stop(code);return bytes;
  }catch(e){if(e instanceof Unavailable)throw e;return stop(code)}finally{await handle.close().catch(()=>undefined)}
}
function parseObject(bytes:Buffer,code:BefPaidDataUnavailableCode):J{
  let value:unknown;try{value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes)) as unknown}catch{return stop(code)}
  if(!rec(value)||hasSecret(value))return stop(code);return value
}
async function ownerRows<T extends R>(tx:Tx,text:string):Promise<T[]>{return getRows(await tx.execute(sql.raw(text)),'owner_cutoff_unavailable') as T[]}
function prepPins(p:Prep,runId:string,index:number):string{
  const created=p.created_at instanceof Date?p.created_at.toISOString():new Date(p.created_at).toISOString();
  if(!Number.isFinite(Date.parse(created)))return stop('preparation_unavailable');
  return hjson({preparationId:p.preparation_id,runId,taskIndex:index,claimId:p.claim_id,leaseId:p.lease_id,environmentId:p.environment_id,
    releaseIdentity:p.release_identity,manifestHash:p.manifest_hash,taskId:p.task_id,caseId:p.case_id,caseHash:p.case_hash,initialStateSha256:p.initial_state_sha256,
    executionIdentityHash:p.execution_identity_hash,environmentManifestSha256:p.environment_manifest_sha256,applicationSourceHash:p.application_source_hash,createdAt:created})
}
function stateProjection(s:TaskCase['initialState']):J{return {balances:[...s.balances].sort((a,b)=>(a.account+'|'+a.assetId).localeCompare(b.account+'|'+b.assetId)),
  allowances:[...s.allowances].sort((a,b)=>(a.owner+'|'+a.tokenAssetId+'|'+a.spender).localeCompare(b.owner+'|'+b.tokenAssetId+'|'+b.spender)),
  deliveredComponentIds:[...s.deliveredComponentIds].sort(),fulfilledObligationIds:[...s.fulfilledObligationIds].sort()}}
/**
 * AICODE-NOTE: The preparation producer stores state hashes on the outer evidence object and
 * reports the baseline block as an eth_blockNumber hex quantity. Preserve that producer envelope.
 */
export function parsePaidDataBaselineState(evidenceValue:unknown,initialState:TaskCase['initialState'],databaseBaselineStateSha256:string|null):{number:string;blockHash:string}{
  const evidence=rec(evidenceValue)?evidenceValue:null,state=evidence&&rec(evidence.state)?evidence.state:null;
  const expected=initialState.stateSha256.toLowerCase();
  if(!evidence||!state||state.sameBlock!==true||!rec(state.projection)||!Array.isArray(state.reads)||
    evidence.stateSha256!==expected||evidence.expectedStateSha256!==expected||databaseBaselineStateSha256?.toLowerCase()!==expected||
    canonicalTaskJson(state.projection)!==canonicalTaskJson(stateProjection(initialState))||hjson(state.projection)!==expected)
    return stop('preparation_unavailable');
  const number=qty(state.blockNumber),blockHash=txHash(state.blockHash);
  if(number===null||!blockHash)return stop('preparation_unavailable');
  return {number:number.toString(10),blockHash}
}
async function preparationEvidence(root:string,p:Prep,runId:string,index:number,c:TaskCase){
  const fixture=evidenceRef(p.fixture_evidence),baseline=evidenceRef(p.baseline_evidence);
  if(!fixture||!baseline||fixture.path===baseline.path||fixture.sha256===baseline.sha256)stop('preparation_unavailable');
  const [fb,bb]=await Promise.all([readFile(root,fixture.path,PREP,256*1024,'preparation_unavailable',fixture.sha256),
    readFile(root,baseline.path,PREP,256*1024,'preparation_unavailable',baseline.sha256)]);
  const f=parseM1PreparationEvidence(fb,'fixture'),b=parseM1PreparationEvidence(bb,'baseline'),pins=prepPins(p,runId,index);
  for(const [doc,kind] of [[f,'fixture'],[b,'baseline']] as const)
    if(!rec(doc)||doc.schemaVersion!=='owner-bef-task-preparation-evidence/v1'||doc.kind!==kind||doc.preparationId!==p.preparation_id||
      doc.environmentId!==p.environment_id||doc.publicPinsSha256!==pins||!rec(doc.evidence))stop('preparation_unavailable');
  const fe=f.evidence as J;
  if(!m1PreparationHealthMatches(fe.environmentHealth,fe.publicStatus,{environmentId:p.environment_id,preparationId:p.preparation_id,
    generationId:p.generation_id,environmentManifestHash:p.environment_manifest_sha256,applicationSourceHash:p.application_source_hash}))
    stop('preparation_unavailable');
  const baselineState=parsePaidDataBaselineState(b.evidence,c.initialState,p.baseline_state_sha256);
  return {fixture,baseline,number:baselineState.number,blockHash:baselineState.blockHash}
}
type ValidatedTaskRelease=NonNullable<Awaited<ReturnType<TaskReleaseQuerySource['getValidatedReleaseRecord']>>>;
function releasedAssetAddress(release:ValidatedTaskRelease,assetId:'USDC'|'WETH'):string{
  const identity=release.manifest.executionIdentity,decimals=assetId==='USDC'?6:18;
  const assets=identity.assets.filter((asset)=>asset.assetId===assetId&&asset.kind==='erc20'&&asset.chainId===identity.localChainId&&asset.decimals===decimals);
  if(assets.length!==1)return stop('release_binding_mismatch');
  const address=addr(assets[0]!.address);if(!address)return stop('release_binding_mismatch');return address
}
/**
 * AICODE-NOTE: The pinned runtime manifest names public ERC-20 addresses at funding.token and
 * the two pool token0/token1 pairs. Exempt only those exact release-bound scanner-copy fields.
 */
export function parsePinnedRuntimeManifest(bytes:Buffer,release:ValidatedTaskRelease):J{
  let value:unknown;try{value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes)) as unknown}catch{return stop('release_binding_mismatch')}
  if(!rec(value))return stop('release_binding_mismatch');
  const usdc=releasedAssetAddress(release,'USDC'),weth=releasedAssetAddress(release,'WETH');
  if(usdc===weth)return stop('release_binding_mismatch');
  const funding=rec(value.funding)?value.funding:null,observedFundingToken=funding?addr(funding.token):null;
  if(!funding||observedFundingToken!==usdc)return stop('release_binding_mismatch');
  const scan:{[key:string]:unknown}={...value,funding:{...funding}};
  delete (scan.funding as J).token;
  if(rec(value.contracts)){
    const contracts=value.contracts,scanContracts:{[key:string]:unknown}={...contracts};
    for(const poolName of ['pool','pool3000'] as const){
      const pool=rec(contracts[poolName])?contracts[poolName] as J:null;
      if(!pool)continue;
      const hasToken0=Object.prototype.hasOwnProperty.call(pool,'token0'),hasToken1=Object.prototype.hasOwnProperty.call(pool,'token1');
      if(!hasToken0&&!hasToken1)continue;
      const token0=addr(pool.token0),token1=addr(pool.token1);
      if(!hasToken0||!hasToken1||!token0||!token1||token0===token1||
        !new Set([token0,token1]).has(usdc)||!new Set([token0,token1]).has(weth))return stop('release_binding_mismatch');
      const scanPool:{[key:string]:unknown}={...pool};delete scanPool.token0;delete scanPool.token1;scanContracts[poolName]=scanPool;
    }
    scan.contracts=scanContracts;
  }
  if(hasSecret(scan))return stop('release_binding_mismatch');
  return value
}type Manifest={sha256:string;json:J;policy:J;catalog:J[];assets:J[];resources:Map<string,Buffer>;byResource:Map<string,J>};
async function loadManifest(root:string,p:Prep,release:NonNullable<Awaited<ReturnType<TaskReleaseQuerySource['getValidatedReleaseRecord']>>>):Promise<Manifest>{
  const bytes=await readFile(root,'infrastructure/benchmark-environment/manifest.json','infrastructure/benchmark-environment/',MAX_MANIFEST,'release_binding_mismatch');
  const fileHash=sha(bytes);
  if(fileHash!==p.environment_manifest_sha256.toLowerCase()||fileHash!==release.manifest.executionIdentity.environmentManifestSha256.toLowerCase())
    stop('release_binding_mismatch');
  const json=parsePinnedRuntimeManifest(bytes,release);
  if(json.schemaVersion!=='bef-runtime-manifest/v1'||!rec(json.x402)||!Array.isArray((json.x402 as J).catalog)||
    !rec((json.x402 as J).eip712Domain))stop('release_binding_mismatch');
  const x=json.x402 as J,catalog:J[]=[],resources=new Map<string,Buffer>(),byResource=new Map<string,J>();
  const assets=release.manifest.executionIdentity.assets.map((a)=>({assetId:a.assetId,kind:a.kind,chainId:a.chainId,
    address:a.address?String(a.address).toLowerCase():null,decimals:a.decimals}));
  for(const d of x.catalog as unknown[]){
    if(!rec(d)||typeof d.resourceId!=='string'||typeof d.resourcePath!=='string'||!hash(d.resourceSha256)||typeof d.contentType!=='string'||
      typeof d.schema!=='string'||!Array.isArray(d.offers)||!rec(d.provenance))stop('release_binding_mismatch');
    if(String(d.resourcePath).startsWith('/')||String(d.resourcePath).includes('\\')||
      String(d.resourcePath).split('/').some((p)=>!p||p==='.'||p==='..'))stop('release_binding_mismatch');
    const raw=await readFile(root,String(d.resourcePath),'',MAX_RESOURCE,'release_binding_mismatch',String(d.resourceSha256));
    const payload=parseObject(raw,'release_binding_mismatch');
    if(payload.resourceId!==d.resourceId||payload.schema!==d.schema)stop('release_binding_mismatch');
    const offers=(d.offers as unknown[]).map((o)=>{
      if(!rec(o)||typeof o.id!=='string'||typeof o.amount!=='string'||! /^(?:0|[1-9][0-9]{0,77})$/.test(o.amount))stop('release_binding_mismatch');
      return {id:o.id,amount:o.amount}
    });
    const entry:J={resourceId:d.resourceId,resourceSha256:String(d.resourceSha256).toLowerCase(),contentType:d.contentType,schema:d.schema,
      dataType:typeof d.dataType==='string'?d.dataType:null,provenance:d.provenance,offers,payloadSha256:sha(raw),payloadByteCount:raw.length,
      payloadTopLevelFields:Object.keys(payload).sort()};
    catalog.push(entry);byResource.set(String(d.resourceId),entry);resources.set(String(d.resourceId),raw);
  }
  const policy:J={scheme:x.scheme,network:x.network,asset:typeof x.asset==='string'?x.asset.toLowerCase():x.asset,
    assetTransferMethod:x.assetTransferMethod,eip712Domain:x.eip712Domain};
  if(hasSecret({policy,catalog}))stop('release_binding_mismatch');
  return {sha256:fileHash,json,policy,catalog,assets,resources,byResource}
}
function caseComponents(c:TaskCase):Array<{componentId:string;resourceId:string}>{
  let list:unknown[]=[];if(c.taskId==='M1')list=[c.objective.component];else if(c.taskId==='H3')list=[c.objective.referenceComponent];
  else if(c.taskId==='M2')list=c.objective.catalog.map((offer)=>({componentId:offer.offerId,resourceId:offer.resourceId}));
  else if(c.taskId==='H1'||c.taskId==='U1')list=c.objective.requiredComponents;
  return list.map((v)=>{
    if(!rec(v))stop('release_binding_mismatch');
    return {componentId:String(v.componentId),resourceId:String(v.resourceId)}
  })
}

function safeResponse(kind:string,v:J):J{
  const pick=(x:unknown,keys:string[]):J=>{if(!rec(x))return {};const o:J={};for(const k of keys)if(x[k]!==undefined)o[k]=valueSafe(x[k]);return o};
  if(kind==='inspect_catalog'){
    const catalog=Array.isArray(v.catalog)?v.catalog.map((e)=>{const r=rec(e)?e:{},offers=Array.isArray(r.offers)?r.offers.map((o)=>{
      const z=rec(o)?o:{};return {id:z.id,payment:pick(z.payment,['scheme','network','asset','amount','payTo','transferMethod'])}}):[];
      return {...pick(r,['resourceId','resourceSha256','contentType','schema','dataType','provenance']),offers}}):[];
    return {...pick(v,['freeInspection','deliveryState']),catalog};
  }
  if(kind==='inspect_offer')return {...pick(v,['resourceId','resourceSha256','contentType','schema','dataType','provenance','freeInspection','deliveryState']),
    offers:Array.isArray(v.offers)?v.offers.map((o)=>{const z=rec(o)?o:{};return {id:z.id,payment:pick(z.payment,['scheme','network','asset','amount','payTo','transferMethod'])}}):[]};
  if(kind==='pay'||kind==='purchase')return {...pick(v,['operationId','status','deliveryHandle']),
    payment:pick(v.payment,['transactionHash','receiptStatus','amount','asset','network','payTo'])};
  return pick(v,['operationId','resourceId','contentType','contentHash']);
}
function safeProtocol(v:unknown):J|null{
  if(!rec(v))return null;const keys=['schema','resourceId','offerId','resourceSha256','amountUnits','network','asset','readHandle','acceptedTerms',
    'befOperationId','payOperationId','deliveryMatchesPinnedResource','befServerSdkVersions','ownerSignerSdkVersions','challengeResponseSha256',
    'challengeHeaderSha256','x402Version'];const o:J={};for(const k of keys)if(v[k]!==undefined)o[k]=valueSafe(v[k]);return o;
}
function actionPayloadHash(runId:string,index:number,cmd:TaskActionCommand):string{return hjson({runId,taskIndex:index,command:cmd})}
const EVIDENCE_KEYS=new Set(['schema','actionId','runId','taskIndex','actionSequence','ownerOperationId','actionKind','commandSha256','environmentId',
  'generationId','manifestSha256','applicationSourceSha256','idempotencyKey','status','reasonCode','requestStartedAt','requestFinishedAt','httpStatus',
  'befOperationId','transactionHash','outcome','receiptStatus','rawResponseSha256','participantToolResponse','receiptGasUsed','receiptEffectiveGasPriceWei',
  'paymentProtocol','environmentHealth']);
type Loaded={row:ActionRow;command:Extract<TaskActionCommand,{kind:'inspect_catalog'|'inspect_offer'|'purchase'|'pay'|'retrieve'}>;
  packet:PaidDataAction;response:J|null};
async function loadActions(root:string,run:J,p:Prep,runId:string,index:number,cutoff:number,source:ActionRow[],m:Manifest){
  if(source.length!==cutoff||cutoff>MAX_ACTIONS)stop('owner_cutoff_mismatch');
  const out:Loaded[]=[],seenOwnerOps=new Set<string>(),byId=new Map<string,Loaded>();
  for(let i=0;i<source.length;i++){
    const row=source[i]!,n=seq(row.action_sequence),er=evidenceRef(row.evidence_path&&row.evidence_hash?
      {path:row.evidence_path,sha256:row.evidence_hash,boundary:BOUNDARY}:null);
    if(n!==i+1||row.id!==row.id.toLowerCase()||!UUID.test(row.id)||row.run_id!==runId||row.task_index!==index||
      row.owner_id!==run.owner_id||row.agent_id!==run.agent_id||row.task_id!==p.task_id||row.environment_id!==p.environment_id||
      !er||!HASH.test(row.payload_hash)||row.history_revision!==row.receipt_revision||row.history_status!==row.receipt_status||
      row.history_evidence_hash!==row.evidence_hash||row.history_evidence_path!==row.evidence_path||
      (row.history_transaction_hash?.toLowerCase()||null)!==(row.transaction_hash?.toLowerCase()||null)||seenOwnerOps.has(row.operation_id))
      stop('action_evidence_unavailable');
    seenOwnerOps.add(row.operation_id);
    const parsed=TaskActionCommandSchema.safeParse(parse(row.command_json,'action_evidence_unavailable'));
    if(!parsed.success||parsed.data.kind!==row.action_kind||actionPayloadHash(runId,index,parsed.data)!==row.payload_hash.toLowerCase())
      stop('action_evidence_unavailable');
    if(!['observed','rejected_before_execution'].includes(row.receipt_status))stop('action_evidence_unavailable');
    if(!['inspect_catalog','inspect_offer','purchase','pay','retrieve'].includes(parsed.data.kind))continue;
    const cmd=parsed.data as Loaded['command'],bytes=await readFile(root,er.path,ACTION,MAX_EVIDENCE,'action_evidence_unavailable',er.sha256);
    let evidence:unknown;try{evidence=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes)) as unknown}catch{return stop('action_evidence_unavailable')}
    if(!rec(evidence))stop('action_evidence_unavailable');
    const response=rec(evidence.participantToolResponse)?evidence.participantToolResponse:null;
    const protocol=rec(evidence.paymentProtocol)?evidence.paymentProtocol:null;
    const scrub=structuredClone(evidence);if(rec(scrub.participantToolResponse)){delete scrub.participantToolResponse.content;delete scrub.participantToolResponse.contentBytes}
    const befId=typeof evidence.befOperationId==='string'&&UUID.test(evidence.befOperationId)?evidence.befOperationId.toLowerCase():null;
    const tx=txHash(evidence.transactionHash),rawHash=hash(evidence.rawResponseSha256);
    if(hasSecret(scrub)||Object.keys(evidence).some((k)=>!EVIDENCE_KEYS.has(k))||evidence.schema!=='bef-task-action-observation-v1'||
      evidence.actionId!==row.id||evidence.runId!==runId||Number(evidence.taskIndex)!==index||
      String(evidence.actionSequence)!==String(n)||evidence.ownerOperationId!==row.operation_id||evidence.actionKind!==cmd.kind||
      evidence.commandSha256!==row.payload_hash.toLowerCase()||evidence.environmentId!==p.environment_id||evidence.generationId!==p.generation_id||
      evidence.manifestSha256!==p.environment_manifest_sha256.toLowerCase()||evidence.applicationSourceSha256!==p.application_source_hash.toLowerCase()||
      evidence.idempotencyKey!=='task-action-'+row.id||evidence.status!==row.receipt_status)stop('action_evidence_unavailable');
    if(row.receipt_status==='observed'&&(!response||!rawHash))stop('action_evidence_unavailable');
    if(row.receipt_status==='rejected_before_execution'&&(response||tx||row.transaction_hash!==null))stop('action_evidence_unavailable');
    if((cmd.kind==='inspect_catalog'||cmd.kind==='inspect_offer')&&row.receipt_status==='observed'&&
      (!response||!readOnlyToolResponseMatches(cmd,response)||protocol!==null))stop('action_evidence_unavailable');
    if(cmd.kind==='pay'&&row.receipt_status==='observed'&&(!response||!protocol||!befId||
      protocol.schema!=='bef-x402-split-payment-observation-v1'||protocol.befOperationId!==befId||response.operationId!==befId||
      response.status!=='payment_confirmed'||response.deliveryHandle!==befId||!rec(response.payment)||
      txHash(response.payment.transactionHash)!==tx||row.transaction_hash?.toLowerCase()!==tx))stop('action_evidence_unavailable');
    let retrieved:PaidDataAction['retrievedContent']=null;
    if(cmd.kind==='retrieve'&&row.receipt_status==='observed'){
      if(!response||!protocol||!befId||protocol.schema!=='bef-x402-retrieve-observation-v1'||protocol.payOperationId!==befId||
        protocol.deliveryMatchesPinnedResource!==true||typeof response.contentBytes!=='string'||typeof response.resourceId!=='string'||
        typeof response.contentType!=='string'||typeof response.contentHash!=='string'||!rec(response.content))stop('action_evidence_unavailable');
      const data=Buffer.from(response.contentBytes,'base64'),contentSha=sha(data),definition=m.byResource.get(response.resourceId);
      if(!definition||data.length<1||data.length>MAX_RESOURCE||data.toString('base64')!==response.contentBytes||
        contentSha!==response.contentHash.toLowerCase()||contentSha!==String(definition.resourceSha256).toLowerCase()||
        response.contentType!==definition.contentType)stop('action_evidence_unavailable');
      let decoded:unknown;try{decoded=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(data)) as unknown}catch{return stop('action_evidence_unavailable')}
      const expected=JSON.parse(m.resources.get(response.resourceId)!.toString('utf8')) as unknown;
      if(canonicalTaskJson(decoded)!==canonicalTaskJson(response.content)||canonicalTaskJson(decoded)!==canonicalTaskJson(expected))
        stop('action_evidence_unavailable');
      retrieved={payloadSchemaVersion:'bef-delivery-envelope/v1',resourceSchema:String(definition.schema),resourceId:response.resourceId,contentType:response.contentType,contentSha256:contentSha,byteCount:data.length,validJson:true};
    }
    if(['inspect_catalog','inspect_offer','retrieve'].includes(cmd.kind)&&row.transaction_hash!==null)stop('action_evidence_unavailable');
    const packet:PaidDataAction={actionId:row.id,actionSequence:n,ownerOperationId:row.operation_id,actionKind:cmd.kind,
      commandSha256:row.payload_hash.toLowerCase(),receiptStatus:row.receipt_status as PaidDataAction['receiptStatus'],actionEvidence:er,
      befOperationId:befId,transactionHash:tx,rawResponseSha256:rawHash,safeResponse:response?safeResponse(cmd.kind,response):null,
      paymentProtocol:safeProtocol(protocol),retrievedContent:retrieved};
    const item:Loaded={row,command:cmd,packet,response};out.push(item);byId.set(row.id,item);
  }
  for(const item of out){
    if(item.command.kind==='pay'&&item.packet.receiptStatus==='observed'){
      const offer=byId.get(item.command.offerReadActionId);
      if(!offer||!['inspect_catalog','inspect_offer'].includes(offer.command.kind)||offer.packet.actionSequence>=item.packet.actionSequence||
        !item.packet.paymentProtocol||item.packet.paymentProtocol.resourceId!==item.command.resourceId||
        item.packet.paymentProtocol.offerId!==item.command.offerId||!rec(item.packet.paymentProtocol.readHandle)||
        !rec(item.packet.paymentProtocol.acceptedTerms))stop('action_evidence_unavailable');
    }
    if(item.command.kind==='retrieve'&&item.packet.receiptStatus==='observed'){
      const pay=byId.get(item.command.payActionId);
      if(!pay||pay.command.kind!=='pay'||pay.packet.receiptStatus!=='observed'||pay.packet.actionSequence>=item.packet.actionSequence||
        pay.packet.befOperationId!==item.packet.befOperationId||pay.packet.ownerOperationId===item.packet.ownerOperationId)
        stop('action_evidence_unavailable');
    }
  }
  return {items:out,allCount:source.length}
}

async function captureCensus(port:BefPaidDataReadOnlyPostgresPort,env:string,generation:string):Promise<{session:J;census:Census}>{
  try{return await port.withRepeatableRead(async(query)=>{
    const sess=getRows(await query("SELECT current_user current_user,session_user session_user,current_database() database_name,"+
      "current_setting('transaction_read_only') transaction_read_only,current_setting('transaction_isolation') transaction_isolation,"+
      "(SELECT rolsuper FROM pg_roles WHERE rolname=current_user) rolsuper,(SELECT rolbypassrls FROM pg_roles WHERE rolname=current_user) rolbypassrls,"+
      "has_schema_privilege(current_user,'public','CREATE') schema_create"),'observer_census_unavailable');
    const tables=['bef_environment','bef_generation','bef_operation','bef_payment','bef_delivery','bef_transaction_cost','bef_x402_observation'];
    const priv=getRows(await query("SELECT table_name,has_table_privilege(current_user,'public.'||table_name,'SELECT') can_select,"+
      "has_table_privilege(current_user,'public.'||table_name,'INSERT') can_insert,has_table_privilege(current_user,'public.'||table_name,'UPDATE') can_update,"+
      "has_table_privilege(current_user,'public.'||table_name,'DELETE') can_delete,has_table_privilege(current_user,'public.'||table_name,'TRUNCATE') can_truncate "+
      "FROM unnest(ARRAY['"+tables.join("','")+"']) table_name"),'observer_census_unavailable');
    const byTable=new Map(priv.map((x)=>[String(x.table_name),x])),s=sess[0];
    if(sess.length!==1||!s||s.current_user!=='bef_observer'||s.session_user!=='bef_observer'||s.transaction_read_only!=='on'||
      s.transaction_isolation!=='repeatable read'||s.rolsuper!==false||s.rolbypassrls!==false||s.schema_create!==false||
      tables.some((name)=>{const p=byTable.get(name);return !p||p.can_select!==true||p.can_insert!==false||p.can_update!==false||p.can_delete!==false||p.can_truncate!==false}))
      stop('observer_role_invalid');
    const session={currentUser:'bef_observer',sessionUser:'bef_observer',databaseName:String(s.database_name),transactionReadOnly:'on',
      transactionIsolation:'repeatable read',superuser:false,bypassRls:false};
    const gen=getRows(await query("SELECT g.generation_id::text,g.env_id,g.participant_id,g.payer_address,trim(g.manifest_sha256) manifest_sha256,"+
      "g.status,g.resource_variant,g.expires_at::text,g.fenced_at::text,e.chain_id::text,e.node_identity,trim(e.manifest_sha256) environment_manifest_sha256 "+
      "FROM bef_generation g JOIN bef_environment e ON e.env_id=g.env_id WHERE g.env_id=$1 AND g.generation_id=$2::uuid",[env,generation]),
      'observer_census_unavailable');
    if(gen.length!==1)stop('observer_census_unavailable');
    const ops=getRows(await query("SELECT operation_id::text,env_id,generation_id::text,participant_id,idempotency_key_sha256,"+
      "trim(request_sha256) request_sha256,operation_kind,status,receipt_status,transaction_hash,trim(response_sha256) response_sha256,"+
      "started_at::text,completed_at::text,selected_offer_id,selected_amount_units::text,selected_resource_id,"+
      "trim(selected_resource_sha256) selected_resource_sha256,payment_response_mode FROM bef_operation "+
      "WHERE env_id=$1 AND generation_id=$2::uuid ORDER BY started_at,operation_id LIMIT 2049",[env,generation]),'observer_census_unavailable');
    const payments=getRows(await query("SELECT payment_id::text,operation_id::text,env_id,generation_id::text,payer_address,network,asset_address,"+
      "amount_units::text,facilitator_address,transaction_hash,receipt_status,token_delta_units::text,observed_at::text,"+
      "payer_balance_before::text,payer_balance_after::text,facilitator_balance_before::text,facilitator_balance_after::text "+
      "FROM bef_payment WHERE env_id=$1 AND generation_id=$2::uuid ORDER BY observed_at,payment_id LIMIT 2049",[env,generation]),'observer_census_unavailable');
    const deliveries=getRows(await query("SELECT d.delivery_id::text,d.operation_id::text,o.env_id,o.generation_id::text,d.resource_id,"+
      "trim(d.content_sha256) content_sha256,d.content_bytes::text byte_count,d.delivered_at::text FROM bef_delivery d "+
      "JOIN bef_operation o ON o.operation_id=d.operation_id WHERE o.env_id=$1 AND o.generation_id=$2::uuid "+
      "ORDER BY d.delivered_at,d.delivery_id LIMIT 2049",[env,generation]),'observer_census_unavailable');
    const costs=getRows(await query("SELECT operation_id::text,env_id,generation_id::text,transaction_hash,payer_address,payer_role,receipt_status,"+
      "transaction_from,receipt_from,receipt_block_number::text,receipt_block_hash,gas_used::text,effective_gas_price_wei::text,gas_cost_wei::text,"+
      "modeled_gas_fee_usdc_units::text,manifest_sha256,created_at::text FROM bef_transaction_cost "+
      "WHERE env_id=$1 AND generation_id=$2::uuid ORDER BY transaction_hash LIMIT 2049",[env,generation]),'observer_census_unavailable');
    const x=ops.length?getRows(await query("SELECT observation_id::text,env_id,generation_id::text,operation_id::text,variant_id,phase,request_sha256,"+
      "safe_request->'paymentRequirements' payment_requirements,safe_request->'paymentPayload'->>'x402Version' x402_version,"+
      "response_sha256,outcome,transaction_hash,observed_at::text FROM bef_x402_observation WHERE env_id=$1 AND generation_id=$2::uuid "+
      "ORDER BY observed_at,observation_id LIMIT 2049",[env,generation]),'observer_census_unavailable'):[];
    if([ops,payments,deliveries,costs,x].some((a)=>a.length>MAX_ROWS))stop('observer_census_unavailable');
    const x402=x.map((row)=>{
      const req=parse(row.payment_requirements,'observer_census_unavailable');if(!rec(req))stop('observer_census_unavailable');
      const extra=rec(req.extra)?req.extra:{};
      return {...project(row,['observation_id','env_id','generation_id','operation_id','variant_id','phase','request_sha256','x402_version',
        'response_sha256','outcome','transaction_hash','observed_at']),
        requirements:{scheme:req.scheme,network:req.network,asset:req.asset,amount:req.amount,payTo:req.payTo,
          maxTimeoutSeconds:req.maxTimeoutSeconds===undefined?null:String(req.maxTimeoutSeconds),
          extra:{assetTransferMethod:extra.assetTransferMethod,paymentFlow:extra.paymentFlow,name:extra.name,version:extra.version}}};
    });
    const census:Census={generation:project(gen[0]!,['generation_id','env_id','participant_id','payer_address','manifest_sha256','status',
        'resource_variant','expires_at','fenced_at','chain_id','node_identity','environment_manifest_sha256']),
      operations:ops.map((r)=>project(r,['operation_id','env_id','generation_id','participant_id','idempotency_key_sha256','request_sha256','operation_kind',
        'status','receipt_status','transaction_hash','response_sha256','started_at','completed_at','selected_offer_id','selected_amount_units',
        'selected_resource_id','selected_resource_sha256','payment_response_mode'])),
      payments:payments.map((r)=>project(r,['payment_id','operation_id','env_id','generation_id','payer_address','network','asset_address','amount_units',
        'facilitator_address','transaction_hash','receipt_status','token_delta_units','observed_at','payer_balance_before','payer_balance_after',
        'facilitator_balance_before','facilitator_balance_after'])),
      deliveries:deliveries.map((r)=>project(r,['delivery_id','operation_id','env_id','generation_id','resource_id','content_sha256','byte_count','delivered_at'])),
      costs:costs.map((r)=>project(r,['operation_id','env_id','generation_id','transaction_hash','payer_address','payer_role','receipt_status',
        'transaction_from','receipt_from','receipt_block_number','receipt_block_hash','gas_used','effective_gas_price_wei','gas_cost_wei',
        'modeled_gas_fee_usdc_units','manifest_sha256','created_at'])),x402Observations:x402};
    if(hasSecret(census)||Buffer.byteLength(canonicalTaskJson(census),'utf8')>MAX_PACKET)stop('observer_census_unavailable');
    return {session,census}
  })}catch(e){if(e instanceof Unavailable)throw e;stop('observer_census_unavailable')}
}

class RpcRecorder{
  constructor(private readonly port:BefPaidDataReadOnlyRpcPort){}
  async get(method:string,params:readonly unknown[]):Promise<unknown>{
    if(!['eth_chainId','eth_blockNumber','eth_getBlockByNumber','eth_getTransactionByHash','eth_getTransactionReceipt'].includes(method))
      stop('rpc_observation_unavailable');
    let value:unknown;try{value=await this.port.request(method,params)}catch{return stop('rpc_observation_unavailable')}
    try{if(Buffer.byteLength(canonicalTaskJson(value),'utf8')>4*1024*1024)stop('rpc_observation_unavailable')}
    catch(e){if(e instanceof Unavailable)throw e;stop('rpc_observation_unavailable')}
    return value
  }
}
function block(v:unknown,expected?:bigint):{number:string;hash:string}{
  if(!rec(v))stop('rpc_observation_unavailable');const n=qty(v.number),h=txHash(v.hash);
  if(n===null||!h||(expected!==undefined&&n!==expected))stop('rpc_observation_unavailable');return {number:n.toString(),hash:h}
}
function topicAddress(v:unknown):string|null{if(typeof v!=='string'||!/^0x[0-9a-f]{64}$/i.test(v))return null;return addr('0x'+v.slice(-40))}
async function paymentEffects(rpc:RpcRecorder,payments:J[],costs:J[],actions:{row:ActionRow;packet:PaidDataAction}[],assets:J[],
  participant:string,manifestHash:string,head:bigint):Promise<J[]>{
  const out:J[]=[];
  for(const payment of payments){
    const operationId=String(payment.operation_id).toLowerCase(),transactionHash=txHash(payment.transaction_hash);
    const linked=actions.filter((a)=>a.packet.actionKind==='pay'&&a.packet.receiptStatus==='observed'&&a.packet.befOperationId===operationId);
    const base:J={operationId,paymentId:String(payment.payment_id).toLowerCase(),transactionHash,sourceOwnerActionIds:linked.map((a)=>a.row.id),
      verification:'unknown'};
    if(!transactionHash){out.push({...base,reasonCode:'payment_transaction_hash_missing'});continue}
    const [rawTx,rawReceipt]=await Promise.all([rpc.get('eth_getTransactionByHash',[transactionHash]),rpc.get('eth_getTransactionReceipt',[transactionHash])]);
    if(!rec(rawTx)||!rec(rawReceipt)||!Array.isArray(rawReceipt.logs)||rawReceipt.logs.length>MAX_ROWS){
      out.push({...base,reasonCode:'rpc_transaction_or_receipt_unavailable'});continue}
    const gotHash=txHash(rawTx.hash),from=addr(rawTx.from),to=addr(rawTx.to),number=qty(rawTx.blockNumber),blockHash=txHash(rawTx.blockHash);
    const nonce=qty(rawTx.nonce),value=qty(rawTx.value),input=rawTx.input;
    const receiptHash=txHash(rawReceipt.transactionHash),receiptNumber=qty(rawReceipt.blockNumber),receiptBlockHash=txHash(rawReceipt.blockHash);
    const receiptIndex=qty(rawReceipt.transactionIndex),receiptFrom=addr(rawReceipt.from),receiptTo=addr(rawReceipt.to);
    const receiptStatus=qty(rawReceipt.status),gas=qty(rawReceipt.gasUsed),gasPrice=qty(rawReceipt.effectiveGasPrice);
    if(gotHash!==transactionHash||!from||!to||number===null||number>head||!blockHash||nonce===null||value===null||typeof input!=='string'||
      receiptHash!==transactionHash||receiptNumber!==number||receiptBlockHash!==blockHash||receiptIndex===null||receiptFrom!==from||
      receiptTo!==to||receiptStatus!==1n||gas===null||gasPrice===null){
      out.push({...base,verification:'contradictory',reasonCode:'rpc_transaction_receipt_mismatch'});continue}
    const token=addr(payment.asset_address),payer=addr(payment.payer_address),facilitator=addr(payment.facilitator_address);
    const asset=assets.find((a)=>a.kind==='erc20'&&addr(a.address)===token);
    if(!token||!payer||!facilitator||!asset){out.push({...base,reasonCode:'bef_payment_asset_unbound'});continue}
    const transfers:J[]=[];let badLog=false;
    for(const log of rawReceipt.logs){
      if(!rec(log)||!Array.isArray(log.topics)||String(log.topics[0]).toLowerCase()!==TRANSFER_TOPIC)continue;
      const logToken=addr(log.address),logAsset=assets.find((a)=>a.kind==='erc20'&&addr(a.address)===logToken);
      if(!logAsset||log.topics.length!==3)continue;
      const sender=topicAddress(log.topics[1]),recipient=topicAddress(log.topics[2]);
      if(sender!==participant&&recipient!==participant)continue;
      if(txHash(log.transactionHash)!==transactionHash||qty(log.blockNumber)!==receiptNumber||txHash(log.blockHash)!==receiptBlockHash||
        qty(log.transactionIndex)!==receiptIndex){badLog=true;break}
      try{transfers.push(decodeM1TransferLog(log,logToken!,String(logAsset.assetId),participant))}catch{badLog=true;break}
    }
    if(badLog){out.push({...base,verification:'contradictory',reasonCode:'rpc_transfer_log_mismatch'});continue}
    const matching=transfers.filter((t)=>t.assetId===asset.assetId&&t.from===participant&&t.to===facilitator&&
      String(t.amountUnits)===String(payment.amount_units));
    const costRows=costs.filter((c)=>String(c.operation_id).toLowerCase()===operationId),cost=costRows.length===1?costRows[0]:null;
    const gasCost=(gas*gasPrice).toString();
    const costMatches=Boolean(cost&&cost.payer_role==='facilitator'&&addr(cost.payer_address)===from&&addr(cost.transaction_from)===from&&
      addr(cost.receipt_from)===receiptFrom&&cost.receipt_status==='success'&&String(cost.receipt_block_number)===receiptNumber!.toString()&&
      txHash(cost.receipt_block_hash)===receiptBlockHash&&String(cost.gas_used)===gas.toString()&&
      String(cost.effective_gas_price_wei)===gasPrice.toString()&&String(cost.gas_cost_wei)===gasCost&&
      String(cost.manifest_sha256).toLowerCase()===manifestHash&&dec(cost.modeled_gas_fee_usdc_units)!==null);
    const amount=dec(payment.amount_units),delta=dec(payment.token_delta_units);
    const balances=amount!==null&&delta===amount&&dec(payment.payer_balance_before)!==null&&dec(payment.payer_balance_after)!==null&&
      BigInt(String(payment.payer_balance_before))-BigInt(String(payment.payer_balance_after))===amount&&
      dec(payment.facilitator_balance_before)!==null&&dec(payment.facilitator_balance_after)!==null&&
      BigInt(String(payment.facilitator_balance_after))-BigInt(String(payment.facilitator_balance_before))===amount;
    const effect=from===facilitator&&to===token&&value===0n&&payer===participant&&payment.receipt_status==='success'&&
      matching.length===1&&balances;
    out.push({...base,verification:effect&&costMatches?'observed':effect?'partial':'contradictory',
      transaction:{hash:transactionHash,from,to,value:value.toString(),nonce:nonce.toString(),blockNumber:number.toString(),blockHash,
        inputSha256:sha(input)},
      receipt:{transactionHash,transactionIndex:receiptIndex.toString(),blockNumber:receiptNumber.toString(),blockHash:receiptBlockHash,
        status:'success',gasUsed:gas.toString(),effectiveGasPriceWei:gasPrice.toString(),logsSha256:hjson(rawReceipt.logs)},
      decodedTransfers:transfers,cost:{present:cost!==null,matchesRpcReceipt:costMatches,gasCostWei:gasCost},
      payment:{assetAddress:token,amountUnits:String(payment.amount_units),payerAddress:payer,facilitatorAddress:facilitator,balancesMatch:balances},
      reasonCode:effect?(costMatches?null:'cost_record_unavailable_or_mismatch'):'payment_effect_mismatch'});
  }
  return out
}
function checkDeliveries(actions:{row:ActionRow;packet:PaidDataAction;response:J|null}[],census:Census):void{
  const ids=new Set<string>();for(const d of census.deliveries){const id=String(d.delivery_id).toLowerCase();
    if(!UUID.test(id)||ids.has(id))stop('rpc_mapping_incomplete');ids.add(id)}
  const byOperation=new Map<string,J[]>();for(const d of census.deliveries){
    const id=String(d.operation_id).toLowerCase(),list=byOperation.get(id)||[];list.push(d);byOperation.set(id,list)}
  for(const action of actions.filter((a)=>a.packet.actionKind==='retrieve'&&a.packet.receiptStatus==='observed')){
    const id=String(action.packet.befOperationId).toLowerCase(),matches=byOperation.get(id)||[],content=action.packet.retrievedContent;
    if(matches.length!==1||!content||!action.response)stop('rpc_mapping_incomplete');
    const delivery=matches[0]!;
    if(delivery.resource_id!==content.resourceId||String(delivery.content_sha256).toLowerCase()!==content.contentSha256||
      String(delivery.byte_count)!==String(content.byteCount))stop('rpc_mapping_incomplete');
    const safe=action.packet.safeResponse||{};safe.deliveryId=String(delivery.delivery_id);action.packet.safeResponse=safe;
  }
}
function requestHash(action:{command:TaskActionCommand;packet:PaidDataAction},environmentId:string):string|null{
  if(action.command.kind!=='pay'||!action.packet.paymentProtocol)return null;
  const protocol=action.packet.paymentProtocol;
  if(!rec(protocol.readHandle)||!rec(protocol.acceptedTerms))return null;
  return splitPayRequestSha256(environmentId,{resourceId:action.command.resourceId,offerId:action.command.offerId,
    readHandle:protocol.readHandle,acceptedTerms:protocol.acceptedTerms});
}
function validateOperationLinks(census:Census,actions:{row:ActionRow;command:TaskActionCommand;packet:PaidDataAction}[],
  env:string,generation:string,participantId:string,manifest:Manifest):string[]{
  const issues:string[]=[],operationMap=new Map(census.operations.map((o)=>[String(o.operation_id).toLowerCase(),o]));
  if(operationMap.size!==census.operations.length)issues.push('duplicate_bef_operation_id');
  for(const a of actions){
    const id=a.packet.befOperationId?.toLowerCase()||null,idem=sha('task-action-'+a.row.id);
    if(a.command.kind==='pay'&&a.packet.receiptStatus==='rejected_before_execution'){
      const byKey=census.operations.filter((op)=>String(op.idempotency_key_sha256).toLowerCase()===idem),op=id?operationMap.get(id):byKey[0];
      if(byKey.length>1||(id!==null&&!op)||(op&&byKey[0]&&String(op.operation_id).toLowerCase()!==String(byKey[0].operation_id).toLowerCase()))
        issues.push('rejected_payment_operation_mismatch');
      if(op){
        const oid=String(op.operation_id).toLowerCase(),protocol=a.packet.paymentProtocol;
        if(op.env_id!==env||String(op.generation_id)!==generation||op.participant_id!==participantId||
          String(op.idempotency_key_sha256).toLowerCase()!==idem||op.operation_kind!=='purchase'||
          !['awaiting_payment','rejected'].includes(String(op.status))||op.receipt_status!=='not_submitted'||op.transaction_hash!==null||
          op.payment_response_mode!=='deferred_delivery'||census.payments.some((v)=>String(v.operation_id).toLowerCase()===oid)||
          census.deliveries.some((v)=>String(v.operation_id).toLowerCase()===oid)||census.costs.some((v)=>String(v.operation_id).toLowerCase()===oid)||
          census.x402Observations.some((v)=>String(v.operation_id).toLowerCase()===oid))issues.push('rejected_payment_has_effect');
        if(protocol&&(!rec(protocol)||op.selected_offer_id!==a.command.offerId||op.selected_resource_id!==a.command.resourceId||
          String(op.selected_resource_sha256).toLowerCase()!==String(protocol.resourceSha256).toLowerCase()||
          String(op.selected_amount_units)!==String(protocol.amountUnits)||String(op.request_sha256).toLowerCase()!==String(requestHash(a,env))))
          issues.push('rejected_payment_operation_mismatch');
        if(op.response_sha256!==null&&String(op.response_sha256).toLowerCase()!==String(a.packet.rawResponseSha256).toLowerCase())
          issues.push('rejected_payment_response_hash_mismatch');
      }else if(census.payments.some((v)=>String(v.operation_id).toLowerCase()===(id||''))||
        census.deliveries.some((v)=>String(v.operation_id).toLowerCase()===(id||''))||census.costs.some((v)=>String(v.operation_id).toLowerCase()===(id||'')))
        issues.push('rejected_payment_has_effect');
      continue;
    }
    if(!id){if(a.packet.receiptStatus==='observed'&&['pay','retrieve'].includes(a.command.kind))issues.push('owner_action_bef_operation_missing');continue}
    const op=operationMap.get(id);
    if(!op){issues.push('owner_action_bef_operation_missing');continue}
    if(op.env_id!==env||String(op.generation_id)!==generation||op.participant_id!==participantId)
      issues.push('operation_binding_mismatch');
    if(a.command.kind==='pay'){
      const command=a.command,protocol=a.packet.paymentProtocol,expected=requestHash(a,env),definition=manifest.byResource.get(command.resourceId);
      const offer=definition&&Array.isArray(definition.offers)?definition.offers.find((v)=>rec(v)&&v.id===command.offerId):null;
      const response=a.packet.safeResponse,paymentResponse=rec(response?.payment)?response.payment:null;
      const accepted=rec(protocol?.acceptedTerms)?protocol.acceptedTerms:null;
      const paymentRows=census.payments.filter((v)=>String(v.operation_id).toLowerCase()===id);
      if(op.operation_kind!=='purchase'||!['settled','delivered'].includes(String(op.status))||op.receipt_status!=='success'||
        op.payment_response_mode!=='deferred_delivery'||String(op.idempotency_key_sha256).toLowerCase()!==idem||
        String(op.transaction_hash).toLowerCase()!==String(a.packet.transactionHash).toLowerCase()||
        String(op.response_sha256).toLowerCase()!==String(a.packet.rawResponseSha256).toLowerCase()||
        op.selected_resource_id!==a.command.resourceId||op.selected_offer_id!==a.command.offerId||!rec(protocol)||!expected||
        String(op.request_sha256).toLowerCase()!==expected.toLowerCase()||!definition||!rec(offer)||
        String(op.selected_resource_sha256).toLowerCase()!==String(definition.resourceSha256).toLowerCase()||
        String(protocol.resourceSha256).toLowerCase()!==String(definition.resourceSha256).toLowerCase()||
        String(op.selected_amount_units)!==String(protocol.amountUnits)||String(offer.amount)!==String(protocol.amountUnits)||
        !rec(paymentResponse)||String(paymentResponse.amount)!==String(protocol.amountUnits)||
        String(paymentResponse.network)!==String(protocol.network)||String(paymentResponse.network)!==String(manifest.policy.network)||
        addr(paymentResponse.asset)!==addr(protocol.asset)||addr(protocol.asset)!==addr(manifest.policy.asset)||
        addr(paymentResponse.payTo)!==addr(accepted?.payTo)||paymentRows.length>1)
        issues.push('payment_operation_mismatch');
      if(paymentRows.length===1){const payment=paymentRows[0]!;
        if(txHash(payment.transaction_hash)!==txHash(a.packet.transactionHash)||String(payment.amount_units)!==String(protocol?.amountUnits)||
          String(payment.network)!==String(protocol?.network)||addr(payment.asset_address)!==addr(protocol?.asset)||
          addr(payment.facilitator_address)!==addr(accepted?.payTo))issues.push('payment_record_mismatch');
      }
      const x402=census.x402Observations.filter((v)=>String(v.operation_id).toLowerCase()===id);
      if(x402.length&&(!rec(protocol)||!x402.some((v)=>rec(v.requirements)&&String(v.requirements.network)===String(protocol.network)&&
        addr(v.requirements.asset)===addr(protocol.asset)&&String(v.requirements.amount)===String(protocol.amountUnits)&&
        addr(v.requirements.payTo)===addr(accepted?.payTo))))issues.push('x402_requirements_mismatch');
    }
    if(a.command.kind==='retrieve'&&(op.operation_kind!=='purchase'||op.payment_response_mode!=='deferred_delivery'||
      !['settled','delivered'].includes(String(op.status))||op.receipt_status!=='success'))issues.push('retrieve_operation_mismatch');
    if(['inspect_catalog','inspect_offer'].includes(a.command.kind)&&
      (String(op.idempotency_key_sha256).toLowerCase()!==idem||op.transaction_hash!==null||
        String(op.response_sha256).toLowerCase()!==String(a.packet.rawResponseSha256).toLowerCase()))
      issues.push('read_operation_mismatch');
  }
  return issues
}type Context={run:J;taskCase:TaskCase;prep:Prep;cutoff:number;reconciled:number;closure:J;binding:J;
  preparation:{fixture:EvidenceReference;baseline:EvidenceReference;number:string;blockHash:string};manifest:Manifest;actions:Loaded[];
  actionCount:number;executionIdentity:J};
async function loadContext(deps:BefPaidDataObservationCollectorDependencies,target:{runId:string;taskIndex:number},tx:Tx):Promise<Context>{
  await tx.execute(sql.raw('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY'));
  const runSql="SELECT r.owner_id::text,r.agent_id::text,r.mode,r.task_ids,r.release_identity,r.manifest_hash,r.status run_status,"+
    "r.cancellation_reason,t.task_id,t.status task_status,t.closure_status,t.closure_id::text,t.closure_operation_id,t.closure_payload_hash,"+
    "t.closure_reason,t.action_cutoff_sequence::text action_cutoff_sequence,t.reconciled_action_sequence::text reconciled_action_sequence "+
    "FROM oid_benchmark_run r JOIN oid_run_task t ON t.run_id=r.id WHERE r.id='"+target.runId+"' AND t.task_index="+target.taskIndex;
  const runs=await ownerRows<J>(tx,runSql),run=runs[0];if(!run)stop('owner_cutoff_unavailable');
  const ids=parse(run.task_ids,'owner_cutoff_mismatch');
  const taskId=String(run.task_id);
  if(!['M1','M2','H1','H3','U1'].includes(taskId)||!['training','ranked'].includes(String(run.mode))||
    run.run_status!=='running'||run.cancellation_reason!==null||!Array.isArray(ids)||ids[target.taskIndex]!==taskId)stop('unsupported_task');
  if(run.task_status!=='active'||run.closure_status!=='closed'||typeof run.closure_id!=='string'||run.action_cutoff_sequence===null)
    stop('owner_cutoff_unavailable');
  const cutoff=seq(run.action_cutoff_sequence),reconciled=seq(run.reconciled_action_sequence);
  if(cutoff===null||reconciled===null||cutoff>MAX_ACTIONS)stop('owner_cutoff_mismatch');
  if(reconciled<cutoff)stop('reconciliation_pending');
  if(!UUID.test(run.closure_id))stop('owner_cutoff_mismatch');
  const closureRows=await ownerRows<J>(tx,"SELECT id::text,operation_id,payload_hash,reason,action_cutoff_sequence::text,"+
    "owner_id::text,agent_id::text FROM oid_run_task_closure WHERE id='"+run.closure_id+"' AND run_id='"+target.runId+
    "' AND task_index="+target.taskIndex);
  const closure=closureRows[0];
  if(!closure||closure.owner_id!==run.owner_id||closure.agent_id!==run.agent_id||seq(closure.action_cutoff_sequence)!==cutoff||
    closure.operation_id!==run.closure_operation_id||closure.payload_hash!==run.closure_payload_hash||closure.reason!==run.closure_reason)
    stop('owner_cutoff_mismatch');
  const prepSql="SELECT i.preparation_id::text,i.claim_id::text,i.lease_id::text,i.environment_id,i.release_identity,i.manifest_hash,"+
    "i.task_id,i.case_id,i.case_hash,i.initial_state_sha256,i.execution_identity_hash,i.environment_manifest_sha256,i.application_source_hash,"+
    "i.created_at,l.state lease_state,o.status observation_status,o.generation_id::text,o.participant_id,o.payer_address,"+
    "o.baseline_state_sha256,o.fixture_evidence,o.baseline_evidence FROM oid_task_preparation_intent i "+
    "JOIN oid_task_environment_lease l ON l.preparation_id=i.preparation_id AND l.lease_id=i.lease_id "+
    "JOIN LATERAL (SELECT status,generation_id,participant_id,payer_address,baseline_state_sha256,fixture_evidence,baseline_evidence "+
    "FROM oid_task_preparation_observation WHERE preparation_id=i.preparation_id ORDER BY revision DESC LIMIT 1) o ON true "+
    "WHERE i.run_id='"+target.runId+"' AND i.task_index="+target.taskIndex;
  const preps=await ownerRows<Prep>(tx,prepSql),prep=preps[0],participant=prep?addr(prep.payer_address):null;
  if(preps.length!==1||!prep||prep.lease_state!=='leased'||prep.observation_status!=='ready'||!prep.generation_id||!prep.participant_id||!participant||
    prep.task_id!==taskId||prep.release_identity!==run.release_identity||prep.manifest_hash!==run.manifest_hash||
    prep.baseline_state_sha256?.toLowerCase()!==prep.initial_state_sha256.toLowerCase())stop('preparation_unavailable');
  const bindings=await ownerRows<J>(tx,"SELECT env_id,generation_id::text,manifest_hash,application_source_hash,participant_id,payer_address "+
    "FROM oid_task_execution_binding WHERE run_id='"+target.runId+"' AND task_index="+target.taskIndex);
  const bindingRow=bindings[0];
  if(bindings.length!==1||!bindingRow||bindingRow.env_id!==prep.environment_id||bindingRow.generation_id!==prep.generation_id||
    String(bindingRow.manifest_hash).toLowerCase()!==prep.environment_manifest_sha256.toLowerCase()||
    String(bindingRow.application_source_hash).toLowerCase()!==prep.application_source_hash.toLowerCase()||
    bindingRow.participant_id!==prep.participant_id||addr(bindingRow.payer_address)!==participant)stop('preparation_unavailable');
  const release=await deps.taskReleaseSource.getValidatedReleaseRecord(String(run.release_identity),String(run.manifest_hash),tx);
  if(!release||release.releaseIdentity!==run.release_identity||release.manifestHash!==run.manifest_hash||
    release.manifest.releaseIdentity!==run.release_identity||release.manifest.manifestHash!==run.manifest_hash)
    stop('release_binding_mismatch');
  const caseList=release.manifest.cases[String(run.mode) as 'training'|'ranked'];
  const taskCase=caseList.find((c)=>c.caseId===prep.case_id&&c.taskId===taskId) as TaskCase|undefined;
  if(!taskCase||taskCase.caseHash!==prep.case_hash||taskCase.executionIdentityHash!==prep.execution_identity_hash||
    taskCase.initialState.stateSha256.toLowerCase()!==prep.initial_state_sha256.toLowerCase()||
    taskCase.executionIdentityHash!==release.manifest.executionIdentityHash)stop('release_binding_mismatch');
  const actionSql="SELECT a.id::text,a.run_id::text,a.task_index,a.owner_id::text,a.agent_id::text,a.task_id,a.environment_id,"+
    "a.action_sequence::text,a.operation_id,a.payload_hash,a.action_kind,a.command_json,r.receipt_revision,r.receipt_status,r.evidence_hash,r.evidence_path,r.transaction_hash,"+
    "h.revision history_revision,h.receipt_status history_status,h.evidence_hash history_evidence_hash,h.evidence_path history_evidence_path,"+
    "h.transaction_hash history_transaction_hash FROM oid_run_task_action a JOIN oid_run_task_action_receipt r ON r.action_id=a.id "+
    "LEFT JOIN LATERAL (SELECT revision,receipt_status,evidence_hash,evidence_path,transaction_hash FROM oid_run_task_action_reconciliation "+
    "WHERE action_id=a.id ORDER BY revision DESC LIMIT 1) h ON true WHERE a.run_id='"+target.runId+"' AND a.task_index="+target.taskIndex+
    " ORDER BY a.action_sequence";
  const actionRows=await ownerRows<ActionRow>(tx,actionSql);
  const m=await loadManifest(deps.repositoryRoot,prep,release);
  const preparation=await preparationEvidence(deps.repositoryRoot,prep,target.runId,target.taskIndex,taskCase);
  const loaded=await loadActions(deps.repositoryRoot,run,prep,target.runId,target.taskIndex,cutoff,actionRows,m);
  const taskBinding={ownerId:run.owner_id,agentId:run.agent_id,runId:target.runId,environmentId:prep.environment_id,
    releaseIdentity:run.release_identity,manifestHash:run.manifest_hash,caseId:taskCase.caseId,caseHash:taskCase.caseHash,
    rubricHash:taskCase.rubricHash,taskId:taskCase.taskId};
  return {run,taskCase,prep,cutoff,reconciled,closure,binding:taskBinding,preparation,manifest:m,actions:loaded.items,
    actionCount:loaded.allCount,executionIdentity:release.manifest.executionIdentity as unknown as J}
}
async function collectLocked(deps:BefPaidDataObservationCollectorDependencies,target:{runId:string;taskIndex:number},tx:Tx):Promise<BefPaidDataCollectionResult>{
  const c=await loadContext(deps,target,tx),p=c.prep,participant=addr(p.payer_address);
  if(!participant)stop('preparation_unavailable');
  const postgres=deps.postgresByEnvironment[p.environment_id],rpcPort=deps.rpcByEnvironment[p.environment_id];
  if(!postgres||!rpcPort||postgres.environmentId!==p.environment_id||rpcPort.environmentId!==p.environment_id)stop('source_not_configured');
  const before=await captureCensus(postgres,p.environment_id,p.generation_id!);
  const generation=before.census.generation,local=rec(c.manifest.json.local)?c.manifest.json.local:null;
  if(generation.env_id!==p.environment_id||generation.generation_id!==p.generation_id||generation.participant_id!==p.participant_id||
    addr(generation.payer_address)!==participant||String(generation.chain_id)!==String(c.executionIdentity.localChainId)||
    generation.status!=='active'||generation.resource_variant!=='canonical'||
    String(generation.manifest_sha256).toLowerCase()!==p.environment_manifest_sha256.toLowerCase()||
    String(generation.environment_manifest_sha256).toLowerCase()!==p.environment_manifest_sha256.toLowerCase()||
    !local||generation.node_identity!==local.identity)stop('rpc_mapping_incomplete');
  const opIssues=validateOperationLinks(before.census,c.actions.map((a)=>({row:a.row,command:a.command,packet:a.packet})),
    p.environment_id,p.generation_id!,p.participant_id!,c.manifest);
  const rpc=new RpcRecorder(rpcPort),chain=qty(await rpc.get('eth_chainId',[]));
  if(chain===null||chain!==BigInt(String(c.executionIdentity.localChainId)))stop('rpc_identity_mismatch');
  const baseN=BigInt(c.preparation.number),baseline=block(await rpc.get('eth_getBlockByNumber',['0x'+baseN.toString(16),false]),baseN);
  if(baseline.hash!==c.preparation.blockHash)stop('rpc_mapping_incomplete');
  const head=qty(await rpc.get('eth_blockNumber',[]));if(head===null||head<baseN)stop('rpc_observation_unavailable');
  const finalBlock=block(await rpc.get('eth_getBlockByNumber',['0x'+head.toString(16),false]),head);
  const effects=await paymentEffects(rpc,before.census.payments,before.census.costs,c.actions.map((a)=>({row:a.row,packet:a.packet})),
    c.manifest.assets,participant,p.environment_manifest_sha256.toLowerCase(),head);
  checkDeliveries(c.actions.map((a)=>({row:a.row,packet:a.packet,response:a.response})),before.census);
  const after=await captureCensus(postgres,p.environment_id,p.generation_id!);
  if(before.session.databaseName!==after.session.databaseName||canonicalTaskJson(before.census)!==canonicalTaskJson(after.census)||
    after.census.generation.status!=='active')stop('observer_census_changed');
  const badDelivery=c.actions.some((a)=>a.packet.actionKind==='retrieve'&&a.packet.receiptStatus==='observed'&&!a.packet.safeResponse?.deliveryId);
  const effectStatus=effects.map((x)=>String(x.verification));
  const missingOwnerLinks=opIssues.includes('owner_action_bef_operation_missing');
  const contradiction=opIssues.some((issue)=>issue!=='owner_action_bef_operation_missing')||badDelivery||effectStatus.includes('contradictory');
  const observedPayIds=c.actions.filter((a)=>a.packet.actionKind==='pay'&&a.packet.receiptStatus==='observed'&&a.packet.befOperationId)
    .map((a)=>String(a.packet.befOperationId).toLowerCase());
  const missingPayment=observedPayIds.some((id)=>before.census.payments.filter((v)=>String(v.operation_id).toLowerCase()===id).length!==1);
  const missingX402=observedPayIds.some((id)=>!before.census.x402Observations.some((v)=>String(v.operation_id).toLowerCase()===id));
  const incomplete=missingOwnerLinks||missingPayment||missingX402||effectStatus.includes('unknown')||effectStatus.includes('partial');
  const observationCutoff=0;
  const coverage={actionCutoffSequence:c.cutoff,observationCutoffSequence:observationCutoff,ownerActionCount:c.actionCount,
    paidActionCount:c.actions.length,befPaymentCount:before.census.payments.length,deliveryCount:before.census.deliveries.length,
    costCount:before.census.costs.length,rpcPaymentProofCount:effects.filter((x)=>x.verification==='observed').length,
    status:contradiction?'contradictory' as const:incomplete?'partial' as const:'observed' as const};
  const packetValue:PaidDataCapturePacket={schemaVersion:'bts-paid-data-run-observation-capture/v1',classification:'run_bound_observations_candidate_not_grade',
    binding:c.binding as PaidDataCapturePacket['binding'],
    closure:{closureId:String(c.closure.id),actionCutoffSequence:c.cutoff,reconciledActionSequence:c.reconciled,
      reason:String(c.closure.reason),operationId:typeof c.closure.operation_id==='string'?c.closure.operation_id:null,
      payloadHash:String(c.closure.payload_hash).toLowerCase()},
    execution:{preparationId:p.preparation_id,leaseId:p.lease_id,generationId:p.generation_id!,environmentId:p.environment_id,
      environmentManifestHash:p.environment_manifest_sha256.toLowerCase(),applicationSourceHash:p.application_source_hash.toLowerCase(),
      executionIdentityHash:p.execution_identity_hash.toLowerCase(),initialStateSha256:p.initial_state_sha256.toLowerCase()},
    preparation:{fixtureEvidence:c.preparation.fixture,baselineEvidence:c.preparation.baseline,
      baselineBlockNumber:c.preparation.number,baselineBlockHash:c.preparation.blockHash},
    manifest:{sha256:c.manifest.sha256,paymentPolicy:c.manifest.policy,catalog:c.manifest.catalog,componentReferences:caseComponents(c.taskCase)},
    ownerActions:c.actions.map((a)=>a.packet),bef:{session:before.session,before:before.census,after:after.census,
      censusSha256:hjson(before.census)},rpc:{localChainId:chain.toString(),baselineBlock:baseline,finalBlock,paymentEffects:effects},coverage};
  let packet:PaidDataCapturePacket;try{packet=validatePaidDataCapturePacket(packetValue)}catch{return stop('capture_evidence_unavailable')}
  const actionResponses=new Map(c.actions.filter((a)=>a.response!==null).map((a)=>[a.row.id,a.response!]));
  const projectionContext={taskCase:c.taskCase,binding:c.binding as import('./task-evaluator.js').TaskEvidenceBinding,
    captureEvidence:{path:OBS+'pending.json',sha256:'0'.repeat(64),boundary:BOUNDARY},
    assets:c.manifest.assets as unknown as Array<{assetId:string;kind:'native'|'erc20';chainId:number;address:string|null}>,actionResponses};
  let projected:TaskObservationBundleCandidate;try{projected=projectPaidDataObservationBundle(packet,projectionContext)}catch{return stop('capture_evidence_unavailable')}
  packet.coverage.observationCutoffSequence=projected.observationCutoffSequence;
  try{packet=validatePaidDataCapturePacket(packet)}catch{return stop('capture_evidence_unavailable')}
  if(hasSecret(packet)||Buffer.byteLength(canonicalTaskJson(packet),'utf8')>MAX_PACKET)stop('capture_evidence_unavailable');
  let evidence:EvidenceReference|null;try{evidence=evidenceRef(await deps.evidenceSink.write(packet))}catch{return stop('capture_evidence_unavailable')}
  if(!evidence||!evidence.path.startsWith(OBS))stop('capture_evidence_unavailable');
  let paidDataCandidate:PaidDataObservationCandidate;try{paidDataCandidate=projectPaidDataCaptureCandidate(packet,c.taskCase)}catch{return stop('rpc_mapping_incomplete')}
  let candidate:TaskObservationBundleCandidate;try{candidate=projectPaidDataObservationBundle(packet,{...projectionContext,captureEvidence:evidence})}catch{return stop('rpc_mapping_incomplete')}
  const boundary={...paidDataCandidate.boundary,observationCutoffSequence:candidate.observationCutoffSequence};
  return {status:'candidate',candidate,paidDataCandidate,boundary,evidence,classification:'run_bound_observations_candidate_not_grade',packet}
}
export async function collectBefPaidDataObservationCandidate(deps:BefPaidDataObservationCollectorDependencies,
  target:{runId:string;taskIndex:number}):Promise<BefPaidDataCollectionResult>{
  if(!UUID.test(target.runId)||!Number.isSafeInteger(target.taskIndex)||target.taskIndex<0||target.taskIndex>11)return unavailable('invalid_target');
  try{return await deps.db.transaction(async(tx)=>collectLocked(deps,target,tx))}
  catch(e){if(e instanceof Unavailable)return unavailable(e.reasonCode);return unavailable('owner_cutoff_unavailable')}
}
