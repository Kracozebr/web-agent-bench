import {readBoundedDiagnosticText} from './mcp-diagnostics-io.mjs';
/** Native-side diagnostic projection and durable outbox. No raw transcript or credentials. */
import {createHash,randomUUID} from 'node:crypto';
import {DatabaseSync} from 'node:sqlite';
import {mkdir,lstat,realpath} from 'node:fs/promises';
import {resolve,relative,isAbsolute,sep} from 'node:path';
import {StringDecoder} from 'node:string_decoder';
import {statSync,readdirSync} from 'node:fs';

export const DIAGNOSTIC_ERROR_CODES=['UNKNOWN_ERROR','INVALID_ARGUMENTS','INPUT_VALIDATION_ERROR','INVALID_OPERATION_ID','INVALID_AGENT_ID','INVALID_RUN_ID','INVALID_TASK_INDEX','INVALID_TASK_ACTION','INVALID_ANSWER','ACTION_NOT_FOUND','TASK_CLOSED','TASK_DEADLINE','UNAUTHORIZED','FORBIDDEN','RATE_LIMITED','IDEMPOTENCY_CONFLICT','INTERNAL_ERROR','TRANSPORT_TIMEOUT','CONNECTION_REFUSED','CONNECTION_LOST','CLIENT_RUNTIME_ERROR','CLIENT_PARSE_ERROR','UNSUPPORTED_MCP_CLIENT_PROFILE','COMBINED_PURCHASE_UNAVAILABLE','DIAGNOSTICS_PARSER_FAILURE','DIAGNOSTICS_STORAGE_FAILURE','DIAGNOSTICS_QUOTA_EXCEEDED','CONFIGURATION_ERROR','CORRELATION_UNAVAILABLE','TASK_ACTION_NOT_FOUND','INVALID_TASK_TARGET','INVALID_TASK_ANSWER','AGENT_ACCESS_REVOKED','RUN_NOT_FOUND','MODE_NOT_ALLOWED','RUN_MODE_FENCED','PLATFORM_RECOVERY_IN_PROGRESS','TASK_RECONCILIATION_REQUIRED','TASK_NOT_FOUND','TASK_NOT_ACTIVE','TASK_DEADLINE_UNAVAILABLE','TASK_EXECUTION_IDENTITY_UNAVAILABLE','INVALID_ACTION_RECEIPT','ACTION_RECEIPT_CONFLICT','TASK_CUTOFF_CONFLICT','ACCEPTED_QUEUE_GLOBAL_CAPACITY','ACCEPTED_QUEUE_OWNER_LIMIT','ACCESS_ALREADY_REVOKED','ACCESS_REVISION_CONFLICT','AGENT_ACCESS_CHANGED','AGENT_BUDGET_EXCEEDED','AGENT_NOT_FOUND','BETA_ALREADY_CLOSED','BETA_BONUS_BALANCE_REQUIRED','CASH_CEILING_EXCEEDED','CASH_PERMISSION_REQUIRED','CONNECTION_INTENT_MISMATCH','CONNECTION_UNAVAILABLE','CREDENTIAL_EXISTS','DIAGNOSTICS_CASE_CONFLICT','DIAGNOSTICS_CASE_NOT_FOUND','DIAGNOSTICS_LINK_NOT_FOUND','DIAGNOSTICS_SEGMENT_CLOSED','DIAGNOSTICS_SEQUENCE_GAP','DIAGNOSTICS_UNAUTHORIZED','DIAGNOSTICS_UNAVAILABLE','DIAGNOSTIC_AUTHORIZATION_CAPACITY','DIAGNOSTIC_AUTH_REQUIRED','DIAGNOSTIC_ORIGIN_UNAVAILABLE','EXECUTOR_NOT_READY','GLOBAL_INTENT_CAPACITY','IMAGE_PROCESSING_FAILED','INSUFFICIENT_FUNDS','INVALID_ACTIONID','INVALID_AGENTID','INVALID_AMOUNT','INVALID_BETA_CLOSURE','INVALID_CANDIDATE_LIMIT','INVALID_CLAIMID','INVALID_COORDINATOR_CANCELLATION','INVALID_CREDENTIAL_INTENT','INVALID_DECISION','INVALID_DIAGNOSTICS','INVALID_DIAGNOSTIC_AUTHORIZATION','INVALID_EXPIRY','INVALID_FIELD','INVALID_INTENTID','INVALID_LIMIT','INVALID_MODE','INVALID_OAUTH_FLOW','INVALID_OAUTH_QUERY','INVALID_OWNERID','INVALID_PERMISSIONS','INVALID_RELEASE_EXPECTATION','INVALID_REPORT','INVALID_REPORT_BODY','INVALID_REPORT_CURSOR','INVALID_REPORT_ID','INVALID_REPORT_IMAGE','INVALID_REPORT_IMAGES','INVALID_REPORT_IMAGE_CHUNK','INVALID_REPORT_IMAGE_ID','INVALID_REPORT_IMAGE_UPLOAD','INVALID_REPORT_LINK','INVALID_REPORT_STATUS','INVALID_REPORT_TITLE','INVALID_REQUEST','INVALID_REVISION','INVALID_RUNID','INVALID_SELECTEDCONNECTIONID','INVALID_TASK_SELECTION','MISDIRECTED_REQUEST','MODE_NOT_AUTHORIZED','OAUTH_CALLBACK_INVALID','OAUTH_CLIENT_NOT_REGISTERED','OAUTH_CODE_ALREADY_BOUND','OAUTH_FLOW_COMPLETED','OAUTH_FLOW_EXPIRED','OAUTH_FLOW_MISMATCH','OAUTH_PROVIDER_REDIRECT_INVALID','OAUTH_PROVIDER_REDIRECT_MISSING','OAUTH_REQUEST_NOT_SUPPORTED','OPERATION_ID_CONFLICT','ORIGIN_NOT_ALLOWED','OWNER_NOT_ADMITTED','OWNER_NOT_FOUND','PENDING_INTENT_LIMIT','PINNED_RELEASE_UNAVAILABLE','PLATFORM_RECOVERY_NOT_EXHAUSTED','POLICY_CHANGED','PREPARED_EXECUTOR_HANDOFF_FAILED','REAUTHORIZATION_REQUIRED','RELEASE_INCOMPLETE','RELEASE_INVALID','RELEASE_UNAVAILABLE','REPORT_CONTAINS_CREDENTIAL_MATERIAL','REPORT_IMAGE_CHUNK_CONFLICT','REPORT_IMAGE_CHUNK_HASH_MISMATCH','REPORT_IMAGE_CHUNK_ORDER','REPORT_IMAGE_CONFLICT','REPORT_IMAGE_INTEGRITY_FAILED','REPORT_IMAGE_LIMIT','REPORT_IMAGE_NOT_FOUND','REPORT_IMAGE_ROLLING_QUOTA','REPORT_IMAGE_STAGING_LIMIT','REPORT_IMAGE_STORAGE_LIMIT','REPORT_IMAGE_STORAGE_LOW','REPORT_IMAGE_TOO_LARGE','REPORT_IMAGE_TYPE_UNSUPPORTED','REPORT_IMAGE_UNAVAILABLE','REPORT_IMAGE_UPLOAD_CLOSED','REPORT_IMAGE_UPLOAD_FAILED','REPORT_IMAGE_UPLOAD_HASH_MISMATCH','REPORT_IMAGE_UPLOAD_INCOMPLETE','REPORT_IMAGE_UPLOAD_IN_PROGRESS','REPORT_LINK_NOT_FOUND','REPORT_NOT_FOUND','REPORT_RATE_LIMITED','REPORT_RETENTION_EXPIRED','REPORT_REVISION_CONFLICT','REPORT_STATUS_TRANSITION_INVALID','REVISION_CONFLICT','RUN_INTENT_EXPIRED','RUN_INTENT_NOT_FOUND','RUN_INTENT_TERMINAL','RUN_NOT_PREPARING','RUN_POLICY_UNCONFIGURED','RUN_STORAGE_CAPACITY_LOW','STALE_AGENT_POLICY','STALE_OWNER_POLICY','STALE_RUN_CLAIM','STALE_RUN_INTENT','SUCCESSOR_PREPARATION_POLICY_UNAVAILABLE','TASK_EXECUTION_BINDING_ALREADY_EXISTS','TASK_PREPARATION_AMBIGUOUS','TASK_PREPARATION_NOT_READY','TASK_PREPARATION_SESSION_UNAVAILABLE','UNKNOWN_FIELD','UNSUPPORTED_MEDIA_TYPE','CLIENT_EXECUTION_FAILED'];
export const DIAGNOSTIC_RUN_STATUSES=['queued','preparing','running','cancellation_requested','cancelled','expired','completed','failed','unknown','disqualified'];
export const DIAGNOSTIC_TOOLS=['identity.preflight','runs.accept_launch_intent','runs.current_task','runs.task_action','runs.task_action_status','runs.finish_task','support.report','support.report_receipt','unknown'];
export const DIAGNOSTIC_FIELD_PATHS=['agentId','operationId','intentId','runId','taskIndex','actionId','command','command.kind','command.amount','command.recipient','command.route','answer','unknown_field'];
export const LOCAL_DIAGNOSTIC_LIMITS=Object.freeze({envelopeBytes:2048,caseRows:4096,bundleBytes:8*1024*1024,batchBytes:64*1024,batchRows:128,spoolBytes:64*1024*1024,spoolRows:32768,spoolCases:128});
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,HASH=/^[a-f0-9]{64}$/;
const STAGES=['ingress','authentication','sdk_validation','handler','admission','dispatch','receipt','client_validation','client_runtime','transport'];
const TASKS=['S1','S2','S3','S4','M1','M2','M3','M4','H1','H2','H3','U1'];
const VERSIONS=['0.165.0','0.166.0','unknown'],MODELS=['gpt-6-luna','gpt-6.1-sol','gpt-6-astra','gpt-6.1-terra','unknown'],EFFORTS=['low','medium','high','xhigh','max','ultra','unknown'];
const iso=value=>typeof value==='string'&&/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/.test(value)&&Number.isFinite(Date.parse(value));
const need=(v,code)=>{if(!v)throw new Error(code)};
const bytes=v=>Buffer.byteLength(typeof v==='string'?v:canonicalDiagnosticJson(v));
export function canonicalDiagnosticJson(value){const visit=v=>Array.isArray(v)?v.map(visit):v&&typeof v==='object'?Object.fromEntries(Object.entries(v).filter(([,x])=>x!==undefined).sort(([a],[b])=>a.localeCompare(b,'en')).map(([k,x])=>[k,visit(x)])):v;return JSON.stringify(visit(value));}
export const diagnosticHash=value=>createHash('sha256').update(canonicalDiagnosticJson(value)).digest('hex');
const textHash=value=>createHash('sha256').update(value).digest('hex');
const safeInt=(v,min,max)=>Number.isSafeInteger(v)&&v>=min&&v<=max;
export function validateClientDiagnosticEnvelope(e){
  const required=['eventId','source','stage','tool','outcome','startedAt','completedAt','durationMs'];
  const optional=['errorCode','traceId','callIdHash','operationIdHash','actionId','taskId','taskIndex','httpStatus','rpcCode','fieldPaths','schemaHash','contractHash','client','clientVersion','model','reasoningEffort','clientRunStatus','clientRunObservedAt'];
  need(e&&typeof e==='object'&&!Array.isArray(e)&&required.every(k=>Object.hasOwn(e,k))&&Object.keys(e).every(k=>required.includes(k)||optional.includes(k)),'DIAGNOSTICS_INVALID_ENVELOPE');
  need(UUID.test(e.eventId)&&e.source==='client'&&STAGES.includes(e.stage)&&DIAGNOSTIC_TOOLS.includes(e.tool)&&['success','error','unknown'].includes(e.outcome)&&iso(e.startedAt)&&iso(e.completedAt)&&safeInt(e.durationMs,0,86400000),'DIAGNOSTICS_INVALID_ENVELOPE');
  need(e.outcome!=='error'||DIAGNOSTIC_ERROR_CODES.includes(e.errorCode),'DIAGNOSTICS_INVALID_ENVELOPE');
  for(const k of ['traceId','actionId'])if(e[k]!==undefined)need(UUID.test(e[k]),'DIAGNOSTICS_INVALID_ENVELOPE');
  for(const k of ['callIdHash','operationIdHash','schemaHash','contractHash'])if(e[k]!==undefined)need(HASH.test(e[k]),'DIAGNOSTICS_INVALID_ENVELOPE');
  if(e.errorCode!==undefined)need(DIAGNOSTIC_ERROR_CODES.includes(e.errorCode),'DIAGNOSTICS_INVALID_ENVELOPE');
  if(e.fieldPaths!==undefined)need(Array.isArray(e.fieldPaths)&&e.fieldPaths.length<=8&&e.fieldPaths.every(x=>DIAGNOSTIC_FIELD_PATHS.includes(x)),'DIAGNOSTICS_INVALID_ENVELOPE');
  if(e.taskId!==undefined)need(TASKS.includes(e.taskId),'DIAGNOSTICS_INVALID_ENVELOPE');
  if(e.taskIndex!==undefined)need(safeInt(e.taskIndex,0,11),'DIAGNOSTICS_INVALID_ENVELOPE');
  if(e.httpStatus!==undefined)need(safeInt(e.httpStatus,100,599),'DIAGNOSTICS_INVALID_ENVELOPE');
  if(e.rpcCode!==undefined)need(safeInt(e.rpcCode,-2147483648,2147483647),'DIAGNOSTICS_INVALID_ENVELOPE');
  if(e.client!==undefined)need(['codex_cli','codex_desktop','claude_code','claude_desktop','hermes','unknown'].includes(e.client),'DIAGNOSTICS_INVALID_ENVELOPE');
  for(const [k,allowed] of [['clientVersion',VERSIONS],['model',MODELS],['reasoningEffort',EFFORTS]])if(e[k]!==undefined)need(allowed.includes(e[k]),'DIAGNOSTICS_INVALID_ENVELOPE');
  if(e.clientRunStatus!==undefined||e.clientRunObservedAt!==undefined)need(DIAGNOSTIC_RUN_STATUSES.includes(e.clientRunStatus)&&typeof e.clientRunObservedAt==='string'&&e.clientRunObservedAt.length===24&&iso(e.clientRunObservedAt)&&e.stage==='client_runtime'&&e.outcome==='error','DIAGNOSTICS_INVALID_ENVELOPE');
  need(bytes(e)<=LOCAL_DIAGNOSTIC_LIMITS.envelopeBytes,'DIAGNOSTICS_ENVELOPE_TOO_LARGE');return e;
}

function nativeResultObject(item){
  if(item?.result?.structuredContent&&typeof item.result.structuredContent==='object')return item.result.structuredContent;
  for(const part of item?.result?.content??[]){if(part?.type==='text'&&typeof part.text==='string'&&part.text.length<=8192){try{const p=JSON.parse(part.text);if(p&&typeof p==='object'&&!Array.isArray(p))return p;}catch{}}}
  return null;
}
function knownFailure(item){
  const body=nativeResultObject(item),err=body?.error??item?.error;
  let code=carrier(item).errorCode??(DIAGNOSTIC_ERROR_CODES.includes(err?.code)?err.code:null);
  const message=typeof item?.error?.message==='string'?item.error.message:'';
  // AICODE-NOTE: Recognize fixed framework templates/registered enums only; never retain message excerpts or values.
  if(!code&&/^Input validation error: Invalid arguments for tool\b/.test(message))code='INPUT_VALIDATION_ERROR';
  if(!code){for(const candidate of DIAGNOSTIC_ERROR_CODES){if(candidate!=='UNKNOWN_ERROR'&&new RegExp('\\b'+candidate+'\\b').test(message)){code=candidate;break;}}}
  if(!code&&/\bECONNREFUSED\b/.test(message))code='CONNECTION_REFUSED';
  if(!code&&/\bETIMEDOUT\b/.test(message))code='TRANSPORT_TIMEOUT';
  const fieldPaths=DIAGNOSTIC_FIELD_PATHS.filter(p=>p!=='unknown_field'&&new RegExp('(?:^|[\\s,;])'+p.replaceAll('.','\\.')+'\\s*:').test(message)).slice(0,8);
  const rpc=message.match(/\bMcp error:\s*(-\d{1,10})\s*:/i);
  const rpcCode=Number.isInteger(err?.code)&&safeInt(err.code,-2147483648,2147483647)?err.code:rpc&&safeInt(Number(rpc[1]),-2147483648,2147483647)?Number(rpc[1]):undefined;
  return {errorCode:code??'UNKNOWN_ERROR',...(fieldPaths.length?{fieldPaths}:{}),...(rpcCode!==undefined?{rpcCode}:{})};
}
function carrier(item){
  const body=nativeResultObject(item);
  const options=[item?.result?._meta?.['w3bench/diagnostics'],body?._meta?.['w3bench/diagnostics'],item?.error?.data?._meta?.['w3bench/diagnostics'],item?.result?._meta?.w3benchDiagnostics,body?._meta?.w3benchDiagnostics,item?.error?.data?._meta?.w3benchDiagnostics];
  const v=options.find(x=>x&&typeof x==='object'&&!Array.isArray(x));
  const fieldPaths=Array.isArray(v?.fieldPaths)?[...new Set(v.fieldPaths.filter(p=>DIAGNOSTIC_FIELD_PATHS.includes(p)))].slice(0,8):[];
  return {present:!!v,recorded:v?.capture==='recorded',...(DIAGNOSTIC_ERROR_CODES.includes(v?.errorCode)?{errorCode:v.errorCode}:{}),projection:{...(UUID.test(v?.traceId)?{traceId:v.traceId}:{}),...(HASH.test(v?.schemaHash)?{schemaHash:v.schemaHash}:{}),...(HASH.test(v?.contractHash)?{contractHash:v.contractHash}:{}),...(fieldPaths.length?{fieldPaths}:{})}};
}

export class NativeDiagnosticCollector {
  constructor({onEnvelope,onGap=()=>{},now=()=>new Date(),clientVersion='unknown',model='unknown',reasoningEffort='unknown',maxLineChars=256*1024,maxCalls=4096,expectedIntentId,onRunObservation=()=>true}={}){
    need(typeof onEnvelope==='function','DIAGNOSTICS_SINK_REQUIRED');need(expectedIntentId===undefined||UUID.test(expectedIntentId),'DIAGNOSTICS_INVALID_CASE');this.onRunObservation=onRunObservation;this.expectedIntentId=expectedIntentId;this.knownRunId=null;this.lastRunObservation=null;Object.assign(this,{onEnvelope,onGap,now,maxLineChars,maxCalls});
    this.context={client:'codex_cli',clientVersion:VERSIONS.includes(clientVersion)?clientVersion:'unknown',model:MODELS.includes(model)?model:'unknown',reasoningEffort:EFFORTS.includes(reasoningEffort)?reasoningEffort:'unknown'};
    this.decoder=new StringDecoder('utf8');this.pending='';this.dropLine=false;this.calls=new Map();this.completed=new Set();this.sequence=0;this.gaps=new Set();
  }
  gap(code){
    need(DIAGNOSTIC_ERROR_CODES.includes(code),'DIAGNOSTICS_INVALID_GAP');if(this.gaps.has(code))return;this.gaps.add(code);
    // AICODE-NOTE: Preserve the completeness marker even if the sink cannot
    // accept its reason envelope. Direct delivery is deliberately nonrecursive.
    try{this.onGap(code);}catch{/* The in-memory gap still prevents all-clear. */}
    const at=this.now().toISOString();try{this.onEnvelope(validateClientDiagnosticEnvelope({eventId:randomUUID(),source:'client',stage:'client_runtime',tool:'unknown',outcome:'error',errorCode:code,startedAt:at,completedAt:at,durationMs:0,...this.context,...this.runObservation()}));}catch{/* Storage/quota failure cannot recursively report itself. */}
  }
  runObservation(){return this.lastRunObservation?{...this.lastRunObservation}:{};}
  bindRegisteredRun(registration){
    if(!registration||typeof registration!=='object'||registration.runId==null)return false;
    if(!this.expectedIntentId||registration.intentId!==this.expectedIntentId||!UUID.test(registration.runId)||this.knownRunId&&this.knownRunId!==registration.runId){this.gap('CORRELATION_UNAVAILABLE');return false;}
    this.knownRunId=registration.runId;return true;
  }
  observeRunResult(tool,body,failed,callIdHash,traceId){
    if(failed||!['runs.accept_launch_intent','runs.current_task'].includes(tool)||!body||typeof body!=='object')return;
    const run=body.run&&typeof body.run==='object'?body.run:body;
    const runId=tool==='runs.accept_launch_intent'?(run.id??run.runId):run.runId;
    if(runId===undefined&&run.status===undefined)return;
    if(!UUID.test(runId)||!DIAGNOSTIC_RUN_STATUSES.includes(run.status)){this.gap('CORRELATION_UNAVAILABLE');return;}
    if(tool==='runs.accept_launch_intent'){
      if(!this.expectedIntentId||run.intentId!==this.expectedIntentId||this.knownRunId&&this.knownRunId!==runId){this.gap('CORRELATION_UNAVAILABLE');return;}
      this.knownRunId=runId;
    }
    if(!this.knownRunId||runId!==this.knownRunId){this.gap('CORRELATION_UNAVAILABLE');return;}
    const observedAt=this.now().toISOString();if(observedAt.length!==24){this.gap('CORRELATION_UNAVAILABLE');return;}
    this.lastRunObservation={clientRunStatus:run.status,clientRunObservedAt:observedAt};this.lastRunTerminal=typeof run.terminal==='boolean'?run.terminal:undefined;
    const projection={runId,status:run.status,observedAt,sourceCallIdHash:callIdHash,sourceTool:tool,...(UUID.test(traceId)?{traceId}:{}),...(typeof run.terminal==='boolean'?{terminal:run.terminal}:{})};
    try{if(!HASH.test(callIdHash)||this.onRunObservation(projection)===false)this.gap('DIAGNOSTICS_STORAGE_FAILURE');}catch{this.gap('DIAGNOSTICS_STORAGE_FAILURE');}
  }
  feed(chunk){for(const char of this.decoder.write(chunk)){if(char==='\n'){if(!this.dropLine)this.consume(this.pending);this.pending='';this.dropLine=false;}else if(!this.dropLine){if(this.pending.length<this.maxLineChars)this.pending+=char;else{this.pending='';this.dropLine=true;this.gap('DIAGNOSTICS_PARSER_FAILURE');}}}}
  consume(line){
    if(!line)return;let event;try{event=JSON.parse(line);}catch{this.gap('DIAGNOSTICS_PARSER_FAILURE');return;}
    const item=event?.item&&typeof event.item==='object'?event.item:event;
    if(item?.type==='error'){this.emit({eventId:randomUUID(),source:'client',stage:'client_runtime',tool:'unknown',outcome:'error',errorCode:'CLIENT_RUNTIME_ERROR',startedAt:this.now().toISOString(),completedAt:this.now().toISOString(),durationMs:0,...this.context});return;}
    if(!String(item?.type??event?.type??'').includes('mcp_tool_call'))return;
    const server=item.server??item.server_name??item.serverName;if(!['w3bench_user','owner_identity'].includes(server))return;
    const rawId=[item.call_id,item.id,event.id].find(x=>typeof x==='string'&&x.length<=512),id=rawId?textHash(rawId):'anonymous_'+(++this.sequence);
    if(this.completed.has(id))return;
    if(!this.calls.has(id)){
      if(this.completed.size+this.calls.size>=this.maxCalls){this.gap('DIAGNOSTICS_QUOTA_EXCEEDED');return;}
      const name=[item.tool_name,item.name,item.toolName,typeof item.tool==='string'?item.tool:item.tool?.name].find(x=>typeof x==='string');
      const args=item.arguments&&typeof item.arguments==='object'?item.arguments:{};
      const start={eventId:randomUUID(),source:'client',stage:'handler',tool:DIAGNOSTIC_TOOLS.includes(name)?name:'unknown',startedAt:this.now().toISOString(),...(rawId?{callIdHash:id}:{}),...this.context};
      if(typeof args.operationId==='string'&&args.operationId.length<=128)start.operationIdHash=textHash(args.operationId);
      // AICODE-NOTE: Caller arguments are unverified claims. A failed lookup may
      // deliberately name a foreign/missing action or task; retain only its hash
      // and correlate trusted relations through the server trace journal.
      this.calls.set(id,start);
    }
    const status=item.status;if(!['completed','failed'].includes(status)&&event.type!=='item.completed')return;
    const start=this.calls.get(id),completedAt=this.now().toISOString();this.calls.delete(id);this.completed.add(id);
    const body=nativeResultObject(item),failed=status==='failed'||item?.result?.isError===true||body?.error||typeof item?.error?.message==='string';
    this.observeRunResult(start.tool,body,!!failed,start.callIdHash,carrier(item).projection.traceId);
    const failure=failed?knownFailure(item):{};
    const stage=failure.errorCode==='INPUT_VALIDATION_ERROR'?'client_validation':['CONNECTION_REFUSED','TRANSPORT_TIMEOUT','CONNECTION_LOST'].includes(failure.errorCode)?'transport':start.stage;
    const metadata=carrier(item);if(metadata.present&&!metadata.recorded||!metadata.projection.traceId&&stage!=='client_validation')this.gap('CORRELATION_UNAVAILABLE');
    const fieldPaths=[...new Set([...(metadata.projection.fieldPaths??[]),...(failure.fieldPaths??[])])].slice(0,8);
    this.emit({...start,stage,outcome:failed?'error':status==='completed'?'success':'unknown',completedAt,durationMs:Math.max(0,Math.min(86400000,Date.parse(completedAt)-Date.parse(start.startedAt))),...failure,...metadata.projection,...(fieldPaths.length?{fieldPaths}:{})});
  }
  emit(value){try{if(this.onEnvelope(validateClientDiagnosticEnvelope(value.stage==='client_runtime'&&value.outcome==='error'?{...value,...this.runObservation()}:value))===false)this.gap('DIAGNOSTICS_QUOTA_EXCEEDED');}catch{this.gap('DIAGNOSTICS_STORAGE_FAILURE');}}
  close({interrupted=false}={}){
    const tail=this.decoder.end();if(tail)this.pending+=tail;if(this.pending&&!this.dropLine)this.consume(this.pending);this.pending='';
    if(interrupted||this.calls.size){const end=this.now().toISOString();for(const start of this.calls.values())this.emit({...start,stage:'client_runtime',outcome:'unknown',errorCode:'CLIENT_RUNTIME_ERROR',completedAt:end,durationMs:Math.max(0,Math.min(86400000,Date.parse(end)-Date.parse(start.startedAt)))});this.calls.clear();this.gap('CLIENT_RUNTIME_ERROR');}
    return {complete:this.gaps.size===0,gaps:[...this.gaps]};
  }
}

async function managedDirectory(path){
  const target=resolve(path);await mkdir(target,{recursive:true,mode:0o700});
  let current=target;while(true){const s=await lstat(current);need(s.isDirectory()&&!s.isSymbolicLink()&&(await realpath(current)).toLowerCase()===current.toLowerCase(),'DIAGNOSTICS_SPOOL_PATH_INVALID');const parent=resolve(current,'..');if(parent===current)break;current=parent;}
  return target;
}
export function validateLocalRunObservation(v){
  need(v&&typeof v==='object'&&Object.keys(v).every(k=>['runId','status','observedAt','sourceCallIdHash','sourceTool','traceId','terminal'].includes(k))&&UUID.test(v.runId)&&DIAGNOSTIC_RUN_STATUSES.includes(v.status)&&typeof v.observedAt==='string'&&v.observedAt.length===24&&iso(v.observedAt)&&HASH.test(v.sourceCallIdHash)&&['runs.accept_launch_intent','runs.current_task'].includes(v.sourceTool)&&(v.traceId===undefined||UUID.test(v.traceId))&&(v.terminal===undefined||typeof v.terminal==='boolean'),'DIAGNOSTICS_INVALID_RUN_OBSERVATION');return v;
}
export function diagnosticProcessLiveness(pid){if(!safeInt(pid,1,2147483647))return 'unknown';try{process.kill(pid,0);return 'alive';}catch(error){return error.code==='ESRCH'?'dead':'unknown';}}
const json=row=>row?JSON.parse(row.payload):null;
export async function openDiagnosticSpool({directory,now=()=>new Date(),limits={}}){
  const root=await managedDirectory(directory),dbPath=resolve(root,'diagnostics.sqlite');
  need(readdirSync(root).every(name=>['diagnostics.sqlite','diagnostics.sqlite-wal','diagnostics.sqlite-shm','diagnostics.sqlite-journal'].includes(name)),'DIAGNOSTICS_SPOOL_PATH_INVALID');
  const existing=await lstat(dbPath).catch(e=>{if(e.code==='ENOENT')return null;throw e});need(!existing||existing.isFile()&&!existing.isSymbolicLink(),'DIAGNOSTICS_SPOOL_PATH_INVALID');
  for(const path of [dbPath+'-wal',dbPath+'-shm',dbPath+'-journal']){const info=await lstat(path).catch(e=>{if(e.code==='ENOENT')return null;throw e});need(!info||info.isFile()&&!info.isSymbolicLink()&&info.nlink===1,'DIAGNOSTICS_SPOOL_PATH_INVALID');}
  need(!existing||existing.nlink===1,'DIAGNOSTICS_SPOOL_PATH_INVALID');
  const cap={...LOCAL_DIAGNOSTIC_LIMITS,...limits};
  const diskBytes=cap.diskBytes??LOCAL_DIAGNOSTIC_LIMITS.spoolBytes;
  need(safeInt(diskBytes,256*1024,LOCAL_DIAGNOSTIC_LIMITS.spoolBytes),'DIAGNOSTICS_LIMIT_INVALID');
  const initialFiles=readdirSync(root).map(name=>({name,size:(()=>{try{return statSync(resolve(root,name)).size;}catch(e){if(e.code==='ENOENT')return 0;throw e;}})()}));
  need(initialFiles.reduce((n,f)=>n+f.size,0)<=diskBytes,'DIAGNOSTICS_QUOTA_EXCEEDED');
  // Do not grow an existing legacy WAL during implicit recovery. An operator must
  // checkpoint that older spool separately; it remains preserved and unavailable.
  need(!initialFiles.some(f=>f.name.endsWith('-wal')&&f.size>0),'DIAGNOSTICS_SPOOL_MODE_INVALID');
  // AICODE-NOTE: WAL may grow indefinitely behind a pinned reader. Rollback DELETE,
  // no cache spill/savepoints, and a page cap reserve one original image per page
  // plus journal framing before any allocation, including schema/control metadata.
  const db=new DatabaseSync(dbPath);try{
    db.exec('PRAGMA busy_timeout=5000; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA cache_spill=OFF; PRAGMA temp_store=MEMORY; PRAGMA mmap_size=0;');
    need(db.prepare('PRAGMA journal_mode').get().journal_mode==='delete','DIAGNOSTICS_SPOOL_MODE_INVALID');
    const pageSize=Number(db.prepare('PRAGMA page_size').get().page_size),reserve=Math.max(32768,Math.min(1024*1024,Math.floor(diskBytes/8))),maxPages=Math.floor((diskBytes-reserve)/(2*pageSize+8));
    need(maxPages>=16&&Number(db.prepare('PRAGMA page_count').get().page_count)<=maxPages,'DIAGNOSTICS_QUOTA_EXCEEDED');
    need(Number(db.prepare('PRAGMA max_page_count='+maxPages).get().max_page_count)===maxPages,'DIAGNOSTICS_QUOTA_EXCEEDED');
  }catch(error){db.close();throw error;}

  db.exec(`CREATE TABLE IF NOT EXISTS cases(local_id TEXT PRIMARY KEY,session_id TEXT UNIQUE NOT NULL,intent_id TEXT UNIQUE,remote_id TEXT,created_at INTEGER NOT NULL,state TEXT NOT NULL,gap TEXT,report_id TEXT);
    CREATE TABLE IF NOT EXISTS segments(id TEXT PRIMARY KEY,local_id TEXT NOT NULL REFERENCES cases(local_id),created_at INTEGER NOT NULL,state TEXT NOT NULL DEFAULT 'open',next_batch INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY,segment_id TEXT NOT NULL REFERENCES segments(id),payload TEXT NOT NULL,bytes INTEGER NOT NULL,batch_sequence INTEGER);
    CREATE TABLE IF NOT EXISTS batches(segment_id TEXT NOT NULL REFERENCES segments(id),sequence INTEGER NOT NULL,payload TEXT NOT NULL,bytes INTEGER NOT NULL,hash TEXT NOT NULL,completion TEXT NOT NULL,acked INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(segment_id,sequence));`);
  if(!db.prepare('PRAGMA table_info(cases)').all().some(c=>c.name==='binding_json'))db.exec('ALTER TABLE cases ADD COLUMN binding_json TEXT');
  const instanceId=randomUUID();
  for(const [name,type] of [['owner_instance','TEXT'],['owner_pid','INTEGER'],['owner_released','INTEGER NOT NULL DEFAULT 0']])if(!db.prepare('PRAGMA table_info(segments)').all().some(c=>c.name===name))db.exec('ALTER TABLE segments ADD COLUMN '+name+' '+type);
  db.exec('CREATE TABLE IF NOT EXISTS run_observations(segment_id TEXT PRIMARY KEY REFERENCES segments(id),projection TEXT NOT NULL)');
  // AICODE-NOTE: Scanning all retained payloads on every call is quadratic.
  // These fixed counters are derived once from actual rows under the writer
  // lock, then maintained by triggers in the SAME transaction as each allocation.
  // They are not an in-memory reservation or caller-supplied usage estimate.
  try{db.exec('BEGIN IMMEDIATE');
    const hasCaseCounter=db.prepare('PRAGMA table_info(cases)').all().some(c=>c.name==='event_rows');
    if(!hasCaseCounter){db.exec('ALTER TABLE cases ADD COLUMN event_rows INTEGER NOT NULL DEFAULT 0');db.exec('UPDATE cases SET event_rows=(SELECT count(*) FROM events e JOIN segments s ON s.id=e.segment_id WHERE s.local_id=cases.local_id)');}
    db.exec(`CREATE TABLE IF NOT EXISTS allocation_counters(id INTEGER PRIMARY KEY CHECK(id=1),event_rows INTEGER NOT NULL CHECK(event_rows>=0),event_bytes INTEGER NOT NULL CHECK(event_bytes>=0),batch_bytes INTEGER NOT NULL CHECK(batch_bytes>=0),case_count INTEGER NOT NULL CHECK(case_count>=0),segment_count INTEGER NOT NULL CHECK(segment_count>=0));
      INSERT INTO allocation_counters(id,event_rows,event_bytes,batch_bytes,case_count,segment_count)
        SELECT 1,(SELECT count(*) FROM events),(SELECT coalesce(sum(bytes),0) FROM events),(SELECT coalesce(sum(bytes),0) FROM batches),(SELECT count(*) FROM cases),(SELECT count(*) FROM segments) ON CONFLICT(id) DO NOTHING;
      CREATE INDEX IF NOT EXISTS diagnostic_events_segment_batch ON events(segment_id,batch_sequence);
      CREATE INDEX IF NOT EXISTS diagnostic_segments_local ON segments(local_id);
      CREATE TRIGGER IF NOT EXISTS diagnostic_event_allocate AFTER INSERT ON events BEGIN
        UPDATE allocation_counters SET event_rows=event_rows+1,event_bytes=event_bytes+NEW.bytes WHERE id=1;
        UPDATE cases SET event_rows=event_rows+1 WHERE local_id=(SELECT local_id FROM segments WHERE id=NEW.segment_id);
      END;
      CREATE TRIGGER IF NOT EXISTS diagnostic_event_release AFTER DELETE ON events BEGIN
        UPDATE allocation_counters SET event_rows=event_rows-1,event_bytes=event_bytes-OLD.bytes WHERE id=1;
        UPDATE cases SET event_rows=event_rows-1 WHERE local_id=(SELECT local_id FROM segments WHERE id=OLD.segment_id);
      END;
      CREATE TRIGGER IF NOT EXISTS diagnostic_event_resize AFTER UPDATE OF bytes ON events BEGIN
        UPDATE allocation_counters SET event_bytes=event_bytes+NEW.bytes-OLD.bytes WHERE id=1;
      END;
      CREATE TRIGGER IF NOT EXISTS diagnostic_batch_allocate AFTER INSERT ON batches BEGIN UPDATE allocation_counters SET batch_bytes=batch_bytes+NEW.bytes WHERE id=1;END;
      CREATE TRIGGER IF NOT EXISTS diagnostic_batch_release AFTER DELETE ON batches BEGIN UPDATE allocation_counters SET batch_bytes=batch_bytes-OLD.bytes WHERE id=1;END;
      CREATE TRIGGER IF NOT EXISTS diagnostic_batch_resize AFTER UPDATE OF bytes ON batches BEGIN UPDATE allocation_counters SET batch_bytes=batch_bytes+NEW.bytes-OLD.bytes WHERE id=1;END;
      CREATE TRIGGER IF NOT EXISTS diagnostic_case_allocate AFTER INSERT ON cases BEGIN UPDATE allocation_counters SET case_count=case_count+1 WHERE id=1;END;
      CREATE TRIGGER IF NOT EXISTS diagnostic_case_release AFTER DELETE ON cases BEGIN UPDATE allocation_counters SET case_count=case_count-1 WHERE id=1;END;
      CREATE TRIGGER IF NOT EXISTS diagnostic_segment_allocate AFTER INSERT ON segments BEGIN UPDATE allocation_counters SET segment_count=segment_count+1 WHERE id=1;END;
      CREATE TRIGGER IF NOT EXISTS diagnostic_segment_release AFTER DELETE ON segments BEGIN UPDATE allocation_counters SET segment_count=segment_count-1 WHERE id=1;END;`);
    db.exec('COMMIT');
  }catch(error){try{db.exec('ROLLBACK');}catch{}db.close();throw error;}
  let physicalPeakBytes=0,journalPeakBytes=0;
  const diskSnapshot=()=>{const files=readdirSync(root).filter(n=>n.startsWith('diagnostics.sqlite')).map(name=>({name,bytes:(()=>{try{return statSync(resolve(root,name)).size;}catch(e){if(e.code==='ENOENT')return 0;throw e;}})()})),total=files.reduce((n,f)=>n+f.bytes,0);physicalPeakBytes=Math.max(physicalPeakBytes,total);journalPeakBytes=Math.max(journalPeakBytes,files.find(f=>f.name.endsWith('-journal'))?.bytes??0);return {limitBytes:diskBytes,bytes:total,physicalPeakBytes,journalPeakBytes,files};};
  const transaction=fn=>{db.exec('BEGIN IMMEDIATE');try{const result=fn();diskSnapshot();db.exec('COMMIT');diskSnapshot();return result;}catch(e){try{db.exec('ROLLBACK');}catch{/* SQLITE_FULL may already have rolled back atomically. */}if(e?.errcode===13||String(e?.message).includes('database or disk is full'))throw new Error('DIAGNOSTICS_QUOTA_EXCEEDED');throw e;}};
  const caseRow=id=>db.prepare('SELECT * FROM cases WHERE local_id=?').get(id);
  const gap=(id,reason)=>{need(DIAGNOSTIC_ERROR_CODES.includes(reason),'DIAGNOSTICS_INVALID_GAP');db.prepare("UPDATE cases SET state='partial',gap=coalesce(gap,?) WHERE local_id=?").run(reason,id);};
  const usage=()=>{const c=db.prepare('SELECT event_rows,event_bytes+batch_bytes AS bytes,case_count FROM allocation_counters WHERE id=1').get();need(c,'DIAGNOSTICS_STORAGE_FAILURE');return {rows:Number(c.event_rows),bytes:Number(c.bytes),cases:Number(c.case_count)};};
  const api={
    directory:root,instanceId,
    diskUsage(){return {...diskSnapshot(),journalMode:db.prepare('PRAGMA journal_mode').get().journal_mode,maxPages:Number(db.prepare('PRAGMA max_page_count').get().max_page_count),pageSize:Number(db.prepare('PRAGMA page_size').get().page_size),pageCount:Number(db.prepare('PRAGMA page_count').get().page_count)};},
    createCase({diagnosticSessionId=randomUUID(),intentId,binding}={}){need(UUID.test(diagnosticSessionId)&&(!intentId||UUID.test(intentId)),'DIAGNOSTICS_INVALID_CASE');return transaction(()=>{
      const old=intentId?db.prepare('SELECT * FROM cases WHERE intent_id=?').get(intentId):db.prepare('SELECT * FROM cases WHERE session_id=?').get(diagnosticSessionId);if(binding)need(UUID.test(binding.agentId)&&UUID.test(binding.connectionId)&&Object.keys(binding).length===2,'DIAGNOSTICS_INVALID_BINDING');if(old){need((old.binding_json??null)===(binding?canonicalDiagnosticJson(binding):null),'DIAGNOSTICS_BINDING_INVALID');return old;}
      need(usage().cases<cap.spoolCases,'DIAGNOSTICS_QUOTA_EXCEEDED');const local_id=randomUUID();db.prepare("INSERT INTO cases(local_id,session_id,intent_id,created_at,binding_json,state) VALUES(?,?,?,?,?, 'open')").run(local_id,diagnosticSessionId,intentId??null,now().getTime(),binding?canonicalDiagnosticJson(binding):null);return caseRow(local_id);
    });},
    createSegment(localId){return transaction(()=>{const c=caseRow(localId);need(c&&!['expired','retention_expired','conflict'].includes(c.state),'DIAGNOSTICS_CASE_NOT_FOUND');need(Number(db.prepare('SELECT segment_count AS n FROM allocation_counters WHERE id=1').get().n)<32768,'DIAGNOSTICS_QUOTA_EXCEEDED');const id=randomUUID();db.prepare('INSERT INTO segments(id,local_id,created_at,owner_instance,owner_pid,owner_released) VALUES(?,?,?,?,?,0)').run(id,localId,now().getTime(),instanceId,process.pid);db.prepare("UPDATE cases SET state='open' WHERE local_id=?").run(localId);return id;});},
    recordRunObservation(segmentId,projection){validateLocalRunObservation(projection);return transaction(()=>{const segment=db.prepare('SELECT * FROM segments WHERE id=?').get(segmentId);need(segment?.state==='open'&&segment.owner_instance===instanceId,'DIAGNOSTICS_SEGMENT_CLOSED');db.prepare('INSERT INTO run_observations(segment_id,projection) VALUES(?,?) ON CONFLICT(segment_id) DO UPDATE SET projection=excluded.projection').run(segmentId,canonicalDiagnosticJson(projection));return true;});},
    intentObservation(intentId){const row=db.prepare('SELECT o.projection FROM run_observations o JOIN segments s ON s.id=o.segment_id JOIN cases c ON c.local_id=s.local_id WHERE c.intent_id=? ORDER BY s.created_at DESC,s.rowid DESC LIMIT 1').get(intentId);return row?validateLocalRunObservation(JSON.parse(row.projection)):null;},
    runObservation(segmentId){const row=db.prepare('SELECT projection FROM run_observations WHERE segment_id=?').get(segmentId);return row?validateLocalRunObservation(JSON.parse(row.projection)):null;},
    recoverAbandonedCaptures({processLiveness=diagnosticProcessLiveness}={}){
      const results=[];const candidates=db.prepare("SELECT s.* FROM segments s JOIN cases c ON c.local_id=s.local_id WHERE s.state='open' AND c.state NOT IN ('expired','retention_expired','conflict')").all();
      for(const candidate of candidates){if(candidate.owner_instance===instanceId||!(candidate.owner_released===1||candidate.owner_instance&&processLiveness(candidate.owner_pid)==='dead'))continue;
        const claimed=transaction(()=>{const row=db.prepare('SELECT * FROM segments WHERE id=?').get(candidate.id);if(row.state!=='open'||row.owner_instance!==candidate.owner_instance||row.owner_released!==candidate.owner_released)return false;db.prepare('UPDATE segments SET owner_instance=?,owner_pid=?,owner_released=0 WHERE id=?').run(instanceId,process.pid,row.id);gap(row.local_id,'CLIENT_RUNTIME_ERROR');return true;});if(!claimed)continue;
        try{const observation=api.runObservation(candidate.id),digest=textHash('recovered:'+candidate.id),eventId=digest.slice(0,8)+'-'+digest.slice(8,12)+'-8'+digest.slice(13,16)+'-a'+digest.slice(17,20)+'-'+digest.slice(20,32),at=now().toISOString();
          api.append(candidate.id,{eventId,source:'client',stage:'client_runtime',tool:'unknown',outcome:'error',errorCode:'CLIENT_RUNTIME_ERROR',startedAt:at,completedAt:at,durationMs:0,client:'codex_cli',...(observation?{clientRunStatus:observation.status,clientRunObservedAt:observation.observedAt}:{})});
          for(;;){const batch=api.stageBatch(candidate.id,{completion:'partial'});if(!batch||batch.completion!=='open')break;}results.push({localCaseId:candidate.local_id,segmentId:candidate.id,state:'recovered_partial'});
        }catch{try{gap(candidate.local_id,'DIAGNOSTICS_STORAGE_FAILURE');}catch{}results.push({localCaseId:candidate.local_id,segmentId:candidate.id,state:'unavailable'});}
      }return results;
    },
    append(segmentId,envelope){validateClientDiagnosticEnvelope(envelope);return transaction(()=>{
      const segment=db.prepare('SELECT * FROM segments WHERE id=?').get(segmentId);need(segment&&segment.state==='open','DIAGNOSTICS_SEGMENT_CLOSED');
      const previous=db.prepare('SELECT payload FROM events WHERE id=?').get(envelope.eventId),payload=canonicalDiagnosticJson(envelope);if(previous){need(previous.payload===payload,'DIAGNOSTICS_EVENT_CONFLICT');return false;}
      const count=Number(caseRow(segment.local_id).event_rows),u=usage();
      if(count>=cap.caseRows||u.rows>=cap.spoolRows||u.bytes+bytes(payload)>cap.spoolBytes){gap(segment.local_id,'DIAGNOSTICS_QUOTA_EXCEEDED');return false;}
      db.prepare('INSERT INTO events(id,segment_id,payload,bytes) VALUES(?,?,?,?)').run(envelope.eventId,segmentId,payload,bytes(payload));return true;
    });},
    markGap(localId,reason){transaction(()=>gap(localId,reason));},
    stageBatch(segmentId,{completion='open'}={}){need(['open','complete','partial'].includes(completion),'DIAGNOSTICS_INVALID_COMPLETION');return transaction(()=>{
      const segment=db.prepare('SELECT * FROM segments WHERE id=?').get(segmentId);need(segment&&segment.state==='open','DIAGNOSTICS_SEGMENT_CLOSED');
      if(segment.next_batch>=4095&&completion==='open'){gap(segment.local_id,'DIAGNOSTICS_QUOTA_EXCEEDED');return null;}
      need(segment.next_batch<=4095,'DIAGNOSTICS_QUOTA_EXCEEDED');
      const rows=db.prepare('SELECT id,payload FROM events WHERE segment_id=? AND batch_sequence IS NULL ORDER BY rowid LIMIT ?').all(segmentId,cap.batchRows),events=[],ids=[];
      for(const row of rows){const proposed=[...events,JSON.parse(row.payload)],body={segmentId,batchSequence:segment.next_batch,events:proposed,completion};if(bytes({...body,payloadHash:diagnosticHash(body)})>cap.batchBytes)break;events.push(JSON.parse(row.payload));ids.push(row.id);}
      if(!events.length&&completion==='open')return null;
      const remain=Number(db.prepare('SELECT count(*) AS n FROM events WHERE segment_id=? AND batch_sequence IS NULL').get(segmentId).n);
      const finalCompletion=completion!=='open'&&remain>events.length?'open':completion;
      const body={segmentId,batchSequence:segment.next_batch,events,completion:finalCompletion},batch={...body,payloadHash:diagnosticHash(body)},payload=canonicalDiagnosticJson(batch);
      if(usage().bytes+bytes(payload)>cap.spoolBytes){gap(segment.local_id,'DIAGNOSTICS_QUOTA_EXCEEDED');return null;}
      db.prepare('INSERT INTO batches(segment_id,sequence,payload,bytes,hash,completion) VALUES(?,?,?,?,?,?)').run(segmentId,segment.next_batch,payload,bytes(payload),batch.payloadHash,finalCompletion);
      for(const id of ids)db.prepare('UPDATE events SET batch_sequence=? WHERE id=?').run(segment.next_batch,id);
      db.prepare('UPDATE segments SET next_batch=next_batch+1,state=? WHERE id=?').run(finalCompletion==='open'?'open':'closed',segmentId);return batch;
    });},
    pendingCases({binding}={}){const rows=db.prepare("SELECT * FROM cases WHERE state NOT IN ('synced','expired','retention_expired','conflict') ORDER BY created_at,local_id").all();return binding?rows.filter(c=>c.binding_json===canonicalDiagnosticJson(binding)):rows;},
    bindRemote(localId,remote){need(UUID.test(remote.caseId),'DIAGNOSTICS_INVALID_RECEIPT');return transaction(()=>{const c=caseRow(localId);need(c&&(!c.remote_id||c.remote_id===remote.caseId),'DIAGNOSTICS_CASE_CONFLICT');db.prepare('UPDATE cases SET remote_id=? WHERE local_id=?').run(remote.caseId,localId);});},
    pendingBatches(localId){return db.prepare('SELECT b.payload FROM batches b JOIN segments s ON s.id=b.segment_id WHERE s.local_id=? AND b.acked=0 ORDER BY s.created_at,s.rowid,b.sequence').all(localId).map(json);},
    acknowledge(localId,receipt){return transaction(()=>{const c=caseRow(localId);need(c?.remote_id===receipt.caseId&&UUID.test(receipt.segmentId)&&typeof receipt.reportCreated==='boolean'&&typeof receipt.diagnosticsSynced==='boolean'&&safeInt(receipt.highestContiguousSequence,0,4095)&&['open','complete','partial'].includes(receipt.completion)&&(receipt.reportId==null||UUID.test(receipt.reportId)),'DIAGNOSTICS_INVALID_RECEIPT');
      const expected=db.prepare('SELECT b.* FROM batches b JOIN segments s ON s.id=b.segment_id WHERE s.local_id=? AND b.segment_id=? AND b.sequence=?').get(localId,receipt.segmentId,receipt.highestContiguousSequence);
      need(expected&&expected.hash===receipt.highestContiguousHash,'DIAGNOSTICS_WATERMARK_MISMATCH');
      if(receipt.reportCreated)need(UUID.test(receipt.reportId),'DIAGNOSTICS_INVALID_RECEIPT');
      if(receipt.diagnosticsSynced)need(expected.completion!=='open'&&receipt.completion===expected.completion,'DIAGNOSTICS_WATERMARK_MISMATCH');
      db.prepare('UPDATE batches SET acked=1 WHERE segment_id=? AND sequence<=?').run(receipt.segmentId,expected.completion==='open'||receipt.diagnosticsSynced?receipt.highestContiguousSequence:receipt.highestContiguousSequence-1);
      if(receipt.reportCreated)db.prepare('UPDATE cases SET report_id=? WHERE local_id=?').run(receipt.reportId,localId);
      const remaining=Number(db.prepare('SELECT count(*) AS n FROM batches b JOIN segments s ON s.id=b.segment_id WHERE s.local_id=? AND b.acked=0').get(localId).n),open=Number(db.prepare("SELECT count(*) AS n FROM segments WHERE local_id=? AND state='open'").get(localId).n);
      if(receipt.diagnosticsSynced&&remaining===0&&open===0)db.prepare("UPDATE cases SET state='synced' WHERE local_id=?").run(localId);
    });},
    setDeliveryState(localId,state){need(['open','pending','pending_auth','partial','conflict','retention_expired'].includes(state),'DIAGNOSTICS_INVALID_STATE');db.prepare('UPDATE cases SET state=? WHERE local_id=?').run(state,localId);},
    expire(){return transaction(()=>{const cutoff=now().getTime()-30*86400000;const expired=db.prepare("SELECT local_id FROM cases WHERE created_at<? AND state NOT IN ('synced','expired','retention_expired')").all(cutoff);for(const c of expired){db.prepare("UPDATE cases SET state='expired' WHERE local_id=?").run(c.local_id);db.prepare('DELETE FROM batches WHERE segment_id IN (SELECT id FROM segments WHERE local_id=?)').run(c.local_id);db.prepare('DELETE FROM events WHERE segment_id IN (SELECT id FROM segments WHERE local_id=?)').run(c.local_id);db.prepare('DELETE FROM run_observations WHERE segment_id IN (SELECT id FROM segments WHERE local_id=?)').run(c.local_id);}return expired.length;});},
    collectAcknowledged(){return transaction(()=>{const cases=db.prepare("SELECT local_id FROM cases WHERE state='synced'").all();for(const c of cases){need(Number(db.prepare('SELECT count(*) AS n FROM batches b JOIN segments s ON s.id=b.segment_id WHERE s.local_id=? AND b.acked=0').get(c.local_id).n)===0,'DIAGNOSTICS_UNACKNOWLEDGED_GC');db.prepare('DELETE FROM batches WHERE segment_id IN (SELECT id FROM segments WHERE local_id=?)').run(c.local_id);db.prepare('DELETE FROM events WHERE segment_id IN (SELECT id FROM segments WHERE local_id=?)').run(c.local_id);}return cases.length;});},
    exportBundle(localId,{binding}={}){const c=caseRow(localId);need(c,'DIAGNOSTICS_CASE_NOT_FOUND');if(c.binding_json){need(!binding||canonicalDiagnosticJson(binding)===c.binding_json,'DIAGNOSTICS_BINDING_INVALID');binding=JSON.parse(c.binding_json);}if(binding)need(UUID.test(binding.agentId)&&UUID.test(binding.connectionId)&&Object.keys(binding).length===2,'DIAGNOSTICS_INVALID_BINDING');
      const segments=db.prepare('SELECT id FROM segments WHERE local_id=? ORDER BY created_at,rowid').all(localId).map(s=>({segmentId:s.id,batches:db.prepare('SELECT payload FROM batches WHERE segment_id=? ORDER BY sequence').all(s.id).map(json)}));
      const bundle={schemaVersion:'w3bench-diagnostic-bundle/v1',diagnosticSessionId:c.session_id,...(c.intent_id?{intentId:c.intent_id}:{}),...(c.remote_id?{caseId:c.remote_id}:{}),...(binding?{binding}:{}),segments};need(bytes(bundle)<=cap.bundleBytes,'DIAGNOSTICS_BUNDLE_TOO_LARGE');return bundle;
    },
    caseState:caseRow,usage,
    close(){try{transaction(()=>db.prepare("UPDATE segments SET owner_released=1 WHERE owner_instance=? AND state='open'").run(instanceId));}finally{db.close();}}
  };return api;
}

function diagnosticOrigin(value,development=false){const u=new URL(value);need(!u.username&&!u.password&&!u.search&&!u.hash&&u.pathname==='/'&&(u.protocol==='https:'||development&&u.protocol==='http:'&&['127.0.0.1','localhost'].includes(u.hostname)),'DIAGNOSTICS_ORIGIN_INVALID');return u.origin;}
export function createDiagnosticTransport({origin,development=false,getAccessToken,fetchImpl=fetch,signal}){
  const base=diagnosticOrigin(origin,development);need(typeof getAccessToken==='function','DIAGNOSTICS_AUTH_REQUIRED');
  async function request(path,{method='GET',body}={}){const token=await getAccessToken();need(typeof token==='string'&&token.length>=20&&token.length<=4096&&!/\s/.test(token),'DIAGNOSTICS_AUTH_REQUIRED');
    const encoded=body===undefined?undefined:canonicalDiagnosticJson(body);if(encoded)need(bytes(encoded)<=LOCAL_DIAGNOSTIC_LIMITS.batchBytes,'DIAGNOSTICS_BATCH_TOO_LARGE');
    let response;try{response=await fetchImpl(base+path,{method,headers:{authorization:'Bearer '+token,...(encoded?{'content-type':'application/json'}:{})},...(encoded?{body:encoded}:{}),redirect:'error',signal:signal?AbortSignal.any([signal,AbortSignal.timeout(15000)]):AbortSignal.timeout(15000)});}catch{throw new Error('DIAGNOSTICS_TRANSPORT_UNAVAILABLE');}
    if(response.status===401||response.status===403)throw new Error('DIAGNOSTICS_AUTH_REQUIRED');if(response.status===410)throw new Error('DIAGNOSTICS_RETENTION_EXPIRED');if(response.status===409)throw new Error('DIAGNOSTICS_PAYLOAD_CONFLICT');if(response.status===413||response.status===429)throw new Error('DIAGNOSTICS_QUOTA_EXCEEDED');if(!response.ok)throw new Error('DIAGNOSTICS_TRANSPORT_UNAVAILABLE');
    const text=await readBoundedDiagnosticText(response,65536,'DIAGNOSTICS_RECEIPT_INVALID');try{return JSON.parse(text);}catch{throw new Error('DIAGNOSTICS_RECEIPT_INVALID');}}
  return {register:async input=>{const r=await request('/api/diagnostics/cases',{method:'POST',body:input});need(UUID.test(r?.caseId)&&UUID.test(r.diagnosticSessionId)&&(r.intentId??null)===(input.intentId??null)&&(input.intentId||r.diagnosticSessionId===input.diagnosticSessionId)&&(r.runId==null||UUID.test(r.runId))&&(r.reportId==null||UUID.test(r.reportId))&&['open','complete','partial','partial_quota'].includes(r.captureState),'DIAGNOSTICS_RECEIPT_INVALID');return r;},sendBatch:(caseId,batch)=>{need(UUID.test(caseId),'DIAGNOSTICS_CASE_INVALID');return request('/api/diagnostics/cases/'+caseId+'/batches',{method:'POST',body:batch});},receipt:(caseId,segmentId)=>{need(UUID.test(caseId)&&UUID.test(segmentId),'DIAGNOSTICS_CASE_INVALID');return request('/api/diagnostics/cases/'+caseId+'/receipt?segmentId='+segmentId);}};
}
export async function deliverDiagnosticOutbox({spool,transport,sleep=ms=>new Promise(done=>setTimeout(done,ms)),isRunning=()=>true,signal,maxAttempts=5,binding,retryBudget={attempts:0}}){
  need(safeInt(maxAttempts,1,5),'DIAGNOSTICS_RETRY_INVALID');spool.expire();const results=[];need(safeInt(retryBudget.attempts,0,5),'DIAGNOSTICS_RETRY_INVALID');
  for(const initial of spool.pendingCases({binding})){
    let attempt=0,last='pending';
    while(retryBudget.attempts<maxAttempts&&isRunning()&&!signal?.aborted){
      if(attempt>0){let delay=[5000,30000,120000,600000][attempt-1];while(delay>0&&isRunning()&&!signal?.aborted){const step=Math.min(delay,1000);await sleep(step);delay-=step;}}if(!isRunning()||signal?.aborted)break;attempt++;retryBudget.attempts++;
      try{let current=spool.caseState(initial.local_id);if(!current.remote_id){const registered=await transport.register({diagnosticSessionId:current.session_id,...(current.intent_id?{intentId:current.intent_id}:{})});need(isRunning()&&!signal?.aborted,'DIAGNOSTICS_TRANSPORT_UNAVAILABLE');spool.bindRemote(current.local_id,registered);current=spool.caseState(current.local_id);}
        for(const batch of spool.pendingBatches(current.local_id)){need(isRunning()&&!signal?.aborted,'DIAGNOSTICS_TRANSPORT_UNAVAILABLE');await transport.sendBatch(current.remote_id,batch);const receipt=await transport.receipt(current.remote_id,batch.segmentId);need(isRunning()&&!signal?.aborted,'DIAGNOSTICS_TRANSPORT_UNAVAILABLE');spool.acknowledge(current.local_id,receipt);}
        last=spool.caseState(current.local_id).state;if(spool.pendingBatches(current.local_id).some(b=>b.completion!=='open'))throw new Error('DIAGNOSTICS_TRANSPORT_UNAVAILABLE');break;
      }catch(e){if(!isRunning()||signal?.aborted)break;const code=e?.message;last=['DIAGNOSTICS_AUTH_REQUIRED','DIAGNOSTICS_BINDING_INVALID','DIAGNOSTICS_TOKEN_INVALID','DIAGNOSTICS_CREDENTIAL_STORE_UNAVAILABLE'].includes(code)?'pending_auth':code==='DIAGNOSTICS_RETENTION_EXPIRED'?'retention_expired':code==='DIAGNOSTICS_PAYLOAD_CONFLICT'?'conflict':'pending';spool.setDeliveryState(initial.local_id,last);if(last!=='pending'||code==='DIAGNOSTICS_QUOTA_EXCEEDED')break;}
    }
    results.push({localCaseId:initial.local_id,state:last,attempts:attempt});
  }
  return results;
}
