/** Real SQLite local quota/restore probes. No server/native fixtures or usage seeding. */
import {DatabaseSync} from 'node:sqlite';
import {randomUUID,createHash} from 'node:crypto';
import {mkdir,lstat,copyFile,readdir,stat} from 'node:fs/promises';
import {resolve,relative,isAbsolute} from 'node:path';
import {openDiagnosticSpool,canonicalDiagnosticJson,LOCAL_DIAGNOSTIC_LIMITS} from './mcp-diagnostics-client.mjs';
const need=(v,c)=>{if(!v)throw new Error(c)};
const sha=value=>createHash('sha256').update(canonicalDiagnosticJson(value)).digest('hex');
const envelope=large=>{const at=new Date().toISOString();return {eventId:randomUUID(),source:'client',stage:'client_validation',tool:'runs.task_action_status',outcome:'error',errorCode:'TASK_EXECUTION_IDENTITY_UNAVAILABLE',startedAt:at,completedAt:at,durationMs:0,...(large?{traceId:randomUUID(),callIdHash:'a'.repeat(64),operationIdHash:'b'.repeat(64),actionId:randomUUID(),taskId:'H3',taskIndex:11,httpStatus:599,rpcCode:-2147483648,fieldPaths:['operationId','taskIndex','command.recipient','command.amount','command.route','command.kind','unknown_field','actionId'],schemaHash:'c'.repeat(64),contractHash:'d'.repeat(64),client:'claude_desktop',clientVersion:'0.165.0',model:'gpt-6.1-terra',reasoningEffort:'unknown'}:{})};};
export async function observeLocalAllocation(directory,{physicalGuard}={}){
  const file=resolve(directory,'diagnostics.sqlite'),info=await lstat(file);need(info.isFile()&&!info.isSymbolicLink(),'MCD_LOCAL_OBSERVER_PATH_INVALID');const db=new DatabaseSync(file,{readOnly:true});
  let result;try{db.exec('PRAGMA query_only=ON; PRAGMA busy_timeout=5000; BEGIN;');
    const groups=[];for(const [kind,table,columns,payload] of [['event','events','id,segment_id,payload',true],['batch','batches','segment_id,sequence,payload',true],['segment','segments','id,local_id,created_at',false],['case','cases','local_id,session_id,intent_id,binding_json,created_at',false]]){
      const rows=db.prepare(`SELECT ${columns} FROM ${table} ORDER BY 1,2`).all(),aggregate=db.prepare(`SELECT count(*) AS count,${payload?'coalesce(sum(length(CAST(payload AS BLOB))),0)':'0'} AS sumBytes,${payload?'coalesce(max(length(CAST(payload AS BLOB))),0)':'0'} AS maxBytes FROM ${table}`).get();groups.push({kind,count:Number(aggregate.count),sumBytes:Number(aggregate.sumBytes),maxBytes:Number(aggregate.maxBytes),rowsSha256:sha(rows)});
    }
    result={source:'sqlite_observer',queryKind:'diagnostic_allocation_aggregates',observer:{role:'client_sqlite_observer',readOnly:true},groups,reservedGroups:[],sqlite:{pageSize:Number(db.prepare('PRAGMA page_size').get().page_size),maxPageCount:physicalGuard?.maxPages??Number(db.prepare('PRAGMA max_page_count').get().max_page_count),pageCount:Number(db.prepare('PRAGMA page_count').get().page_count),journalMode:db.prepare('PRAGMA journal_mode').get().journal_mode}};db.exec('COMMIT');
  }finally{db.close();}
  if(physicalGuard)result.physicalGuardObservation={source:'sqlite_writer_readonly_pragmas',pageSize:physicalGuard.pageSize,maxPageCount:physicalGuard.maxPages,pageCount:physicalGuard.pageCount};
  result.files=await Promise.all((await readdir(directory)).map(async name=>({name,bytes:(await stat(resolve(directory,name))).size})));return result;
}
function retainedEqual(a,b){return canonicalDiagnosticJson(a.groups)===canonicalDiagnosticJson(b.groups)&&canonicalDiagnosticJson(a.reservedGroups)===canonicalDiagnosticJson(b.reservedGroups);}
async function rejection(fn){try{const value=fn();need(value===false,'MCD_LOCAL_EXPECTED_REJECTION_MISSING');return {errorCode:'DIAGNOSTICS_QUOTA_EXCEEDED',returned:false};}catch(e){if(e.message==='DIAGNOSTICS_QUOTA_EXCEEDED')return {errorCode:e.message};throw e;}}
export async function runMcdLocalCapacityRestore({repoRoot,captureId,writeArtifact,readServerRows}){
  need(typeof captureId==='string'&&/^[A-Za-z0-9_-]{1,80}$/.test(captureId)&&typeof writeArtifact==='function','MCD_LOCAL_CAPTURE_ARGUMENT_INVALID');const root=resolve(repoRoot),directory=resolve(root,'.local/mcd-local-capacity',captureId),part=relative(root,directory);need(part&&!part.startsWith('..')&&!isAbsolute(part),'MCD_LOCAL_CAPTURE_PATH_INVALID');await mkdir(directory,{recursive:true,mode:0o700});
  const capacityProbes=[];
  for(const kind of ['Bytes','Rows','Cases']){
    const path=resolve(directory,'local'+kind);await mkdir(path,{mode:0o700});const spool=await openDiagnosticSpool({directory:path});let lastAccepted=null,attempt;
    try{
      if(kind==='Cases'){for(let i=0;i<LOCAL_DIAGNOSTIC_LIMITS.spoolCases;i++){const c=spool.createCase();lastAccepted={outcome:'accepted',localCaseId:c.local_id};}attempt=()=>spool.createCase();}
      else{
        const segments=Array.from({length:9},()=>{const c=spool.createCase();return spool.createSegment(c.local_id);});let index=0;
        if(kind==='Rows'){for(;index<LOCAL_DIAGNOSTIC_LIMITS.spoolRows;index++){need(spool.append(segments[index%9],envelope(false))===true,'MCD_LOCAL_ROW_FILL_INTERRUPTED');lastAccepted={outcome:'accepted',acceptedEvents:index+1};}attempt=()=>spool.append(segments[0],envelope(false));}
        else{let exhausted=false;for(;index<LOCAL_DIAGNOSTIC_LIMITS.spoolRows;index++){try{const admitted=spool.append(segments[index%9],envelope(true));if(admitted===false){exhausted=true;break;}}catch(error){if(error.message!=='DIAGNOSTICS_QUOTA_EXCEEDED')throw error;exhausted=true;break;}}need(exhausted,'MCD_LOCAL_PHYSICAL_CAP_NOT_REACHED');attempt=()=>spool.append(segments[index%9],envelope(true));}
      }
      // Stabilize the explicit quota marker before the observed rejection pair.
      if(kind==='Rows')await rejection(attempt);
      const before=await observeLocalAllocation(path,{physicalGuard:spool.diskUsage()}),blocked=await rejection(attempt),after=await observeLocalAllocation(path,{physicalGuard:spool.diskUsage()});need(retainedEqual(before,after),'MCD_LOCAL_REJECTION_CHANGED_RETAINED_ROWS');
      const prefix='local-'+kind.toLowerCase(),probe={limit:'local'+kind,mode:kind==='Bytes'?'dominated':'exact_over',observationRef:await writeArtifact(prefix+'-before',before),afterObservationRef:await writeArtifact(prefix+'-after',after),blockingResponseRef:await writeArtifact(prefix+'-blocked',blocked)};if(kind!=='Bytes')probe.acceptedResponseRef=await writeArtifact(prefix+'-accepted',lastAccepted);capacityProbes.push(probe);
    }finally{spool.close();}
  }
  const original=resolve(directory,'retention-original'),restored=resolve(directory,'retention-restored');await mkdir(original,{mode:0o700});await mkdir(restored,{mode:0o700});const createdAt=new Date(Date.now()-31*86400000);let spool=await openDiagnosticSpool({directory:original,now:()=>createdAt}),local,segmentId,payload;
  try{local=spool.createCase();segmentId=spool.createSegment(local.local_id);spool.append(segmentId,envelope(false));payload=spool.stageBatch(segmentId,{completion:'complete'});}finally{spool.close();}
  const beforeRestore=await observeLocalAllocation(original);await copyFile(resolve(original,'diagnostics.sqlite'),resolve(restored,'diagnostics.sqlite'));const afterRestore=await observeLocalAllocation(restored);need(retainedEqual(beforeRestore,afterRestore),'MCD_LOCAL_RESTORE_CHANGED_IDENTITY');
  spool=await openDiagnosticSpool({directory:restored});let retention;try{const before=await observeLocalAllocation(restored),beforeServer=readServerRows?await readServerRows():undefined;const expiredCases=spool.expire(),after=await observeLocalAllocation(restored),afterServer=readServerRows?await readServerRows():undefined;const sum=d=>d.groups.filter(g=>['event','batch'].includes(g.kind)).reduce((n,g)=>n+g.sumBytes,0);need(expiredCases===1&&sum(before)>0&&sum(after)===0,'MCD_LOCAL_EXPIRY_NOT_OBSERVED');retention={source:'sqlite_observer',observer:{role:'client_sqlite_observer',readOnly:true},elapsedDays:(Date.now()-createdAt.getTime())/86400000,probeClock:'controlled_local_creation_time_then_actual_resume_clock',beforePendingBytes:sum(before),afterResumePendingBytes:sum(after),...(readServerRows?{serverRowsBefore:beforeServer,serverRowsAfter:afterServer}:{}),beforeObservationRef:await writeArtifact('local-expiry-before',before),afterObservationRef:await writeArtifact('local-expiry-after',after),localRestore:{beforeRef:await writeArtifact('local-restore-before',beforeRestore),afterRef:await writeArtifact('local-restore-after',afterRestore),diagnosticSessionId:local.session_id,localCaseId:local.local_id,segmentId,payloadHash:payload.payloadHash,reportId:null,authority:'not_restored'}};}finally{spool.close();}
  return {capacityProbes,localRetention:retention,localRetentionRef:await writeArtifact('local-retention',retention),runtimeStatus:'local_fragments_only',missingBoundaries:readServerRows?['current_helper_authorization_and_server_intake_closed_http_probes']:['independent_server_rows_around_local_expiry','current_helper_authorization_and_server_intake_closed_http_probes']};
}
