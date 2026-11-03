/** Physical client producer; execution performs an actual approved native model run.
 * Never installs runtime-inputs and never supplies missing browser/SQL evidence. */
import {DatabaseSync} from 'node:sqlite';
import {createHash} from 'node:crypto';
import {readFile,writeFile,mkdir,lstat,realpath} from 'node:fs/promises';
import {resolve,relative,isAbsolute,dirname} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {diagnosticLauncher,readReviewedHandoff} from './mcp-diagnostics-launcher.mjs';
import {canonicalDiagnosticJson,validateClientDiagnosticEnvelope,validateLocalRunObservation} from './mcp-diagnostics-client.mjs';
const need=(v,c)=>{if(!v)throw new Error(c)};
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const SOURCES=['tools/mcp-diagnostics-client.mjs','tools/mcp-diagnostics-oauth.mjs','tools/mcp-diagnostics-io.mjs','tools/mcp-diagnostics-launcher.mjs','tools/run-mcd-client-capture.mjs','infrastructure/owner-identity/codex-bench.ps1','infrastructure/owner-identity/run-codex-google-local.mjs','tools/run_aci_native.mjs','packages/owner-web/lib/run-handoff.ts'];
async function regular(file,maxBytes){const info=await lstat(file);need(info.isFile()&&!info.isSymbolicLink()&&info.nlink===1&&info.size<=maxBytes,'MCD_CAPTURE_FILE_INVALID');return readFile(file);}
function inside(root,path){const absolute=resolve(root,path),part=relative(root,absolute);need(part&&!part.startsWith('..')&&!isAbsolute(part),'MCD_CAPTURE_PATH_INVALID');return absolute;}
async function inventory(root){return Object.fromEntries(await Promise.all(SOURCES.map(async file=>[file,hash(await regular(resolve(root,file),1024*1024))])));}
export function projectActualClientRows({eventRows,batchRows,caseRow,segmentId,nativeSummary,runObservation}){
  need(caseRow&&UUID.test(segmentId)&&Array.isArray(eventRows)&&Array.isArray(batchRows),'MCD_CAPTURE_ROWS_INVALID');
  const events=eventRows.map(row=>{need(row.segment_id===segmentId,'MCD_CAPTURE_SEGMENT_MISMATCH');const e=JSON.parse(row.payload);validateClientDiagnosticEnvelope(e);return e;});
  // Setup/collection failure envelopes have no native call ID and must not be
  // relabelled as actual native tool calls.
  if(runObservation)validateLocalRunObservation(runObservation);
  const calls=events.filter(e=>e.callIdHash).map(e=>({type:'mcp_tool_call_end',server:'w3bench_user',tool:e.tool,outcome:e.outcome,eventId:e.eventId,callIdHash:e.callIdHash,...(e.traceId?{traceId:e.traceId}:{}),...(e.errorCode?{errorCode:e.errorCode}:{}),startedAt:e.startedAt,completedAt:e.completedAt,durationMs:e.durationMs,...(runObservation?.sourceCallIdHash===e.callIdHash&&runObservation.sourceTool===e.tool?{run:{runId:runObservation.runId,status:runObservation.status,...(runObservation.terminal===undefined?{}:{terminal:runObservation.terminal})},observedAt:runObservation.observedAt}:{})}));
  const batches=batchRows.map(row=>{need(row.segment_id===segmentId,'MCD_CAPTURE_SEGMENT_MISMATCH');return JSON.parse(row.payload);});
  return {runObservation:runObservation??null,events,diagnosticEvents:events.filter(e=>!e.callIdHash),calls,batches,case:{localCaseId:caseRow.local_id,caseId:caseRow.remote_id,diagnosticSessionId:caseRow.session_id,intentId:caseRow.intent_id,reportId:caseRow.report_id,state:caseRow.state,gap:caseRow.gap},localToolCalls:nativeSummary.localToolCallCount===0?[]:[{kind:'observed_local_tool',count:nativeSummary.localToolCallCount??null}]};
}
export async function readActualClientSpool({repoRoot,localCaseId,segmentId,nativeSummary}){
  need(UUID.test(localCaseId)&&UUID.test(segmentId),'MCD_CAPTURE_IDENTIFIERS_MISSING');const file=resolve(repoRoot,'.local/diagnostics-helper/spool/diagnostics.sqlite');const info=await lstat(file);need(info.isFile()&&!info.isSymbolicLink()&&info.nlink===1,'MCD_CAPTURE_FILE_INVALID');
  const db=new DatabaseSync(file,{readOnly:true});try{db.exec('PRAGMA query_only=ON; PRAGMA busy_timeout=5000;');const observed=db.prepare('SELECT projection FROM run_observations WHERE segment_id=?').get(segmentId),runObservation=observed?JSON.parse(observed.projection):null;const caseRow=db.prepare('SELECT * FROM cases WHERE local_id=?').get(localCaseId),eventRows=db.prepare('SELECT segment_id,payload FROM events WHERE segment_id=? ORDER BY rowid').all(segmentId),batchRows=db.prepare('SELECT segment_id,payload,acked FROM batches WHERE segment_id=? ORDER BY sequence').all(segmentId);need(db.prepare('SELECT local_id FROM segments WHERE id=?').get(segmentId)?.local_id===localCaseId,'MCD_CAPTURE_SEGMENT_MISMATCH');return {source:'sqlite_observer',observer:{role:'client_sqlite_observer',readOnly:true},queryKind:'actual_safe_client_events_and_batches',...projectActualClientRows({eventRows,batchRows,caseRow,segmentId,nativeSummary,runObservation})};}finally{db.close();}
}
export async function runMcdClientCapture({jobFile,repoRoot=resolve(dirname(fileURLToPath(import.meta.url)),'..')}){
  const job=JSON.parse((await regular(jobFile,16384)).toString('utf8'));need(job&&Object.keys(job).every(k=>['schemaVersion','origin','handoffFile','outputDirectory'].includes(k))&&job.schemaVersion==='mcd-native-client-job/v1'&&typeof job.origin==='string'&&typeof job.handoffFile==='string'&&typeof job.outputDirectory==='string','MCD_CAPTURE_JOB_INVALID');
  const handoffFile=inside(repoRoot,job.handoffFile),outputDirectory=inside(repoRoot,job.outputDirectory);need(relative(repoRoot,outputDirectory).replaceAll('\\','/').startsWith('.local/'),'MCD_CAPTURE_PATH_INVALID');await mkdir(outputDirectory,{recursive:true,mode:0o700});need((await realpath(outputDirectory)).toLowerCase()===outputDirectory.toLowerCase(),'MCD_CAPTURE_PATH_INVALID');
  const {selection}=await readReviewedHandoff(handoffFile),before=await inventory(repoRoot),startedAt=new Date().toISOString();
  // This is the only execution path: real pinned CLI/OAuth, never a fixture or
  // metadata-only probe. No raw stdout, prompts or native credentials are saved.
  const result=await diagnosticLauncher({action:'run',origin:job.origin,handoffFile,repoRoot});const finishedAt=new Date().toISOString(),after=await inventory(repoRoot);need(canonicalDiagnosticJson(before)===canonicalDiagnosticJson(after),'MCD_CAPTURE_SOURCE_CHANGED');
  need(result.native&&UUID.test(result.localCaseId)&&UUID.test(result.segmentId),'MCD_CAPTURE_NATIVE_EVIDENCE_UNAVAILABLE');
  const observation=await readActualClientSpool({repoRoot,localCaseId:result.localCaseId,segmentId:result.segmentId,nativeSummary:result.native});need(observation.case.intentId===selection.intentId,'MCD_CAPTURE_INTENT_MISMATCH');
  const write=async(name,value)=>{const bytes=Buffer.from(JSON.stringify(value,null,2)+'\n');need(bytes.length<=8*1024*1024,'MCD_CAPTURE_TOO_LARGE');const file=resolve(outputDirectory,name);await writeFile(file,bytes,{flag:'wx',mode:0o600});return {path:relative(repoRoot,file).replaceAll('\\','/'),sha256:hash(bytes)};};
  const nativeRef=await write('native.json',{implementation:'native_codex_cli',clientVersion:'0.165.0',boundary:'actual_pinned_native_model_process',startedAt,finishedAt,calls:observation.calls,localToolCalls:observation.localToolCalls,summary:result.native,lastRunObservation:result.native.clientRunObservation??{},selection:{agentId:selection.agentId,intentId:selection.intentId,mode:selection.mode},serverOutcome:'requires_independent_run_intent_audit'});
  const outboxRef=await write('client-outbox.json',observation);
  const deliveryRef=await write('client-delivery.json',{mechanism:'deterministic_helper',trigger:result.native.exitCode===0?'native_exit':'native_error',caseId:result.caseId,reportId:result.reportId,segmentId:result.segmentId,state:result.diagnosticState,attempts:result.delivery,collectionGaps:result.collectionGaps,receipt:'requires_actual_http_and_independent_postgresql_observer',adminBrowser:'not_observed_by_client_producer'});
  const manifest={schemaVersion:'mcd-client-fragments/v1',scenarioId:'MCD-SC-002',sourceInputs:{before,after},raw:{native:nativeRef,clientOutbox:outboxRef,clientDelivery:deliveryRef},missingBoundaries:['explicit_owner_browser_pkce_consent','sc002_negative_variants_with_business_and_diagnostic_observer_pairs','actual_http_receipt_with_postgresql_watermarks','admin_browser_click_and_database_match','independent_run_intent_audit'],runtimeStatus:'incomplete'};
  const manifestRef=await write('client-fragments.json',manifest);return {manifestRef,nativeRef,outboxRef,deliveryRef,runtimeStatus:'incomplete',caseId:result.caseId,segmentId:result.segmentId};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){const args=process.argv.slice(2);if(args.length!==2||args[0]!=='--job'){process.stderr.write('Usage: node tools/run-mcd-client-capture.mjs --job <private job JSON>\n');process.exitCode=1;}else runMcdClientCapture({jobFile:args[1]}).then(r=>process.stdout.write(JSON.stringify(r,null,2)+'\n')).catch(error=>{process.stderr.write((/^MCD_[A-Z_]+$/.test(error?.message)?error.message:'MCD_CLIENT_CAPTURE_FAILED')+'\n');process.exitCode=1;});}
