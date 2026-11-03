/** Actual unified checkpoint/cold-restore producer. Declared synthetic reference
 * history is preserved as database data, never promoted to chain/grade evidence. */
import assert from 'node:assert/strict';
import {createHash,randomUUID} from 'node:crypto';
import {constants,createReadStream} from 'node:fs';
import {chmod,copyFile,lstat,mkdir,open,readFile,readdir,writeFile} from 'node:fs/promises';
import {resolve,relative,isAbsolute,sep} from 'node:path';
import {pathToFileURL} from 'node:url';
import http from 'node:http';
import pg from 'pg';
import {DatabaseSync} from 'node:sqlite';
import {createLocalCombinedBackup} from '../../../infrastructure/owner-identity/beta-backup-local.mjs';
import {openDiagnosticSpool,createDiagnosticTransport,deliverDiagnosticOutbox} from '../../../tools/mcp-diagnostics-client.mjs';
import {observeLocalAllocation} from '../../../tools/mcd-local-capacity-restore.mjs';

const sha=v=>createHash('sha256').update(v).digest('hex');
const canonical=v=>JSON.stringify(Array.isArray(v)?v.map(x=>JSON.parse(canonical(x))):v&&typeof v==='object'?Object.fromEntries(Object.entries(v).sort(([a],[b])=>a<b?-1:a>b?1:0).map(([k,x])=>[k,JSON.parse(canonical(x))])):v);
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const tableNames=['oid_diagnostic_oauth_request','oid_diagnostic_oauth_grant','oid_diagnostic_oauth_token'];
const contained=(base,path)=>{const p=relative(resolve(base),resolve(path));return p!==''&&!isAbsolute(p)&&p!=='..'&&!p.startsWith('..'+sep);};
const withDatabase=(url,name)=>{const value=new URL(url);value.pathname='/'+name;return value.href;};
const failurePhases=new Set(['preconditions','source_fixture','source_checkpoint','cold_restore','interrupted_upload_checkpoint','missing_or_tampered_received_evidence','remote_pending_absent_from_server','independent_client_server_restore','revoked_helper','local_30_day_expiry','stopped_or_uninstalled_helper','historical_aggregate_only','server_intake_closed','intake_original_export_validation','intake_closure_persist','intake_source_restart','intake_wait_for_purge','intake_original_owner_http','intake_fresh_owner_http','intake_helper_delivery','intake_sqlite_state']);
const intakeCodes=new Set(['REPORT_RETENTION_EXPIRED','DIAGNOSTICS_CASE_NOT_FOUND','DIAGNOSTICS_CASE_CONFLICT','DIAGNOSTICS_LINK_NOT_FOUND','DIAGNOSTICS_QUOTA_EXCEEDED','UNAUTHORIZED','FORBIDDEN','INTERNAL_ERROR','RATE_LIMITED']);
export function projectMcdColdRestoreFailure(error,state={}){
 const sourceFrames=[];for(const line of String(error?.stack??'').split(/\r?\n/).slice(1)){const match=line.replaceAll('\\','/').match(/((?:packages|infrastructure|tools)\/[A-Za-z0-9_./-]+\.(?:mjs|js|ts)):(\d+):(\d+)/);if(match)sourceFrames.push({path:match[1],line:Number(match[2]),column:Number(match[3])});if(sourceFrames.length===8)break;}
 const ref=state.purgeObservationRef,safeRef=ref&&/^artifacts\/runs\/mcp-call-diagnostics\/[a-f0-9-]{36}\/[a-z0-9_.-]+\.json$/.test(ref.path??'')&&/^[a-f0-9]{64}$/.test(ref.sha256??'');
 return {phase:failurePhases.has(state.phase)?state.phase:'preconditions',errorName:['Error','AssertionError','TypeError','RangeError','SyntaxError'].includes(error?.name)?error.name:'UnknownError',...(typeof error?.code==='string'&&/^[A-Z0-9]{5}$/.test(error.code)?{sqlState:error.code}:{}),sourceFrames,...(safeRef?{purgeObservationRef:{path:ref.path,sha256:ref.sha256}}:{}),httpObservations:(state.httpObservations??[]).slice(0,12).map(value=>({phase:failurePhases.has(value.phase)?value.phase:'server_intake_closed',path:'/api/owner/diagnostics/import',httpStatus:Number.isInteger(value.httpStatus)&&value.httpStatus>=100&&value.httpStatus<=599?value.httpStatus:null,...(intakeCodes.has(value.errorCode)?{errorCode:value.errorCode}:{})}))};
}

async function readOnly(url,work){
 const parsed=new URL(url);assert.equal(parsed.hostname,'postgres');assert.equal(parsed.username,'oid_observer');assert.match(parsed.pathname,/^\/oid_(?:acceptance|restore)_[a-f0-9]{32}$/);
 const c=new pg.Client({connectionString:url,application_name:'mcd-cold-readonly-observer'});await c.connect();
 try{await c.query('BEGIN READ ONLY');const row=(await c.query("SELECT current_user AS role,current_database() AS \"databaseName\",current_setting('transaction_read_only') AS mode")).rows[0];assert.equal(row.role,'oid_observer');assert.equal(row.mode,'on');const result=await work(c,{role:row.role,readOnly:true,databaseName:row.databaseName});await c.query('COMMIT');return result;}catch(error){await c.query('ROLLBACK').catch(()=>{});throw error;}finally{await c.end();}
}

export async function observeMcdRestoreDiagnostics(url,caseIds){
 assert(caseIds.length>0&&caseIds.every(id=>UUID.test(id)));
 return readOnly(url,async(c,observer)=>{
  const cases=(await c.query(`SELECT c.id AS "caseId",'client_diagnostics' AS kind,c.owner_id AS "ownerId",c.agent_id AS "agentId",c.connection_id AS "connectionId",c.diagnostic_session_id AS "diagnosticSessionId",c.intent_id AS "intentId",r.id AS "runId",c.report_id AS "reportId",c.created_at AS "createdAt",c.updated_at AS "updatedAt",c.capture_state AS "captureState",c.event_count AS "eventCount",c.error_count AS "errorCount" FROM oid_mcp_diagnostic_case c LEFT JOIN oid_benchmark_run r ON r.intent_id=c.intent_id WHERE c.id=ANY($1::uuid[]) ORDER BY c.id`,[caseIds])).rows;
  const events=(await c.query('SELECT envelope,case_id AS "caseId",responsibility,attribution_reason AS "attributionReason",evidence_ids AS "evidenceIds" FROM oid_mcp_diagnostic_event WHERE case_id=ANY($1::uuid[]) ORDER BY case_id,event_id',[caseIds])).rows.map(({envelope,...rest})=>({...envelope,...rest}));
  const reports=(await c.query(`SELECT r.id,c.id AS "caseId",c.owner_id AS "ownerId",'client_diagnostics' AS kind FROM oid_mcp_diagnostic_case c JOIN oid_support_report r ON r.id=c.report_id WHERE c.id=ANY($1::uuid[]) ORDER BY r.id`,[caseIds])).rows;
  const batches=(await c.query('SELECT case_id AS "caseId",segment_id AS "segmentId",batch_sequence AS "batchSequence",payload_hash AS "payloadHash",completion FROM oid_mcp_diagnostic_batch WHERE case_id=ANY($1::uuid[]) ORDER BY case_id,segment_id,batch_sequence',[caseIds])).rows;
  const audits=(await c.query('SELECT a.report_id AS "reportId",a.event_type AS "eventType",a.revision FROM oid_support_report_audit a JOIN oid_mcp_diagnostic_case c ON c.report_id=a.report_id WHERE c.id=ANY($1::uuid[]) ORDER BY a.report_id,a.revision,a.event_type',[caseIds])).rows;
  return JSON.parse(JSON.stringify({source:'postgresql_observer',observer,scope:{caseIds,fullDatabaseFingerprintsVerifiedSeparately:true},cases,events,reports,batches,audits}));
 });
}

async function rawAuthority(url){return readOnly(url,async(c,observer)=>JSON.parse(JSON.stringify({source:'postgresql_observer',observer,
 accessGrants:(await c.query('SELECT id,owner_id AS "ownerId",agent_id AS "agentId",source,role,access_generation AS "accessGeneration",revoked_at AS "revokedAt",expires_at AS "expiresAt" FROM oid_agent_access_grant ORDER BY id')).rows,
 executionLeases:(await c.query('SELECT agent_id AS "agentId",owner_id AS "ownerId",run_id AS "runId",claim_id AS "claimId",state FROM oid_run_execution_slot ORDER BY agent_id')).rows})));}

async function apiRefused(origin){
 const url=new URL('/healthz',origin);assert.equal(url.protocol,'http:');assert.equal(url.hostname,'127.0.0.1');
 return new Promise((done,reject)=>{const req=http.get(url,response=>{response.resume();reject(Error('mcd_cold_api_still_served'));});req.setTimeout(3000,()=>req.destroy(Error('mcd_cold_api_probe_timeout')));req.on('error',error=>{if(error.code==='ECONNREFUSED')done({url:url.href,outcome:'connection_refused',errorCode:'ECONNREFUSED'});else reject(Error('mcd_cold_api_not_proven_refused'));});});
}

async function fileRef(input,path){
 assert(contained(input.repoRoot,path));const info=await lstat(path);assert(info.isFile()&&!info.isSymbolicLink());assert(info.size<=2*1024*1024*1024+32*1024*1024);
 const hash=createHash('sha256');for await(const chunk of createReadStream(path))hash.update(chunk);return {path:relative(input.repoRoot,path).split(sep).join('/'),sha256:hash.digest('hex')};
}

async function fixtureUiData(input){
 const {ownerPage:page,adminPage:admin,observer,writer}=input;
 await admin.goto('/admin/bonus-codes',{waitUntil:'domcontentloaded'});await admin.getByTestId('bonus-code-label').fill('MCD unified backup fixture '+input.captureId.slice(0,8));await admin.getByTestId('bonus-code-kind').selectOption('group');await admin.getByTestId('bonus-code-amount').fill('1');await admin.getByTestId('bonus-code-maximum').fill('1');
 const issued=admin.waitForResponse(r=>new URL(r.url()).pathname==='/api/admin/bonus-codes'&&r.request().method()==='POST');await admin.getByTestId('bonus-code-issue-submit').click();const issueHttp=await issued;assert.equal(issueHttp.status(),201);let secret=(await issueHttp.json()).secret;assert.equal(typeof secret,'string');await admin.getByTestId('bonus-code-secret-hide').click();
 await page.goto('/billing',{waitUntil:'domcontentloaded'});await page.getByTestId('bonus-code-input').fill(secret);secret='';const claim=page.waitForResponse(r=>new URL(r.url()).pathname==='/api/owner/bonus-codes/redeem'&&r.request().method()==='POST');await page.getByTestId('bonus-code-redeem-submit').click();const claimHttp=await claim;assert.equal(claimHttp.status(),200);await page.getByTestId('bonus-code-redemption-receipt').waitFor({state:'visible'});
 await page.goto('/diagnostics?caseId='+input.caseId,{waitUntil:'domcontentloaded'});await page.getByTestId('diagnostic-details').waitFor({state:'visible'});const screenshot=await page.getByTestId('diagnostic-details').screenshot();assert(screenshot.length>0&&screenshot.length<=5*1024*1024);
 await page.goto('/reports',{waitUntil:'domcontentloaded'});await page.getByLabel('Title',{exact:true}).fill('SC006 unified backup screenshot fixture');await page.getByLabel('What happened?').fill('Synthetic acceptance fixture: preserve this actual diagnostic screenshot and report through unified backup. This is not a benchmark failure or a chain execution claim.');await page.locator('#report-image').setInputFiles({name:'mcd-diagnostics.png',mimeType:'image/png',buffer:screenshot});
 const submitted=page.waitForResponse(r=>new URL(r.url()).pathname==='/api/owner/reports'&&r.request().method()==='POST');await page.getByRole('button',{name:'Submit report',exact:true}).click();const reportHttp=await submitted;assert.equal(reportHttp.status(),201);const reportId=(await reportHttp.json()).report.id;assert(UUID.test(reportId));
 const rows=await observer.query('SELECT id,report_id,storage_key,output_bytes,output_sha256 FROM oid_support_image_upload WHERE report_id=$1::uuid AND owner_id=$2::uuid AND status=\'attached\' ORDER BY id',[reportId,input.ownerId]);assert.equal(rows.length,1);const image=rows[0];
 const imagePath=resolve(input.privateDataDir,'reports/images',image.storage_key+'.webp'),bytes=await readFile(imagePath);assert.equal(bytes.length,Number(image.output_bytes));assert.equal(sha(bytes),image.output_sha256);
 const artifact=resolve(writer.directory,'actual-server-report-image.webp');await writeFile(artifact,bytes,{flag:'wx',mode:0o600});
 const sourceCounts=await observer.query('SELECT (SELECT count(*)::int FROM oid_bonus_grant) AS bonuses,(SELECT count(*)::int FROM oid_run_task_evaluation) AS evaluations,(SELECT count(*)::int FROM oid_support_report) AS reports,(SELECT count(*)::int FROM oid_support_image_upload WHERE status=\'attached\') AS screenshots');
 assert(sourceCounts[0].bonuses>0&&sourceCounts[0].evaluations>0&&sourceCounts[0].reports>0&&sourceCounts[0].screenshots>0,'actual backup source must contain each declared data family');
 const setupRef=await writer.write('sc006-real-ui-fixture',{classification:'real_ui_bonus_claim_report_and_screenshot_with_declared_nonchain_reference_history',bonusIssueStatus:issueHttp.status(),bonusClaimStatus:claimHttp.status(),reportSubmitStatus:reportHttp.status(),reportId,image:{uploadId:image.id,reportId,storageKey:image.storage_key,bytes:bytes.length,sha256:sha(bytes)},sourceCounts:sourceCounts[0]});
 return {setupRef,image:{...image,sourcePath:imagePath,artifactRef:await fileRef(input,artifact)}};
}

function clientIdentity(directory){const db=new DatabaseSync(resolve(directory,'diagnostics.sqlite'),{readOnly:true});try{db.exec('PRAGMA query_only=ON; BEGIN');return {source:'sqlite_observer',observer:{role:'client_sqlite_observer',readOnly:true},cases:db.prepare('SELECT local_id,session_id,intent_id,remote_id,report_id,binding_json,created_at,state FROM cases ORDER BY local_id').all(),segments:db.prepare('SELECT id,local_id,next_batch,state FROM segments ORDER BY id').all(),batches:db.prepare('SELECT segment_id,sequence,hash,completion,acked FROM batches ORDER BY segment_id,sequence').all()};}finally{db.close();}}

async function sealTree(root,path=root){assert(path===root||contained(root,path));const info=await lstat(path);assert(!info.isSymbolicLink());if(info.isDirectory()){for(const name of await readdir(path))await sealTree(root,resolve(path,name));await chmod(path,0o500);}else{assert(info.isFile());await chmod(path,0o400);}}

async function fenceClone(input,restore){
 const name=restore.restoreDatabaseName;assert.match(name,/^oid_restore_[a-f0-9]{32}$/);assert.notEqual(name,new URL(input.databaseUrl).pathname.slice(1));
 const admin=new pg.Client({connectionString:withDatabase(input.databaseUrl,'owner_identity')});await admin.connect();try{await admin.query('ALTER DATABASE "'+name+'" SET default_transaction_read_only=on');}finally{await admin.end();}
 const owner=new pg.Client({connectionString:withDatabase(input.databaseUrl,name),application_name:'mcd-cold-owner-write-negative'});await owner.connect();let ownerWriteProbe;
 try{const identity=(await owner.query("SELECT current_user AS role,current_database() AS \"databaseName\",current_setting('default_transaction_read_only') AS \"defaultTransactionReadOnly\",current_setting('transaction_read_only') AS \"transactionReadOnly\"")).rows[0];let sqlState=null;try{await owner.query('UPDATE public.oid_ledger_entry SET id=id WHERE false');}catch(error){sqlState=error.code;}ownerWriteProbe={...identity,sqlState};assert.equal(identity.role,'oid_owner');assert.equal(identity.databaseName,name);assert.equal(identity.defaultTransactionReadOnly,'on');assert.equal(identity.transactionReadOnly,'on');assert.equal(sqlState,'25006');}finally{await owner.end();}
 const observerUrl=withDatabase(input.observerDatabaseUrl,name),raw=await rawAuthority(observerUrl);
 const proof=await readOnly(observerUrl,async(c,observer)=>{
  const databaseSettings=(await c.query('SELECT current_database() AS "databaseName",setconfig FROM pg_db_role_setting WHERE setdatabase=(SELECT oid FROM pg_database WHERE datname=current_database()) AND setrole=0 ORDER BY setdatabase')).rows;
  assert(databaseSettings.some(r=>r.setconfig.includes('default_transaction_read_only=on')));
  const helperAuthorityTables=[];for(const table of tableNames){const count=(await c.query('SELECT count(*)::int AS n FROM '+table)).rows[0].n;assert.equal(count,0);helperAuthorityTables.push({name:table,count});}
  const enabled="NOT EXISTS(SELECT 1 FROM pg_db_role_setting WHERE setdatabase=(SELECT oid FROM pg_database WHERE datname=current_database()) AND setrole=0 AND 'default_transaction_read_only=on'=ANY(setconfig))";
  const effectiveAccessGrants=(await c.query('SELECT id FROM oid_agent_access_grant WHERE revoked_at IS NULL AND expires_at>clock_timestamp() AND '+enabled+' ORDER BY id')).rows;
  const effectiveExecutionLeases=(await c.query("SELECT agent_id,run_id,claim_id FROM oid_run_execution_slot WHERE state='running' AND "+enabled+' ORDER BY agent_id')).rows;
  assert.equal(effectiveAccessGrants.length,0);assert.equal(effectiveExecutionLeases.length,0);
  return {source:'postgresql_observer',observer,databaseSettings,ownerWriteProbe,helperAuthorityTables,rawAccessGrants:raw.accessGrants,rawExecutionLeases:raw.executionLeases,effectiveAccessGrants,effectiveExecutionLeases,authorityMeaning:'effective_authority_requires_database_writes_raw_history_preserved',servedApi:false,apiProbe:await apiRefused(input.apiOrigin)};
 });await sealTree(restore.restoreRoot);return {proof,observerUrl};
}

async function localExpiry(input){
 const directory=resolve(input.repoRoot,'.local/mcd-sc006-expiry',input.captureId);await mkdir(directory,{recursive:true,mode:0o700});const createdAt=new Date(Date.now()-31*86400000);let spool=await openDiagnosticSpool({directory,now:()=>createdAt});
 try{const c=spool.createCase(),s=spool.createSegment(c.local_id),at=createdAt.toISOString();assert(spool.append(s,{eventId:randomUUID(),source:'client',stage:'transport',tool:'runs.current_task',outcome:'error',errorCode:'CONNECTION_REFUSED',startedAt:at,completedAt:at,durationMs:0}));spool.stageBatch(s,{completion:'partial'});}finally{spool.close();}
 const before=await observeLocalAllocation(directory),serverRowsBefore=await input.observer.query('SELECT (SELECT count(*)::int FROM oid_mcp_diagnostic_case) AS cases,(SELECT count(*)::int FROM oid_mcp_diagnostic_event) AS events');
 spool=await openDiagnosticSpool({directory});try{assert.equal(spool.expire(),1);}finally{spool.close();}
 const after=await observeLocalAllocation(directory),serverRowsAfter=await input.observer.query('SELECT (SELECT count(*)::int FROM oid_mcp_diagnostic_case) AS cases,(SELECT count(*)::int FROM oid_mcp_diagnostic_event) AS events');
 const pending=value=>value.groups.filter(g=>['event','batch'].includes(g.kind)).reduce((n,g)=>n+g.sumBytes,0);
 assert(pending(before)>0);assert.equal(pending(after),0);assert.deepEqual(serverRowsAfter,serverRowsBefore);
 return {source:'sqlite_observer',elapsedDays:(Date.now()-createdAt.getTime())/86400000,probeClock:'declared31day_creation_fixture_then_actual_resume_clock',beforePendingBytes:pending(before),afterResumePendingBytes:pending(after),serverRowsBefore,serverRowsAfter,beforeObservationRef:await input.writer.write('sc006-expiry-before',before),afterObservationRef:await input.writer.write('sc006-expiry-after',after)};
}

async function stoppedManagedHelper(){
 const matchingProcesses=[],unreadable=[];
 for(const name of await readdir('/proc'))if(/^\d+$/.test(name))try{const args=(await readFile('/proc/'+name+'/cmdline')).toString('utf8').split('\0');if(args.some(arg=>arg.endsWith('/tools/mcp-diagnostics-launcher.mjs')))matchingProcesses.push({pid:Number(name),executable:'mcp-diagnostics-launcher.mjs'});}catch(error){if(error.code!=='ENOENT'&&error.code!=='ESRCH')unreadable.push(Number(name));}
 assert.equal(unreadable.length,0);assert.equal(matchingProcesses.length,0);
 return {source:'procfs_observer',observedAt:new Date().toISOString(),registeredExecutable:'mcp-diagnostics-launcher.mjs',matchingProcesses,unreadable,state:'not_running',remotePurgeClaimed:false,scope:'controlled_managed_spool_only_no_global_remote_purge_claim'};
}

async function runMcdColdRestore(input,state){
 const {observer,writer,server}=input,controls=server?.privateControls;const blocked=reason=>({blocked:{reason}});
 if(!controls||!input.stopApi||!input.getRuntimeRecoverySecrets||!input.connectionInvalidationPaths?.journalPath)return blocked('actual_canonical_pending_outbox_or_operator_inputs_missing');
 const dbName=new URL(input.databaseUrl).pathname.slice(1);assert.match(dbName,/^oid_acceptance_[a-f0-9]{32}$/);assert(contained(input.captureIsolationRoot,input.privateDataDir));assert(contained(input.captureIsolationRoot,input.closureStatePath));
 const invalidationModule=await import(pathToFileURL(resolve(input.repoRoot,'packages/owner-identity/dist/agent-connection-invalidation-state.js')).href),paths=input.connectionInvalidationPaths;
 const invalidation=invalidationModule.createAgentConnectionInvalidationStore({journalPath:paths.journalPath,floorPath:paths.floorPath,expectedJournalId:paths.journalId});
 const spare=controls.spare;await invalidation.appendIntent({kind:'connection_revoke',operationId:'mcd_sc006_fixture_revoke_'+randomUUID().replaceAll('-',''),ownerId:spare.ownerId,agentId:spare.agentId,connectionId:spare.helperGrantId});
 state.phase='source_fixture';const setup=await fixtureUiData(input),selected=[...new Set([input.caseId,controls.canonical.caseId])];
 const scoped={business:()=>observer.business(),diagnostics:()=>observeMcdRestoreDiagnostics(input.observerDatabaseUrl,selected)};
 const variants=[],add=async(name,execute,request={boundary:'actual_unified_backup_and_independent_observation'})=>{state.phase=name;const v=await input.captureMcdVariant({name,request,execute,observer:scoped,writer});variants.push(v);};
 const originalSpool=await openDiagnosticSpool({directory:controls.canonical.spoolDirectory});let clientBundle;try{clientBundle=originalSpool.exportBundle(controls.canonical.localId);}finally{originalSpool.close();}
 const pendingRef=await writer.write('sc006-client-pending-not-server-received',clientBundle),revocationsBefore=await invalidation.read();assert(revocationsBefore.events.length>0);
 await input.stopApi();await apiRefused(input.apiOrigin);
 const beforeDatabase=await observeMcdRestoreDiagnostics(input.observerDatabaseUrl,selected),beforeDatabaseRef=await writer.write('sc006-server-received-diagnostics',beforeDatabase),businessRef=await writer.write('sc006-server-business',await observer.business()),rawAuthorityBeforeRef=await writer.write('sc006-raw-authority-before',await rawAuthority(input.observerDatabaseUrl));
 const runIds=(await observer.query('SELECT id FROM oid_benchmark_run ORDER BY id')).map(r=>r.id);assert(runIds.length>0);
 const sourceBuildSha256=sha(canonical(input.sourceInputsBefore)),checkpointId=randomUUID();
 const officialRefs=[beforeDatabaseRef,businessRef,setup.setupRef,setup.image.artifactRef];
 const officialEvidenceRefs={sourceProfile:'mcd_actual_diagnostic_http_ui_and_declared_nonchain_reference_history_preservation',runIds,sourceBuildSha256,
  files:officialRefs.map(r=>({relativePath:r.path,sourcePath:r.path,role:'mcd_received_evidence',sha256:r.sha256}))};
 await observer.suspend();let provider,checkpoint,restore,sourceResumed=false;
 try{
  state.phase='source_checkpoint';provider=await createLocalCombinedBackup({repoRoot:input.repoRoot,databaseUrl:input.databaseUrl,observerDatabaseUrl:input.observerDatabaseUrl,privateDataDir:input.privateDataDir,closureStatePath:input.closureStatePath,sourceBuildSha256,officialEvidenceRefs,
   getRuntimeRecoverySecrets:input.getRuntimeRecoverySecrets,stopApi:input.stopApi,restartApi:input.restartApi,resumeSourceAfterCheckpoint:false,hostBridgeRoot:input.hostBridgeRoot,hostOperatorRoot:input.hostOperatorRoot,backupRoot:input.backupRoot,restoreRoot:input.restoreRoot,checkpointId,kind:'pre_migration'});
  input.onProgress?.({phase:'mcd_actual_unified_checkpoint_waiting_for_host_broker',checkpointId,hostJobRoot:provider.hostJobRoot});
  let checkpointInventoryRef,fullSourceRef;
  observer.resume();
  await add('interrupted_upload_checkpoint',async()=>{await observer.suspend();try{checkpoint=await provider.createCheckpoint();assert.equal(checkpoint.status,'checkpoint_verified');assert.equal(checkpoint.writesMayBeEnabled,false);checkpointInventoryRef=await writer.write('sc006-actual-checkpoint-inventory',checkpoint.inventory);fullSourceRef=await writer.write('sc006-full-source-fingerprints',{source:'postgresql_observer',before:checkpoint.source.before,after:checkpoint.source.after});return {boundary:'unified_checkpoint_operator',outcome:checkpoint.status,checkpointInventoryRef,fullSourceRef,clientPendingReference:pendingRef};}finally{observer.resume();}});
  const cipher=checkpoint.inventory.files.find(r=>r.kind==='sealed_bundle');assert(cipher);const originalBundle=resolve(writer.directory,'sc006-source-encrypted-bundle.enc');await copyFile(resolve(checkpoint.bundleRoot,cipher.path),originalBundle,constants.COPYFILE_EXCL);const beforeBundleRef=await fileRef(input,originalBundle);assert.equal(beforeBundleRef.sha256,cipher.sha256);
  const tamperRoot=resolve(writer.directory,'sc006-tampered-checkpoint');await mkdir(tamperRoot,{mode:0o700});await copyFile(checkpoint.inventoryPath,resolve(tamperRoot,'inventory.json'),constants.COPYFILE_EXCL);const tamperFile=resolve(tamperRoot,'checkpoint.bundle.enc');await copyFile(originalBundle,tamperFile,constants.COPYFILE_EXCL);const handle=await open(tamperFile,'r+');try{const at=(await handle.stat()).size-1,b=Buffer.alloc(1);await handle.read(b,0,1,at);b[0]^=1;await handle.write(b,0,1,at);}finally{await handle.close();}const afterTamperRef=await fileRef(input,tamperFile);assert.notEqual(afterTamperRef.sha256,beforeBundleRef.sha256);
  await add('missing_or_tampered_received_evidence',async()=>{let errorCode;try{await provider.restoreCheckpoint({checkpoint:{bundleRoot:tamperRoot}});}catch(error){if(['beta_backup_file_integrity','beta_backup_bundle_ciphertext_integrity'].includes(error.message))errorCode=error.message;else throw error;}assert(errorCode);return {boundary:'unified_backup_restore_verifier',outcome:'rejected',errorCode,checkpointInventoryRef,beforeBundleRef,afterTamperRef};});
  state.phase='cold_restore';restore=await provider.restoreCheckpoint();assert.equal(restore.status,'verified_unserved');assert.equal(restore.writesMayBeEnabled,false);assert.equal(restore.retention.expired,false);
  const secrets=restore.takeRuntimeSecrets();for(const key of Object.keys(secrets))secrets[key]='';
  const {proof:fence,observerUrl}=await fenceClone(input,restore),afterDatabase=await observeMcdRestoreDiagnostics(observerUrl,selected),afterDatabaseRef=await writer.write('sc006-cold-restored-diagnostics',afterDatabase);
  const fullRestoredDatabaseRef=await writer.write('sc006-full-restored-fingerprints',{source:'postgresql_observer',observer:afterDatabase.observer,snapshot:restore.observations.beforeRetention});
  const restoredImagePath=resolve(restore.privateDataDir,'reports/images',setup.image.storage_key+'.webp'),restoredImageBytes=await readFile(restoredImagePath);assert.equal(restoredImageBytes.length,Number(setup.image.output_bytes));assert.equal(sha(restoredImageBytes),setup.image.output_sha256);
  const restoredImageArtifact=resolve(writer.directory,'sc006-restored-server-report-image.webp');await writeFile(restoredImageArtifact,restoredImageBytes,{flag:'wx',mode:0o600});
  const imageRestoreProofRef=await writer.write('sc006-actual-image-restore',{source:'postgresql_observer_and_filesystem_hash',uploadId:setup.image.id,reportId:setup.image.report_id,bytes:Number(setup.image.output_bytes),sha256:setup.image.output_sha256,sourceFileRef:setup.image.artifactRef,restoredFileRef:await fileRef(input,restoredImageArtifact)});
  for(const key of ['cases','events','reports','batches','audits'])assert.deepEqual(afterDatabase[key],beforeDatabase[key]);
  const originalAuthority=await readFile(resolve(input.repoRoot,rawAuthorityBeforeRef.path),'utf8').then(JSON.parse);assert.deepEqual(fence.rawAccessGrants,originalAuthority.accessGrants);assert.deepEqual(fence.rawExecutionLeases,originalAuthority.executionLeases);
  const revocationsAfter=await invalidation.read();assert.deepEqual(revocationsAfter,revocationsBefore);
  const officialManifestRef=await writer.write('sc006-restored-official-manifest',JSON.parse(await readFile(resolve(restore.officialEvidenceRoot,'../operator/official-evidence-manifest.json'),'utf8')));
  const receivedFiles=[beforeDatabaseRef,businessRef],serverManifestRef=await writer.write('sc006-server-received-manifest',{schemaVersion:'mcd-server-received-checkpoint-manifest/v1',classification:'actual_server_rows_exported_as_official_backup_evidence_not_client_spool',checkpointInventoryRef,officialManifestRef,diagnostics:{files:receivedFiles},clientPendingOutsideCheckpoint:[pendingRef.path]});
  await add('remote_pending_absent_from_server',async()=>({boundary:'actual_restored_official_manifest',serverManifestRef,clientPendingReferences:[pendingRef]}));
  const sourceLocalIdentity=clientIdentity(controls.canonical.spoolDirectory),restoredLocal=resolve(input.repoRoot,'.local/mcd-sc006-client-restored',input.captureId);await mkdir(restoredLocal,{recursive:true,mode:0o700});await copyFile(resolve(controls.canonical.spoolDirectory,'diagnostics.sqlite'),resolve(restoredLocal,'diagnostics.sqlite'),constants.COPYFILE_EXCL);const restoredLocalIdentity=clientIdentity(restoredLocal);assert.deepEqual(restoredLocalIdentity,sourceLocalIdentity);
  await input.restartApi();sourceResumed=true;
  let localRestore;await add('independent_client_server_restore',async()=>{localRestore={source:'sqlite_observer',beforeRef:await writer.write('sc006-client-original-identities',sourceLocalIdentity),afterRef:await writer.write('sc006-client-restored-identities',restoredLocalIdentity),serverCaseId:controls.canonical.caseId,serverReportId:restoredLocalIdentity.cases[0].report_id,clientPendingBatchHashes:restoredLocalIdentity.batches.filter(r=>!r.acked).map(r=>r.hash)};assert.equal(localRestore.serverReportId,beforeDatabase.cases.find(c=>c.caseId===controls.canonical.caseId).reportId);return localRestore;});
  await invalidation.appendIntent({kind:'connection_revoke',operationId:'mcd_sc006_current_helper_revoke_'+randomUUID().replaceAll('-',''),ownerId:controls.canonical.ownerId,agentId:controls.canonical.agentId,connectionId:controls.canonical.helperGrantId});
  await add('revoked_helper',async()=>{const response=await controls.transport.request('/api/diagnostics/cases/'+controls.canonical.caseId+'/batches',{bearer:controls.canonical.bearer,body:controls.canonical.pendingFinalBatch});assert.equal(response.httpStatus,401);const spool=await openDiagnosticSpool({directory:restoredLocal});try{const result=await deliverDiagnosticOutbox({spool,transport:createDiagnosticTransport({origin:input.apiOrigin,development:true,getAccessToken:async()=>controls.canonical.bearer}),maxAttempts:1,binding:{agentId:controls.canonical.agentId,connectionId:controls.canonical.connectionId}});assert(result.some(r=>r.state==='pending_auth'));}finally{spool.close();}return response;},{method:'POST',path:'/api/diagnostics/cases/:caseId/batches',control:'current_external_helper_revoke'});
  let localRetention;await add('local_30_day_expiry',async()=>{localRetention=await localExpiry(input);return {boundary:'actual_local_launcher_resume_expiry',localRetention};});
  let stoppedHelper;await add('stopped_or_uninstalled_helper',async()=>{stoppedHelper=await stoppedManagedHelper();return stoppedHelper;});
  await add('historical_aggregate_only',async()=>{const rows=await observer.query('SELECT r.id,r.status FROM oid_benchmark_run r WHERE r.owner_id=$1::uuid AND NOT EXISTS(SELECT 1 FROM oid_mcp_diagnostic_case c WHERE c.intent_id=r.intent_id) ORDER BY r.id LIMIT 1',[input.ownerId]);assert.equal(rows.length,1);const response=await input.ownerPage.request.get('/api/owner/diagnostics/cases?runId='+rows[0].id);assert.equal(response.status(),200);const body=await response.json();assert.deepEqual(body.cases,[]);return {httpStatus:response.status(),cases:body.cases,referenceHistory:rows,classification:'declared_nonchain_reference_history_has_no_reconstructed_diagnostic_events'};});
  let serverIntakeClosedStatus,serverIntakeClosedCode,serverIntakeOutboxObservation,purgeObservationRef;const ownerIntakeControls=[];
  await add('server_intake_closed',async()=>{
   state.phase='intake_original_export_validation';
   const originalExport=input.originalOwnedExport;assert(originalExport&&originalExport.caseId===input.caseId,'actual original owned UI export is required');
   const originalRows=await observer.query('SELECT id AS "caseId",diagnostic_session_id AS "diagnosticSessionId",owner_id AS "ownerId",agent_id AS "agentId",connection_id AS "connectionId" FROM oid_mcp_diagnostic_case WHERE id=$1::uuid',[input.caseId]);assert.equal(originalRows.length,1);
   const originalCase=originalRows[0];assert.equal(originalCase.ownerId,input.ownerId);assert.equal(originalExport.diagnosticSessionId,originalCase.diagnosticSessionId);assert.equal(originalExport.binding.agentId,originalCase.agentId);assert.equal(originalExport.binding.connectionId,originalCase.connectionId);
   const originalCaseRef=await writer.write('sc006-original-owned-export-case',{source:'postgresql_observer',observer:observer.identity,...originalCase});
   const postOwner=async(phase,request)=>{state.phase=phase;const response=await input.ownerPage.request.post('/api/owner/diagnostics/import',{headers:{origin:input.publicOrigin},data:request}),body=await response.json();const observed={phase,httpStatus:response.status(),...(intakeCodes.has(body.error?.code)?{errorCode:body.error.code}:{})};state.httpObservations.push(observed);return {response,observed};};
   const validOriginal=await postOwner('intake_original_export_validation',originalExport),preExpiryResponseRef=await writer.write('sc006-original-owned-export-before-expiry-response',validOriginal.observed);assert.equal(validOriginal.observed.httpStatus,200,'the exact original UI export must replay before expiry');
   await input.stopApi();const end=new Date(Date.now()-31*86400000).toISOString();
   const closureEvidence=await writer.write('sc006-controlled-audited-beta-end',{classification:'controlled31day_beta_end_fixture_in_disposable_acceptance_only_not_historical_production_fact',databaseName:dbName,betaEndedAt:end});
   const module=await import(pathToFileURL(resolve(input.repoRoot,'packages/owner-identity/dist/report-closure-state.js')).href);
   state.phase='intake_closure_persist';await module.createReportClosureStateStore(input.closureStatePath).persistAuthoritativeClosure({betaEndedAt:end,sourceEvidenceSha256:closureEvidence.sha256});state.phase='intake_source_restart';await input.restartApi();
   state.phase='intake_wait_for_purge';let purgeObservation,purged=false;
   const sourceCases=checkpoint.source.before.tableFingerprints.oid_mcp_diagnostic_case.rowCount,sourceEvents=checkpoint.source.before.tableFingerprints.oid_mcp_diagnostic_event.rowCount;
   for(let attempt=0;attempt<120&&!purged;attempt++){
    const counts=await observer.query('SELECT (SELECT count(*)::int FROM oid_mcp_diagnostic_case) AS cases,(SELECT count(*)::int FROM oid_mcp_diagnostic_event) AS events');
    const retention=await observer.query('SELECT case_count AS "caseCount",event_count AS "eventCount",beta_ended_at AS "betaEndedAt",expires_at AS "expiresAt",deleted_at AS "deletedAt" FROM oid_mcp_diagnostic_retention_receipt ORDER BY id');
    purgeObservation={source:'postgresql_observer',observer:observer.identity,counts,retention};purged=counts[0].cases===0&&counts[0].events===0&&retention.length===1&&Number(retention[0].caseCount)===Number(sourceCases)&&Number(retention[0].eventCount)===Number(sourceEvents);
    if(!purged)await new Promise(done=>setTimeout(done,500));
   }
   purgeObservationRef=await writer.write('sc006-source-post-retention-purge',purgeObservation);state.purgeObservationRef=purgeObservationRef;assert(purged,'actual source purge and matching deletion receipt must precede stale-export controls');
   const value={segmentId:randomUUID(),batchSequence:0,events:[],completion:'partial'};
   const requests=[{kind:'original_owned_export_after_purge',phase:'intake_original_owner_http',request:originalExport,originalCaseRef,preExpiryResponseRef},{kind:'fresh_owned_export',phase:'intake_fresh_owner_http',request:{diagnosticSessionId:randomUUID(),binding:originalExport.binding,batch:{...value,payloadHash:sha(canonical(value))}}}];
   for(const control of requests){const requestRef=await writer.write('sc006-'+control.kind+'-request',control.request),{observed}=await postOwner(control.phase,control.request),responseRef=await writer.write('sc006-'+control.kind+'-response',observed);ownerIntakeControls.push({kind:control.kind,requestRef,responseRef,...(control.originalCaseRef?{originalCaseRef:control.originalCaseRef,preExpiryResponseRef:control.preExpiryResponseRef}:{})});if(control.kind==='original_owned_export_after_purge'){serverIntakeClosedStatus=observed.httpStatus;serverIntakeClosedCode=observed.errorCode;}assert.equal(observed.httpStatus,410);assert.equal(observed.errorCode,'REPORT_RETENTION_EXPIRED');}
   // A separate still-authorized helper proves that intake closure itself,
   // rather than revoked authorization, terminates local retries durably.
   const active=controls.active,dir=resolve(input.repoRoot,'.local/mcd-sc006-intake-closed',input.captureId);await mkdir(dir,{recursive:true,mode:0o700});
   const spool=await openDiagnosticSpool({directory:dir});let localCaseId;const httpResponses=[];
   try{
    const c=spool.createCase({binding:{agentId:active.agentId,connectionId:active.connectionId}});localCaseId=c.local_id;const s=spool.createSegment(c.local_id);assert(spool.stageBatch(s,{completion:'partial'}));
    const transport=createDiagnosticTransport({origin:input.apiOrigin,development:true,getAccessToken:async()=>active.bearer,fetchImpl:async(url,init)=>{const result=await fetch(url,init);httpResponses.push({path:new URL(url).pathname,httpStatus:result.status});return result;}});
    state.phase='intake_helper_delivery';await deliverDiagnosticOutbox({spool,transport,maxAttempts:1,binding:{agentId:active.agentId,connectionId:active.connectionId}});
   }finally{spool.close();}
   state.phase='intake_sqlite_state';const identity=clientIdentity(dir),localCase=identity.cases.find(c=>c.local_id===localCaseId);assert.equal(localCase.state,'retention_expired');assert(httpResponses.some(r=>r.httpStatus===410));
   serverIntakeOutboxObservation={source:'sqlite_observer',observer:identity.observer,localCaseId,state:localCase.state,httpResponses,identityRef:await writer.write('sc006-closed-intake-client-identities',identity)};
   return {httpStatus:serverIntakeClosedStatus,errorCode:serverIntakeClosedCode,closureEvidence,ownerIntakeControls,serverIntakeOutboxObservation};
  });
  const raw={beforeDatabaseRef,afterDatabaseRef,serverManifestRef,receivedFiles,clientPendingReferences:[pendingRef],serverWriteMode:'disabled',restoredAccessGrants:fence.effectiveAccessGrants,restoredExecutionLeases:fence.effectiveExecutionLeases,readOnlyFenceRef:await writer.write('sc006-actual-readonly-fence',fence),rawAuthorityBeforeRef,revocationsBefore,revocationsAfter,localRetention,localRestore,serverIntakeClosedStatus,ownerIntakeControls,purgeObservationRef,serverIntakeOutboxObservation,stoppedHelper,checkpointInventoryRef,fullSourceRef,fullRestoredDatabaseRef,imageRestoreProofRef,sourceFixtureRef:setup.setupRef};
  return {scenario006:{variants,raw:{restore:await writer.write('sc006-restore',raw)}}};
 }finally{observer.resume();if(!sourceResumed)await input.restartApi().catch(()=>{});}
}

export async function captureMcdColdRestore(input){
 const state={phase:'preconditions',httpObservations:[]};try{return await runMcdColdRestore(input,state);}catch(error){
  const errorCode=typeof error?.message==='string'&&/^(?:beta_backup_[a-z_]+|mcd_[a-z_]+)$/.test(error.message)?error.message:'mcd_actual_cold_restore_boundary_incomplete';
  const partialReference=await input.writer.write('sc006-blocked-actual-boundary',{boundary:'actual_unified_checkpoint_restore_producer',errorCode,...projectMcdColdRestoreFailure(error,state),qualification:'blocked_no_physical_acceptance_claim'});
  return {blocked:{reason:errorCode,partialReference}};
 }
}

