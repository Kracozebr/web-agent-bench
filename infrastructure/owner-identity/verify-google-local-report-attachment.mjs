import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { dirname, basename, isAbsolute, parse, relative, resolve, sep } from 'node:path';
import { lstat, mkdir, readFile, realpath, writeFile } from 'node:fs/promises';

const requireOwnerIdentity=createRequire('/workspace/packages/owner-identity/package.json');
const requireOwnerAcceptance=createRequire('/workspace/packages/owner-acceptance/package.json');
const {Client}=requireOwnerAcceptance('pg');
const sharp=requireOwnerIdentity('sharp');
const REPOSITORY_ROOT=resolve(dirname(fileURLToPath(import.meta.url)),'../..');
const GOOGLE_LOCAL_ROOT=resolve(REPOSITORY_ROOT,'.local/owner-identity/google-local');
const SNAPSHOT_ROOT=resolve(GOOGLE_LOCAL_ROOT,'report-attachment');
const RUNTIME_PATH=resolve(GOOGLE_LOCAL_ROOT,'runtime.json');
const READY_PATH=resolve(GOOGLE_LOCAL_ROOT,'ready.json');
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HASH=/^[0-9a-f]{64}$/;
const MAX_IMAGE_BYTES=5*1024*1024;
const MAX_IMAGE_PIXELS=16_000_000;
let failureStage='startup';

function fail(code){const error=new Error('report_attachment_verification_failed');error.safeCode=code;throw error;}
function digest(value){return createHash('sha256').update(value).digest('hex');}
function pathWithin(root,target){const rel=relative(root,target);return rel===''||(!rel.startsWith(`..${sep}`)&&rel!=='..'&&!isAbsolute(rel));}
function parseArguments(argv){
 const values=new Map();
 for(let index=0;index<argv.length;index+=1){
  const name=argv[index];
  if(!['--agent-report-id','--owner-report-id','--output','--compare-before'].includes(name)||values.has(name))fail('arguments_invalid');
  const value=argv[index+1];if(typeof value!=='string'||value.startsWith('--'))fail('arguments_invalid');
  values.set(name,value);index+=1;
 }
 const agentReportId=values.get('--agent-report-id'),ownerReportId=values.get('--owner-report-id'),output=values.get('--output');
 if(!UUID.test(agentReportId??'')||!UUID.test(ownerReportId??'')||agentReportId.toLowerCase()===ownerReportId.toLowerCase()||!output)fail('arguments_invalid');
 return {agentReportId:agentReportId.toLowerCase(),ownerReportId:ownerReportId.toLowerCase(),output,
  compareBefore:values.get('--compare-before')};
}

async function assertDirectoryChain(path){
 const absolute=resolve(path),root=resolve(absolute,parseRoot(absolute));
 let current=root;
 for(const part of absolute.slice(root.length).split(sep).filter(Boolean)){
  current=resolve(current,part);const info=await lstat(current);
  if(info.isSymbolicLink()||!info.isDirectory())fail('private_path_component_invalid');
 }
}
function parseRoot(path){
 // Node's path.parse is kept local to avoid accepting a drive-relative path.
 return parse(path).root;
}

async function assertSnapshotPath(input,allowMissing){
 const target=resolve(REPOSITORY_ROOT,input);
 if(!pathWithin(SNAPSHOT_ROOT,target)||!target.endsWith('.json')||basename(target).length>96)fail('snapshot_path_invalid');
 await mkdir(SNAPSHOT_ROOT,{recursive:true,mode:0o700});
 await assertDirectoryChain(SNAPSHOT_ROOT);
 const rootReal=await realpath(SNAPSHOT_ROOT),parentReal=await realpath(dirname(target));
 if(!pathWithin(rootReal,parentReal))fail('snapshot_root_mismatch');
 try{const info=await lstat(target);if(!info.isFile()||info.isSymbolicLink()||allowMissing)fail('snapshot_path_exists');}
 catch(error){if(error.code!=='ENOENT'||!allowMissing)throw error;}
 return target;
}

async function loadRuntimeBinding(){
 const runtime=JSON.parse(await readFile(RUNTIME_PATH,'utf8'));
 const databaseName=runtime?.schemaVersion==='real-google-local-runtime/v1'&&typeof runtime.databaseName==='string'
  ?runtime.databaseName:null;
 if(!/^oid_google_local_[a-f0-9]{32}$/.test(databaseName??''))fail('runtime_binding_invalid');
 const ready=JSON.parse(await readFile(READY_PATH,'utf8'));
 if(ready?.schemaVersion!=='real-google-local-ready/v1'||ready.status!=='ready'||ready.googleMode!=='google'||ready.databaseName!==databaseName)
  fail('runtime_not_ready');
 return {databaseName,databaseNameSha256:digest(databaseName)};
}

async function queryFingerprint(client,label,query,parameters,maxRows=50_000){
 const result=await client.query(query,[...parameters,maxRows+1]);
 if(result.rows.length>maxRows)fail(`${label}_snapshot_limit_exceeded`);
 return {count:result.rows.length,sha256:digest(JSON.stringify(result.rows))};
}

async function benchmarkStateSnapshot(client,ownerIds){
 const bound=[ownerIds];
 const ledger=await queryFingerprint(client,'ledger',`SELECT id::text,entry_type,source_kind,available_delta_units::text,
   reserved_delta_units::text,expired_delta_units::text,created_at::text FROM oid_ledger_entry
   WHERE owner_id=ANY($1::uuid[]) ORDER BY id::text LIMIT $2`,bound);
 const runs=await queryFingerprint(client,'runs',`SELECT id::text,status,mode,task_ids,release_identity,manifest_hash,
   quote_price_units::text,cash_ceiling_units::text,queued_at::text,queue_deadline::text,started_at::text,
   overall_deadline::text,cancellation_requested_at::text,finished_at::text,terminal_reason,cancellation_reason
   FROM oid_benchmark_run WHERE owner_id=ANY($1::uuid[]) ORDER BY id::text LIMIT $2`,bound);
 const tasks=await queryFingerprint(client,'tasks',`SELECT t.run_id::text,t.task_index,t.task_id,t.status,t.closure_status,
   t.accepted_action_sequence::text,t.action_cutoff_sequence::text,t.reconciled_action_sequence::text,
   t.started_at::text,t.deadline_at::text,t.finished_at::text
   FROM oid_run_task t JOIN oid_benchmark_run r ON r.id=t.run_id WHERE r.owner_id=ANY($1::uuid[])
   ORDER BY t.run_id::text,t.task_index LIMIT $2`,bound);
 const actions=await queryFingerprint(client,'actions',`SELECT a.id::text,a.run_id::text,a.task_index,a.action_sequence::text,
   a.action_kind,a.payload_hash,a.accepted_at::text,receipt.receipt_status,receipt.receipt_revision,
   receipt.evidence_hash,receipt.transaction_hash,receipt.updated_at::text,outbox.status AS outbox_status,
   outbox.created_at::text AS outbox_created_at,outbox.delivered_at::text AS outbox_delivered_at
   FROM oid_run_task_action a JOIN oid_benchmark_run r ON r.id=a.run_id
   LEFT JOIN oid_run_task_action_receipt receipt ON receipt.action_id=a.id
   LEFT JOIN oid_run_task_action_outbox outbox ON outbox.action_id=a.id
   WHERE r.owner_id=ANY($1::uuid[]) ORDER BY a.run_id::text,a.task_index,a.action_sequence LIMIT $2`,bound);
 const evaluations=await queryFingerprint(client,'evaluations',`SELECT e.run_id::text,e.task_index,e.task_id,e.input_hash,e.result_hash,
   e.result_json->>'status' AS evaluation_status,e.result_json->>'outcome' AS outcome
   FROM oid_run_task_evaluation e JOIN oid_benchmark_run r ON r.id=e.run_id WHERE r.owner_id=ANY($1::uuid[])
   ORDER BY e.run_id::text,e.task_index LIMIT $2`,bound);
 return {ledger,runs,tasks,actions,evaluations};
}

async function verifyImageFile(row,imageRootReal){
 const checks={storagePathBound:false,fileByteCountMatches:false,fileSha256Matches:false,webpEncodingValid:false,
  dimensionsMatch:false,normalizedOutputValid:false};
 if(!UUID.test(row.storage_key??'')||!HASH.test(row.output_sha256??''))return checks;
 const expected=resolve(imageRootReal,`${row.storage_key}.webp`);
 if(!pathWithin(imageRootReal,expected)||basename(expected)!==`${row.storage_key}.webp`)return checks;
 try{
  const info=await lstat(expected),resolved=await realpath(expected);
  if(info.isSymbolicLink()||!info.isFile()||!pathWithin(imageRootReal,resolved)||basename(resolved)!==basename(expected))return checks;
  checks.storagePathBound=true;
  const bytes=await readFile(resolved);
  checks.fileByteCountMatches=bytes.length===row.output_bytes;
  checks.fileSha256Matches=bytes.length===row.output_bytes&&digest(bytes)===row.output_sha256;
  checks.webpEncodingValid=bytes.length>=12&&bytes.subarray(0,4).toString('ascii')==='RIFF'&&bytes.subarray(8,12).toString('ascii')==='WEBP';
  const metadata=await sharp(bytes,{limitInputPixels:MAX_IMAGE_PIXELS,failOn:'warning',sequentialRead:true,animated:false}).metadata();
  const width=Number(row.width),height=Number(row.height),pixels=width*height;
  checks.dimensionsMatch=metadata.format==='webp'&&metadata.width===width&&metadata.height===height&&
   Number.isSafeInteger(width)&&Number.isSafeInteger(height)&&width>0&&height>0&&pixels<=MAX_IMAGE_PIXELS&&
   (metadata.pages===undefined||metadata.pages===1);
  checks.normalizedOutputValid=bytes.length>0&&bytes.length<=MAX_IMAGE_BYTES&&row.output_bytes===bytes.length&&row.output_mime==='image/webp'&&
   ['image/png','image/jpeg','image/webp'].includes(row.input_mime)&&Number.isInteger(row.input_bytes)&&row.input_bytes>0&&
   row.input_bytes<=MAX_IMAGE_BYTES&&row.expected_input_bytes===row.input_bytes&&checks.webpEncodingValid&&checks.dimensionsMatch&&
   metadata.exif===undefined&&metadata.xmp===undefined&&metadata.iptc===undefined;
 }catch{ return checks; }
 return checks;
}

async function snapshotReports(client,reportIds,imageRootReal){
 const reportsResult=await client.query(`SELECT r.id::text,r.owner_id::text,r.agent_id::text,r.source,r.reporter_kind,
   r.reporter_id::text,r.status,r.revision,
   (SELECT count(*)::int FROM oid_support_image_upload u WHERE u.report_id=r.id AND u.status='attached') AS attached_image_count,
   (SELECT count(*)::int FROM oid_support_report_audit a WHERE a.report_id=r.id AND a.actor_owner_id=r.owner_id
     AND a.actor_agent_id IS NULL AND a.event_type='owner_attached_image' AND a.revision=r.revision
     AND a.operation_id ~ '^[A-Za-z0-9_-]{12,128}$' AND a.payload_hash ~ '^[0-9a-f]{64}$') AS owner_attach_audit_count
   FROM oid_support_report r WHERE r.id=ANY($1::uuid[]) ORDER BY r.id::text`,[reportIds]);
 const rawReports=reportsResult.rows;
 const labels=new Map([[reportIds[0],'agent'],[reportIds[1],'owner']]);
 const reports=rawReports.map(row=>{
  const label=labels.get(row.id);
  const principalMatches=label==='agent'
   ?row.source==='agent'&&row.reporter_kind==='agent'&&row.agent_id!==null&&row.reporter_id===row.agent_id
   :row.source==='owner'&&row.reporter_kind==='owner'&&row.reporter_id===row.owner_id;
  return {label,present:true,sourceValid:label==='agent'?row.source==='agent':row.source==='owner',principalMatches,
   status:row.status,revision:row.revision,attachedImageCount:Number(row.attached_image_count),
   ownerAttachAuditCount:Number(row.owner_attach_audit_count)};
 });
 const uploadsResult=await client.query(`SELECT u.id::text AS upload_id,u.report_id::text AS report_id,u.owner_id::text AS upload_owner_id,
   u.uploader_kind,u.uploader_id::text AS uploader_id,u.uploader_agent_id::text AS uploader_agent_id,
   u.status,u.input_mime,u.expected_input_bytes,u.input_bytes,u.output_bytes,u.output_sha256,u.output_mime,u.width,u.height,u.storage_key::text AS storage_key,
   r.owner_id::text AS report_owner_id,r.revision,
   EXISTS(SELECT 1 FROM oid_support_report_audit a WHERE a.report_id=r.id AND a.actor_owner_id=r.owner_id AND a.actor_agent_id IS NULL
     AND a.event_type='owner_attached_image' AND a.revision=r.revision AND a.operation_id ~ '^[A-Za-z0-9_-]{12,128}$'
     AND a.payload_hash ~ '^[0-9a-f]{64}$' AND a.metadata->'imageIds' @> jsonb_build_array(u.id::text)) AS attachment_audit_bound
   FROM oid_support_image_upload u JOIN oid_support_report r ON r.id=u.report_id
   WHERE r.id=ANY($1::uuid[]) AND u.status='attached' ORDER BY r.id::text,u.id::text`,[reportIds]);
 const images=[];
 for(const row of uploadsResult.rows){
  const reportLabel=labels.get(row.report_id);
  const fileChecks=await verifyImageFile(row,imageRootReal);
  images.push({report:reportLabel,uploadPrincipalMatches:row.status==='attached'&&row.uploader_kind==='owner'&&
    row.uploader_id===row.report_owner_id&&row.upload_owner_id===row.report_owner_id&&row.uploader_agent_id===null,
   attachmentAuditBound:row.attachment_audit_bound===true,...fileChecks});
 }
 const reportOwnerIds=[...new Set(rawReports.map(row=>row.owner_id))];
 const allReportsPresent=rawReports.length===2&&new Set(reports.map(row=>row.label)).size===2;
 const sameOwner=reportOwnerIds.length===1;
 return {reports,images,ownerIds:reportOwnerIds,allReportsPresent,sameOwner,
  sourcePrincipalsValid:reports.length===2&&reports.every(row=>row.sourceValid&&row.principalMatches)};
}

async function verifyPrivateImageRoot(databaseName){
 const localNamespaceRoot=resolve('/local-google-data',databaseName);
 const privateRoot=resolve(localNamespaceRoot,'private-data');
 const imageRoot=resolve(privateRoot,'reports','images');
 if(!pathWithin(resolve('/local-google-data'),localNamespaceRoot)||!pathWithin(localNamespaceRoot,privateRoot)||!pathWithin(privateRoot,imageRoot))fail('private_path_binding_invalid');
 await assertDirectoryChain(localNamespaceRoot);
 await assertDirectoryChain(privateRoot);
 const reportsRoot=resolve(privateRoot,'reports');
 for(const directory of [reportsRoot,imageRoot]){
  try{
   const info=await lstat(directory);
   if(info.isSymbolicLink()||!info.isDirectory())fail('private_path_component_invalid');
  }catch(error){
   if(error.code==='ENOENT')return imageRoot;
   throw error;
  }
 }
 const privateReal=await realpath(privateRoot),imageReal=await realpath(imageRoot);
 if(!pathWithin(privateReal,imageReal))fail('private_path_root_mismatch');
 return imageReal;
}

function equalFingerprints(before,current){
 return ['ledger','runs','tasks','actions','evaluations'].every(key=>before?.[key]?.count===current?.[key]?.count&&
  before?.[key]?.sha256===current?.[key]?.sha256);
}

async function main(){
 failureStage='arguments';
 const args=parseArguments(process.argv.slice(2));
 failureStage='snapshot_paths';
 const outputPath=await assertSnapshotPath(args.output,true);
 const comparePath=args.compareBefore?await assertSnapshotPath(args.compareBefore,false):null;
 failureStage='runtime_binding';
 const {databaseName,databaseNameSha256}=await loadRuntimeBinding();
 failureStage='private_image_root';
 const imageRootReal=await verifyPrivateImageRoot(databaseName);
 const reportIds=[args.agentReportId,args.ownerReportId];
 failureStage='observer_secret';
 const observerPassword=(await readFile('/run/secrets/observer_password','utf8')).trim();
 if(observerPassword.length<16)fail('observer_secret_unavailable');
 const connectionString=new URL(`postgres://oid_observer@postgres:5432/${databaseName}`);connectionString.password=observerPassword;
 const client=new Client({connectionString:connectionString.href,application_name:'google_report_attachment_readonly_verifier'});
 let transactionOpen=false;
 let captured;
 try{
  failureStage='observer_connect';
  await client.connect();
  failureStage='observer_transaction';
  await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');transactionOpen=true;
  failureStage='observer_identity';
  const identity=(await client.query(`SELECT current_database() AS database,current_user AS role,
    current_setting('transaction_read_only') AS read_only`)).rows[0];
  if(identity?.database!==databaseName||identity.role!=='oid_observer'||identity.read_only!=='on')fail('observer_binding_invalid');
  failureStage='report_snapshot';
  const reportState=await snapshotReports(client,reportIds,imageRootReal);
  if(!reportState.sameOwner||reportState.ownerIds.length!==1)fail('report_owner_binding_invalid');
  failureStage='benchmark_snapshot';
  const benchmarkState=await benchmarkStateSnapshot(client,reportState.ownerIds);
  await client.query('COMMIT');transactionOpen=false;
  captured={schemaVersion:'google-local-report-attachment-snapshot/v1',classification:'private_readonly_report_attachment_evidence',
   capturedAt:new Date().toISOString(),runtime:{namespace:'google-local',databaseNameSha256},
   observer:{role:'oid_observer',transactionReadOnly:'on'},
   reportIdentitySha256:digest(reportIds.join('\n')),reports:reportState.reports,images:reportState.images,
   reportBinding:{allReportsPresent:reportState.allReportsPresent,sameOwner:reportState.sameOwner,
    sourcePrincipalsValid:reportState.sourcePrincipalsValid},benchmarkState};
 }catch(error){
  if(transactionOpen)await client.query('ROLLBACK').catch(()=>undefined);
  throw error;
 }finally{await client.end().catch(()=>undefined);}

 failureStage='comparison';
 let comparison=null;
 if(comparePath){
  const before=JSON.parse(await readFile(comparePath,'utf8'));
  if(before?.schemaVersion!=='google-local-report-attachment-snapshot/v1'||before.runtime?.databaseNameSha256!==databaseNameSha256||
   before.reportIdentitySha256!==captured.reportIdentitySha256)fail('baseline_binding_invalid');
  const reportMetadataUnchanged=before.reports.length===captured.reports.length&&before.reports.every(old=>{
   const now=captured.reports.find(item=>item.label===old.label);
   return now&&old.present===now.present&&old.sourceValid===now.sourceValid&&old.principalMatches===now.principalMatches&&
    old.status===now.status&&old.revision===now.revision;
  });
  const baselineAgent=before.reports.find(item=>item.label==='agent');
  const currentAgent=captured.reports.find(item=>item.label==='agent');
  const baselineOwner=before.reports.find(item=>item.label==='owner');
  const currentOwner=captured.reports.find(item=>item.label==='owner');
  comparison={baselinePresent:true,reportMetadataUnchanged,
   ledgerRunsActionsAndEvaluationsUnchanged:equalFingerprints(before.benchmarkState,captured.benchmarkState),
   agentAttachmentCountIncreased:!!baselineAgent&&!!currentAgent&&currentAgent.attachedImageCount>baselineAgent.attachedImageCount,
   ownerControlAttachmentCountUnchanged:!!baselineOwner&&!!currentOwner&&currentOwner.attachedImageCount===baselineOwner.attachedImageCount};
 }
 failureStage='snapshot_write';
 await writeFile(outputPath,`${JSON.stringify(captured,null,2)}\n`,{flag:'wx',mode:0o600});
 const agentImages=captured.images.filter(image=>image.report==='agent');
 const agentReport=captured.reports.find(report=>report.label==='agent');
 const attachmentsComplete=!!agentReport&&agentReport.attachedImageCount>0&&agentImages.length>0&&agentImages.every(image=>image.uploadPrincipalMatches&&image.attachmentAuditBound&&
   image.storagePathBound&&image.fileByteCountMatches&&image.fileSha256Matches&&image.webpEncodingValid&&
   image.dimensionsMatch&&image.normalizedOutputValid);
 const afterPass=!!comparison&&comparison.reportMetadataUnchanged&&comparison.ledgerRunsActionsAndEvaluationsUnchanged&&
  comparison.agentAttachmentCountIncreased&&comparison.ownerControlAttachmentCountUnchanged&&captured.reportBinding.allReportsPresent&&captured.reportBinding.sourcePrincipalsValid&&attachmentsComplete;
 const summary={status:comparison?(afterPass?'passed':'incomplete'):'baseline_captured',observerRole:'oid_observer',
  transactionReadOnly:true,reportCount:captured.reports.length,attachedImageCounts:Object.fromEntries(captured.reports.map(report=>[report.label,report.attachedImageCount])),
  attachmentChecks:{allAgentUploadsOwnerBound:agentImages.length>0&&agentImages.every(image=>image.uploadPrincipalMatches),
   allAgentAuditsBound:agentImages.length>0&&agentImages.every(image=>image.attachmentAuditBound),
   allAgentPrivatePathsBound:agentImages.length>0&&agentImages.every(image=>image.storagePathBound),
   allAgentImageHashesAndSizesMatch:agentImages.length>0&&agentImages.every(image=>image.fileByteCountMatches&&image.fileSha256Matches),
   allAgentOutputsNormalizedWebp:agentImages.length>0&&agentImages.every(image=>image.webpEncodingValid&&image.dimensionsMatch&&image.normalizedOutputValid)},
  comparison,benchmarkStateUnchanged:comparison?.ledgerRunsActionsAndEvaluationsUnchanged??null,
  snapshotWritten:true};
 console.log(JSON.stringify(summary));
 if(comparison&&!afterPass)process.exitCode=2;
}

main().catch(error=>{
 const code=typeof error?.safeCode==='string'&&/^[a-z0-9_]{1,64}$/.test(error.safeCode)?error.safeCode:
  typeof error?.code==='string'&&/^[0-9A-Z]{5}$/.test(error.code)?`database_${error.code.toLowerCase()}`:'report_attachment_verification_failed';
 process.stderr.write(`${failureStage}:${code}\n`);process.exitCode=1;
});
