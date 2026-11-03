/** Fixed Windows capacity-job bridge. No shell/commands, credentials or tunable
 * limits cross this file IPC boundary. The host executes the same SQLite probe. */
import assert from 'node:assert/strict';
import {createHash,randomUUID} from 'node:crypto';
import {mkdir,lstat,readFile,writeFile,rename,readdir,realpath} from 'node:fs/promises';
import {resolve,relative,isAbsolute,sep} from 'node:path';

const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const HASH=/^[a-f0-9]{64}$/;
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const canonical=value=>JSON.stringify(Object.fromEntries(Object.entries(value).sort(([a],[b])=>a.localeCompare(b,'en'))));
const delay=ms=>new Promise(done=>setTimeout(done,ms));
const exists=async file=>{try{await lstat(file);return true;}catch(error){if(error.code==='ENOENT')return false;throw error;}};

async function directory(root,path){
  const part=relative(root,path);assert(part&&!part.startsWith('..')&&!isAbsolute(part));
  await mkdir(path,{recursive:true,mode:0o700});const info=await lstat(path);assert(info.isDirectory()&&!info.isSymbolicLink());
  assert.equal(await realpath(path),path);
}
async function jsonFile(file,maxBytes=2*1024*1024){
  const info=await lstat(file);assert(info.isFile()&&!info.isSymbolicLink()&&info.nlink===1&&info.size<=maxBytes,'invalid host IPC file');
  const bytes=await readFile(file);assert(bytes.length<=maxBytes);return {bytes,value:JSON.parse(bytes)};
}
async function atomicJson(file,value){
  assert(!await exists(file),'host IPC target already exists');const temp=file+'.'+randomUUID()+'.tmp';
  await writeFile(temp,JSON.stringify(value,null,2)+'\n',{flag:'wx',mode:0o600});await rename(temp,file);
}
function sourceMap(value){assert(value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).length);for(const [path,hash] of Object.entries(value))assert(typeof path==='string'&&!path.includes('\\')&&!path.startsWith('/')&&!path.split('/').includes('..')&&HASH.test(hash));return value;}

export function validateMcdHostResult(value,{captureId,jobId,jobSha256,sourceInputs}){
  assert(value&&Object.keys(value).every(k=>['schemaVersion','captureId','jobId','jobSha256','probeId','host','sourceInputs','local'].includes(k)));
  assert.equal(value.schemaVersion,'mcd-local-capacity-host-result/v1');assert.equal(value.captureId,captureId);assert.equal(value.jobId,jobId);assert.equal(value.jobSha256,jobSha256);
  assert.equal(value.probeId,captureId+'-host-'+jobId);assert.equal(value.host?.platform,'win32');assert.match(value.host?.nodeVersion??'',/^v24\./);
  assert.equal(canonical(sourceMap(value.sourceInputs?.before)),canonical(sourceInputs));assert.equal(canonical(sourceMap(value.sourceInputs?.after)),canonical(sourceInputs));
  assert(value.local&&Array.isArray(value.local.capacityProbes));assert.deepEqual(value.local.capacityProbes.map(p=>p.limit).sort(),['localBytes','localCases','localRows']);
  return value.local;
}

export async function runMcdHostCapacity(input){
  const {captureId,repoRoot,observer,writer}=input;assert(UUID.test(captureId));assert.match(observer.identity?.databaseName??'',/^oid_acceptance_[a-f0-9]{32}$/);
  const sourceInputs=sourceMap(input.sourceInputsBefore),jobId=randomUUID(),root=resolve(repoRoot),jobRoot=resolve(root,'.local/mcd-local-capacity-jobs',captureId);
  await directory(root,jobRoot);for(const name of ['requests','responses'])await directory(root,resolve(jobRoot,name));
  const jobFile=resolve(jobRoot,'job.json'),job={schemaVersion:'mcd-local-capacity-host-job/v1',captureId,jobId,sourceInputs};
  await atomicJson(jobFile,job);const jobSha256=sha(await readFile(jobFile));
  input.onProgress?.({phase:'mcd_local_capacity_waiting_for_host',captureId,jobId,jobPath:relative(root,jobFile).split(sep).join('/'),sourceInputCount:Object.keys(sourceInputs).length});
  const processed=new Map(),serverObservations=[],start=Date.now();let expectedSequence=0,lastProgress=0;
  while(Date.now()-start<30*60*1000){
    for(const name of (await readdir(resolve(jobRoot,'requests'))).filter(name=>name.endsWith('.json')).sort()){
      assert(UUID.test(name.slice(0,-5)),'host IPC request filename invalid');
      const requestFile=resolve(jobRoot,'requests',name),{bytes,value:request}=await jsonFile(requestFile,4096),requestHash=sha(bytes);
      if(processed.has(name)){assert.equal(processed.get(name),requestHash);continue;}
      assert(Object.keys(request).every(k=>['schemaVersion','captureId','jobId','requestId','sequence','kind'].includes(k)));
      assert.equal(request.schemaVersion,'mcd-local-server-counts/v1');assert.equal(request.captureId,captureId);assert.equal(request.jobId,jobId);assert.equal(request.requestId,name.slice(0,-5));
      assert.equal(request.kind,'read_server_rows');assert.equal(request.sequence,expectedSequence);assert(expectedSequence<2);
      const rows=await observer.query('SELECT (SELECT count(*)::int FROM oid_mcp_diagnostic_case) AS cases,(SELECT count(*)::int FROM oid_mcp_diagnostic_event) AS events,(SELECT count(*)::int FROM oid_support_report) AS reports');
      assert.equal(rows.length,1);assert(Object.keys(rows[0]).length===3&&['cases','events','reports'].every(k=>Number.isSafeInteger(rows[0][k])&&rows[0][k]>=0));
      const response={schemaVersion:'mcd-local-server-counts/v1',captureId,jobId,requestId:request.requestId,sequence:expectedSequence,source:'postgresql_observer',observer:observer.identity,rows};
      await atomicJson(resolve(jobRoot,'responses',name),response);
      const originalRequestFile=resolve(writer.directory,'windows-host-server-request-'+expectedSequence+'.json');await writeFile(originalRequestFile,bytes,{flag:'wx',mode:0o600});
      const requestRef={path:relative(root,originalRequestFile).split(sep).join('/'),sha256:requestHash};
      const responseRef=await writer.write('windows-host-server-counts-'+expectedSequence,response);
      assert.equal(responseRef.sha256,sha(await readFile(resolve(jobRoot,'responses',name))));
      serverObservations.push({requestRef,responseRef});
      processed.set(name,requestHash);expectedSequence++;
    }
    const statusFile=resolve(jobRoot,'status.json');if(await exists(statusFile)){
      const {value:status}=await jsonFile(statusFile,16384);assert.equal(status.captureId,captureId);assert.equal(status.jobId,jobId);
      if(status.state==='failed')throw Object.assign(new Error('host local capacity probe failed'),{code:'MCD_LOCAL_HOST_PROBE_FAILED',safeDiagnostic:{phase:'host_local_capacity',hostState:'failed',messageOmitted:true}});
      if(Date.now()-lastProgress>60000){input.onProgress?.({phase:'mcd_local_capacity_host_running',elapsedSeconds:Math.floor((Date.now()-start)/1000),hostState:['running','complete'].includes(status.state)?status.state:'unknown'});lastProgress=Date.now();}
    }
    const resultFile=resolve(jobRoot,'result.json');if(await exists(resultFile)){
      const {bytes,value}=await jsonFile(resultFile,16*1024*1024),local=validateMcdHostResult(value,{captureId,jobId,jobSha256,sourceInputs});assert.equal(expectedSequence,2);
      const refs=[];for(const probe of local.capacityProbes)for(const key of ['observationRef','afterObservationRef','blockingResponseRef','acceptedResponseRef'])if(probe[key])refs.push(probe[key]);
      for(const ref of refs){assert(typeof ref.path==='string'&&ref.path.startsWith('artifacts/runs/mcp-call-diagnostics/'+captureId+'/host-local-capacity/')&&!ref.path.includes('\\')&&!ref.path.split('/').includes('..')&&HASH.test(ref.sha256));const {bytes:actual}=await jsonFile(resolve(root,ref.path),8*1024*1024);assert.equal(sha(actual),ref.sha256);}
      const jobRef=await writer.write('windows-host-local-capacity-job',job);assert.equal(jobRef.sha256,jobSha256);
      const originalFile=resolve(writer.directory,'windows-host-local-capacity-original-result.json');await writeFile(originalFile,bytes,{flag:'wx',mode:0o600});
      const resultRef={path:relative(root,originalFile).split(sep).join('/'),sha256:sha(bytes)};
      const evidenceRef=await writer.write('windows-host-local-capacity-evidence',{schemaVersion:'mcd-local-capacity-host-evidence/v1',jobRef,resultRef,serverObservations});
      input.onProgress?.({phase:'mcd_local_capacity_host_complete',elapsedSeconds:Math.floor((Date.now()-start)/1000),capacityProbeCount:local.capacityProbes.length});
      return {...local,hostCapacityEvidenceRef:evidenceRef};
    }
    await delay(250);
  }
  throw Object.assign(new Error('host capacity deadline reached'),{code:'MCD_LOCAL_HOST_DEADLINE'});
}
