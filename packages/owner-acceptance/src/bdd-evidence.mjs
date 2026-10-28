/** Publish immutable per-scenario raw capture bundles. Python adapters independently derive every passing claim. */
import {randomUUID} from 'node:crypto';
import {mkdir,readFile,writeFile,rename} from 'node:fs/promises';
import {resolve} from 'node:path';
import {assertSecretFree,sha256} from './evidence.mjs';
const CHANGES={'benchmark-task-suite':{prefix:'BTS',count:34},'benchmark-run-lifecycle':{prefix:'BRL',count:25}};
function sourceHashMap(inventory){
 if(!Array.isArray(inventory))return inventory;
 const entries=[];const seen=new Set();
 for(const row of inventory){
  if(!row||typeof row.path!=='string'||!row.path||row.path.includes('\\')||row.path.includes(':')||
    row.path.split('/').some(part=>!part||part==='.'||part==='..')||!(/^[0-9a-f]{64}$/).test(row.sha256)||seen.has(row.path))throw new Error('invalid_bdd_source_inventory');
  seen.add(row.path);entries.push([row.path,row.sha256]);
 }
 return Object.fromEntries(entries);
}
export function benchmarkBddCaptureDecision(capture,sourceStable){
 const rawReason=capture?.blockedReasonCode??capture?.reasonCode;
 const reasonCode=typeof rawReason==='string'&&/^[A-Za-z0-9_]{1,96}$/.test(rawReason)?rawReason:'runtime_variants_incomplete';
 if(capture?.status==='failed')return {status:'failed',reasonCode};
 if(sourceStable!==true)return {status:'blocked',reasonCode:'source_inputs_changed_during_run'};
 return {status:capture?.status==='verified'?'passed':'blocked',reasonCode};
}
export async function saveBenchmarkBddEvidence({repositoryRoot,changeName,scenarioId,capture,provenance,status='blocked',reasonCode='runtime_variants_incomplete'}){
 const profile=CHANGES[changeName];if(!profile||!['blocked','failed','passed'].includes(status))throw new Error('invalid_bdd_scope');
 const ids=Array.from({length:profile.count},(_,i)=>profile.prefix+'-SC-'+String(i+1).padStart(3,'0'));if(!ids.includes(scenarioId))throw new Error('invalid_bdd_scenario');
 const contractPath='tests/bdd/changes/'+changeName+'/harness-contracts.json',contractBytes=await readFile(resolve(repositoryRoot,contractPath)),contract=JSON.parse(contractBytes),row=contract.protected_scenarios[scenarioId];if(!row)throw new Error('bdd_contract_missing');
 const runId=randomUUID(),root=resolve(repositoryRoot,'artifacts/runs/acceptance',scenarioId),directory=resolve(root,'runs',runId);await mkdir(directory,{recursive:true});
 const captureFile=changeName==='benchmark-run-lifecycle'?'runtime-evidence.json':'runtime-capture.json';
 const artifacts=[];for(const [name,payload] of [[captureFile,capture],['provenance.json',{...provenance,inputHashesBefore:sourceHashMap(provenance.inputHashesBefore),inputHashesAfter:sourceHashMap(provenance.inputHashesAfter),contractSha256:sha256(contractBytes),changeName,scenarioId,localForkOnly:true}]]){
  assertSecretFree(payload);const bytes=Buffer.from(JSON.stringify(payload,null,2)+'\n');await writeFile(resolve(directory,name),bytes,{flag:'wx'});artifacts.push({path:name,sha256:sha256(bytes),contentType:'application/json',boundary:row.boundary});
 }
 const claimStatus=status==='passed'?'observed':'not_run';
 const manifest={schemaVersion:changeName+'-acceptance/v1',specProfile:'active-delta',scenarioId,runId,status,...(status==='blocked'?{blockedReasonCode:reasonCode}:{}),
  observations:Object.fromEntries(row.required_observations.map(name=>[name,{status:claimStatus}])),negativeVariants:Object.fromEntries(row.negative_variants.map(name=>[name,{status:claimStatus}])),artifacts};
 assertSecretFree(manifest);await writeFile(resolve(directory,'manifest.json'),JSON.stringify(manifest,null,2)+'\n',{flag:'wx'});
 const indexPath=resolve(root,'manifest.json');let previous=[];try{const value=JSON.parse(await readFile(indexPath,'utf8'));if(value.schemaVersion!==changeName+'-evidence-index/v1'||value.scenarioId!==scenarioId||!Array.isArray(value.runs))throw new Error('bdd_index_conflict');previous=value.runs;}catch(e){if(e.code!=='ENOENT')throw e;}
 const index={schemaVersion:changeName+'-evidence-index/v1',scenarioId,latestRunId:runId,status,runs:[...previous,runId]};const temporary=resolve(root,'.manifest-'+runId+'.tmp');await writeFile(temporary,JSON.stringify(index,null,2)+'\n',{flag:'wx'});await rename(temporary,indexPath);
 return {scenarioId,runId,status,path:'artifacts/runs/acceptance/'+scenarioId+'/runs/'+runId+'/manifest.json',sha256:sha256(await readFile(resolve(directory,'manifest.json')))};
}