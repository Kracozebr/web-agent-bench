/** Source-pinned offline finalizer, run only AFTER the isolated API process closed. */
import {createHash} from 'node:crypto';
import {readFile,writeFile,readdir,lstat,realpath} from 'node:fs/promises';
import {resolve,relative,sep,isAbsolute} from 'node:path';
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const SHA=/^[a-f0-9]{64}$/;
const requiredSources=['packages/owner-acceptance/src/agent-client-connection-cases.mjs','packages/owner-acceptance/src/agent-client-connection-owner-case.mjs','packages/owner-acceptance/src/agent-client-connection-finalize.mjs','tools/run_aci_native.mjs','infrastructure/owner-identity/run-codex-google-local.mjs','packages/owner-identity/src/agent-mcp-acceptance-observer.ts'];
async function file(root,path,maxBytes=32*1024*1024){
  if(typeof path!=='string'||path.includes('\\')||path.split('/').some(x=>!x||x==='.'||x==='..')||isAbsolute(path))throw new Error('aci_finalizer_path_invalid');
  const target=resolve(root,path);if(!target.startsWith(resolve(root)+sep))throw new Error('aci_finalizer_path_invalid');
  let current=resolve(root);for(const part of path.split('/')){current=resolve(current,part);const s=await lstat(current);if(s.isSymbolicLink()||(await realpath(current)).toLowerCase()!==current.toLowerCase())throw new Error('aci_finalizer_path_invalid');}
  const meta=await lstat(target);if(!meta.isFile()||meta.size>maxBytes)throw new Error('aci_finalizer_file_invalid');return readFile(target);
}
async function referenced(root,ref){if(!SHA.test(ref?.sha256??''))throw new Error('aci_finalizer_reference_invalid');const bytes=await file(root,ref.path);if(hash(bytes)!==ref.sha256)throw new Error('aci_finalizer_reference_changed');return JSON.parse(bytes);}
async function reference(root,path){const bytes=await file(root,path);return {path,sha256:hash(bytes)};}
function nativeProjection(turn){
  const out={};for(const key of ['schemaVersion','captureId','kind','client','clientVersion','authMethod','sourcePins','exitCode','terminalEvent','promptSha256','startedAt','finishedAt','mcpToolCallCount','localToolCallCount'])out[key]=turn[key];
  return out;
}
export async function finalizeAgentClientConnectionCapture({partialRef,repoRoot,captureId,apiStopReceipt,outputPath}){
  const stop=apiStopReceipt;
  if(!stop||!Number.isSafeInteger(stop.processId)||stop.processId<=0||stop.signal!==null||!(stop.exitCode===0||(stop.requested===true&&stop.exitCode===143))||!/^[a-f0-9-]{36}$/.test(captureId))throw new Error('aci_finalizer_api_not_closed_cleanly');
  const root=resolve(repoRoot),partial=await referenced(root,partialRef),proof=partial.result?.aci;
  if(partial.schemaVersion!=='agent-client-connection-partial/v1'||partial.captureId!==captureId||proof?.captureId!==captureId)throw new Error('aci_finalizer_partial_binding_invalid');
  const provenance=partial.provenance,before=provenance?.inputHashesBefore,after=provenance?.inputHashesAfter;
  if(!before||!after||provenance.sourceStableDuringRun!==true||JSON.stringify(before)!==JSON.stringify(after)||requiredSources.some(path=>!before[path]))throw new Error('aci_finalizer_source_inventory_invalid');
  for(const [path,digest]of Object.entries(before))if(!SHA.test(digest)||hash(await file(root,path))!==digest)throw new Error('aci_finalizer_source_changed');
  const directory=`artifacts/runs/agent-client-connection/${captureId}`;
  const traceRef=await reference(root,`${directory}/mcp-projections.jsonl`),trace=(await file(root,traceRef.path)).toString('utf8').trim().split('\n').filter(Boolean).map(x=>JSON.parse(x));
  if(!trace.length)throw new Error('aci_finalizer_empty_trace');
  const names=(await readdir(resolve(root,directory))).filter(name=>/^observer-[a-f0-9-]{36}-status\.json$/.test(name));
  const statusRefs=[];
  for(const name of names){const ref=await reference(root,`${directory}/${name}`),status=await referenced(root,ref);if(status.schemaVersion!=='aci-mcp-observer-status/v1'||status.errors?.length)throw new Error('aci_finalizer_observer_failed');statusRefs.push(ref);}
  const allStatuses=await Promise.all(statusRefs.map(ref=>referenced(root,ref)));
  if(!allStatuses.some(status=>status.processId===stop.processId))throw new Error('aci_finalizer_stop_process_not_flushed');
  for(const epoch of new Set(trace.map(x=>x.epoch))){
    const statuses=await Promise.all(statusRefs.map(ref=>referenced(root,ref))),matching=statuses.filter(x=>x.epoch===epoch),packets=trace.filter(x=>x.epoch===epoch);
    if(matching.length!==1||packets.length!==matching[0].records||packets.some((x,i)=>x.sequence!==i+1))throw new Error('aci_finalizer_observer_not_fully_closed');
  }
  const nativeRefs=[],nativeTurns=[];
  for(let index=1;index<=proof.nativeTurns.length;index++){
    const turn=JSON.parse(await file(root,`.local/aci-native/${captureId}/response-${index}.json`,1024*1024));
    if(turn.captureId!==captureId||turn.kind!==proof.nativeTurns[index-1].kind||turn.promptSha256!==proof.nativeTurns[index-1].promptSha256||turn.authMethod!=='native_oauth'||turn.sourcePins?.helperSha256!==before['tools/run_aci_native.mjs']||turn.sourcePins?.baseHelperSha256!==before['infrastructure/owner-identity/run-codex-google-local.mjs'])throw new Error('aci_finalizer_native_turn_binding_invalid');
    const projected=nativeProjection(turn),path=`${directory}/native-turn-${index}.json`;
    await writeFile(resolve(root,path),JSON.stringify(projected)+'\n',{flag:'wx',mode:0o600});nativeRefs.push(await reference(root,path));nativeTurns.push(projected);
  }
  const result={...partial,schemaVersion:'agent-client-connection-capture/v1',result:{...partial.result,aci:{...proof,nativeTurns,nativeSourceReferences:nativeRefs,mcp:trace,mcpTrace:traceRef,observerStatusReferences:statusRefs,observerErrors:[],finalizedAfterApiClose:true}},finalization:{schemaVersion:'aci-finalization/v1',partialRef,apiStopReceipt:stop,at:new Date().toISOString()}};
  const destination=outputPath??`${directory}/capture-final.json`;
  if(!destination.startsWith(directory+'/')||destination.includes('..')||destination.includes('\\'))throw new Error('aci_finalizer_output_invalid');
  await writeFile(resolve(root,destination),JSON.stringify(result,null,2)+'\n',{flag:'wx',mode:0o600});
  return reference(root,destination);
}
