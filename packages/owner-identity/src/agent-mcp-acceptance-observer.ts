import {createHash,randomUUID} from 'node:crypto';
import {appendFile, mkdir,lstat,realpath,writeFile} from 'node:fs/promises';
import {resolve, sep} from 'node:path';

export interface AgentMcpAcceptanceEvent {
  requestId: string;
  phase: 'request' | 'response';
  body: unknown;
  principal?: {ownerId: string; agentId: string; grantId: string};
  protocolVersion?: string;
  httpStatus?: number;
  authenticateScheme?: 'Bearer';
}
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const TOOLS=new Set(['identity.preflight','runs.accept_launch_intent','runs.current_task','runs.task_action','runs.task_action_status','runs.finish_task','support.report','support.report_receipt']);
const STATUS=new Set(['allowed','denied','ready','queued','preparing','running','completed','cancelled','expired','failed','unknown','disqualified','pending','accepted','succeeded','confirmed','rejected','not_submitted','submitted','connected','authorized','revoked','new']);
const STATES=new Set(['task_ready','waiting_queue','preparing_task','reconciling_actions','evaluating_task','preparing_next_task','finalizing_run','cancelling_run','awaiting_terminal','terminal']);
const id=(value:unknown)=>typeof value==='string'&&UUID.test(value)?value:undefined;
const obj=(value:unknown):Record<string,unknown>=>value!==null&&typeof value==='object'&&!Array.isArray(value)?value as Record<string,unknown>:{};
function boundedJson(value:unknown,maxBytes=1024*1024){
  let budget=0,nodes=0;
  const text=JSON.stringify(value,(key,part)=>{budget+=key.length+8;if(++nodes>20000)throw new Error('aci_projection_size_limit');if(typeof part==='string')budget+=part.length*3;if(budget>maxBytes)throw new Error('aci_projection_size_limit');return part;})??'null';
  if(Buffer.byteLength(text)>maxBytes)throw new Error('aci_projection_size_limit');return text;
}
const sha=(value:unknown)=>createHash('sha256').update(boundedJson(value)).digest('hex');
function rpcId(value:unknown){return typeof value==='number'&&Number.isSafeInteger(value)?value:typeof value==='string'?{sha256:sha(value)}:null;}
function scopedFields(value:unknown,depth=0):Record<string,unknown>{
  if(depth>4)return {};
  const source=obj(value),out:Record<string,unknown>={};
  for(const key of ['runId','intentId','agentId','ownerId','grantId','connectionId','selectedConnectionId','actionId','closureId','reportId'])if(id(source[key]))out[key]=source[key];
  for(const key of ['status','state'])if(typeof source[key]==='string'&&(key==='status'?STATUS:STATES).has(source[key] as string))out[key]=source[key];
  for(const key of ['terminal','admitted','replayed'])if(typeof source[key]==='boolean')out[key]=source[key];
  for(const key of ['taskIndex','retryAfterMs','actionCutoffSequence','accessGeneration'])if(Number.isSafeInteger(source[key])&&(source[key] as number)>=0)out[key]=source[key];
  for(const key of ['terminalReason','cancellationReason','reason'])if(source[key]===null||['coordinator_evaluation_unknown','coordinator_preparation_failed','coordinator_interrupted_preparation','coordinator_executor_session_lost','coordinator_platform_failure','task_deadline','owner_cancelled'].includes(source[key] as string))out[key]=source[key];
  if(typeof source.taskId==='string'&&/^(S[1-4]|M[1-4]|H[1-3]|U1)$/.test(source.taskId))out.taskId=source.taskId;
  if(Array.isArray(source.modes))out.modes=source.modes.filter(x=>x==='training'||x==='ranked');
  if(['2025-06-18','2026-07-28'].includes(source.protocolVersion as string))out.protocolVersion=source.protocolVersion;
  if(source.permissions&&typeof source.permissions==='object'){
    const permissions=obj(source.permissions),safe:Record<string,boolean>={};for(const key of ['training','ranked','forumMessages','customTopics'])if(typeof permissions[key]==='boolean')safe[key]=permissions[key] as boolean;out.permissions=safe;
  }
  for(const key of ['run','task','identity','connection','principal','preflight'])if(source[key]===null)out[key]=null;else if(source[key]&&typeof source[key]==='object')out[key]=scopedFields(source[key],depth+1);
  return out;
}

/** AICODE-NOTE: Acceptance projections cannot retain tool bodies, OAuth parameters or arbitrary strings. */
export function projectAgentMcpAcceptance(event:AgentMcpAcceptanceEvent){
  const raw=boundedJson(event.body,event.phase==='request'?64*1024:1024*1024);
  const body=obj(event.body),out:Record<string,unknown>={rpcId:rpcId(body.id)};
  if(['initialize','notifications/initialized','tools/list','tools/call'].includes(body.method as string))out.method=body.method;
  if(body.method==='initialize'){
    const params=obj(body.params),client=obj(params.clientInfo);
    if(['2025-06-18','2026-07-28'].includes(params.protocolVersion as string))out.protocolVersion=params.protocolVersion;
    out.clientNameSha256=sha(client.name??null);
    if(typeof client.version==='string'&&/^\d{1,4}\.\d{1,4}\.\d{1,4}(?:[-+][a-zA-Z0-9.]{1,30})?$/.test(client.version))out.clientVersion=client.version;
  }
  if(body.method==='tools/call'){
    const params=obj(body.params);if(TOOLS.has(params.name as string)){out.toolName=params.name;out.arguments=scopedFields(params.arguments);}
  }
  if(body.result){
    const result=obj(body.result);
    out.result=scopedFields(result);
    if(['2025-06-18','2026-07-28'].includes(result.protocolVersion as string))obj(out.result).protocolVersion=result.protocolVersion;
    if(Array.isArray(result.tools))out.tools=result.tools.flatMap(raw=>{const tool=obj(raw);return TOOLS.has(tool.name as string)?[{name:tool.name,inputSchemaSha256:sha(tool.inputSchema)}]:[];});
    const content:Array<Record<string,unknown>>=[];
    if(result.structuredContent)content.push(scopedFields(result.structuredContent));
    if(Array.isArray(result.content))for(const part of result.content.slice(0,16)){const text=obj(part).text;if(typeof text==='string'&&text.length<=65536)try{content.push(scopedFields(JSON.parse(text)));}catch{/* Unknown text never leaves memory. */}}
    if(content.length)out.content=content;
    if(typeof result.isError==='boolean')out.isError=result.isError;
  }
  const error=obj(body.error);if(Number.isSafeInteger(error.code))out.error={code:error.code};
  const principal=event.principal&&[event.principal.ownerId,event.principal.agentId,event.principal.grantId].every(x=>id(x))?{ownerId:event.principal.ownerId,agentId:event.principal.agentId,grantId:event.principal.grantId}:undefined;
  // Hashes the bounded decoded JSON-RPC input, not original HTTP/SSE framing bytes.
  return {at:new Date().toISOString(),phase:event.phase,requestId:id(event.requestId)??{sha256:sha(event.requestId)},protocolVersion:['2025-06-18','2026-07-28'].includes(event.protocolVersion??'')?event.protocolVersion:null,httpStatus:Number.isSafeInteger(event.httpStatus)?event.httpStatus:null,authenticateScheme:event.authenticateScheme==='Bearer'?'Bearer':null,principal,projection:out,payloadSha256:createHash('sha256').update(raw).digest('hex'),payloadHashMode:'decoded_json_rpc_input',rawPersisted:false};
}

export async function createAgentMcpAcceptanceObserver(options:{enabled:boolean;nodeEnv:string;databaseName:string;repoRoot:string;captureId:string;publicOrigin:string}){
  const origin=new URL(options.publicOrigin);
  if(!options.enabled||options.nodeEnv!=='development'||!/^oid_acceptance_[a-f0-9]{32}$/.test(options.databaseName)||!UUID.test(options.captureId)||origin.protocol!=='http:'||!['127.0.0.1','localhost','[::1]'].includes(origin.hostname))throw new Error('aci_observer_not_disposable');
  const root=resolve(options.repoRoot),directory=resolve(root,'artifacts/runs/agent-client-connection',options.captureId);
  if(!directory.startsWith(root+sep))throw new Error('aci_observer_path_invalid');
  // Validate every existing/created ancestor, never follow an artifact symlink.
  if((await realpath(root)).toLowerCase()!==root.toLowerCase())throw new Error('aci_observer_path_invalid');
  let current=root;
  for(const component of directory.slice(root.length+1).split(sep)){
    current=resolve(current,component);await mkdir(current).catch(e=>{if(e.code!=='EEXIST')throw e;});const meta=await lstat(current);
    if(!meta.isDirectory()||meta.isSymbolicLink()||(await realpath(current)).toLowerCase()!==current.toLowerCase())throw new Error('aci_observer_path_invalid');
  }
  const path=resolve(directory,'mcp-projections.jsonl');
  await writeFile(path,'',{flag:'wx',mode:0o600}).catch(e=>{if(e.code!=='EEXIST')throw e;});
  const traceMeta=await lstat(path);if(!traceMeta.isFile()||traceMeta.isSymbolicLink()||traceMeta.size>64*1024*1024)throw new Error('aci_observer_path_invalid');
  const epoch=randomUUID();let bytes=traceMeta.size,count=0,pending=Promise.resolve(),closed=false;const errors:string[]=[];
  return {
    observe(event:AgentMcpAcceptanceEvent){
      // Never affect MCP authority or response delivery if evidence recording fails.
      if(closed)return;
      if(++count>10000){if(!errors.includes('record_limit'))errors.push('record_limit');return;}
      try{const line=JSON.stringify({epoch,sequence:count,...projectAgentMcpAcceptance(event)})+'\n';bytes+=Buffer.byteLength(line);if(bytes>64*1024*1024){if(!errors.includes('byte_limit'))errors.push('byte_limit');return;}pending=pending.then(async()=>{const meta=await lstat(path);if(!meta.isFile()||meta.isSymbolicLink())throw new Error('aci_observer_path_invalid');await appendFile(path,line,{mode:0o600});}).catch(()=>{if(!errors.includes('write_failed'))errors.push('write_failed');});}catch{if(!errors.includes('projection_failed'))errors.push('projection_failed');}
    },
    async close(){if(closed){await pending;return {path,epoch,records:count,errors:[...errors]};}closed=true;await pending;const status={schemaVersion:'aci-mcp-observer-status/v1',epoch,processId:process.pid,records:count,errors:[...errors],closedAt:new Date().toISOString()};await writeFile(resolve(directory,`observer-${epoch}-status.json`),JSON.stringify(status),{flag:'wx',mode:0o600});return {path,...status};},
  };
}
