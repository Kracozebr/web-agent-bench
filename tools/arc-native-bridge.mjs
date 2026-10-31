/** Disposable native participant bridge. Credentials and jobs stay in ignored .local, never acceptance artifacts. */
import {createServer, request as httpRequest} from 'node:http';
import {createHash, randomUUID} from 'node:crypto';
import {mkdir, readFile, writeFile, rename, unlink} from 'node:fs/promises';
import {resolve} from 'node:path';

export const ARC_NATIVE_TOOLS = ['identity.preflight','runs.accept_launch_intent','runs.current_task','runs.task_action','runs.task_action_status','runs.finish_task'];
export const sha256 = value => createHash('sha256').update(value).digest('hex');
export function privateCaptureDirectory(repoRoot,captureId) {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,100}$/.test(captureId)) throw new Error('invalid_capture_id');
  return resolve(repoRoot,'.local','arc-native',captureId);
}
const sleep = ms => new Promise(done=>setTimeout(done,ms));
const safeString = value => typeof value==='string' && value.length<=160 && /^[a-zA-Z0-9_.:/ -]*$/.test(value);
function fields(value,keys) {
  if (!value || typeof value!=='object' || Array.isArray(value)) return undefined;
  return Object.fromEntries(keys.filter(key=>safeString(value[key]) || typeof value[key]==='boolean' || value[key]===null || Number.isFinite(value[key])).map(key=>[key,value[key]]));
}
export function projectNativeRequest(json) {
  const out=fields(json,['id','method'])??{};
  if (json?.method==='initialize') out.initialize={...fields(json.params,['protocolVersion']),clientInfo:fields(json.params?.clientInfo,['name','version','title'])};
  if (json?.method==='tools/call') {
    out.toolName=ARC_NATIVE_TOOLS.includes(json.params?.name)?json.params.name:'unrecognized_tool';
    out.arguments=fields(json.params?.arguments,['runId','taskIndex','operationId','actionId','intentId','agentId']);
    out.command=fields(json.params?.arguments?.command,['kind']);
  }
  return out;
}
function projectPayload(value) {
  const out=fields(value,['status','allowed','admitted','reason','actionId','closureId','actionCutoffSequence','state','retryAfterMs','runId','intentId','agentId','policyVersion','accessGeneration'])??{};
  out.run=fields(value?.run,['runId','status','terminal','terminalReason','cancellationReason']);
  out.task=value?.task===null?null:fields(value?.task,['runId','taskIndex','taskId','participantToolProtocol']);
  out.error=fields(value?.error,['code']);
  return out;
}
export function projectNativeResponse(json) {
  const out=fields(json,['id'])??{};
  out.error=fields(json?.error,['code']);
  if (json?.result) {
    out.initialize=fields(json.result,['protocolVersion']);
    out.result=projectPayload(json.result.structuredContent??json.result);
    out.content=(json.result.content??[]).slice(0,4).filter(x=>x.type==='text').map(x=>{
      try {return projectPayload(JSON.parse(x.text));} catch {return {unparsed:true};}
    });
    if (Array.isArray(json.result.tools)) out.toolNames=json.result.tools.map(x=>x.name).filter(x=>ARC_NATIVE_TOOLS.includes(x));
  }
  return out;
}

/** Project a finite SSE body without persisting data lines, event ids or arbitrary text. */
export function projectNativeResponseBytes(bytes,contentType='application/json') {
  if(String(contentType).toLowerCase().split(';',1)[0].trim()!=='text/event-stream') {
    try{return projectNativeResponse(JSON.parse(bytes.toString('utf8')));}catch{return {nonJson:true};}
  }
  // AICODE-NOTE: Native 0.165 emits finite SSE even with server responseMode=json.
  // Keep forwarding unchanged; distinguish multiple/incomplete frames instead of picking a convenient result.
  const blocks=bytes.toString('utf8').replace(/\r\n?/g,'\n').split('\n\n');
  const incomplete=blocks.pop();
  const frames=[];let dataFrameCount=0,malformedFrameCount=0;
  for(const block of blocks) {
    const lines=block.split('\n').filter(line=>line==='data'||line.startsWith('data:'));
    if(!lines.length)continue;
    if(++dataFrameCount>128)return {nonJson:true,sseFrameLimitExceeded:true};
    const data=lines.map(line=>line==='data'?'':line.slice(5).replace(/^ /,'')).join('\n');
    try {
      const json=JSON.parse(data);
      if(!json||typeof json!=='object'||Array.isArray(json)||json.jsonrpc!=='2.0')throw new Error('invalid_jsonrpc');
      frames.push({frameIndex:dataFrameCount-1,projection:projectNativeResponse(json)});
    }catch {malformedFrameCount++;}
  }
  const incompleteDataFrame=incomplete.split('\n').some(line=>line==='data'||line.startsWith('data:'));
  if(dataFrameCount===1&&frames.length===1&&!incompleteDataFrame)return frames[0].projection;
  return {nonJson:frames.length===0,sseFrames:frames,sseDataFrameCount:dataFrameCount,malformedFrameCount,incompleteDataFrame};
}

// AICODE-NOTE: Store projections plus raw-byte hashes only. This is not a replayable raw transcript.
export async function startNativeProxy({publicOrigin,agentBearer,port=4500,maxBytes=1024*1024,maxPackets=4000}) {
  const target=new URL(publicOrigin);
  if (target.protocol!=='http:' || !['127.0.0.1','localhost'].includes(target.hostname) || target.username || target.password || target.pathname!=='/') throw new Error('invalid_native_target');
  const trace=[]; let sequence=0;
  const record=(direction,bytes,meta={})=>{
    if (trace.length>=maxPackets) throw new Error('native_trace_limit');
    let json;try {json=JSON.parse(bytes.toString('utf8'));} catch {json=null;}
    const projection=direction==='request'?(json?projectNativeRequest(json):{nonJson:true}):projectNativeResponseBytes(bytes,meta.contentType);
    if(JSON.stringify(projection).includes(agentBearer))throw new Error('native_projection_contains_credential');
    trace.push({sequence:++sequence,observedAt:new Date().toISOString(),direction,...meta,bytes:bytes.length,rawSha256:sha256(bytes),rawPersisted:false,projection});
  };
  const server=createServer(async(req,res)=>{
    if (req.url!=='/api/agent/mcp' || req.method!=='POST') {res.writeHead(404);res.end();return;}
    // This listener is loopback-published by Docker. Still reject any different participant credential.
    if (req.headers.authorization!==`Bearer ${agentBearer}`) {res.writeHead(401);res.end();return;}
    const chunks=[];let bytes=0;
    try {
      for await(const chunk of req) {bytes+=chunk.length;if(bytes>maxBytes) throw new Error('native_request_limit');chunks.push(chunk);}
      const body=Buffer.concat(chunks);record('request',body);
      const headers={host:target.host,'content-type':'application/json',accept:'application/json, text/event-stream',authorization:`Bearer ${agentBearer}`,'content-length':body.length};
      for (const key of ['mcp-protocol-version','mcp-session-id']) if(typeof req.headers[key]==='string') headers[key]=req.headers[key];
      const upstream=httpRequest(new URL('/api/agent/mcp',target),{method:'POST',headers},response=>{
        const received=[];let size=0;
        response.on('data',chunk=>{size+=chunk.length;if(size>maxBytes){response.destroy();upstream.destroy();res.destroy();return;}received.push(chunk);});
        response.on('end',()=>{
          try {const result=Buffer.concat(received);const mediaType=response.headers['content-type']?.toLowerCase().split(';',1)[0].trim();
            record('response',result,{httpStatus:response.statusCode,contentType:['application/json','text/event-stream'].includes(mediaType)?mediaType:'other'});
            const safeHeaders={'content-type':response.headers['content-type']??'application/json'};
            for(const key of ['mcp-session-id','mcp-protocol-version']) if(response.headers[key])safeHeaders[key]=response.headers[key];
            res.writeHead(response.statusCode??502,safeHeaders);res.end(result);
          } catch {res.destroy();}
        });
        response.on('error',()=>res.destroy());
      });
      upstream.setTimeout(70000,()=>upstream.destroy());upstream.on('error',()=>{if(!res.headersSent)res.writeHead(502);res.end();});upstream.end(body);
    }catch {if(!res.headersSent)res.writeHead(413);res.end();}
  });
  await new Promise((done,fail)=>{server.once('error',fail);server.listen(port,'0.0.0.0',done);});
  return {trace,port:server.address().port,close:async()=>{server.closeAllConnections();await new Promise(done=>server.close(done));}};
}

export function createArcNativeIntentRunner({repoRoot,captureId,port=4500,timeoutMs=12*60*1000}) {
  if (!Number.isFinite(timeoutMs)||timeoutMs<=0||timeoutMs>12*60*1000) throw new Error('invalid_native_timeout');
  let used=false;
  return async function onArcNativeIntentReady({agentBearer,agentId,intentId,handoffPrompt,publicOrigin}) {
    if(used)throw new Error('native_capture_already_used');used=true;
    if(typeof agentBearer!=='string'||agentBearer.length<20||/\s/.test(agentBearer)||typeof handoffPrompt!=='string'||!handoffPrompt||Buffer.byteLength(handoffPrompt)>65536||handoffPrompt.includes(agentBearer))throw new Error('invalid_native_input');
    const directory=privateCaptureDirectory(repoRoot,captureId);await mkdir(directory,{recursive:true,mode:0o700});
    const credentialPath=resolve(directory,'credential.txt'),promptPath=resolve(directory,'handoff.txt');
    const jobId=randomUUID(),promptSha256=sha256(Buffer.from(handoffPrompt,'utf8'));
    await writeFile(credentialPath,agentBearer,{flag:'wx',mode:0o600});
    let proxy,completed=false,published=false;
    try {
      await writeFile(promptPath,handoffPrompt,{flag:'wx',mode:0o600});
      proxy=await startNativeProxy({publicOrigin,agentBearer,port});
      const job={schemaVersion:'arc-native-job/v1',captureId,jobId,agentId,intentId,promptSha256,credentialFile:'credential.txt',promptFile:'handoff.txt',enabledTools:ARC_NATIVE_TOOLS,createdAt:new Date().toISOString()};
      await writeFile(resolve(directory,'job.tmp'),JSON.stringify(job),{flag:'wx',mode:0o600});await rename(resolve(directory,'job.tmp'),resolve(directory,'job.json'));
      published=true;
      const until=Date.now()+timeoutMs;
      while(Date.now()<until){
        const result=await readFile(resolve(directory,'completed.json'),'utf8').then(JSON.parse).catch(()=>null);
        if(result){
          if(result.jobId!==jobId||result.promptSha256!==promptSha256||JSON.stringify(result).includes(agentBearer))throw new Error('native_job_mismatch');
          completed=true;
          return {...result.native,wireTrace:{schemaVersion:'arc-native-wire-projections/v1',rawPersisted:false,packets:proxy.trace},sourcePins:result.sourcePins,helperSummary:result.helperSummary};
        }
        await sleep(500);
      }
      await writeFile(resolve(directory,'callback-timeout.json'),JSON.stringify({jobId,observedAt:new Date().toISOString()}),{flag:'wx',mode:0o600});
      throw new Error('native_callback_timeout_model_may_still_be_running');
    } finally {
      if(proxy)await proxy.close();
      // A running model owns the key until the broker writes completed.json; never delete somebody else's path.
      if(completed||!published)await unlink(credentialPath).catch(error=>{if(error.code!=='ENOENT')throw error;});
    }
  };
}
