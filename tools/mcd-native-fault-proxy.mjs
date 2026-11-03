/** Qualification-only, origin-preserving loopback transport boundary. Never logs wire data. */
import http from 'node:http';
import {createHash} from 'node:crypto';
import {parseMcdWireText} from '../packages/owner-acceptance/src/mcp-diagnostics-wire.mjs';

const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const sha=v=>createHash('sha256').update(v).digest('hex');
const need=(v,c)=>{if(!v)throw new Error(c);};
const stamp=()=>new Date().toISOString();
function projection(value){
  if(value?.result?.isError||value?.error)return null;
  if(value?.result?.structuredContent)return value.result.structuredContent;
  for(const item of value?.result?.content??[])if(item?.type==='text')try{return JSON.parse(item.text);}catch{}
  return null;
}
function requestTarget(body,armed){
  let value;try{value=JSON.parse(body);}catch{return null;}
  const args=value?.params?.arguments;
  if(!armed||value.method!=='tools/call'||value.params?.name!=='runs.task_action'||!uuid.test(args?.runId??'')||args.runId!==armed.runId||
    typeof args.operationId!=='string'||sha(args.operationId)!==armed.operationIdHash||!Number.isInteger(args.taskIndex)||args.taskIndex<0||args.taskIndex>11||
    args.command?.kind!=='inspect_catalog'||Object.keys(args.command).length!==1)return null;
  return {runId:args.runId,taskIndex:args.taskIndex,operationIdHash:sha(args.operationId),requestSha256:sha(body)};
}

export async function startMcdNativeFaultProxy({publicOrigin='http://127.0.0.1:3000',upstreamOrigin='http://127.0.0.1:3001',foreignCaseId,onObservation=()=>{},observationLimit=4096,testOnlyEphemeralPorts=false}={}){
  const publicUrl=new URL(publicOrigin),upstream=new URL(upstreamOrigin);
  for(const url of [publicUrl,upstream])need(url.protocol==='http:'&&url.hostname==='127.0.0.1'&&url.pathname==='/'&&!url.search&&!url.hash&&!url.username&&!url.password,'MCD_NATIVE_PROXY_ORIGIN_INVALID');
  need(testOnlyEphemeralPorts?publicUrl.port==='0'&&upstream.port&&upstream.port!=='0':publicUrl.port==='3000'&&upstream.port==='3001','MCD_NATIVE_PROXY_PORT_INVALID');
  need(foreignCaseId===undefined||uuid.test(foreignCaseId),'MCD_NATIVE_PROXY_CASE_INVALID');
  need(Number.isInteger(observationLimit)&&observationLimit>=1&&observationLimit<=4096,'MCD_NATIVE_PROXY_OBSERVATION_BOUND');
  const observations=[],sockets=new Set();let armed=null,dropped=false,closed=false,observationOverflowCount=0;
  const observe=value=>{if(observations.length>=observationLimit){observationOverflowCount++;return;}const safe=Object.freeze(value);observations.push(safe);try{onObservation(safe);}catch{/* Observation cannot repeat a forwarded action. */}};
  const server=http.createServer((request,response)=>{
    const enteredAt=stamp(),path=new URL(request.url,publicUrl).pathname;
    // AICODE-NOTE: Credentials and request bodies exist in RAM only and are never included in observations.
    const headers={...request.headers};delete headers.connection;delete headers['proxy-connection'];
    let bytes=0,chunks=[],target=null,forward;
    const begin=body=>{
      if(body&&path==='/api/agent/mcp')target=requestTarget(body,armed);
      forward=http.request({hostname:'127.0.0.1',port:upstream.port,path:request.url,method:request.method,headers},incoming=>{
        const upstreamHeadersAt=stamp(),foreign=foreignCaseId&&request.headers['x-w3bench-diagnostic-case']===foreignCaseId&&path==='/api/agent/mcp';
        incoming.once('error',()=>response.destroy());incoming.once('aborted',()=>response.destroy());
        if(!target){
          response.writeHead(incoming.statusCode,incoming.headers);incoming.pipe(response);
          incoming.once('end',()=>{if(foreign)observe({kind:'foreign_case_transport',enteredAt,upstreamHeadersAt,completedAt:stamp(),httpStatus:incoming.statusCode,caseId:foreignCaseId,
            ...(uuid.test(incoming.headers['x-w3bench-diagnostic-trace']??'')?{traceId:incoming.headers['x-w3bench-diagnostic-trace']}:{})});});return;
        }
        let responseBytes=0,responseChunks=[],overflow=false;
        incoming.on('data',part=>{responseBytes+=part.length;
          if(overflow){response.write(part);return;}
          if(responseBytes>256*1024){overflow=true;response.writeHead(incoming.statusCode,incoming.headers);for(const b of responseChunks)response.write(b);responseChunks=[];response.write(part);}else responseChunks.push(part);
        });
        incoming.on('end',()=>{
          if(overflow){response.end();observe({kind:'not_dropped_response_bound',...target,enteredAt,completedAt:stamp(),httpStatus:incoming.statusCode});return;}
          const raw=Buffer.concat(responseChunks),parsed=parseMcdWireText(raw.toString('utf8'),incoming.headers['content-type']),receipt=projection(parsed.value);
          const admitted=incoming.statusCode===200&&receipt?.admitted===true&&uuid.test(receipt.actionId??'')&&receipt.runId===target.runId&&receipt.taskIndex===target.taskIndex;
          if(admitted&&!dropped){dropped=true;const upstreamCompletedAt=stamp();
            observe({kind:'admission_response_dropped',...target,enteredAt,upstreamHeadersAt,upstreamCompletedAt,droppedAt:stamp(),httpStatus:incoming.statusCode,actionId:receipt.actionId,responseSha256:sha(raw),responseBytes,wireFraming:parsed.proof.framing});
            response.destroy();
          }else{response.writeHead(incoming.statusCode,incoming.headers);response.end(raw);
            // AICODE-NOTE: Only the armed harmless command may expose this safe
            // replay proof. Operation arguments and credentials stay in RAM.
            observe(admitted&&dropped?{kind:'admission_retry_response',...target,enteredAt,completedAt:stamp(),httpStatus:incoming.statusCode,actionId:receipt.actionId,replayed:receipt.replayed===true,responseSha256:sha(raw),responseBytes,wireFraming:parsed.proof.framing}:{kind:'not_dropped_unverified_admission',...target,enteredAt,completedAt:stamp(),httpStatus:incoming.statusCode});}
          responseChunks=[];
        });
      });
      forward.on('error',()=>{if(!response.headersSent){response.writeHead(502,{'content-type':'application/json'});response.end('{"error":{"code":"MCD_NATIVE_PROXY_UPSTREAM_UNAVAILABLE"}}');}else response.destroy();});
      forward.setTimeout(30000,()=>forward.destroy());if(body)forward.end(body);else request.pipe(forward);
    };
    // Only MCP request bodies need bounded in-memory inspection; all other traffic streams unchanged.
    if(request.method==='POST'&&path==='/api/agent/mcp'){
      request.on('data',part=>{bytes+=part.length;if(bytes>1024*1024){request.destroy();return;}chunks.push(part);});
      request.on('end',()=>{const body=Buffer.concat(chunks);chunks=[];begin(body);});
    }else begin();
    request.once('aborted',()=>{forward?.destroy();response.destroy();});request.once('error',()=>{forward?.destroy();response.destroy();});
    response.once('close',()=>{if(!response.writableFinished)forward?.destroy();});
  });
  server.on('connection',socket=>{sockets.add(socket);socket.once('close',()=>sockets.delete(socket));});
  try{await new Promise((done,reject)=>{server.once('error',()=>reject(new Error('MCD_NATIVE_PROXY_LISTEN_FAILED')));server.listen(Number(publicUrl.port),'127.0.0.1',done);});}catch(error){server.close();throw error;}
  return {origin:'http://127.0.0.1:'+server.address().port,observations,arm({runId,operationIdHash}){need(!closed&&!dropped&&uuid.test(runId)&&/^[a-f0-9]{64}$/.test(operationIdHash),'MCD_NATIVE_PROXY_ARM_INVALID');need(!armed||armed.runId===runId&&armed.operationIdHash===operationIdHash,'MCD_NATIVE_PROXY_ALREADY_ARMED');armed={runId,operationIdHash};},
    get dropped(){return dropped;},get observationOverflowCount(){return observationOverflowCount;},get captureOutcome(){return observationOverflowCount?'partial_overflow':'bounded_observation';},async close(){if(closed)return;closed=true;for(const socket of sockets)socket.destroy();await new Promise(done=>server.close(done));}};
}
