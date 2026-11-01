import {createServer,request as httpRequest} from 'node:http';

// AICODE-NOTE: Disposable-fixture negative control. It never fabricates a
// successful request or changes a payment: only GET /healthz may return 503,
// after a read-only predicate confirms the exact fenced predecessor.
export async function startSuccessorHealthFaultProxy({upstreamOrigin}) {
  const upstream=new URL(upstreamOrigin);
  if(upstream.protocol!=='http:'||upstream.pathname!=='/'||upstream.search||upstream.hash||upstream.username||upstream.password||
    !['127.0.0.1','localhost','host.docker.internal'].includes(upstream.hostname))throw new Error('successor_fault_upstream_invalid');
  let predicate=null,target=null,armedAt=null,predicateErrors=0,omitted=0;
  const interventions=[],sockets=new Set();
  const server=createServer(async(incoming,outgoing)=>{
    const requestedAt=new Date().toISOString();
    const path=incoming.url??'/';
    if(!path.startsWith('/')||path.startsWith('//')){outgoing.writeHead(400).end();return;}
    const health=incoming.method==='GET'&&new URL(path,upstream).pathname==='/healthz';
    if(health&&predicate){
      target=null;
      try{target=await predicate();}catch{predicateErrors++;}
      if(target){
        const incident={ordinal:interventions.length+omitted+1,observedAt:requestedAt,requestedAt,method:'GET',path:'/healthz',httpStatus:503,responseStatus:503,
          runId:target.runId,taskId:'M1',mode:'unavailable',taskIndex:1,predecessorTaskIndex:target.taskIndex,predecessorFinishedAt:target.predecessorFinishedAt};
        if(interventions.length<1000)interventions.push(incident);else omitted++;
        outgoing.writeHead(503,{'content-type':'application/json','cache-control':'no-store'}).end(JSON.stringify({status:'unavailable',boundary:'acceptance_successor_health_fault'}));return;
      }
    }
    const forwarded=httpRequest({hostname:upstream.hostname,port:upstream.port||80,path,method:incoming.method,
      headers:{...incoming.headers,host:upstream.host,connection:'close'},timeout:45000},response=>{
      outgoing.writeHead(response.statusCode??502,response.headers);response.on('error',()=>outgoing.destroy());response.pipe(outgoing);
    });
    forwarded.once('timeout',()=>forwarded.destroy());
    forwarded.once('error',()=>{if(!outgoing.headersSent)outgoing.writeHead(502);outgoing.end();});
    incoming.once('error',()=>forwarded.destroy());incoming.pipe(forwarded);
  });
  server.on('connection',socket=>{sockets.add(socket);socket.once('close',()=>sockets.delete(socket));});
  await new Promise((r,j)=>{server.once('error',j);server.listen(0,'127.0.0.1',r);});
  return {origin:`http://127.0.0.1:${server.address().port}`,
    arm(check){if(predicate||typeof check!=='function')throw new Error('successor_fault_arm_invalid');predicate=check;armedAt=new Date().toISOString();},
    snapshot(){return {schemaVersion:'successor-preparation-health-fault/v1',kind:'successor_preparation_unavailable',mode:'health_unavailable_after_fenced_predecessor',armedAt,
      interventions:[...interventions],omittedInterventions:omitted,predicateErrors};},
    reset(){predicate=null;target=null;},
    async close(){for(const socket of sockets)socket.destroy();await new Promise(r=>server.close(r));}};
}
