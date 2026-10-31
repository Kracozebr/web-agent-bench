import test from 'node:test';
import assert from 'node:assert/strict';
import {globalAgent} from 'node:http';
import {createConnection} from 'node:net';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {fileURLToPath} from 'node:url';
import {startBetaRecoveryFaultProxy} from '../packages/owner-acceptance/src/beta-recovery-fault-proxy.mjs';

const pause=ms=>new Promise(done=>setTimeout(done,ms));
async function killOwnedChild(child){
 if(child&&child.exitCode===null&&child.signalCode===null){const exited=once(child,'exit');child.kill('SIGKILL');await exited;}
}

async function stalledConnectProbe(){
 // AICODE-NOTE: The private child isolates globalAgent changes. Python deliberately
 // does not accept until commanded; a full loopback backlog stalls a real TCP connect.
 const python="import socket,sys\ns=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\ns.bind(('127.0.0.1',0))\ns.listen(0)\nprint(s.getsockname()[1],flush=True)\nsys.stdin.readline()\ns.settimeout(2)\nfor i in range(2):\n c,a=s.accept()\n if i==1:\n  c.settimeout(1)\n  c.recv(8192)\n  c.sendall(b'HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\nConnection: close\\r\\n\\r\\nOK')\n c.close()\ns.close()\n";
 const listener=spawn('python3',['-u','-c',python],{stdio:['pipe','pipe','ignore']});
 const previousTimeout=globalAgent.options.timeout,previousCreate=globalAgent.createConnection;
 let filler,proxy,forwardedSocket,attempts=0,constructorTimeout,settled=false,request;
 const controller=new AbortController();
 try{
  const [chunk]=await once(listener.stdout,'data');const port=Number(String(chunk).trim());
  assert.ok(Number.isInteger(port)&&port>0);
  filler=createConnection({host:'127.0.0.1',port});
  await Promise.race([once(filler,'connect'),pause(1000).then(()=>{throw Error('private_backlog_filler_timeout');})]);
  globalAgent.options.timeout=50;
  globalAgent.createConnection=function(options,...rest){
   attempts++;constructorTimeout=options.timeout;
   forwardedSocket=previousCreate.call(this,options,...rest);return forwardedSocket;
  };
  proxy=await startBetaRecoveryFaultProxy({upstreamOrigin:'http://127.0.0.1:'+port});
  request=fetch(proxy.origin+'/healthz',{signal:controller.signal}).then(async response=>{
   settled=true;return{status:response.status,body:await response.text()};
  },error=>{settled=true;throw error;});
  // Observe beyond the shorter Agent default without changing the declared45s budget.
  await pause(250);
  assert.equal(attempts,1,'the proxy must create only the original upstream connection');
  assert.equal(forwardedSocket.connecting,true,'the private backlog must actually hold TCP connection establishment');
  assert.equal(settled,false,'the shorter global Agent timeout must not produce an early proxy502');
  assert.equal(proxy.snapshot().transportFailures.length,0);
  assert.equal(constructorTimeout,45000,'the declared proxy budget must apply before connection succeeds');
  listener.stdin.end('accept\n');
  const result=await Promise.race([request,pause(3000).then(()=>{throw Error('private_listener_drain_timeout');})]);
  assert.deepEqual(result,{status:200,body:'OK'});
  assert.equal(attempts,1,'successful delayed connection must not require an upstream retry');
  return{pendingAfterMs:250,configuredGlobalTimeoutMs:50,effectivePreconnectTimeoutMs:constructorTimeout,attempts,status:result.status};
 }finally{
  controller.abort();request?.catch(()=>{});filler?.destroy();
  globalAgent.destroy();globalAgent.options.timeout=previousTimeout;globalAgent.createConnection=previousCreate;
  await killOwnedChild(listener);await proxy?.close();
 }
}

if(process.env.OID_PRIVATE_PRECONNECT_TEST_CHILD==='1'){
 try{console.log(JSON.stringify({ok:true,...await stalledConnectProbe()}));}
 catch{console.log(JSON.stringify({ok:false,code:'PROXY_PRECONNECT_BUDGET_REGRESSION'}));process.exitCode=1;}
}else{
 test('proxy declared budget covers a stalled real TCP connect without retry or global Agent timeout leakage',{timeout:10000},async()=>{
  const child=spawn(process.execPath,[fileURLToPath(import.meta.url)],{
   env:{...process.env,OID_PRIVATE_PRECONNECT_TEST_CHILD:'1'},stdio:['ignore','pipe','pipe']});
  const hardStop=setTimeout(()=>{if(child.exitCode===null&&child.signalCode===null)child.kill('SIGKILL');},7500);
  let stdout='',stderr='';child.stdout.on('data',b=>stdout+=b);child.stderr.on('data',b=>stderr+=b);
  try{const [code]=await once(child,'exit');
   assert.equal(code,0,'isolated preconnect probe must succeed: '+stdout.trim());
   assert.equal(stderr,'');const report=JSON.parse(stdout.trim());assert.equal(report.ok,true);
   assert.equal(report.attempts,1);assert.equal(report.effectivePreconnectTimeoutMs,45000);
  }finally{clearTimeout(hardStop);await killOwnedChild(child);}
 });
}
