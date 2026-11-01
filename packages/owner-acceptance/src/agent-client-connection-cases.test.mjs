import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,readFile,writeFile,mkdir,lstat,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {resolve,sep} from 'node:path';
import {createHash,randomUUID} from 'node:crypto';
import {createAciNativeSession,runAgentClientConnectionOwnerCase} from './agent-client-connection-cases.mjs';
const sleep=ms=>new Promise(done=>setTimeout(done,ms));
const sha=x=>createHash('sha256').update(x).digest('hex');
async function wait(file){for(let n=0;n<100;n++){try{return JSON.parse(await readFile(file,'utf8'));}catch(e){if(e.code!=='ENOENT')throw e;}await sleep(20);}throw new Error('unit_fixture_timeout');}
async function cleanup(path){if(!resolve(path).startsWith(resolve(tmpdir())+sep)||!path.split(sep).at(-1).startsWith('aci-session-unit-'))throw new Error('unsafe_test_cleanup');await rm(path,{recursive:true,force:false});}
test('ACI producer uses exact native registration, real callback binding and prompt hash across private IPC only',async()=>{
  const repoRoot=await mkdtemp(resolve(tmpdir(),'aci-session-unit-')),captureId=randomUUID(),directory=resolve(repoRoot,'.local/aci-native',captureId);
  const callbackUri='http://127.0.0.1:38765/callback/native_server_id',state='synthetic-unit-state',code='synthetic-unit-code';
  const setup={serverUrl:'http://127.0.0.1:3000/api/agent/mcp',resource:'http://127.0.0.1:3000/api/agent/mcp',clientId:'unit_public',development:true};
  const url=new URL('http://127.0.0.1:3000/api/auth/oauth2/authorize');for(const [key,value]of Object.entries({client_id:setup.clientId,redirect_uri:callbackUri,resource:setup.resource,response_type:'code',code_challenge_method:'S256',code_challenge:'synthetic-unit-challenge',state}))url.searchParams.set(key,value);
  const callback=callbackUri+`?code=${code}&state=${state}`;const events=[];
  const worker=(async()=>{
    await wait(resolve(directory,'job.json'));
    await writeFile(resolve(directory,'registration.json'),JSON.stringify({schemaVersion:'aci-native-registration/v1',callbackUri,clientId:setup.clientId,setupAuthorizationCancelled:true}));
    const registered=await wait(resolve(directory,'registration-approved.json'));assert.equal(registered.callbackUri,callbackUri);events.push('native_registration_confirmed');
    await writeFile(resolve(directory,'private-login.json'),JSON.stringify({url:url.href}));
    const returned=await wait(resolve(directory,'private-callback.json'));assert.equal(returned.url,callback);events.push('actual_callback_delivered');
    await writeFile(resolve(directory,'authorized.json'),JSON.stringify({authMethod:'native_oauth',client:'codex_cli',isolatedHome:true,callbackUri}));
    const request=await wait(resolve(directory,'request-1.json'));assert.equal(request.kind,'preflight');
    await writeFile(resolve(directory,'response-1.json'),JSON.stringify({schemaVersion:'aci-native-turn/v1',kind:request.kind,authMethod:'native_oauth',promptSha256:sha(request.prompt)}));
    const close=await wait(resolve(directory,'request-2.json'));assert.equal(close.kind,'close');
  })();
  void worker.catch(()=>{});
  try{
    const session=await createAciNativeSession({repoRoot,captureId,setup,onNativeRegistration:async r=>{assert.equal(r.callbackUri,callbackUri);events.push('fixture_exact_registration');},onAuthorizationUrl:async r=>{assert.equal(r.authorizationUrl,url.href);events.push('owner_browser_consent');return {callbackUrl:callback,evidence:{clicked:true}};}});
    await session.turn({kind:'preflight',prompt:'synthetic unit preflight, never an acceptance capture'});await session.close();await worker;
    assert.deepEqual(events,['fixture_exact_registration','native_registration_confirmed','owner_browser_consent','actual_callback_delivered']);
    assert.equal(await lstat(resolve(directory,'private-login.json')).then(()=>true,e=>{if(e.code==='ENOENT')return false;throw e;}),false);
    assert.equal(JSON.stringify(session.authorization).includes(code),false);
  }finally{await worker.catch(()=>{});await cleanup(repoRoot);}
});
test('ACI producer refuses missing independent observers or a synthetic launch boundary',async()=>{
  await assert.rejects(runAgentClientConnectionOwnerCase({}),/aci_independent_boundaries_required/);
});
test('ACI native waits short-circuit on scoped safe failure without propagating arbitrary diagnostic fields',async()=>{
  for(const variant of ['valid','foreign_capture','wrong_schema','missing']){
    const repoRoot=await mkdtemp(resolve(tmpdir(),'aci-session-unit-')),captureId=randomUUID(),directory=resolve(repoRoot,'.local/aci-native',captureId);
    await mkdir(directory,{recursive:true});
    if(variant!=='missing')await writeFile(resolve(directory,'status-error.json'),JSON.stringify({schemaVersion:variant==='wrong_schema'?'untrusted':'aci-native-failure/v1',captureId:variant==='foreign_capture'?randomUUID():captureId,status:'blocked',reasonCode:'http://private/callback?code=SECRET_CANARY&state=SECRET_CANARY',raw:'SECRET_CANARY'}));
    let consentCalled=false;const started=Date.now();
    try{
      await assert.rejects(createAciNativeSession({repoRoot,captureId,setup:{serverUrl:'http://127.0.0.1:3000/api/agent/mcp',resource:'http://127.0.0.1:3000/api/agent/mcp',clientId:'unit_public',development:true},timeoutMs:100,onNativeRegistration:async()=>{},onAuthorizationUrl:async()=>{consentCalled=true;}}),error=>{
        const expected=variant==='valid'?'aci_native_reported_failure':variant==='missing'?'aci_native_wait_timeout':'aci_native_failure_status_invalid';
        assert.equal(error.message,expected);assert.equal(JSON.stringify({message:error.message,...error}).includes('SECRET_CANARY'),false);return true;
      });
      assert.equal(consentCalled,false);assert(Date.now()-started<1000);
    }finally{await cleanup(repoRoot);}
  }
});
test('ACI rejects duplicate and legacy OAuth resource indicators before browser consent',async()=>{
  const endpoint='http://127.0.0.1:3000/api/agent/mcp',legacy='http://127.0.0.1:3000/api/agent';
  for(const resources of [[endpoint,endpoint],[endpoint,legacy],[legacy]]){
    const repoRoot=await mkdtemp(resolve(tmpdir(),'aci-session-unit-')),captureId=randomUUID(),directory=resolve(repoRoot,'.local/aci-native',captureId),callbackUri='http://127.0.0.1:38765/callback/native_server_id';
    const setup={serverUrl:endpoint,resource:endpoint,clientId:'unit_public',development:true};let consentCalled=false;
    const worker=(async()=>{
      await wait(resolve(directory,'job.json'));await writeFile(resolve(directory,'registration.json'),JSON.stringify({callbackUri,clientId:setup.clientId}));await wait(resolve(directory,'registration-approved.json'));
      const url=new URL('http://127.0.0.1:3000/api/auth/oauth2/authorize');for(const [name,value]of Object.entries({client_id:setup.clientId,redirect_uri:callbackUri,response_type:'code',code_challenge_method:'S256',code_challenge:'synthetic',state:'synthetic'}))url.searchParams.set(name,value);for(const resource of resources)url.searchParams.append('resource',resource);
      await writeFile(resolve(directory,'private-login.json'),JSON.stringify({url:url.href}));
    })();void worker.catch(()=>{});
    try{await assert.rejects(createAciNativeSession({repoRoot,captureId,setup,onNativeRegistration:async()=>{},onAuthorizationUrl:async()=>{consentCalled=true;}}),error=>error.message==='aci_native_authorization_binding_invalid');assert.equal(consentCalled,false);await worker;}
    finally{await worker.catch(()=>{});await cleanup(repoRoot);}
  }
});
