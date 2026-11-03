import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,randomUUID} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {DIAGNOSTIC_CLIENT_ID,DIAGNOSTIC_CALLBACK,validateDiagnosticOAuthProfile,createDiagnosticAuthorization,validateDiagnosticCallback,diagnosticCredentialTarget,createDiagnosticCredentialStore,exchangeDiagnosticAuthorization,createDiagnosticTokenProvider} from './mcp-diagnostics-oauth.mjs';
const origin='http://127.0.0.1:3000',binding={agentId:'2f6c98f3-c7b4-428e-856d-e0dd15634c5d',connectionId:'3f6c98f3-c7b4-428e-856d-e0dd15634c5d'};
const profile={clientId:DIAGNOSTIC_CLIENT_ID,resource:origin+'/api/diagnostics',scopes:['diagnostics:write','offline_access'],redirectUri:DIAGNOSTIC_CALLBACK,authorizationEndpointUrl:origin+'/api/diagnostics/oauth/authorize',tokenEndpointUrl:origin+'/api/diagnostics/oauth/token'};
const token=(extra={})=>({access_token:'A'.repeat(43),refresh_token:'R'.repeat(43),token_type:'Bearer',expires_in:300,scope:'diagnostics:write offline_access',diagnosticBinding:binding,...extra});

test('helper OAuth profile is a fixed distinct client/resource/scope/callback and rejects arbitrary endpoint credential exfiltration',()=>{
  assert.deepEqual(validateDiagnosticOAuthProfile(profile,{origin,development:true}),profile);
  for(const patch of [{clientId:'codex'},{resource:origin+'/api/agent/mcp'},{scopes:['agent:operate','offline_access']},{redirectUri:'http://127.0.0.1:38765/callback'},{tokenEndpointUrl:'https://foreign.example/token'},{authorizationEndpointUrl:origin+'/api/diagnostics/oauth/authorize?token=secret'}])assert.throws(()=>validateDiagnosticOAuthProfile({...profile,...patch},{origin,development:true}),/PROFILE_INVALID/);
  assert.throws(()=>validateDiagnosticOAuthProfile(profile,{origin}),/ORIGIN_INVALID/);
});

test('authorization uses S256, cryptographic independent state/verifier, exact scope/resource and exact authorization request schema',()=>{
  const request=createDiagnosticAuthorization(profile),u=new URL(request.url);
  assert.equal(u.searchParams.get('client_id'),DIAGNOSTIC_CLIENT_ID);assert.equal(u.searchParams.get('resource'),profile.resource);assert.equal(u.searchParams.get('scope'),'diagnostics:write offline_access');assert.equal(u.searchParams.get('code_challenge_method'),'S256');assert.equal(u.searchParams.get('code_challenge'),createHash('sha256').update(request.verifier).digest('base64url'));assert.notEqual(request.state,request.verifier);assert.equal(u.searchParams.has('connection_id'),false);assert.equal(u.searchParams.has('access_token'),false);assert.equal(u.searchParams.has('client_secret'),false);
});

test('callback rejects mismatched/repeated state, wrong origin/host, query injection and denied owner consent',()=>{
  const state='S'.repeat(43),code='C'.repeat(43),url=DIAGNOSTIC_CALLBACK+'?code='+code+'&state='+state;
  assert.equal(validateDiagnosticCallback(url,{state}),code);
  for(const [candidate,context] of [[url+'&state='+state,{state}],[url+'&code='+code,{state}],[url+'&access_token=secret',{state}],[url.replace('38766','38765'),{state}],[url,{state:'T'.repeat(43)}],[url,{state,host:'foreign.example'}]])assert.throws(()=>validateDiagnosticCallback(candidate,context));
  assert.throws(()=>validateDiagnosticCallback(DIAGNOSTIC_CALLBACK+'?error=access_denied&state='+state,{state}),/AUTH_DENIED/);
});

test('credential namespace is bound to helper origin/card/connection and cannot target native credential entries',async()=>{
  const calls=[],values=new Map(),store=createDiagnosticCredentialStore({command:async input=>{calls.push(input);if(input.operation==='write'){values.set(input.target,input.secret);return {ok:true};}if(input.operation==='read')return {ok:true,secret:values.get(input.target)??null};values.delete(input.target);return {ok:true};}}),target=diagnosticCredentialTarget({origin,...binding});
  assert.match(target,/^W3BenchDiagnostics:v1:[a-f0-9]{64}$/);assert.notEqual(target,diagnosticCredentialTarget({origin,...binding,connectionId:randomUUID()}));assert.equal(await store.get(target),null);
  await store.set(target,'R'.repeat(43));assert.equal(await store.get(target),'R'.repeat(43));assert.deepEqual(JSON.parse(values.get(target)),{refreshToken:'R'.repeat(43)});assert(!values.get(target).includes('access_token'));
  await assert.rejects(store.get('Codex:auth'),/TARGET_INVALID/);await assert.rejects(store.set('auth.json','R'.repeat(43)),/TARGET_INVALID/);assert.equal(calls.some(c=>c.target.includes('Codex')),false);await store.delete(target);assert.equal(await store.get(target),null);
});

test('code exchange saves only helper refresh token after verifying exact diagnostic grant/binding',async()=>{
  let posted,saved;const result=await exchangeDiagnosticAuthorization({profile,origin,development:true,code:'C'.repeat(43),verifier:'V'.repeat(64),store:{async set(target,value){saved={target,value};}},fetchImpl:async(url,args)=>{posted={url,args};return Response.json(token());},now:()=>1000});
  assert.equal(posted.url,profile.tokenEndpointUrl);assert.equal(posted.args.redirect,'error');const form=new URLSearchParams(posted.args.body);assert.equal(form.get('grant_type'),'authorization_code');assert.equal(form.get('code_verifier'),'V'.repeat(64));assert.equal(form.get('resource'),profile.resource);assert.equal(form.get('client_id'),DIAGNOSTIC_CLIENT_ID);assert.equal(form.has('client_secret'),false);assert.equal(saved.value,'R'.repeat(43));assert.equal(result.expiresAt,301000);assert.deepEqual(result.binding,binding);assert(!saved.target.includes('R'.repeat(10)));
});

test('refresh is singleflight, rotates only own grant and never reads native credential files',async()=>{
  let stored='R'.repeat(43),refreshes=0,gets=0;const store={async get(){gets++;return stored;},async set(_target,value){stored=value;}};
  const provider=createDiagnosticTokenProvider({profile,origin,development:true,binding,store,now:()=>1000,fetchImpl:async(_url,args)=>{refreshes++;assert.equal(new URLSearchParams(args.body).get('refresh_token'),'R'.repeat(43));await Promise.resolve();return Response.json(token({refresh_token:'N'.repeat(43)}));}});
  assert.deepEqual(await Promise.all([provider.getAccessToken(),provider.getAccessToken()]),['A'.repeat(43),'A'.repeat(43)]);assert.equal(refreshes,1);assert.equal(gets,1);assert.equal(stored,'N'.repeat(43));assert.equal(await provider.getAccessToken(),'A'.repeat(43));assert.equal(refreshes,1);
  const source=await readFile(new URL('./mcp-diagnostics-oauth.mjs',import.meta.url),'utf8');assert.equal(source.includes("from 'node:fs"),false);assert.equal(source.includes('CODEX_HOME'),false);assert.equal(source.includes('auth.json'),false);
});

test('wrong scope/binding/token response cannot be cached and invalid refresh becomes pending authorization without raw errors',async()=>{
  for(const patch of [{scope:'agent:operate offline_access'},{diagnosticBinding:{...binding,connectionId:randomUUID()}},{access_token:'secret\nheader'}]){
    let writes=0;const p=createDiagnosticTokenProvider({profile,origin,development:true,binding,store:{async get(){return 'R'.repeat(43);},async set(){writes++;}},fetchImpl:async()=>Response.json(token(patch))});await assert.rejects(p.getAccessToken(),/DIAGNOSTICS_(TOKEN|BINDING)_INVALID/);assert.equal(writes,0);
  }
  const denied=createDiagnosticTokenProvider({profile,origin,development:true,binding,store:{async get(){return 'R'.repeat(43);}},fetchImpl:async()=>Response.json({error:'invalid_grant',error_description:'sk-DO-NOT-PERSIST'},{status:400})});await assert.rejects(denied.getAccessToken(),/^Error: DIAGNOSTICS_AUTH_REQUIRED$/);
});

test('untrusted token endpoint is rejected before own refresh credential is read',()=>{
  let reads=0;assert.throws(()=>createDiagnosticTokenProvider({profile:{...profile,tokenEndpointUrl:'https://foreign.example/steal'},origin,development:true,binding,store:{get(){reads++;}}}),/PROFILE_INVALID/);assert.equal(reads,0);
});
