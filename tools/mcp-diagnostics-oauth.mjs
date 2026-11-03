import {readBoundedDiagnosticText} from './mcp-diagnostics-io.mjs';
/** Diagnostic helper owns this OAuth grant/store; native Codex credentials are never opened. */
import {createHash,randomBytes,timingSafeEqual} from 'node:crypto';
import {createServer} from 'node:http';
import {spawn} from 'node:child_process';

export const DIAGNOSTIC_CLIENT_ID='w3bench-diagnostics-helper-v1';
export const DIAGNOSTIC_CALLBACK='http://127.0.0.1:38766/diagnostics/callback';
export const DIAGNOSTIC_SCOPES=['diagnostics:write','offline_access'];
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const need=(v,code)=>{if(!v)throw new Error(code)};
const digest=value=>createHash('sha256').update(value).digest('hex');
const opaque=value=>typeof value==='string'&&/^[A-Za-z0-9_-]{20,1024}$/.test(value);
function baseOrigin(origin,development){const u=new URL(origin);need(!u.username&&!u.password&&!u.search&&!u.hash&&u.pathname==='/'&&(u.protocol==='https:'||development&&u.protocol==='http:'&&['127.0.0.1','localhost'].includes(u.hostname)),'DIAGNOSTICS_ORIGIN_INVALID');return u.origin;}
export function validateDiagnosticOAuthProfile(profile,{origin,development=false}={}){
  const base=baseOrigin(origin,development);need(profile&&profile.clientId===DIAGNOSTIC_CLIENT_ID&&profile.resource===base+'/api/diagnostics'&&profile.redirectUri===DIAGNOSTIC_CALLBACK&&Array.isArray(profile.scopes)&&profile.scopes.length===2&&DIAGNOSTIC_SCOPES.every(x=>profile.scopes.includes(x)),'DIAGNOSTICS_OAUTH_PROFILE_INVALID');
  for(const [key,path] of [['authorizationEndpointUrl','/api/diagnostics/oauth/authorize'],['tokenEndpointUrl','/api/diagnostics/oauth/token']]){const u=new URL(profile[key]);need(u.origin===base&&u.pathname===path&&!u.search&&!u.hash&&!u.username&&!u.password,'DIAGNOSTICS_OAUTH_PROFILE_INVALID');}
  return Object.freeze({clientId:profile.clientId,resource:profile.resource,scopes:[...DIAGNOSTIC_SCOPES],redirectUri:DIAGNOSTIC_CALLBACK,authorizationEndpointUrl:profile.authorizationEndpointUrl,tokenEndpointUrl:profile.tokenEndpointUrl});
}
export function diagnosticCredentialTarget({origin,agentId,connectionId}){need(UUID.test(agentId)&&UUID.test(connectionId),'DIAGNOSTICS_BINDING_INVALID');const u=new URL(origin);need(!u.username&&!u.password&&!u.search&&!u.hash&&u.pathname==='/','DIAGNOSTICS_ORIGIN_INVALID');return 'W3BenchDiagnostics:v1:'+digest(u.origin+'\n'+DIAGNOSTIC_CLIENT_ID+'\n'+agentId+'\n'+connectionId);}
export function createDiagnosticAuthorization(profile,{random=randomBytes}={}){
  const verifier=random(48).toString('base64url'),state=random(32).toString('base64url');
  const url=new URL(profile.authorizationEndpointUrl);url.searchParams.set('response_type','code');url.searchParams.set('client_id',DIAGNOSTIC_CLIENT_ID);url.searchParams.set('redirect_uri',profile.redirectUri);url.searchParams.set('resource',profile.resource);url.searchParams.set('scope',DIAGNOSTIC_SCOPES.join(' '));url.searchParams.set('code_challenge_method','S256');url.searchParams.set('code_challenge',createHash('sha256').update(verifier).digest('base64url'));url.searchParams.set('state',state);
  return {url:url.href,state,verifier};
}
export function validateDiagnosticCallback(requestUrl,{state,host='127.0.0.1:38766'}={}){
  need(host==='127.0.0.1:38766','DIAGNOSTICS_CALLBACK_INVALID');const u=new URL(requestUrl,DIAGNOSTIC_CALLBACK);
  need(u.origin==='http://127.0.0.1:38766'&&u.pathname==='/diagnostics/callback'&&!u.hash&&!u.username&&!u.password&&[...u.searchParams.keys()].every(x=>['code','state','error'].includes(x)),'DIAGNOSTICS_CALLBACK_INVALID');
  const received=u.searchParams.getAll('state');need(received.length===1&&typeof state==='string'&&state.length>=32&&received[0].length===state.length&&timingSafeEqual(Buffer.from(received[0]),Buffer.from(state)),'DIAGNOSTICS_CALLBACK_STATE_INVALID');
  if(u.searchParams.has('error')){need(!u.searchParams.has('code')&&u.searchParams.getAll('error').length===1,'DIAGNOSTICS_CALLBACK_INVALID');throw new Error(u.searchParams.get('error')==='access_denied'?'DIAGNOSTICS_AUTH_DENIED':'DIAGNOSTICS_AUTH_REQUIRED');}
  const codes=u.searchParams.getAll('code');need(codes.length===1&&opaque(codes[0]),'DIAGNOSTICS_CALLBACK_INVALID');return codes[0];
}

// AICODE-NOTE: Static Win32 bridge, own fixed namespace only. Secrets cross stdin/stdout in memory, never argv or disk.
const WINDOWS_CREDENTIAL_SCRIPT=String.raw`
$ErrorActionPreference='Stop'
try {
  $inputData=[Console]::In.ReadToEnd()|ConvertFrom-Json
  if($inputData.target -cnotmatch '^W3BenchDiagnostics:v1:[a-f0-9]{64}$'){throw 'invalid_target'}
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class W3DiagnosticCredentials {
 [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] public struct Credential { public uint Flags;public uint Type;public string TargetName;public string Comment;public long LastWritten;public uint CredentialBlobSize;public IntPtr CredentialBlob;public uint Persist;public uint AttributeCount;public IntPtr Attributes;public string TargetAlias;public string UserName; }
 [DllImport("Advapi32.dll",EntryPoint="CredWriteW",CharSet=CharSet.Unicode,SetLastError=true)] public static extern bool Write(ref Credential value,uint flags);
 [DllImport("Advapi32.dll",EntryPoint="CredReadW",CharSet=CharSet.Unicode,SetLastError=true)] public static extern bool Read(string target,uint type,uint flags,out IntPtr pointer);
 [DllImport("Advapi32.dll",EntryPoint="CredDeleteW",CharSet=CharSet.Unicode,SetLastError=true)] public static extern bool Delete(string target,uint type,uint flags);
 [DllImport("Advapi32.dll")] public static extern void CredFree(IntPtr pointer);
}
'@
  if($inputData.operation -ceq 'read') {
    $pointer=[IntPtr]::Zero
    if(-not [W3DiagnosticCredentials]::Read($inputData.target,1,0,[ref]$pointer)) {
      if([Runtime.InteropServices.Marshal]::GetLastWin32Error() -eq 1168){[Console]::Out.Write('{"ok":true,"secret":null}');exit 0};throw 'read_failed'
    }
    try {$value=[Runtime.InteropServices.Marshal]::PtrToStructure($pointer,[type][W3DiagnosticCredentials+Credential]);if($value.CredentialBlobSize -gt 2560){throw 'size'};$blob=New-Object byte[] $value.CredentialBlobSize;[Runtime.InteropServices.Marshal]::Copy($value.CredentialBlob,$blob,0,$blob.Length);$secret=[Text.Encoding]::UTF8.GetString($blob);[Console]::Out.Write((@{ok=$true;secret=$secret}|ConvertTo-Json -Compress))}finally{[W3DiagnosticCredentials]::CredFree($pointer)}
  } elseif($inputData.operation -ceq 'write') {
    $blob=[Text.Encoding]::UTF8.GetBytes([string]$inputData.secret);if($blob.Length -lt 1 -or $blob.Length -gt 2560){throw 'size'};$pointer=[Runtime.InteropServices.Marshal]::AllocHGlobal($blob.Length)
    try {[Runtime.InteropServices.Marshal]::Copy($blob,0,$pointer,$blob.Length);$value=New-Object W3DiagnosticCredentials+Credential;$value.Type=1;$value.TargetName=$inputData.target;$value.CredentialBlobSize=$blob.Length;$value.CredentialBlob=$pointer;$value.Persist=2;$value.UserName='W3Bench diagnostics helper';if(-not [W3DiagnosticCredentials]::Write([ref]$value,0)){throw 'write_failed'};[Console]::Out.Write('{"ok":true}')}finally{for($i=0;$i -lt $blob.Length;$i++){[Runtime.InteropServices.Marshal]::WriteByte($pointer,$i,0)};[Runtime.InteropServices.Marshal]::FreeHGlobal($pointer)}
  } elseif($inputData.operation -ceq 'delete') {
    if(-not [W3DiagnosticCredentials]::Delete($inputData.target,1,0) -and [Runtime.InteropServices.Marshal]::GetLastWin32Error() -ne 1168){throw 'delete_failed'};[Console]::Out.Write('{"ok":true}')
  } else {throw 'operation'}
} catch {[Console]::Out.Write('{"ok":false,"code":"CREDENTIAL_STORE_UNAVAILABLE"}');exit 1}
`;
async function windowsCredentialCommand(input){
  need(process.platform==='win32','DIAGNOSTICS_CREDENTIAL_STORE_UNAVAILABLE');
  return new Promise((done,reject)=>{const child=spawn('powershell.exe',['-NoProfile','-NonInteractive','-WindowStyle','Hidden','-Command',WINDOWS_CREDENTIAL_SCRIPT],{windowsHide:true,stdio:['pipe','pipe','pipe']});let output='',count=0,settled=false;
    const fail=()=>{if(!settled){settled=true;reject(new Error('DIAGNOSTICS_CREDENTIAL_STORE_UNAVAILABLE'));}};
    const timer=setTimeout(()=>{child.kill();fail();},15000);child.once('error',()=>{clearTimeout(timer);fail();});child.stdout.on('data',b=>{count+=b.length;if(count>8192){child.kill();fail();}else output+=b.toString('utf8');});child.stderr.on('data',()=>{});
    child.once('close',code=>{clearTimeout(timer);if(settled)return;try{const value=JSON.parse(output);if(code!==0||value.ok!==true)throw 0;settled=true;done(value);}catch{fail();}});child.stdin.on('error',fail);child.stdin.end(JSON.stringify(input),'utf8');});
}
export function createDiagnosticCredentialStore({command=windowsCredentialCommand}={}){
  const target=t=>need(typeof t==='string'&&/^W3BenchDiagnostics:v1:[a-f0-9]{64}$/.test(t),'DIAGNOSTICS_CREDENTIAL_TARGET_INVALID');
  return {async get(t){target(t);const result=await command({operation:'read',target:t});if(result.secret===null)return null;need(typeof result.secret==='string'&&Buffer.byteLength(result.secret)<=2560,'DIAGNOSTICS_CREDENTIAL_STORE_UNAVAILABLE');let v;try{v=JSON.parse(result.secret);}catch{throw new Error('DIAGNOSTICS_CREDENTIAL_STORE_UNAVAILABLE');}need(v&&Object.keys(v).length===1&&opaque(v.refreshToken),'DIAGNOSTICS_CREDENTIAL_STORE_UNAVAILABLE');return v.refreshToken;},
    async set(t,refreshToken){target(t);need(opaque(refreshToken),'DIAGNOSTICS_TOKEN_INVALID');const secret=JSON.stringify({refreshToken});need(Buffer.byteLength(secret)<=2560,'DIAGNOSTICS_CREDENTIAL_TOO_LARGE');await command({operation:'write',target:t,secret});},
    async delete(t){target(t);await command({operation:'delete',target:t});}};
}

async function tokenRequest(profile,form,{fetchImpl=fetch}={}){
  let response;try{response=await fetchImpl(profile.tokenEndpointUrl,{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({...form,client_id:DIAGNOSTIC_CLIENT_ID,resource:profile.resource,scope:DIAGNOSTIC_SCOPES.join(' ')}),redirect:'error',signal:AbortSignal.timeout(15000)});}catch{throw new Error('DIAGNOSTICS_AUTH_TRANSPORT_UNAVAILABLE');}
  const text=await readBoundedDiagnosticText(response,16384,'DIAGNOSTICS_TOKEN_INVALID');let body;try{body=JSON.parse(text);}catch{throw new Error('DIAGNOSTICS_TOKEN_INVALID');}
  if(!response.ok)throw new Error(['invalid_grant','invalid_client','access_denied'].includes(body?.error)?'DIAGNOSTICS_AUTH_REQUIRED':'DIAGNOSTICS_AUTH_TRANSPORT_UNAVAILABLE');
  const scopes=typeof body.scope==='string'?body.scope.split(/\s+/):[];
  need(typeof body.access_token==='string'&&body.access_token.length>=20&&body.access_token.length<=4096&&!/\s/.test(body.access_token)&&body.token_type?.toLowerCase()==='bearer'&&opaque(body.refresh_token)&&Number.isSafeInteger(body.expires_in)&&body.expires_in>=1&&body.expires_in<=86400&&scopes.includes('diagnostics:write')&&scopes.every(s=>DIAGNOSTIC_SCOPES.includes(s)),'DIAGNOSTICS_TOKEN_INVALID');
  const binding=body.diagnosticBinding;need(binding&&Object.keys(binding).length===2&&UUID.test(binding.agentId)&&UUID.test(binding.connectionId),'DIAGNOSTICS_BINDING_INVALID');
  return {accessToken:body.access_token,refreshToken:body.refresh_token,expiresIn:body.expires_in,binding};
}
export async function exchangeDiagnosticAuthorization({profile,code,verifier,origin,development=false,store,fetchImpl=fetch,now=()=>Date.now()}){
  profile=validateDiagnosticOAuthProfile(profile,{origin,development});
  need(opaque(code)&&typeof verifier==='string'&&/^[A-Za-z0-9_-]{43,128}$/.test(verifier),'DIAGNOSTICS_AUTH_REQUIRED');
  const token=await tokenRequest(profile,{grant_type:'authorization_code',code,redirect_uri:profile.redirectUri,code_verifier:verifier},{fetchImpl});
  const target=diagnosticCredentialTarget({origin,...token.binding});await store.set(target,token.refreshToken);
  return {accessToken:token.accessToken,expiresAt:now()+token.expiresIn*1000,binding:token.binding,credentialTarget:target};
}
export function createDiagnosticTokenProvider({profile,origin,development=false,binding,store,fetchImpl=fetch,now=()=>Date.now(),initialToken}){
  profile=validateDiagnosticOAuthProfile(profile,{origin,development});
  const target=diagnosticCredentialTarget({origin,...binding});let memory=initialToken??null,pending=null;
  return {binding,async getAccessToken(){if(memory?.accessToken&&memory.expiresAt>now()+30000)return memory.accessToken;if(pending)return pending;
    pending=(async()=>{const refreshToken=await store.get(target);need(refreshToken,'DIAGNOSTICS_AUTH_REQUIRED');const next=await tokenRequest(profile,{grant_type:'refresh_token',refresh_token:refreshToken},{fetchImpl});need(next.binding.agentId===binding.agentId&&next.binding.connectionId===binding.connectionId,'DIAGNOSTICS_BINDING_INVALID');await store.set(target,next.refreshToken);memory={accessToken:next.accessToken,expiresAt:now()+next.expiresIn*1000};return memory.accessToken;})();
    try{return await pending;}finally{pending=null;}
  }};
}
export async function authorizeDiagnosticHelper({profile,origin,development=false,store,openBrowser,fetchImpl=fetch,timeoutMs=180000,now=()=>Date.now()}){
  profile=validateDiagnosticOAuthProfile(profile,{origin,development});
  need(typeof openBrowser==='function'&&Number.isSafeInteger(timeoutMs)&&timeoutMs>0&&timeoutMs<=180000,'DIAGNOSTICS_AUTH_SETUP_INVALID');
  const request=createDiagnosticAuthorization(profile);let settle;
  const completed=new Promise((done,reject)=>{settle={done,reject}});let used=false;
  const server=createServer((req,res)=>{if(used){res.writeHead(409);res.end('Authorization already consumed');return;}try{need(req.method==='GET','DIAGNOSTICS_CALLBACK_INVALID');const code=validateDiagnosticCallback(req.url,{state:request.state,host:req.headers.host});used=true;res.writeHead(200,{'content-type':'text/plain; charset=utf-8','cache-control':'no-store'});res.end('Completing diagnostic authorization. Return to the launcher.');settle.done(code);}catch(e){res.writeHead(400,{'content-type':'text/plain; charset=utf-8','cache-control':'no-store'});res.end('Diagnostic authorization was not accepted.');if(['DIAGNOSTICS_AUTH_DENIED','DIAGNOSTICS_AUTH_REQUIRED'].includes(e.message)){used=true;settle.reject(new Error(e.message));}}});
  let timer;try{await new Promise((done,reject)=>{server.once('error',()=>reject(new Error('DIAGNOSTICS_AUTH_CALLBACK_UNAVAILABLE')));server.listen(38766,'127.0.0.1',done);});timer=setTimeout(()=>settle.reject(new Error('DIAGNOSTICS_AUTH_TIMEOUT')),timeoutMs);await openBrowser(request.url);const code=await completed;return await exchangeDiagnosticAuthorization({profile,code,verifier:request.verifier,origin,development,store,fetchImpl,now});}
  finally{clearTimeout(timer);server.closeAllConnections();await new Promise(done=>server.close(done));}
}
