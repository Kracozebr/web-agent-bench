/** Acceptance-only native OAuth client. No global configuration, bearer injection or raw transcript. */
import {spawn} from 'node:child_process';
import {createHash} from 'node:crypto';
import {mkdir,readFile,writeFile,rename,lstat,unlink,realpath} from 'node:fs/promises';
import {resolve,dirname,sep} from 'node:path';
import {fileURLToPath} from 'node:url';
import {EventSummary,createPrivateCodexHome,verifyPrivateCodexHome,cleanupPrivateCodexHome,verifyExecutableBundle} from '../infrastructure/owner-identity/run-codex-google-local.mjs';

export const ACI_TOOLS=['identity.preflight','runs.accept_launch_intent','runs.current_task','runs.task_action','runs.task_action_status','runs.finish_task','support.report','support.report_receipt'];
const hash=value=>createHash('sha256').update(value).digest('hex');
const sleep=ms=>new Promise(done=>setTimeout(done,ms));
const SAFE_PHASES=new Set(['platform_guard','job_wait','bundle_verification','private_home','native_version','native_add','config_read','registration_wait','native_login','credential_check','request_wait','native_preflight','native_launch','native_revoked_preflight']);
const SAFE_FAILURES=new Set(['aci_native_requires_windows','aci_endpoint_invalid','aci_registration_invalid','aci_private_path_invalid','aci_private_file_invalid','aci_capture_id_invalid','aci_job_invalid','aci_job_timeout','aci_native_interrupted','aci_native_command_failed','aci_native_version_mismatch','aci_native_add_config_missing','aci_callback_registration_invalid','aci_native_registration_not_confirmed','aci_callback_invalid','aci_callback_delivery_failed','aci_login_url_unavailable','aci_login_url_invalid','aci_config_contains_credential','aci_native_request_invalid','aci_native_cleanup_failed','aci_native_preflight_not_verified','codex_bundle_component_missing','codex_bundle_hash_mismatch','codex_bundle_manifest_invalid','auth_source_replaced','auth_link_unavailable','codex_auth_not_found','codex_home_invalid']);
const SAFE_DIAGNOSTICS=new Set(['argument_rejected','config_rejected','credential_store_failed','connection_failed','invalid_client','invalid_scope','invalid_redirect','discovery_failed','issuer_mismatch','stdin_unavailable','invalid_approval_config','approval_required','http_400','http_401','http_403','http_500']);
export function classifyAciNativeDiagnostic(text){
  const patterns={argument_rejected:/unexpected argument|unrecognized (?:option|argument)|unknown (?:option|argument|subcommand)|invalid value/i,
    config_rejected:/failed to (?:load|parse).*config|invalid toml|error.*configuration/i,
    credential_store_failed:/keyring|credential store.*(?:fail|error)|failed.*(?:credential|keychain)/i,
    connection_failed:/connection refused|connection reset|failed to connect|error sending request|dns error|timed out/i,
    invalid_client:/\binvalid_client\b|client.*not.*registered/i,
    invalid_scope:/\binvalid_scope\b/i,invalid_redirect:/redirect.*(?:mismatch|not allowed|invalid)|\binvalid_redirect_uri\b/i,
    discovery_failed:/discovery.*(?:failed|error)|failed.*(?:metadata|discover)|authorization server metadata/i,
    issuer_mismatch:/issuer.*(?:mismatch|missing|invalid)|missing.*issuer/i,
    stdin_unavailable:/not a terminal|stdin.*(?:closed|error)|failed to read.*(?:stdin|input)/i,
    invalid_approval_config:/(?:invalid|unsupported|failed to parse).*approval|approval.*(?:invalid|unsupported)|configuration.*(?:tool|approval)/i,
    approval_required:/tool.*(?:requires?|need).*approval|approval.*(?:required|unavailable|disabled)/i,
    http_400:/\b(?:HTTP(?:\/\d(?:\.\d)?)?\s*[:=]?\s*400|400\s+Bad Request)\b/i,
    http_401:/\b(?:HTTP(?:\/\d(?:\.\d)?)?\s*[:=]?\s*401|401\s+Unauthorized)\b/i,
    http_403:/\b(?:HTTP(?:\/\d(?:\.\d)?)?\s*[:=]?\s*403|403\s+Forbidden)\b/i,
    http_500:/\b(?:HTTP(?:\/\d(?:\.\d)?)?\s*[:=]?\s*500|500\s+Internal Server Error)\b/i};
  return Object.entries(patterns).filter(([,pattern])=>pattern.test(text)).map(([name])=>name);
}
export function safeAciNativeFailure(error,{captureId,phase,commandReceipt}={}){
  return {schemaVersion:'aci-native-failure/v1',captureId:/^[a-f0-9-]{36}$/.test(captureId??'')?captureId:null,status:'blocked',
    phase:SAFE_PHASES.has(phase)?phase:'platform_guard',reasonCode:SAFE_FAILURES.has(error?.message)?error.message:'aci_native_internal_failure',
    command:commandReceipt?{stage:SAFE_PHASES.has(commandReceipt.stage)?commandReceipt.stage:'platform_guard',exitCode:Number.isInteger(commandReceipt.exitCode)?commandReceipt.exitCode:null,signal:['SIGTERM','SIGKILL','SIGINT'].includes(commandReceipt.signal)?commandReceipt.signal:null,
      stdoutBytes:Number.isSafeInteger(commandReceipt.stdoutBytes)?commandReceipt.stdoutBytes:0,stderrBytes:Number.isSafeInteger(commandReceipt.stderrBytes)?commandReceipt.stderrBytes:0,
      timedOut:commandReceipt.timedOut===true,outputLimitExceeded:commandReceipt.outputLimitExceeded===true,
      diagnosticCodes:Array.isArray(commandReceipt.diagnosticCodes)?commandReceipt.diagnosticCodes.filter(code=>SAFE_DIAGNOSTICS.has(code)):[]}:null,
    rawOutputPersisted:false,at:new Date().toISOString()};
}
async function persistAciNativeFailure(repoRoot,captureId,status){
  const privateDirectory=await ensureAciPrivateDirectory(repoRoot,captureId);
  await atomic(resolve(privateDirectory,'status-error.json'),status);
  let current=resolve(repoRoot);const directory=resolve(repoRoot,'artifacts/runs/agent-client-connection',captureId);
  for(const part of directory.slice(current.length+1).split(sep)){current=resolve(current,part);await mkdir(current,{mode:0o700}).catch(e=>{if(e.code!=='EEXIST')throw e;});const metadata=await lstat(current);if(!metadata.isDirectory()||metadata.isSymbolicLink()||(await realpath(current)).toLowerCase()!==current.toLowerCase())throw new Error('aci_private_path_invalid');}
  await writeFile(resolve(directory,'native-status-error.json'),JSON.stringify(status,null,2)+'\n',{flag:'wx',mode:0o600});
}
export const ACI_CALLBACK='http://127.0.0.1:38765/callback';
const nativeConfig=['--no-daemon','-c','mcp_oauth_credentials_store="file"','-c','mcp_oauth_callback_port=38765','-c',`mcp_oauth_callback_url=${JSON.stringify(ACI_CALLBACK)}`];
export function aciEndpoint(value,development=false){
  const u=new URL(value);
  if(u.username||u.password||u.search||u.hash||u.pathname!=='/api/agent/mcp'||!(u.protocol==='https:'||(development&&u.protocol==='http:'&&['127.0.0.1','[::1]','localhost'].includes(u.hostname))))throw new Error('aci_endpoint_invalid');
  return u.href;
}
export function nativeAddArguments(setup){
  const endpoint=aciEndpoint(setup.serverUrl,setup.development===true),resource=new URL(setup.resource);
  if(resource.href!==endpoint||!/^[-a-zA-Z0-9_.]{1,100}$/.test(setup.clientId))throw new Error('aci_registration_invalid');
  // Native Codex already supplies its MCP endpoint as the OAuth resource. An extra
  // oauth-resource flag appends another indicator; it cannot override that default.
  return ['--no-daemon','mcp','add','w3bench_user','--url',endpoint,'--oauth-client-id',setup.clientId];
}
export function extractPrivateLoginUrl(text,origin){
  const candidates=[...text.matchAll(/https?:\/\/[^\s<>"']+/g)].map(x=>x[0]);
  const urls=candidates.flatMap(value=>{try{return [new URL(value)];}catch{return [];}}).filter(u=>u.origin===origin&&u.searchParams.has('code_challenge')&&u.searchParams.has('state'));
  if(urls.length!==1)throw new Error('aci_login_url_unavailable');
  const u=urls[0];
  if(u.username||u.password||u.hash||u.searchParams.get('code_challenge_method')!=='S256'||u.searchParams.get('response_type')!=='code')throw new Error('aci_login_url_invalid');
  return u.href;
}
export function validateAciCallback(value){
  const url=new URL(value);
  if(url.origin!==new URL(ACI_CALLBACK).origin||!/^\/callback(?:\/[a-zA-Z0-9_-]{1,100})?$/.test(url.pathname)||url.username||url.password||url.search||url.hash)throw new Error('aci_callback_registration_invalid');
  return url.href;
}
export function nativeModelArguments(){
  // AICODE-NOTE: mcp add, not the platform, created this isolated client's configuration.
  // Do not use ignore-user-config here: it would discard that native OAuth connection.
  return ['--no-daemon','exec','--ephemeral','--json','--sandbox','read-only','--skip-git-repo-check','--ignore-rules',
    '--config','project_doc_max_bytes=0','--config','cli_auth_credentials_store="file"',
    ...['apps','plugins','multi_agent','shell_tool','unified_exec','shell_snapshot','browser_use','browser_use_external','browser_use_full_cdp_access','computer_use','browser_annotation_api'].flatMap(x=>['--disable',x]),
    '--config',`mcp_servers.w3bench_user.enabled_tools=${JSON.stringify(ACI_TOOLS)}`,
    '--config','mcp_servers.w3bench_user.required=true',
    '--config','mcp_servers.w3bench_user.default_tools_approval_mode="auto"',
    '--config',`mcp_servers.w3bench_user.tools={ ${ACI_TOOLS.map(name=>`${JSON.stringify(name)} = { approval_mode = "approve" }`).join(', ')} }`,'-'];
}
/** The base observer recognizes its original owner_identity alias. This local
 * adapter recognizes the actual w3bench_user events without rewriting any event,
 * identity, tool result, protocol label or server wire evidence. */
export class AciEventSummary extends EventSummary {
  consume(line){
    const oldCount=this.mcpToolCalls,oldNames=new Set(this.toolNames),oldPreflight=[this.preflightAllowed,this.preflightDenied,this.preflightUnclassified];super.consume(line);let event;try{event=JSON.parse(line);}catch{return;}
    const item=event?.item&&typeof event.item==='object'?event.item:event;
    for(const text of [item?.message,item?.error?.message])if(typeof text==='string')for(const code of classifyAciNativeDiagnostic(text))if(['invalid_approval_config','approval_required'].includes(code))this.errorCodes.add(code);
    const server=[item?.server,item?.server_name,item?.serverName].find(x=>typeof x==='string');
    const toolValue=item?.tool,name=[item?.tool_name,item?.name,item?.toolName,typeof toolValue==='string'?toolValue:toolValue?.name??toolValue?.toolName].find(x=>typeof x==='string');
    if(server==='owner_identity'){
      // Retain the inherited event/error census, but its original server is not
      // an authorized ACI observation and must never satisfy native preflight.
      if(this.mcpToolCalls>oldCount&&this.toolNames.has(name)){this.unknownMcpToolCalls++;this.toolNames=oldNames;}
      [this.preflightAllowed,this.preflightDenied,this.preflightUnclassified]=oldPreflight;
    }
    if(server!=='w3bench_user'||!ACI_TOOLS.includes(name))return;
    if(this.mcpToolCalls>oldCount){this.unknownMcpToolCalls=Math.max(0,this.unknownMcpToolCalls-1);this.toolNames.add(name);}
    if(name!=='identity.preflight'||!['completed','failed'].includes(item?.status))return;
    const id=typeof item.call_id==='string'?item.call_id:typeof item.id==='string'?item.id:typeof event.id==='string'?event.id:'';
    if(id&&this.preflightResultIds.has(id))return;if(!id&&event.type!=='item.completed')return;
    if(id&&this.preflightResultIds.size<10000)this.preflightResultIds.add(id);
    let status=item?.status==='completed'&&item?.result?.isError!==true?item?.result?.structuredContent?.status:null;
    if(!status&&item?.status==='completed'&&item?.result?.isError!==true&&Array.isArray(item?.result?.content))for(const part of item.result.content){if(typeof part?.text==='string'&&part.text.length<=4096)try{const value=JSON.parse(part.text);if(['allowed','denied'].includes(value?.status)){status=value.status;break;}}catch{/* No text is retained. */}}
    if(status==='allowed')this.preflightAllowed++;else if(status==='denied')this.preflightDenied++;else this.preflightUnclassified++;
  }
}
export function assertAciNativePreflight(summary){
  if(summary.exitCode!==0||summary.terminalEvent!=='turn.completed'||summary.preflightAllowed!==1||summary.preflightDenied!==0||summary.preflightUnclassified!==0||summary.mcpToolCallCount!==1||summary.mcpToolErrorCount!==0||summary.unknownMcpToolCallCount!==0||summary.localToolCallCount!==0||summary.mcpToolNames?.length!==1||summary.mcpToolNames[0]!=='identity.preflight')throw new Error('aci_native_preflight_not_verified');
}
async function json(file){const s=await lstat(file);if(!s.isFile()||s.isSymbolicLink()||s.size>131072)throw new Error('aci_private_file_invalid');return JSON.parse(await readFile(file,'utf8'));}
async function atomic(file,value){await writeFile(file+'.tmp',JSON.stringify(value),{flag:'wx',mode:0o600});await rename(file+'.tmp',file);}
export function aciPrivateDirectory(repoRoot,captureId){if(!/^[a-f0-9-]{36}$/.test(captureId))throw new Error('aci_capture_id_invalid');return resolve(repoRoot,'.local/aci-native',captureId);}
export async function ensureAciPrivateDirectory(repoRoot,captureId){
  const root=resolve(repoRoot),target=aciPrivateDirectory(root,captureId);
  if((await realpath(root)).toLowerCase()!==root.toLowerCase())throw new Error('aci_private_path_invalid');
  let current=root;
  for(const component of target.slice(root.length+1).split(sep)){
    current=resolve(current,component);await mkdir(current,{mode:0o700}).catch(e=>{if(e.code!=='EEXIST')throw e;});const meta=await lstat(current);
    if(!meta.isDirectory()||meta.isSymbolicLink()||(await realpath(current)).toLowerCase()!==current.toLowerCase())throw new Error('aci_private_path_invalid');
  }
  return target;
}
function environment(home){const env={CODEX_HOME:home};for(const key of ['PATH','PATHEXT','SystemRoot','WINDIR','USERPROFILE','APPDATA','LOCALAPPDATA','TEMP','TMP','COMSPEC'])if(process.env[key])env[key]=process.env[key];return env;}
async function waitJson(file,until,signal){while(Date.now()<until){if(signal?.aborted)throw new Error('aci_native_interrupted');try{return await json(file);}catch(e){if(e.code!=='ENOENT')throw e;}await sleep(250);}throw new Error('aci_job_timeout');}

export async function runAciNative({repoRoot,captureId,executable,waitMs=12*60*1000}){
  let phase='platform_guard',commandReceipt=null;
  try{
  if(process.platform!=='win32')throw new Error('aci_native_requires_windows');
  const directory=await ensureAciPrivateDirectory(repoRoot,captureId),until=Date.now()+waitMs;
  phase='job_wait';const job=await waitJson(resolve(directory,'job.json'),until);
  if(job.schemaVersion!=='aci-native-job/v1'||job.captureId!==captureId)throw new Error('aci_job_invalid');
  const args=nativeAddArguments(job.setup);
  executable=resolve(executable??resolve(repoRoot,'.local/codex-runner-inspection/package/vendor/x86_64-pc-windows-msvc/bin/codex.exe'));
  phase='bundle_verification';await verifyExecutableBundle(executable);
  phase='private_home';
  const home=await createPrivateCodexHome();const env=environment(home.path);env.CODEX_MANAGED_PACKAGE_ROOT=resolve(dirname(executable),'../../..');env.CODEX_MANAGED_BY_NPM='1';
  const workspace=resolve(directory,'empty-workspace');await mkdir(workspace,{mode:0o700});
  const pins={nativeExeSha256:hash(await readFile(executable)),codeModeHostSha256:hash(await readFile(resolve(dirname(executable),'codex-code-mode-host.exe'))),helperSha256:hash(await readFile(fileURLToPath(import.meta.url))),baseHelperSha256:hash(await readFile(resolve(repoRoot,'infrastructure/owner-identity/run-codex-google-local.mjs')))};
  let child=null,closed=true;const controller=new AbortController();
  const interrupt=()=>{controller.abort();if(!closed)child?.kill('SIGTERM');};process.on('SIGINT',interrupt);process.on('SIGTERM',interrupt);
  async function command(argv,{prompt,onOutput,model=false,interactive=false,cancelOnAuthorization=false,timeoutMs=60000}={}){
    await verifyPrivateCodexHome(home);let bytes=0,stdoutBytes=0,stderrBytes=0,buffer='',cancelledAuthorizationUrl=null,timedOut=false,outputLimitExceeded=false;const startedAt=new Date().toISOString();
    commandReceipt={stage:phase,exitCode:null,signal:null,stdoutBytes:0,stderrBytes:0,timedOut:false,outputLimitExceeded:false,diagnosticCodes:[]};
    child=spawn(executable,argv,{cwd:workspace,env,windowsHide:true,stdio:['pipe','pipe','pipe']});closed=false;
    const summary=model?new AciEventSummary(()=>child.kill('SIGTERM')):null;
    const consume=chunk=>{bytes+=chunk.length;if(bytes>(model?16:2)*1024*1024){outputLimitExceeded=true;child.kill('SIGTERM');return;}if(!model){buffer+=chunk.toString('utf8');if(cancelOnAuthorization&&!cancelledAuthorizationUrl){try{cancelledAuthorizationUrl=extractPrivateLoginUrl(buffer,new URL(job.setup.serverUrl).origin);child.kill('SIGTERM');}catch{/* Keep collecting until a real authorization URL or exit. */}}onOutput?.(buffer,child);}else summary.feed(chunk);};
    child.stdout.on('data',chunk=>{stdoutBytes+=chunk.length;consume(chunk);});child.stderr.on('data',chunk=>{stderrBytes+=chunk.length;if(model)summary.observeStderr(chunk);else consume(chunk);});if(!interactive)child.stdin.end(prompt??'');
    const timer=setTimeout(()=>{timedOut=true;child.kill('SIGTERM');},timeoutMs);
    const ended=await new Promise((done,fail)=>{child.once('error',fail);child.once('close',(code,signal)=>done({code,signal}));}).finally(()=>{clearTimeout(timer);closed=true;});
    const exitCode=ended.signal?1:ended.code??1;
    commandReceipt={stage:phase,exitCode:ended.code,signal:ended.signal,stdoutBytes,stderrBytes,timedOut,outputLimitExceeded,diagnosticCodes:model?[...summary.errorCodes].filter(code=>SAFE_DIAGNOSTICS.has(code)):classifyAciNativeDiagnostic(buffer)};
    await verifyPrivateCodexHome(home);
    if(exitCode!==0&&!cancelledAuthorizationUrl)throw new Error('aci_native_command_failed');
    return model?{exitCode,...summary.sanitizedSnapshot(),terminalEvent:summary.terminalEvent,promptSha256:hash(Buffer.from(prompt)),startedAt,finishedAt:new Date().toISOString()}:{exitCode,verifiedVersion:buffer.split(/\r?\n/).some(x=>x.trim()==='codex-cli 0.165.0')?'0.165.0':null,cancelledAuthorizationUrl};
  }
  try{
    phase='native_version';
    const version=await command(['--version']);if(version.verifiedVersion!=='0.165.0')throw new Error('aci_native_version_mismatch');
    // Native credential persistence belongs to the client, separately from config.toml.
    phase='native_add';const added=await command([...nativeConfig,...args.slice(1)],{cancelOnAuthorization:true,timeoutMs:60000});
    phase='config_read';
    const writtenConfig=await readFile(resolve(home.path,'config.toml'),'utf8');
    if(!writtenConfig.includes('[mcp_servers.w3bench_user]')||!writtenConfig.includes(job.setup.serverUrl)||/access_token|refresh_token|client_secret|bearer_token/.test(writtenConfig))throw new Error('aci_native_add_config_missing');
    const savedCallback=[...writtenConfig.matchAll(/^callback_url\s*=\s*"([^"\r\n]+)"\s*$/gm)];
    const callbackUri=validateAciCallback(added.cancelledAuthorizationUrl?new URL(added.cancelledAuthorizationUrl).searchParams.get('redirect_uri'):savedCallback.length===1?savedCallback[0][1]:ACI_CALLBACK);
    await atomic(resolve(directory,'registration.json'),{schemaVersion:'aci-native-registration/v1',callbackUri,clientId:job.setup.clientId,setupAuthorizationCancelled:!!added.cancelledAuthorizationUrl,configurationSha256:hash(writtenConfig)});
    phase='registration_wait';const registration=await waitJson(resolve(directory,'registration-approved.json'),Date.now()+180000,controller.signal);
    if(registration.callbackUri!==callbackUri||registration.clientId!==job.setup.clientId)throw new Error('aci_native_registration_not_confirmed');
    let published=false;
    let callbackDelivery=Promise.resolve();
    phase='native_login';const login=command([...nativeConfig,'mcp','login','w3bench_user','--scopes','agent:operate,offline_access','--no-browser'],{interactive:true,timeoutMs:180000,onOutput:(text,loginChild)=>{
      if(published)return;let url;try{url=extractPrivateLoginUrl(text,new URL(job.setup.serverUrl).origin);}catch{return;}
      published=true;callbackDelivery=(async()=>{
        await atomic(resolve(directory,'private-login.json'),{url});
        const callback=await waitJson(resolve(directory,'private-callback.json'),Date.now()+175000,controller.signal);
        const uri=new URL(callback.url),expected=new URL(callbackUri);
        if(uri.origin!==expected.origin||uri.pathname!==expected.pathname||!uri.searchParams.get('code')||!uri.searchParams.get('state')||uri.searchParams.get('state')!==new URL(url).searchParams.get('state'))throw new Error('aci_callback_invalid');
        await unlink(resolve(directory,'private-callback.json'));
        loginChild.stdin.end(uri.href+'\n');
      })().catch(()=>{loginChild.kill('SIGTERM');throw new Error('aci_callback_delivery_failed');});
      void callbackDelivery.catch(()=>{});
    }});
    await login;await callbackDelivery;if(!published)throw new Error('aci_login_url_unavailable');
    phase='credential_check';const config=await readFile(resolve(home.path,'config.toml'),'utf8');
    if(/bearer_token|access_token|refresh_token|client_secret/.test(config))throw new Error('aci_config_contains_credential');
    await atomic(resolve(directory,'authorized.json'),{schemaVersion:'aci-native-authorized/v1',captureId,callbackUri,setupAuthorizationCancelled:!!added.cancelledAuthorizationUrl,configurationSha256:hash(config),configurationWriter:'native_cli_mcp_add',nativeAddArguments:args,platformProcessCount:0,platformPackageCount:0,sourcePins:pins,client:'codex_cli',clientVersion:'0.165.0',authMethod:'native_oauth',isolatedHome:true});
    for(let index=1;index<=4;index++){
      phase='request_wait';
      const request=await waitJson(resolve(directory,`request-${index}.json`),Date.now()+waitMs,controller.signal);
      if(request.kind==='close')break;
      if(!['preflight','launch','revoked_preflight'].includes(request.kind)||typeof request.prompt!=='string'||Buffer.byteLength(request.prompt)>65536)throw new Error('aci_native_request_invalid');
      phase='native_'+request.kind;const result=await command([...nativeConfig,...nativeModelArguments().slice(1)],{model:true,prompt:request.prompt,timeoutMs:12*60*1000});
      if(request.kind==='preflight')try{assertAciNativePreflight(result);}catch(error){await atomic(resolve(directory,`failed-turn-${index}.json`),{schemaVersion:'aci-native-failed-turn/v1',captureId,kind:request.kind,...result});throw error;}
      await atomic(resolve(directory,`response-${index}.json`),{schemaVersion:'aci-native-turn/v1',captureId,kind:request.kind,client:'codex_cli',clientVersion:'0.165.0',authMethod:'native_oauth',sourcePins:pins,...result});
    }
  }finally{
    process.off('SIGINT',interrupt);process.off('SIGTERM',interrupt);
    if(!closed)child?.kill('SIGTERM');
    // Existing audited cleanup checks the resolved private target before recursive removal.
    if(closed){const cleanup=await cleanupPrivateCodexHome(home);if(!cleanup.succeeded||!cleanup.authAliasPreserved)throw new Error('aci_native_cleanup_failed');}
    for(const name of ['private-login.json','private-callback.json'])await unlink(resolve(directory,name)).catch(e=>{if(e.code!=='ENOENT')throw e;});
  }
  }catch(error){const status=safeAciNativeFailure(error,{captureId,phase,commandReceipt});await persistAciNativeFailure(repoRoot,captureId,status).catch(()=>{});throw Object.assign(new Error(status.reasonCode),{safeStatus:status});}
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  if(process.argv.length!==4||process.argv[2]!=='--capture-id'){process.stderr.write('Usage: node tools/run_aci_native.mjs --capture-id <uuid>\n');process.exitCode=2;}
  else try{await runAciNative({repoRoot:resolve(dirname(fileURLToPath(import.meta.url)),'..'),captureId:process.argv[3]});process.stdout.write('{"status":"completed"}\n');}catch(error){process.stderr.write(JSON.stringify(error.safeStatus??safeAciNativeFailure(error,{captureId:process.argv[3]}))+'\n');process.exitCode=1;}
}
