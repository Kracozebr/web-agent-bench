/** ACI orchestration only. The client owns config/OAuth, and observers cannot authorize actions. */
import {createHash} from 'node:crypto';
import {mkdir,readFile,writeFile,rename,lstat,unlink} from 'node:fs/promises';
import {resolve} from 'node:path';
import {ensureAciPrivateDirectory,aciEndpoint,ACI_CALLBACK,validateAciCallback} from '../../../tools/run_aci_native.mjs';
const digest=value=>createHash('sha256').update(value).digest('hex');
const sleep=ms=>new Promise(done=>setTimeout(done,ms));
async function atomic(file,body){await writeFile(file+'.tmp',JSON.stringify(body),{mode:0o600,flag:'wx'});await rename(file+'.tmp',file);}
async function checkNativeFailure(directory,captureId){
  const file=resolve(directory,'status-error.json');let status;
  try{
    const meta=await lstat(file);if(!meta.isFile()||meta.isSymbolicLink()||meta.size>65536)throw new Error('aci_native_failure_status_invalid');
    try{status=JSON.parse(await readFile(file,'utf8'));}catch{throw new Error('aci_native_failure_status_invalid');}
  }catch(error){if(error.code==='ENOENT')return;throw new Error('aci_native_failure_status_invalid');}
  if(status?.schemaVersion!=='aci-native-failure/v1'||status.status!=='blocked'||status.captureId!==captureId)throw new Error('aci_native_failure_status_invalid');
  // Deliberately do not propagate reason text, command output, URI or arbitrary properties.
  throw new Error('aci_native_reported_failure');
}
async function waitJson(file,timeoutMs,{directory,captureId}){const until=Date.now()+timeoutMs;while(Date.now()<until){await checkNativeFailure(directory,captureId);try{const meta=await lstat(file);if(!meta.isFile()||meta.isSymbolicLink()||meta.size>1048576)throw new Error('aci_private_input_invalid');return JSON.parse(await readFile(file,'utf8'));}catch(error){if(error.code!=='ENOENT')throw error;}await sleep(250);}throw new Error('aci_native_wait_timeout');}

export async function createAciNativeSession({repoRoot,captureId,setup,onAuthorizationUrl,onNativeRegistration,onStage=()=>{},timeoutMs=180000}){
  aciEndpoint(setup.serverUrl,setup.development===true);
  if(typeof onAuthorizationUrl!=='function')throw new Error('aci_real_consent_callback_required');
  const directory=await ensureAciPrivateDirectory(repoRoot,captureId);
  const waitNative=(file,ms)=>waitJson(resolve(directory,file),ms,{directory,captureId});
  onStage('native_setup_job');
  await atomic(resolve(directory,'job.json'),{schemaVersion:'aci-native-job/v1',captureId,setup});
  const registration=await waitNative('registration.json',timeoutMs);
  onStage('native_exact_registration');
  const callbackUri=validateAciCallback(registration.callbackUri);
  if(registration.clientId!==setup.clientId||typeof onNativeRegistration!=='function')throw new Error('aci_actual_native_registration_required');
  await onNativeRegistration({callbackUri,clientId:setup.clientId,setupAuthorizationCancelled:registration.setupAuthorizationCancelled});
  await atomic(resolve(directory,'registration-approved.json'),{callbackUri,clientId:setup.clientId});
  const privateLogin=await waitNative('private-login.json',timeoutMs);
  onStage('native_browser_consent');
  const url=new URL(privateLogin.url);
  const resources=url.searchParams.getAll('resource');
  if(setup.resource!==setup.serverUrl||resources.length!==1||resources[0]!==setup.resource||url.origin!==new URL(setup.serverUrl).origin||url.searchParams.get('code_challenge_method')!=='S256'||url.searchParams.get('response_type')!=='code'||url.searchParams.get('client_id')!==setup.clientId||url.searchParams.get('redirect_uri')!==callbackUri)throw new Error('aci_native_authorization_binding_invalid');
  // AICODE-NOTE: URL/code/state stay in transient private IPC. The callback is a real
  // browser-consent redirect consumed by the official native no-browser login flow.
  const consentResult=await onAuthorizationUrl({authorizationUrl:url.href,callbackUri});
  const callback=new URL(typeof consentResult==='string'?consentResult:consentResult.callbackUrl);
  if(callback.origin!==new URL(callbackUri).origin||callback.pathname!==new URL(callbackUri).pathname||callback.searchParams.get('state')!==url.searchParams.get('state')||!callback.searchParams.get('code'))throw new Error('aci_native_callback_binding_invalid');
  await atomic(resolve(directory,'private-callback.json'),{url:callback.href});
  await unlink(resolve(directory,'private-login.json'));
  onStage('native_code_exchange');
  const authorization=await waitNative('authorized.json',timeoutMs);let sequence=0;
  if(authorization.authMethod!=='native_oauth'||authorization.client!=='codex_cli'||authorization.isolatedHome!==true)throw new Error('aci_native_authorization_missing');
  return {
    authorization,registration,consent:typeof consentResult==='object'?consentResult.evidence:undefined,
    async turn({kind,prompt,timeoutMs:turnTimeout=12*60*1000}){
      if(!['preflight','launch','revoked_preflight'].includes(kind)||typeof prompt!=='string'||Buffer.byteLength(prompt)>65536)throw new Error('aci_native_turn_invalid');
      const index=++sequence;await atomic(resolve(directory,`request-${index}.json`),{kind,prompt});
      const response=await waitNative(`response-${index}.json`,turnTimeout);
      if(response.schemaVersion!=='aci-native-turn/v1'||response.kind!==kind||response.authMethod!=='native_oauth'||response.promptSha256!==digest(Buffer.from(prompt)))throw new Error('aci_native_turn_binding_invalid');
      return response;
    },
    async close(){await atomic(resolve(directory,`request-${++sequence}.json`),{kind:'close'});},
  };
}

/** Real browser consent using the existing authenticated owner context; no code/state capture. */
export async function consentAciNativeAuthorization({ownerPage,authorizationUrl,callbackUri,selectAndApprove}){
  if(typeof selectAndApprove!=='function')throw new Error('aci_consent_ui_action_required');
  let callback;const expected=new URL(callbackUri);
  const route=async handler=>{const request=new URL(handler.request().url());if(request.origin===expected.origin&&request.pathname===expected.pathname){callback=request.href;await handler.abort();}else await handler.continue();};
  await ownerPage.route(`${expected.origin}${expected.pathname}**`,route);
  try{
    await ownerPage.goto(authorizationUrl);
    await selectAndApprove(ownerPage).catch(error=>{if(!callback)throw error;});
    const until=Date.now()+30000;while(!callback&&Date.now()<until)await sleep(100);
    if(!callback)throw new Error('aci_real_browser_callback_missing');
    return callback;
  }finally{await ownerPage.unroute(`${expected.origin}${expected.pathname}**`,route);await ownerPage.goto(new URL('/agents',authorizationUrl).href);}
}

export const ACI_PREFLIGHT_PROMPT='Use only MCP server w3bench_user. Call identity.preflight once with no agentId hint and a fresh operationId. Do not create or accept a launch intent, start a run, or call another tool. Report only the server-confirmed status and modes.';

/** Root owns fixture creation, backup/restore and actual browser Start action. */
export async function runAgentClientConnectionOwnerCase(input){
  const {repoRoot,captureId,setup,onAuthorizationUrl,onNativeRegistration,observeReadonly,onBrowserLaunch,readMcpProjections}=input;
  if(typeof observeReadonly!=='function'||typeof onBrowserLaunch!=='function'||typeof readMcpProjections!=='function')throw new Error('aci_independent_boundaries_required');
  const proof={schemaVersion:'agent-client-connection-physical-capture/v1',captureId,status:'running',client:'codex_cli',qualificationScope:'local_loopback_development_only',setup:{serverUrl:aciEndpoint(setup.serverUrl,setup.development===true),resource:setup.resource,clientId:setup.clientId,callbackUri:ACI_CALLBACK},nativeTurns:[]};
  let native;
  try{
    proof.beforeConnection=await observeReadonly('before_connection');
    native=await createAciNativeSession({repoRoot,captureId,setup,onAuthorizationUrl,onNativeRegistration,onStage:input.onStage});proof.nativeAuthorization=native.authorization;proof.registration=native.registration;proof.consent=native.consent;proof.setup.callbackUri=native.authorization.callbackUri;proof.setupBrowser=input.setupBrowser;
    input.onStage?.('native_free_preflight');
    proof.beforePreflight=await observeReadonly('before_preflight');
    proof.nativeTurns.push(await native.turn({kind:'preflight',prompt:ACI_PREFLIGHT_PROMPT}));
    proof.afterPreflight=await observeReadonly('after_preflight');
    input.onStage?.('selected_browser_launch');
    proof.launch=await onBrowserLaunch({connection:proof.afterPreflight,client:'codex_cli'});
    if(!proof.launch?.handoffPrompt||!proof.launch.selectedConnectionId||!proof.launch.intentId)throw new Error('aci_selected_browser_launch_missing');
    proof.pendingLaunch=await observeReadonly('pending_launch');
    input.onStage?.('native_selected_launch');
    proof.nativeTurns.push(await native.turn({kind:'launch',prompt:proof.launch.handoffPrompt}));
    proof.afterLaunch=await observeReadonly('after_launch');
    input.onStage?.('native_post_run_observation');
    proof.mcp=await readMcpProjections();
    // A status label is only bookkeeping; independent reader replays every raw boundary.
    proof.status='captured';return {status:'captured_aci_run',aci:proof};
  }catch(error){proof.status='blocked';proof.blocker=['aci_selected_browser_launch_missing','aci_native_authorization_binding_invalid','aci_native_callback_binding_invalid','aci_native_authorization_missing','aci_native_turn_binding_invalid','aci_native_wait_timeout','aci_native_reported_failure','aci_native_failure_status_invalid'].includes(error.message)?error.message:'aci_boundary_capture_failed';return {status:'blocked',aci:proof};}
  finally{if(native)await native.close();}
}
