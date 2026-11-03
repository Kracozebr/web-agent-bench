/** First setup only: observe native-bound identity without helper credentials or automatic delivery. */
import {spawn} from 'node:child_process';
import {createHash,randomUUID} from 'node:crypto';
import {readFile,mkdir} from 'node:fs/promises';
import {resolve,dirname} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {NativeDiagnosticCollector} from './mcp-diagnostics-client.mjs';
import {instrumentedNativeArguments,nativeEnvironment,validateNativeMetadata,runProjectedNative} from './mcp-diagnostics-launcher.mjs';
import {verifyExecutableBundle} from '../infrastructure/owner-identity/run-codex-google-local.mjs';

const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const sha=v=>createHash('sha256').update(v).digest('hex');
const need=(v,c)=>{if(!v)throw new Error(c);};
const sources=['tools/mcd-native-connection-probe.mjs','tools/mcp-diagnostics-client.mjs','tools/mcp-diagnostics-launcher.mjs','tools/run_aci_native.mjs','infrastructure/owner-identity/run-codex-google-local.mjs','packages/owner-identity/src/agents.ts'];
async function inventory(root){return Object.fromEntries(await Promise.all(sources.map(async path=>[path,sha(await readFile(resolve(root,path)))])) );}
export function projectMcdPreflightIdentity(item){
  if(item?.type!=='mcp_tool_call'||(item.server??item.server_name??item.serverName)!=='w3bench_user'||(item.tool??item.tool_name??item.name??item.toolName)!=='identity.preflight'||!['completed'].includes(item.status)||item.error||item.result?.isError)return null;
  let body=item.result?.structuredContent;
  if(!body)for(const part of item.result?.content??[])if(part?.type==='text'&&typeof part.text==='string'&&part.text.length<=8192)try{body=JSON.parse(part.text);break;}catch{}
  if(!body||!['allowed','denied'].includes(body.status)||!UUID.test(body.identity?.agentId??'')||!UUID.test(body.identity?.connectionId??'')||typeof body.permissions?.training!=='boolean'||typeof body.permissions?.ranked!=='boolean')return null;
  const rawId=[item.call_id,item.id].find(v=>typeof v==='string'&&v.length<=512);if(!rawId)return null;
  return {agentId:body.identity.agentId,connectionId:body.identity.connectionId,allowed:body.status==='allowed',modes:body.status==='allowed'?['training','ranked'].filter(mode=>body.permissions[mode]):[],sourceCallIdHash:sha(rawId)};
}
export class McdConnectionProbeCollector extends NativeDiagnosticCollector {
  constructor(){const events=[];super({clientVersion:'0.165.0',maxCalls:4,onEnvelope:e=>{if(events.length>=64)return false;events.push(e);return true;}});this.safeEvents=events;this.identities=new Map();}
  consume(line){super.consume(line);try{const event=JSON.parse(line),item=event.item??event;if(event.type!=='item.completed')return;const value=projectMcdPreflightIdentity(item);if(value){const prior=this.identities.get(value.sourceCallIdHash);if(prior&&JSON.stringify(prior)!==JSON.stringify(value))this.identityContradiction=true;else this.identities.set(value.sourceCallIdHash,value);}else if(item?.type==='mcp_tool_call'&&(item.server??item.server_name??item.serverName)==='w3bench_user'&&(item.tool??item.tool_name??item.name??item.toolName)==='identity.preflight'){const id=[item.call_id,item.id].find(v=>typeof v==='string'&&v.length<=512);if(id&&this.identities.has(sha(id)))this.identityContradiction=true;}}catch{/* Raw output never enters the projection. */}}
  result(native){const calls=this.safeEvents.filter(e=>e.callIdHash);if(this.identityContradiction||native.exitCode!==0||native.localToolCallCount!==0||calls.length!==1||calls[0].tool!=='identity.preflight'||calls[0].outcome!=='success'||this.identities.size!==1)return null;const value=this.identities.get(calls[0].callIdHash);return value?{...value,...(UUID.test(calls[0].traceId??'')?{traceId:calls[0].traceId}:{})}:null;}
}
async function metadata(executable,args){return new Promise((done,reject)=>{let bytes=0,parts=[],failed=false;const c=spawn(executable,['--no-daemon','-c','mcp_oauth_credentials_store="file"',...args],{windowsHide:true,env:nativeEnvironment(process.env,executable),stdio:['ignore','pipe','pipe']});const timer=setTimeout(()=>{failed=true;c.kill();},15000);c.stdout.on('data',b=>{bytes+=b.length;if(bytes>1024*1024){failed=true;c.kill();}else parts.push(b);});c.stderr.on('data',()=>{});c.once('error',()=>{failed=true;});c.once('close',code=>{clearTimeout(timer);try{need(!failed&&code===0,'MCD_NATIVE_PROBE_METADATA_FAILED');done(JSON.parse(Buffer.concat(parts).toString('utf8')));}catch{reject(new Error('MCD_NATIVE_PROBE_METADATA_FAILED'));}parts=[];});});}
export async function probeMcdNativeConnection(repoRoot=resolve(dirname(fileURLToPath(import.meta.url)),'..')){
  const before=await inventory(repoRoot),executable=resolve(repoRoot,'.local/codex-runner-inspection/package/vendor/x86_64-pc-windows-msvc/bin/codex.exe');await verifyExecutableBundle(executable);
  const list=await metadata(executable,['mcp','list','--json']);const names=validateNativeMetadata({list,server:await metadata(executable,['mcp','get','w3bench_user','--json']),origin:'http://127.0.0.1:3000'});
  const collector=new McdConnectionProbeCollector(),operationId='mcd_setup_'+randomUUID().replaceAll('-',''),workspace=resolve(repoRoot,'.local/mcd-native-first-setup',randomUUID());await mkdir(workspace,{recursive:true,mode:0o700});
  const args=instrumentedNativeArguments({otherServers:list,executable});args.pop();args.push('--config','mcp_servers.w3bench_user.enabled_tools=["identity.preflight"]','-');
  // AICODE-NOTE: agentId is omitted; operationId is required by the actual published schema. Neither is read from cached identity data.
  const prompt=`This is a free first-setup connection probe. Use only w3bench_user. Call identity.preflight EXACTLY ONCE with {"operationId":"${operationId}"}, omitting agentId so the existing native OAuth connection binds identity. Do not retry, accept any intent, start any task, submit any report, use local tools/files/shell/browser, or change credentials. Then stop.`;
  const native=await runProjectedNative({executable,args,cwd:workspace,prompt,collector,timeoutMs:180000}),identity=collector.result(native),after=await inventory(repoRoot);need(JSON.stringify(before)===JSON.stringify(after),'MCD_NATIVE_PROBE_SOURCE_CHANGED');
  return {schemaVersion:'mcd-native-first-setup/v1',status:identity?'observed':'blocked',...(identity?{identity}:{reason:'MCD_NATIVE_CONNECTION_PROBE_UNCONFIRMED'}),coverage:'first_setup_only_not_sc002_acceptance',helper:'unconfigured',automaticDelivery:false,sourceInputs:{before,after},safeEvents:collector.safeEvents,native:{...native,terminalEvent:native.terminalEvent??null}};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){if(process.argv.slice(2).join(' ')!=='--probe-connection'){process.stderr.write('Usage: node tools/mcd-native-connection-probe.mjs --probe-connection\n');process.exitCode=1;}else probeMcdNativeConnection().then(value=>process.stdout.write(JSON.stringify(value,null,2)+'\n')).catch(error=>{process.stderr.write(/^MCD_NATIVE_[A-Z_]+$/.test(error?.message)?error.message:'MCD_NATIVE_CONNECTION_PROBE_BLOCKED');process.exitCode=1;});}
