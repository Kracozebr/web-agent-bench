import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {resolve,sep} from 'node:path';
import {spawnSync} from 'node:child_process';
import {verifyExecutableBundle} from '../infrastructure/owner-identity/run-codex-google-local.mjs';
import {aciEndpoint,nativeAddArguments,extractPrivateLoginUrl,nativeModelArguments,ACI_CALLBACK,validateAciCallback,AciEventSummary,assertAciNativePreflight,classifyAciNativeDiagnostic} from './run_aci_native.mjs';
test('ACI native setup permits canonical HTTPS or explicit loopback development only and never a bearer',()=>{
  assert.equal(aciEndpoint('https://bench.example/api/agent/mcp'),'https://bench.example/api/agent/mcp');
  assert.equal(aciEndpoint('http://127.0.0.1:3000/api/agent/mcp',true),'http://127.0.0.1:3000/api/agent/mcp');
  for(const value of ['http://bench.example/api/agent/mcp','https://key@bench.example/api/agent/mcp','https://bench.example/api/agent/mcp?token=x','https://bench.example/api/agent/mcp#token','https://bench.example/stdio'])assert.throws(()=>aciEndpoint(value,true));
  assert.throws(()=>aciEndpoint('http://127.0.0.1:3000/api/agent/mcp'));
  const args=nativeAddArguments({serverUrl:'http://127.0.0.1:3000/api/agent/mcp',resource:'http://127.0.0.1:3000/api/agent/mcp',clientId:'oid-local-mcp-client',development:true});
  assert.deepEqual(args.slice(0,4),['--no-daemon','mcp','add','w3bench_user']);assert.equal(args.some(x=>x.includes('bearer')),false);
  assert.equal(args.includes('--oauth-resource'),false);
  assert.throws(()=>nativeAddArguments({serverUrl:'http://127.0.0.1:3000/api/agent/mcp',resource:'http://127.0.0.1:3000/api/agent',clientId:'public',development:true}));
  assert.throws(()=>nativeAddArguments({serverUrl:'https://bench.example/api/agent/mcp',resource:'https://foreign.example/api/agent',clientId:'public'}));
});
test('ACI private authorization URL extraction requires real OAuth PKCE and expected issuer without exposing it',()=>{
  const url='http://127.0.0.1:3000/api/auth/oauth2/authorize?response_type=code&code_challenge_method=S256&code_challenge=private&state=private';
  assert.equal(extractPrivateLoginUrl('Authorize here: '+url+'\n','http://127.0.0.1:3000'),url);
  assert.throws(()=>extractPrivateLoginUrl(url,'https://foreign.example'),/aci_login_url_unavailable/);
  assert.throws(()=>extractPrivateLoginUrl(url+' '+url,'http://127.0.0.1:3000'),/aci_login_url_unavailable/);
  assert.throws(()=>extractPrivateLoginUrl(url.replace('S256','plain'),'http://127.0.0.1:3000'),/aci_login_url_invalid/);
  assert.equal(ACI_CALLBACK,'http://127.0.0.1:38765/callback');
});
test('ACI actual model turn uses native config and excludes local tools, daemon and bearer override',()=>{
  const args=nativeModelArguments();assert.deepEqual(args.slice(0,2),['--no-daemon','exec']);
  assert.equal(args.includes('--ignore-user-config'),false);assert.equal(args.includes('--ignore-rules'),true);
  for(const name of ['shell_tool','unified_exec','browser_use','computer_use','multi_agent'])assert.equal(args.includes(name),true);
  assert.equal(args.some(x=>x.includes('bearer')),false);assert.equal(args.some(x=>x.startsWith('mcp_servers={')),false);
});
test('ACI registration accepts only exact bounded native loopback callbacks, including issuer-unbound server IDs',()=>{
  assert.equal(validateAciCallback(ACI_CALLBACK),ACI_CALLBACK);
  assert.equal(validateAciCallback(ACI_CALLBACK+'/actual_server-1'),ACI_CALLBACK+'/actual_server-1');
  for(const value of [ACI_CALLBACK+'?code=secret',ACI_CALLBACK+'#fragment',ACI_CALLBACK+'/../../foreign','http://localhost:38765/callback','http://127.0.0.1:38766/callback',ACI_CALLBACK+'/a/b'])assert.throws(()=>validateAciCallback(value));
});
test('ACI approval overrides use one quoted inline tool map and auto default without replacing native OAuth connection',()=>{
  const args=nativeModelArguments(),values=args.flatMap((x,i)=>x==='--config'?[args[i+1]]:[]);
  assert.equal(values.filter(x=>x.startsWith('mcp_servers.w3bench_user.tools.')).length,0);
  const map=values.filter(x=>x.startsWith('mcp_servers.w3bench_user.tools='));assert.equal(map.length,1);
  for(const name of ['identity.preflight','runs.accept_launch_intent','runs.current_task','runs.task_action','runs.task_action_status','runs.finish_task','support.report','support.report_receipt'])assert(map[0].includes(JSON.stringify(name)+' = { approval_mode = "approve" }'));
  assert(values.includes('mcp_servers.w3bench_user.default_tools_approval_mode="auto"'));
  assert.equal(values.some(x=>x.startsWith('mcp_servers=')||x.includes('bearer_token')),false);
});
test('ACI native observation recognizes only actual w3bench preflight and rejects process-zero without a successful MCP call',()=>{
  for(const server of ['w3bench_user','owner_identity','foreign_server']){
    const summary=new AciEventSummary(()=>{});
    summary.feed(Buffer.from(JSON.stringify({type:'item.completed',item:{id:'call1',type:'mcp_tool_call',server,tool:'identity.preflight',status:'completed',result:{content:[{type:'text',text:JSON.stringify({status:'allowed'})}]}}})+'\n'+JSON.stringify({type:'turn.completed'})+'\n'));
    const result={exitCode:0,terminalEvent:summary.terminalEvent,...summary.sanitizedSnapshot()};
    if(server==='w3bench_user'){assert.equal(result.preflightAllowed,1);assert.deepEqual(result.mcpToolNames,['identity.preflight']);assertAciNativePreflight(result);}
    else{assert.equal(result.preflightAllowed,0);assert.throws(()=>assertAciNativePreflight(result),/aci_native_preflight_not_verified/);}
  }
  const failed=new AciEventSummary(()=>{});failed.feed(Buffer.from(JSON.stringify({type:'item.completed',item:{id:'failed',type:'mcp_tool_call',server:'w3bench_user',tool:'identity.preflight',status:'failed',error:{message:'MCP tool configuration has invalid approval. code=SECRET_CANARY'}}})+'\n'+JSON.stringify({type:'turn.completed'})+'\n'));
  const result={exitCode:0,terminalEvent:failed.terminalEvent,...failed.sanitizedSnapshot()};assert.throws(()=>assertAciNativePreflight(result));assert.equal(result.mcpToolErrorCount,1);assert.equal(JSON.stringify(result).includes('SECRET_CANARY'),false);
  assert(classifyAciNativeDiagnostic('configuration disables MCP tool approval').includes('invalid_approval_config'));
});
test('pinned native CLI accepts inline approval config and retains exact transport and tool allowlist without OAuth or a model',{skip:process.env.OID_ACI_NATIVE_CONFIG_TEST!=='1',timeout:30000},async()=>{
  assert.equal(process.platform,'win32');
  const executable=resolve('.local/codex-runner-inspection/package/vendor/x86_64-pc-windows-msvc/bin/codex.exe');await verifyExecutableBundle(executable);
  const home=await mkdtemp(resolve(tmpdir(),'aci-config-read-unit-'));
  try{
    const environment={CODEX_HOME:home};for(const key of ['PATH','PATHEXT','SystemRoot','WINDIR','USERPROFILE','APPDATA','LOCALAPPDATA','TEMP','TMP','COMSPEC'])if(process.env[key])environment[key]=process.env[key];
    const modelArgs=nativeModelArguments(),overrides=modelArgs.flatMap((value,index)=>value==='--config'?[value,modelArgs[index+1]]:[]);
    const result=spawnSync(executable,['--no-daemon','-c','mcp_oauth_credentials_store="file"',...overrides,'-c','mcp_servers.w3bench_user.url="http://127.0.0.1:1/api/agent/mcp"','mcp','get','w3bench_user','--json'],{cwd:home,env:environment,windowsHide:true,encoding:'utf8',timeout:15000,maxBuffer:1024*1024});
    assert.equal(result.status,0,'native isolated configuration read failed (raw output omitted)');
    const config=JSON.parse(result.stdout);
    const expected=['identity.preflight','runs.accept_launch_intent','runs.current_task','runs.task_action','runs.task_action_status','runs.finish_task','support.report','support.report_receipt'];
    // mcp get intentionally omits effective approval policy; this proves native
    // configuration acceptance/allowlist, not an actual permissioned tool call.
    assert.deepEqual([...config.enabled_tools].sort(),[...expected].sort());
    assert.equal(config.transport.type,'streamable_http');assert.equal(config.transport.url,'http://127.0.0.1:1/api/agent/mcp');
  }finally{if(!home.startsWith(resolve(tmpdir())+sep)||!home.split(sep).at(-1).startsWith('aci-config-read-unit-'))throw new Error('unsafe_test_cleanup');await rm(home,{recursive:true,force:false});}
});
