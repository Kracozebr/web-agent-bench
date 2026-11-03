import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {projectMcdPreflightIdentity,McdConnectionProbeCollector} from './mcd-native-connection-probe.mjs';
import {runProjectedNative} from './mcp-diagnostics-launcher.mjs';
const item=()=>({type:'mcp_tool_call',id:'actual-test-call',server:'w3bench_user',tool:'identity.preflight',status:'completed',result:{structuredContent:{status:'allowed',identity:{agentId:randomUUID(),connectionId:randomUUID()},permissions:{training:true,ranked:false,forumMessages:true,customTopics:true},policyVersion:999,private:'CANARY-PRIVATE-POLICY'}}});
test('actual preflight projects exact agent and connection references for helper consent, without policy data',()=>{
  const source=item(),safe=projectMcdPreflightIdentity(source);assert.equal(safe.agentId,source.result.structuredContent.identity.agentId);assert.equal(safe.connectionId,source.result.structuredContent.identity.connectionId);assert.deepEqual(safe.modes,['training']);assert.equal(safe.allowed,true);assert(!JSON.stringify(safe).includes('CANARY'));assert(!Object.hasOwn(safe,'permissions'));
  assert.equal(projectMcdPreflightIdentity({...source,result:{structuredContent:{...source.result.structuredContent,identity:{agentId:source.result.structuredContent.identity.agentId,connectionId:'invalid'}}}}),null);
  assert.equal(projectMcdPreflightIdentity({...source,status:'failed'}),null);assert.equal(projectMcdPreflightIdentity({...source,server:'foreign'}),null);assert.equal(projectMcdPreflightIdentity({...source,result:{structuredContent:{status:'allowed',identity:{agentId:'invalid'},permissions:{training:true,ranked:true}}}}),null);
  source.result.structuredContent.status='denied';assert.deepEqual(projectMcdPreflightIdentity(source).modes,[]);
});
test('real Node subprocess bytes prove safe projection only, NOT native model qualification or server authorization',async()=>{
  const source=item(),collector=new McdConnectionProbeCollector(),payload=JSON.stringify({type:'item.completed',item:source});
  const code='process.stdout.write('+JSON.stringify(payload+'\n')+');process.stdout.write(JSON.stringify({type:"item.completed",item:{type:"agent_message",text:"CANARY-ASSISTANT-TEXT"}})+"\\n");process.stdout.write(JSON.stringify({type:"turn.completed",usage:{input_tokens:1,output_tokens:1}})+"\\n");';
  const native=await runProjectedNative({executable:process.execPath,args:['-e',code],cwd:process.cwd(),prompt:'fixed synthetic primitive',collector,timeoutMs:5000}),safe=collector.result(native);assert.equal(safe.agentId,source.result.structuredContent.identity.agentId);assert(!JSON.stringify({safe,events:collector.safeEvents}).includes('CANARY'));
  collector.feed(Buffer.from(JSON.stringify({type:'item.completed',item:{...source,id:'another-call'}})+'\n'));assert.equal(collector.result(native),null);
});
test('contradictory repeated call identity cannot replace the first observed identity',()=>{
  const collector=new McdConnectionProbeCollector(),source=item(),feed=value=>collector.feed(Buffer.from(JSON.stringify({type:'item.completed',item:value})+'\n'));feed(source);assert(collector.result({exitCode:0,localToolCallCount:0}));
  feed({...source,result:{structuredContent:{...source.result.structuredContent,identity:{agentId:randomUUID()}}}});assert.equal(collector.result({exitCode:0,localToolCallCount:0}),null);
});
