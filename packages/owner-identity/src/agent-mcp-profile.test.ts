import assert from 'node:assert/strict';
import test from 'node:test';
import {loadConfig} from './config.js';
import {selectAgentMcpTransport} from './agent-mcp-profile.js';
const base={OID_DATABASE_URL:'postgres://test.invalid/local',OID_AUTH_SECRET:'test-only-placeholder-not-a-real-secret-value'};
const local=loadConfig({...base,OID_LOCAL_BEF_TASK_COORDINATOR_ENABLED:'true',OID_LOCAL_BEF_TASK_COORDINATOR_CONFIG:'.local/owner-identity/local.json',OID_MCP_TRANSPORT_PROFILE:'codex-local-manual-2025-06-18'});
const initialize={jsonrpc:'2.0',id:1,method:'initialize',params:{protocolVersion:'2025-06-18',clientInfo:{name:'codex-mcp-client',version:'0.165.0'}}};
test('default parser remains strict; selected local manual profile accepts only the pinned client initialization',()=>{
 assert.equal(selectAgentMcpTransport(loadConfig(base),true,initialize,{}),'strict');
 assert.equal(selectAgentMcpTransport(local,true,initialize,{}),'codex-local');
 assert.equal(selectAgentMcpTransport({...local,apiHost:'LOCALHOST',publicOrigin:'http://127.0.0.2:3000'},true,initialize,{}),'codex-local');
 assert.equal(selectAgentMcpTransport(local,true,{method:'tools/list'},{'mcp-method':'tools/list'}),'strict');
 assert.throws(()=>selectAgentMcpTransport(local,false,initialize,{}),/manual agent credential/);
 assert.throws(()=>selectAgentMcpTransport({...local,localBefTaskCoordinatorEnabled:false},true,initialize,{}),/local BEF runtime/);
 for(const params of [{...initialize.params,protocolVersion:'2026-07-28'}, {...initialize.params,clientInfo:{name:'other',version:'0.165.0'}}, {...initialize.params,clientInfo:{name:'codex-mcp-client',version:'0.164.0'}}]) {
  assert.throws(()=>selectAgentMcpTransport(local,true,{...initialize,params},{}),/Unsupported local client profile/);
 }
});
test('compatibility calls reject unknown protocol headers and non-tool method families',()=>{
 assert.equal(selectAgentMcpTransport(local,true,{jsonrpc:'2.0',id:2,method:'tools/list'},{'mcp-protocol-version':'2025-06-18'}),'codex-local');
 assert.throws(()=>selectAgentMcpTransport(local,true,{jsonrpc:'2.0',id:2,method:'tools/call'},{'mcp-protocol-version':'2026-07-28'}),/Unsupported compatibility protocol/);
 assert.throws(()=>selectAgentMcpTransport(local,true,{jsonrpc:'2.0',id:2,method:'resources/read'},{}),/Unsupported compatibility method/);
});