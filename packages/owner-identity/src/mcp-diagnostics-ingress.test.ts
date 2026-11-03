import assert from 'node:assert/strict';
import test from 'node:test';
import {diagnosticResponseCode} from './mcp-diagnostics-ingress.js';

test('HTTP and SDK error projections retain only registered codes across actual error envelopes',()=>{
  assert.equal(diagnosticResponseCode({error:{code:'UNSUPPORTED_MCP_CLIENT_PROFILE',message:'synthetic_canary_private_message'}},400),'UNSUPPORTED_MCP_CLIENT_PROFILE');
  assert.equal(diagnosticResponseCode({error:{code:-32602,message:'synthetic_canary_private_message'}},200),'INPUT_VALIDATION_ERROR');
  assert.equal(diagnosticResponseCode({error:{code:-32600}},400),'INVALID_ARGUMENTS');
  assert.equal(diagnosticResponseCode({code:'FST_ERR_CTP_INVALID_JSON_BODY'},400),'INVALID_ARGUMENTS');
  assert.equal(diagnosticResponseCode({result:{isError:true,content:[{type:'text',text:JSON.stringify({error:{code:'TASK_ACTION_NOT_FOUND',message:'synthetic_canary_private_message'}})}]}},200),'TASK_ACTION_NOT_FOUND');
  assert.equal(diagnosticResponseCode({error:{code:'synthetic_canary_private_code'}},400),'UNKNOWN_ERROR');
  assert.equal(diagnosticResponseCode({result:{content:[]}},200),undefined);
});
