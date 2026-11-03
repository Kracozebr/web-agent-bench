import assert from 'node:assert/strict';
import test from 'node:test';
import {mcdCompilerLocations} from './mcp-diagnostics-compiler-evidence.mjs';
test('MCD build diagnostics retain file/line/code and omit raw messages, excerpts and arbitrary paths',()=>{
  const canary='CANARY_PRIVATE_SOURCE_CONTENT_not_real';
  const input=`src/mcp-diagnostics-policy.ts(40,9): error TS2322: ${canary}\n/workspace/packages/owner-identity/src/handler.ts(2,1): error TS7006: ${canary}\n/tmp/private_config.txt(1,1): error TS1234: ${canary}\n`;
  const result=mcdCompilerLocations(input);
  assert.deepEqual(result,[{file:'src/mcp-diagnostics-policy.ts',line:40,column:9,code:'TS2322'},{file:'packages/owner-identity/src/handler.ts',line:2,column:1,code:'TS7006'},{file:'source_path_omitted',line:1,column:1,code:'TS1234'}]);
  assert(!JSON.stringify(result).includes(canary));assert(!JSON.stringify(result).includes('private_config'));
});
