import assert from 'node:assert/strict';
import test from 'node:test';
import {validateMcdHostResult} from './mcp-diagnostics-host-capacity.mjs';

test('Windows capacity IPC result cannot cross jobs, source versions, platforms or quota kinds',()=>{
  const captureId='11111111-1111-4111-8111-111111111111',jobId='22222222-2222-4222-8222-222222222222',sourceInputs={'tools/mcp-diagnostics-client.mjs':'a'.repeat(64)},jobSha256='b'.repeat(64);
  const context={captureId,jobId,sourceInputs,jobSha256},local={capacityProbes:['localBytes','localRows','localCases'].map(limit=>({limit}))};
  const value={schemaVersion:'mcd-local-capacity-host-result/v1',captureId,jobId,jobSha256,probeId:captureId+'-host-'+jobId,host:{platform:'win32',nodeVersion:'v24.14.1'},sourceInputs:{before:sourceInputs,after:sourceInputs},local};
  assert.equal(validateMcdHostResult(value,context),local);
  for(const change of [{jobId:captureId},{jobSha256:'c'.repeat(64)},{probeId:'arbitrary-path'},{host:{platform:'linux',nodeVersion:'v24.14.1'}},{host:{platform:'win32',nodeVersion:'v22.0.0'}},{sourceInputs:{before:sourceInputs,after:{...sourceInputs,'other-source':'d'.repeat(64)}}},{local:{capacityProbes:[{limit:'localRows'}]}},{command:'arbitrary-shell'}])assert.throws(()=>validateMcdHostResult({...value,...change},context));
});
