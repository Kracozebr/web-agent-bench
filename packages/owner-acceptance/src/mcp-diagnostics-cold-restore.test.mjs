import test from 'node:test';
import assert from 'node:assert/strict';
import {projectMcdColdRestoreFailure} from './mcp-diagnostics-cold-restore.mjs';

test('cold boundary failure retains actual phase/status and relative source location without error messages or wire data',()=>{
 const error=new Error('CANARY-PRIVATE-ERROR-MESSAGE');error.name='AssertionError';error.stack='AssertionError: CANARY-PRIVATE-ERROR-MESSAGE\n    at execute (file:///workspace/packages/owner-acceptance/src/mcp-diagnostics-cold-restore.mjs:212:14)\n    at private (C:\\operator-secret\\credential.txt:1:1)';
 const safe=projectMcdColdRestoreFailure(error,{phase:'intake_original_owner_http',httpObservations:[{phase:'intake_original_owner_http',httpStatus:404,errorCode:'DIAGNOSTICS_CASE_NOT_FOUND',message:'CANARY-RAW-HTTP'}]});
 assert.equal(safe.phase,'intake_original_owner_http');assert.deepEqual(safe.httpObservations,[{phase:'intake_original_owner_http',path:'/api/owner/diagnostics/import',httpStatus:404,errorCode:'DIAGNOSTICS_CASE_NOT_FOUND'}]);
 assert.deepEqual(safe.sourceFrames,[{path:'packages/owner-acceptance/src/mcp-diagnostics-cold-restore.mjs',line:212,column:14}]);assert(!JSON.stringify(safe).includes('CANARY'));assert(!JSON.stringify(safe).includes('operator-secret'));
});
test('SQLSTATE is retained but arbitrary names/codes/locations are excluded and observation count is bounded',()=>{
 const error=new Error('unretained');error.code='57014';error.name='CANARY-SECRET-NAME';error.stack='Error\n at /private/unregistered.txt:5:1';
 const safe=projectMcdColdRestoreFailure(error,{phase:'CANARY-UNREGISTERED-PHASE',purgeObservationRef:{path:'CANARY-PRIVATE-PATH',sha256:'a'.repeat(64),message:'CANARY-RAW'},httpObservations:Array.from({length:20},()=>({phase:'intake_fresh_owner_http',httpStatus:410,errorCode:'CANARY-UNREGISTERED-ERROR'}))});
 assert.equal(safe.sqlState,'57014');assert.equal(safe.errorName,'UnknownError');assert.equal(safe.phase,'preconditions');assert.equal(safe.httpObservations.length,12);assert.deepEqual(safe.sourceFrames,[]);assert(!JSON.stringify(safe).includes('CANARY'));
});
