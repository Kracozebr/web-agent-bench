import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { canonicalDiagnosticJson,diagnosticHash,diagnosticEnvelopeSchema,diagnosticBatchInputSchema,classifyDiagnosticResponsibility,type DiagnosticEnvelope,type DiagnosticEvidence } from './mcp-diagnostics-contract.js';

function event():DiagnosticEnvelope{return {eventId:randomUUID(),source:'client',stage:'client_validation',tool:'runs.task_action',outcome:'error',errorCode:'INVALID_ARGUMENTS',startedAt:'2026-11-02T11:00:00.000Z',completedAt:'2026-11-02T11:00:00.012Z',durationMs:12,fieldPaths:['operationId']};}
test('diagnostic import accepts bounded known errors without raw payload and hashes order canonically',()=>{
 const value=event();assert.equal(diagnosticEnvelopeSchema.safeParse(value).success,true);
 assert.equal(diagnosticHash({events:[value],completion:'partial'}),diagnosticHash({completion:'partial',events:[Object.fromEntries(Object.entries(value).reverse())]}));
 assert.equal(canonicalDiagnosticJson({b:undefined,a:1}),'\u007b"a":1\u007d');
});
test('diagnostics retain exact registered participant error codes without changing attribution',()=>{
 for(const errorCode of ['TASK_ACTION_NOT_FOUND','INVALID_TASK_TARGET','INVALID_TASK_ANSWER','AGENT_ACCESS_REVOKED','RUN_NOT_FOUND','MODE_NOT_ALLOWED','RUN_MODE_FENCED','PLATFORM_RECOVERY_IN_PROGRESS','TASK_RECONCILIATION_REQUIRED','TASK_NOT_FOUND','TASK_NOT_ACTIVE','TASK_DEADLINE_UNAVAILABLE','TASK_EXECUTION_IDENTITY_UNAVAILABLE','INVALID_ACTION_RECEIPT','ACTION_RECEIPT_CONFLICT','TASK_CUTOFF_CONFLICT'] as const){
  assert.equal(diagnosticEnvelopeSchema.safeParse({...event(),errorCode}).success,true);
  assert.equal(classifyDiagnosticResponsibility().responsibility,'unknown');
 }
});
test('diagnostic fields and values reject secret/raw Ranked canaries rather than silently importing them',()=>{
 const canary='sk_CANARY_PRIVATE_RANKED_abcdefghijklmnopqrstuvwxyz';
 for(const key of ['rawMessage','arguments','result','headers','authorization','provider','answer','evidence','responsibility'])assert.equal(diagnosticEnvelopeSchema.safeParse({...event(),[key]:canary}).success,false,key);
 assert.equal(diagnosticEnvelopeSchema.safeParse({...event(),errorCode:canary}).success,false);
 assert.equal(diagnosticEnvelopeSchema.safeParse({...event(),fieldPaths:[canary]}).success,false);
 assert.equal(diagnosticEnvelopeSchema.safeParse({...event(),model:canary}).success,false);
 assert.equal(diagnosticEnvelopeSchema.safeParse({...event(),clientVersion:canary}).success,false);
 assert.equal(diagnosticEnvelopeSchema.safeParse({...event(),eventId:canary}).success,false);
});
test('diagnostic metadata does not permit unbounded numeric timestamps or raw operation IDs',()=>{
 assert.equal(diagnosticEnvelopeSchema.safeParse({...event(),startedAt:'2026-11-02T11:00:00.'+'1'.repeat(3000)+'Z'}).success,false);
 assert.equal(diagnosticEnvelopeSchema.safeParse({...event(),operationId:'some_private_key_material'}).success,false);
 assert.equal(diagnosticEnvelopeSchema.safeParse({...event(),operationIdHash:'a'.repeat(64)}).success,true);
 assert.equal(diagnosticEnvelopeSchema.safeParse({...event(),outcome:'error',errorCode:undefined}).success,false);
});
test('client batches reject arbitrary envelope attribution and hidden data before persistence',()=>{
 const base={segmentId:randomUUID(),batchSequence:0,payloadHash:'a'.repeat(64),events:[event()],completion:'partial'};
 assert.equal(diagnosticBatchInputSchema.safeParse(base).success,true);
 assert.equal(diagnosticBatchInputSchema.safeParse({...base,events:[{...event(),responsibility:'platform_runtime'}]}).success,false);
 assert.equal(diagnosticBatchInputSchema.safeParse({...base,rawTranscript:'CANARY'}).success,false);
});
test('last observed client run state is a paired unverified runtime-error annotation only',()=>{
 const value={...event(),stage:'client_runtime',errorCode:'CLIENT_RUNTIME_ERROR',clientRunStatus:'running',clientRunObservedAt:'2026-11-02T10:59:00.000Z'};
 assert.equal(diagnosticEnvelopeSchema.safeParse(value).success,true);
 for(const invalid of [{...value,clientRunStatus:undefined},{...value,clientRunObservedAt:undefined},{...value,source:'server'},{...value,stage:'handler'},{...value,outcome:'success'},{...value,clientRunStatus:'probably_finished'},{...value,clientRunObservedAt:'not-a-time'},{...value,clientRunId:randomUUID()}])assert.equal(diagnosticEnvelopeSchema.safeParse(invalid).success,false);
 assert.equal(classifyDiagnosticResponsibility().responsibility,'unknown');
});
const proof={independentlyVerified:true,evidenceIds:['a'.repeat(64)]};
const positives:readonly [string,DiagnosticEvidence][]=[
 ['client_contract',{serverValidationRejected:true,compatibilityVerified:true,schemaCompatible:true,violationMatchesPins:true}],
 ['platform_contract',{compatibilityVerified:true,issuedOperationUnrepresentable:true}],
 ['client_runtime',{clientExceptionReproduced:true,matchingValidServerResponse:true}],
 ['platform_runtime',{serverFailure:true,dependencyCauseExcluded:true}],
 ['external_dependency',{dependencyFailure:true,competingCausesExcluded:true}],
 ['expected_policy_denial',{policyMatched:true}]
];
for(const [category,facts]of positives)test(`diagnostic attribution requires exact positive evidence for ${category}`,()=>{
 const result=classifyDiagnosticResponsibility({...proof,...facts});assert.equal(result.responsibility,category);assert.equal(result.attributionReason,'verified_evidence_matrix');assert.deepEqual(result.evidenceIds,proof.evidenceIds);
 assert.equal(classifyDiagnosticResponsibility({...facts}).responsibility,'unknown','unverified client claims cannot establish responsibility');
 assert.equal(classifyDiagnosticResponsibility({...proof,...facts,independentlyVerified:false}).responsibility,'unknown');
});
test('diagnostic attribution preserves ambiguity and rejects conflicting sufficient evidence',()=>{
 assert.equal(classifyDiagnosticResponsibility({...proof,...positives[0]![1],ambiguousTransport:true}).responsibility,'unknown');
 const conflict=classifyDiagnosticResponsibility({...proof,...positives[0]![1],...positives[3]![1]});assert.equal(conflict.responsibility,'unknown');assert.equal(conflict.attributionReason,'conflicting_verified_evidence');
 assert.equal(classifyDiagnosticResponsibility({...proof,serverFailure:true}).responsibility,'unknown','an unspecified HTTP/server error is not proof of its cause');
 assert.equal(classifyDiagnosticResponsibility({...proof,dependencyFailure:true}).responsibility,'unknown');
 assert.equal(classifyDiagnosticResponsibility({...proof,serverValidationRejected:true}).responsibility,'unknown','schema compatibility must be established');
});
