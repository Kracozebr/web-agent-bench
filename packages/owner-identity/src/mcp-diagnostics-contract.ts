import { createHash } from 'node:crypto';
import { z } from 'zod';

export const DIAGNOSTIC_TOOLS = ['identity.preflight','runs.accept_launch_intent','runs.current_task','runs.task_action','runs.task_action_status','runs.finish_task','support.report','support.report_receipt','unknown'] as const;
export const DIAGNOSTIC_STAGES = ['ingress','authentication','sdk_validation','handler','admission','dispatch','receipt','client_validation','client_runtime','transport'] as const;
export const DIAGNOSTIC_RUN_STATUSES = ['queued','preparing','running','cancellation_requested','cancelled','expired','completed','failed','unknown','disqualified'] as const;
export const DIAGNOSTIC_ERROR_CODES = ['UNKNOWN_ERROR','INVALID_ARGUMENTS','INPUT_VALIDATION_ERROR','INVALID_OPERATION_ID','INVALID_AGENT_ID','INVALID_RUN_ID','INVALID_TASK_INDEX','INVALID_TASK_ACTION','INVALID_ANSWER','ACTION_NOT_FOUND','TASK_CLOSED','TASK_DEADLINE','UNAUTHORIZED','FORBIDDEN','RATE_LIMITED','IDEMPOTENCY_CONFLICT','INTERNAL_ERROR','TRANSPORT_TIMEOUT','CONNECTION_REFUSED','CONNECTION_LOST','CLIENT_RUNTIME_ERROR','CLIENT_PARSE_ERROR','UNSUPPORTED_MCP_CLIENT_PROFILE','COMBINED_PURCHASE_UNAVAILABLE','DIAGNOSTICS_PARSER_FAILURE','DIAGNOSTICS_STORAGE_FAILURE','DIAGNOSTICS_QUOTA_EXCEEDED','CONFIGURATION_ERROR','CORRELATION_UNAVAILABLE','TASK_ACTION_NOT_FOUND','INVALID_TASK_TARGET','INVALID_TASK_ANSWER','AGENT_ACCESS_REVOKED','RUN_NOT_FOUND','MODE_NOT_ALLOWED','RUN_MODE_FENCED','PLATFORM_RECOVERY_IN_PROGRESS','TASK_RECONCILIATION_REQUIRED','TASK_NOT_FOUND','TASK_NOT_ACTIVE','TASK_DEADLINE_UNAVAILABLE','TASK_EXECUTION_IDENTITY_UNAVAILABLE','INVALID_ACTION_RECEIPT','ACTION_RECEIPT_CONFLICT','TASK_CUTOFF_CONFLICT','ACCEPTED_QUEUE_GLOBAL_CAPACITY','ACCEPTED_QUEUE_OWNER_LIMIT','ACCESS_ALREADY_REVOKED','ACCESS_REVISION_CONFLICT','AGENT_ACCESS_CHANGED','AGENT_BUDGET_EXCEEDED','AGENT_NOT_FOUND','BETA_ALREADY_CLOSED','BETA_BONUS_BALANCE_REQUIRED','CASH_CEILING_EXCEEDED','CASH_PERMISSION_REQUIRED','CONNECTION_INTENT_MISMATCH','CONNECTION_UNAVAILABLE','CREDENTIAL_EXISTS','DIAGNOSTICS_CASE_CONFLICT','DIAGNOSTICS_CASE_NOT_FOUND','DIAGNOSTICS_LINK_NOT_FOUND','DIAGNOSTICS_SEGMENT_CLOSED','DIAGNOSTICS_SEQUENCE_GAP','DIAGNOSTICS_UNAUTHORIZED','DIAGNOSTICS_UNAVAILABLE','DIAGNOSTIC_AUTHORIZATION_CAPACITY','DIAGNOSTIC_AUTH_REQUIRED','DIAGNOSTIC_ORIGIN_UNAVAILABLE','EXECUTOR_NOT_READY','GLOBAL_INTENT_CAPACITY','IMAGE_PROCESSING_FAILED','INSUFFICIENT_FUNDS','INVALID_ACTIONID','INVALID_AGENTID','INVALID_AMOUNT','INVALID_BETA_CLOSURE','INVALID_CANDIDATE_LIMIT','INVALID_CLAIMID','INVALID_COORDINATOR_CANCELLATION','INVALID_CREDENTIAL_INTENT','INVALID_DECISION','INVALID_DIAGNOSTICS','INVALID_DIAGNOSTIC_AUTHORIZATION','INVALID_EXPIRY','INVALID_FIELD','INVALID_INTENTID','INVALID_LIMIT','INVALID_MODE','INVALID_OAUTH_FLOW','INVALID_OAUTH_QUERY','INVALID_OWNERID','INVALID_PERMISSIONS','INVALID_RELEASE_EXPECTATION','INVALID_REPORT','INVALID_REPORT_BODY','INVALID_REPORT_CURSOR','INVALID_REPORT_ID','INVALID_REPORT_IMAGE','INVALID_REPORT_IMAGES','INVALID_REPORT_IMAGE_CHUNK','INVALID_REPORT_IMAGE_ID','INVALID_REPORT_IMAGE_UPLOAD','INVALID_REPORT_LINK','INVALID_REPORT_STATUS','INVALID_REPORT_TITLE','INVALID_REQUEST','INVALID_REVISION','INVALID_RUNID','INVALID_SELECTEDCONNECTIONID','INVALID_TASK_SELECTION','MISDIRECTED_REQUEST','MODE_NOT_AUTHORIZED','OAUTH_CALLBACK_INVALID','OAUTH_CLIENT_NOT_REGISTERED','OAUTH_CODE_ALREADY_BOUND','OAUTH_FLOW_COMPLETED','OAUTH_FLOW_EXPIRED','OAUTH_FLOW_MISMATCH','OAUTH_PROVIDER_REDIRECT_INVALID','OAUTH_PROVIDER_REDIRECT_MISSING','OAUTH_REQUEST_NOT_SUPPORTED','OPERATION_ID_CONFLICT','ORIGIN_NOT_ALLOWED','OWNER_NOT_ADMITTED','OWNER_NOT_FOUND','PENDING_INTENT_LIMIT','PINNED_RELEASE_UNAVAILABLE','PLATFORM_RECOVERY_NOT_EXHAUSTED','POLICY_CHANGED','PREPARED_EXECUTOR_HANDOFF_FAILED','REAUTHORIZATION_REQUIRED','RELEASE_INCOMPLETE','RELEASE_INVALID','RELEASE_UNAVAILABLE','REPORT_CONTAINS_CREDENTIAL_MATERIAL','REPORT_IMAGE_CHUNK_CONFLICT','REPORT_IMAGE_CHUNK_HASH_MISMATCH','REPORT_IMAGE_CHUNK_ORDER','REPORT_IMAGE_CONFLICT','REPORT_IMAGE_INTEGRITY_FAILED','REPORT_IMAGE_LIMIT','REPORT_IMAGE_NOT_FOUND','REPORT_IMAGE_ROLLING_QUOTA','REPORT_IMAGE_STAGING_LIMIT','REPORT_IMAGE_STORAGE_LIMIT','REPORT_IMAGE_STORAGE_LOW','REPORT_IMAGE_TOO_LARGE','REPORT_IMAGE_TYPE_UNSUPPORTED','REPORT_IMAGE_UNAVAILABLE','REPORT_IMAGE_UPLOAD_CLOSED','REPORT_IMAGE_UPLOAD_FAILED','REPORT_IMAGE_UPLOAD_HASH_MISMATCH','REPORT_IMAGE_UPLOAD_INCOMPLETE','REPORT_IMAGE_UPLOAD_IN_PROGRESS','REPORT_LINK_NOT_FOUND','REPORT_NOT_FOUND','REPORT_RATE_LIMITED','REPORT_RETENTION_EXPIRED','REPORT_REVISION_CONFLICT','REPORT_STATUS_TRANSITION_INVALID','REVISION_CONFLICT','RUN_INTENT_EXPIRED','RUN_INTENT_NOT_FOUND','RUN_INTENT_TERMINAL','RUN_NOT_PREPARING','RUN_POLICY_UNCONFIGURED','RUN_STORAGE_CAPACITY_LOW','STALE_AGENT_POLICY','STALE_OWNER_POLICY','STALE_RUN_CLAIM','STALE_RUN_INTENT','SUCCESSOR_PREPARATION_POLICY_UNAVAILABLE','TASK_EXECUTION_BINDING_ALREADY_EXISTS','TASK_PREPARATION_AMBIGUOUS','TASK_PREPARATION_NOT_READY','TASK_PREPARATION_SESSION_UNAVAILABLE','UNKNOWN_FIELD','UNSUPPORTED_MEDIA_TYPE','CLIENT_EXECUTION_FAILED'] as const;
export const DIAGNOSTIC_FIELD_PATHS = ['agentId','operationId','intentId','runId','taskIndex','actionId','command','command.kind','command.amount','command.recipient','command.route','answer','unknown_field'] as const;
export const DIAGNOSTIC_RESPONSIBILITIES = ['client_contract','client_runtime','platform_contract','platform_runtime','external_dependency','expected_policy_denial','unknown'] as const;
export const DIAGNOSTIC_LIMITS = Object.freeze({ envelopeBytes:2048, caseRows:4096, bundleBytes:8*1024*1024, batchBytes:64*1024,
  ownerBytes:32*1024*1024, ownerRows:16384, ownerCases:128, deploymentBytes:256*1024*1024, deploymentRows:131072,deploymentCases:4096,
  anonymousBytes:4*1024*1024,anonymousRows:2048,controlBytes:8*1024*1024,aggregateBuckets:128 });

export function canonicalDiagnosticJson(value: unknown): string {
  const canonical = (v: unknown): unknown => Array.isArray(v) ? v.map(canonical) : v && typeof v==='object'
    ? Object.fromEntries(Object.entries(v).filter(([,item])=>item!==undefined).sort(([a],[b])=>a.localeCompare(b,'en')).map(([key,item])=>[key,canonical(item)])) : v;
  return JSON.stringify(canonical(value));
}
export function diagnosticHash(value: unknown): string { return createHash('sha256').update(canonicalDiagnosticJson(value)).digest('hex'); }
const hash=z.string().regex(/^[a-f0-9]{64}$/);
export const diagnosticEnvelopeSchema=z.object({
  eventId:z.string().uuid(),source:z.enum(['client','server']),stage:z.enum(DIAGNOSTIC_STAGES),tool:z.enum(DIAGNOSTIC_TOOLS),
  outcome:z.enum(['success','error','unknown']),errorCode:z.enum(DIAGNOSTIC_ERROR_CODES).optional(),
  startedAt:z.string().datetime().length(24),completedAt:z.string().datetime().length(24),durationMs:z.number().int().min(0).max(86_400_000),
  traceId:z.string().uuid().optional(),callIdHash:hash.optional(),operationIdHash:hash.optional(),actionId:z.string().uuid().optional(),
  taskId:z.enum(['S1','S2','S3','S4','M1','M2','M3','M4','H1','H2','H3','U1']).optional(),taskIndex:z.number().int().min(0).max(11).optional(),
  httpStatus:z.number().int().min(100).max(599).optional(),rpcCode:z.number().int().min(-2147483648).max(2147483647).optional(),
  fieldPaths:z.array(z.enum(DIAGNOSTIC_FIELD_PATHS)).max(8).optional(),schemaHash:hash.optional(),contractHash:hash.optional(),
  client:z.enum(['codex_cli','codex_desktop','claude_code','claude_desktop','hermes','unknown']).optional(),
  clientVersion:z.enum(['0.165.0','0.166.0','unknown']).optional(),
  model:z.enum(['gpt-6-luna','gpt-6.1-sol','gpt-6-astra','gpt-6.1-terra','unknown']).optional(),
  reasoningEffort:z.enum(['low','medium','high','xhigh','max','ultra','unknown']).optional(),
  clientRunStatus:z.enum(DIAGNOSTIC_RUN_STATUSES).optional(),clientRunObservedAt:z.string().datetime().length(24).optional()
}).strict().superRefine((value,ctx)=>{
  if(Buffer.byteLength(canonicalDiagnosticJson(value),'utf8')>DIAGNOSTIC_LIMITS.envelopeBytes)ctx.addIssue({code:'custom',message:'Diagnostic envelope is too large'});
  if(value.outcome==='error'&&!value.errorCode)ctx.addIssue({code:'custom',message:'An error requires a registered code'});
  const hasClientRunObservation=value.clientRunStatus!==undefined||value.clientRunObservedAt!==undefined;
  if(hasClientRunObservation&&(value.clientRunStatus===undefined||value.clientRunObservedAt===undefined||value.source!=='client'||value.stage!=='client_runtime'||value.outcome!=='error'))ctx.addIssue({code:'custom',message:'A paired unverified client run observation requires a client runtime error'});
});
export type DiagnosticEnvelope=z.infer<typeof diagnosticEnvelopeSchema>;
export const diagnosticCaseInputSchema=z.object({diagnosticSessionId:z.string().uuid(),intentId:z.string().uuid().optional()}).strict();
export const diagnosticBatchInputSchema=z.object({segmentId:z.string().uuid(),batchSequence:z.number().int().min(0).max(4095),payloadHash:hash,
  events:z.array(diagnosticEnvelopeSchema).max(128),completion:z.enum(['open','complete','partial'])}).strict();
export type DiagnosticBatchInput=z.infer<typeof diagnosticBatchInputSchema>;

/** AICODE-NOTE: Only trusted verifier code supplies evidence. Imported envelopes have no evidence/attribution fields. */
export interface DiagnosticEvidence {
  independentlyVerified?:boolean; evidenceIds?:readonly string[]; conflicting?:boolean; ambiguousTransport?:boolean;
  serverValidationRejected?:boolean; compatibilityVerified?:boolean; schemaCompatible?:boolean; violationMatchesPins?:boolean;
  issuedOperationUnrepresentable?:boolean; clientExceptionReproduced?:boolean; matchingValidServerResponse?:boolean;
  serverFailure?:boolean; dependencyCauseExcluded?:boolean; dependencyFailure?:boolean; competingCausesExcluded?:boolean; policyMatched?:boolean;
}
export function classifyDiagnosticResponsibility(e:DiagnosticEvidence={}) {
  const evidenceIds=(e.evidenceIds??[]).filter(id=>/^[a-f0-9]{64}$/.test(id)||/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(id)).slice(0,8);
  if(!e.independentlyVerified||!evidenceIds.length||e.ambiguousTransport)return {responsibility:'unknown' as const,attributionReason:'insufficient_verified_evidence',evidenceIds};
  const candidates:typeof DIAGNOSTIC_RESPONSIBILITIES[number][]=[];
  if(e.serverValidationRejected&&e.compatibilityVerified&&e.schemaCompatible&&e.violationMatchesPins)candidates.push('client_contract');
  if(e.compatibilityVerified&&e.issuedOperationUnrepresentable)candidates.push('platform_contract');
  if(e.clientExceptionReproduced&&e.matchingValidServerResponse&&!e.serverFailure)candidates.push('client_runtime');
  if(e.serverFailure&&e.dependencyCauseExcluded)candidates.push('platform_runtime');
  if(e.dependencyFailure&&e.competingCausesExcluded)candidates.push('external_dependency');
  if(e.policyMatched)candidates.push('expected_policy_denial');
  if(e.conflicting||candidates.length!==1)return {responsibility:'unknown' as const,attributionReason:candidates.length>1||e.conflicting?'conflicting_verified_evidence':'insufficient_verified_evidence',evidenceIds};
  return {responsibility:candidates[0]!,attributionReason:'verified_evidence_matrix',evidenceIds};
}


