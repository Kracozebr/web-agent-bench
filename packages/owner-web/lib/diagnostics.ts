export type DiagnosticCaptureState = "open" | "complete" | "partial" | "partial_quota" | "unavailable";
export type DiagnosticSourceTrust = "client_observed_unverified" | "server_observed" | "mixed";
export type DiagnosticResponsibility = "unknown" | "client_contract" | "client_runtime" | "platform_contract" | "platform_runtime" | "external_dependency" | "expected_policy_denial";

export interface DiagnosticCaseView {
  caseId: string; kind: "client_diagnostics"; ownerId: string; agentId: string; connectionId: string;
  intentId: string | null; runId: string | null; reportId: string | null;
  createdAt: string; updatedAt: string; captureState: DiagnosticCaptureState;
  eventCount: number; errorCount: number; sourceTrust: DiagnosticSourceTrust;
  countsByTool: Record<string, number>; countsByCode: Record<string, number>; countsByStage: Record<string, number>;
}

export interface DiagnosticEventView {
  eventId: string; source: string; stage: string; tool: string; outcome: string; errorCode?: string;
  startedAt: string; completedAt: string | null; durationMs: number | null;
  traceId?: string; taskId?: string; taskIndex?: number;
  clientRunStatus?: string; clientRunObservedAt?: string;
  responsibility: DiagnosticResponsibility; attributionReason: string; evidenceIds: string[];
}

export interface DiagnosticSegmentReceipt {
  caseId: string; reportId: string | null; segmentId: string | null;
  highestContiguousSequence: number; highestContiguousHash: string | null;
  completion: "open" | "complete" | "partial";
  reportCreated: boolean; diagnosticsSynced: boolean;
}

export interface DiagnosticImportBatch {
  segmentId: string; batchSequence: number; payloadHash: string;
  events: Record<string, unknown>[]; completion: "open" | "complete" | "partial";
}
export interface DiagnosticBundle {
  schemaVersion: "w3bench-diagnostic-bundle/v1"; diagnosticSessionId: string;
  intentId?: string; caseId?: string; binding?: {agentId: string; connectionId: string};
  segments: {segmentId: string; batches: DiagnosticImportBatch[]}[];
}
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const sha = /^[a-f0-9]{64}$/;
export function diagnosticReportCaseId(context: Record<string, unknown>): string | null {
  return context.kind === "client_diagnostics" && typeof context.diagnosticCaseId === "string" && uuid.test(context.diagnosticCaseId) ? context.diagnosticCaseId : null;
}
const object = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
const keys = (v: Record<string, unknown>, allowed: string[]) => Object.keys(v).every(k => allowed.includes(k));
const envelopeKeys = ["eventId","source","stage","tool","outcome","errorCode","startedAt","completedAt","durationMs","traceId","callIdHash","operationIdHash","actionId","taskId","taskIndex","httpStatus","rpcCode","fieldPaths","schemaHash","contractHash","client","clientVersion","model","reasoningEffort","clientRunStatus","clientRunObservedAt"];
const enums: Record<string,string[]> = {
  clientRunStatus:["queued","preparing","running","cancellation_requested","cancelled","expired","completed","failed","unknown","disqualified"],
  source:["client","server"],stage:["ingress","authentication","sdk_validation","handler","admission","dispatch","receipt","client_validation","client_runtime","transport"],
  tool:["identity.preflight","runs.accept_launch_intent","runs.current_task","runs.task_action","runs.task_action_status","runs.finish_task","support.report","support.report_receipt","unknown"],outcome:["success","error","unknown"],
  errorCode:['UNKNOWN_ERROR','INVALID_ARGUMENTS','INPUT_VALIDATION_ERROR','INVALID_OPERATION_ID','INVALID_AGENT_ID','INVALID_RUN_ID','INVALID_TASK_INDEX','INVALID_TASK_ACTION','INVALID_ANSWER','ACTION_NOT_FOUND','TASK_CLOSED','TASK_DEADLINE','UNAUTHORIZED','FORBIDDEN','RATE_LIMITED','IDEMPOTENCY_CONFLICT','INTERNAL_ERROR','TRANSPORT_TIMEOUT','CONNECTION_REFUSED','CONNECTION_LOST','CLIENT_RUNTIME_ERROR','CLIENT_PARSE_ERROR','UNSUPPORTED_MCP_CLIENT_PROFILE','COMBINED_PURCHASE_UNAVAILABLE','DIAGNOSTICS_PARSER_FAILURE','DIAGNOSTICS_STORAGE_FAILURE','DIAGNOSTICS_QUOTA_EXCEEDED','CONFIGURATION_ERROR','CORRELATION_UNAVAILABLE','TASK_ACTION_NOT_FOUND','INVALID_TASK_TARGET','INVALID_TASK_ANSWER','AGENT_ACCESS_REVOKED','RUN_NOT_FOUND','MODE_NOT_ALLOWED','RUN_MODE_FENCED','PLATFORM_RECOVERY_IN_PROGRESS','TASK_RECONCILIATION_REQUIRED','TASK_NOT_FOUND','TASK_NOT_ACTIVE','TASK_DEADLINE_UNAVAILABLE','TASK_EXECUTION_IDENTITY_UNAVAILABLE','INVALID_ACTION_RECEIPT','ACTION_RECEIPT_CONFLICT','TASK_CUTOFF_CONFLICT','ACCEPTED_QUEUE_GLOBAL_CAPACITY','ACCEPTED_QUEUE_OWNER_LIMIT','ACCESS_ALREADY_REVOKED','ACCESS_REVISION_CONFLICT','AGENT_ACCESS_CHANGED','AGENT_BUDGET_EXCEEDED','AGENT_NOT_FOUND','BETA_ALREADY_CLOSED','BETA_BONUS_BALANCE_REQUIRED','CASH_CEILING_EXCEEDED','CASH_PERMISSION_REQUIRED','CONNECTION_INTENT_MISMATCH','CONNECTION_UNAVAILABLE','CREDENTIAL_EXISTS','DIAGNOSTICS_CASE_CONFLICT','DIAGNOSTICS_CASE_NOT_FOUND','DIAGNOSTICS_LINK_NOT_FOUND','DIAGNOSTICS_SEGMENT_CLOSED','DIAGNOSTICS_SEQUENCE_GAP','DIAGNOSTICS_UNAUTHORIZED','DIAGNOSTICS_UNAVAILABLE','DIAGNOSTIC_AUTHORIZATION_CAPACITY','DIAGNOSTIC_AUTH_REQUIRED','DIAGNOSTIC_ORIGIN_UNAVAILABLE','EXECUTOR_NOT_READY','GLOBAL_INTENT_CAPACITY','IMAGE_PROCESSING_FAILED','INSUFFICIENT_FUNDS','INVALID_ACTIONID','INVALID_AGENTID','INVALID_AMOUNT','INVALID_BETA_CLOSURE','INVALID_CANDIDATE_LIMIT','INVALID_CLAIMID','INVALID_COORDINATOR_CANCELLATION','INVALID_CREDENTIAL_INTENT','INVALID_DECISION','INVALID_DIAGNOSTICS','INVALID_DIAGNOSTIC_AUTHORIZATION','INVALID_EXPIRY','INVALID_FIELD','INVALID_INTENTID','INVALID_LIMIT','INVALID_MODE','INVALID_OAUTH_FLOW','INVALID_OAUTH_QUERY','INVALID_OWNERID','INVALID_PERMISSIONS','INVALID_RELEASE_EXPECTATION','INVALID_REPORT','INVALID_REPORT_BODY','INVALID_REPORT_CURSOR','INVALID_REPORT_ID','INVALID_REPORT_IMAGE','INVALID_REPORT_IMAGES','INVALID_REPORT_IMAGE_CHUNK','INVALID_REPORT_IMAGE_ID','INVALID_REPORT_IMAGE_UPLOAD','INVALID_REPORT_LINK','INVALID_REPORT_STATUS','INVALID_REPORT_TITLE','INVALID_REQUEST','INVALID_REVISION','INVALID_RUNID','INVALID_SELECTEDCONNECTIONID','INVALID_TASK_SELECTION','MISDIRECTED_REQUEST','MODE_NOT_AUTHORIZED','OAUTH_CALLBACK_INVALID','OAUTH_CLIENT_NOT_REGISTERED','OAUTH_CODE_ALREADY_BOUND','OAUTH_FLOW_COMPLETED','OAUTH_FLOW_EXPIRED','OAUTH_FLOW_MISMATCH','OAUTH_PROVIDER_REDIRECT_INVALID','OAUTH_PROVIDER_REDIRECT_MISSING','OAUTH_REQUEST_NOT_SUPPORTED','OPERATION_ID_CONFLICT','ORIGIN_NOT_ALLOWED','OWNER_NOT_ADMITTED','OWNER_NOT_FOUND','PENDING_INTENT_LIMIT','PINNED_RELEASE_UNAVAILABLE','PLATFORM_RECOVERY_NOT_EXHAUSTED','POLICY_CHANGED','PREPARED_EXECUTOR_HANDOFF_FAILED','REAUTHORIZATION_REQUIRED','RELEASE_INCOMPLETE','RELEASE_INVALID','RELEASE_UNAVAILABLE','REPORT_CONTAINS_CREDENTIAL_MATERIAL','REPORT_IMAGE_CHUNK_CONFLICT','REPORT_IMAGE_CHUNK_HASH_MISMATCH','REPORT_IMAGE_CHUNK_ORDER','REPORT_IMAGE_CONFLICT','REPORT_IMAGE_INTEGRITY_FAILED','REPORT_IMAGE_LIMIT','REPORT_IMAGE_NOT_FOUND','REPORT_IMAGE_ROLLING_QUOTA','REPORT_IMAGE_STAGING_LIMIT','REPORT_IMAGE_STORAGE_LIMIT','REPORT_IMAGE_STORAGE_LOW','REPORT_IMAGE_TOO_LARGE','REPORT_IMAGE_TYPE_UNSUPPORTED','REPORT_IMAGE_UNAVAILABLE','REPORT_IMAGE_UPLOAD_CLOSED','REPORT_IMAGE_UPLOAD_FAILED','REPORT_IMAGE_UPLOAD_HASH_MISMATCH','REPORT_IMAGE_UPLOAD_INCOMPLETE','REPORT_IMAGE_UPLOAD_IN_PROGRESS','REPORT_LINK_NOT_FOUND','REPORT_NOT_FOUND','REPORT_RATE_LIMITED','REPORT_RETENTION_EXPIRED','REPORT_REVISION_CONFLICT','REPORT_STATUS_TRANSITION_INVALID','REVISION_CONFLICT','RUN_INTENT_EXPIRED','RUN_INTENT_NOT_FOUND','RUN_INTENT_TERMINAL','RUN_NOT_PREPARING','RUN_POLICY_UNCONFIGURED','RUN_STORAGE_CAPACITY_LOW','STALE_AGENT_POLICY','STALE_OWNER_POLICY','STALE_RUN_CLAIM','STALE_RUN_INTENT','SUCCESSOR_PREPARATION_POLICY_UNAVAILABLE','TASK_EXECUTION_BINDING_ALREADY_EXISTS','TASK_PREPARATION_AMBIGUOUS','TASK_PREPARATION_NOT_READY','TASK_PREPARATION_SESSION_UNAVAILABLE','UNKNOWN_FIELD','UNSUPPORTED_MEDIA_TYPE','CLIENT_EXECUTION_FAILED'],
  taskId:["S1","S2","S3","S4","M1","M2","M3","M4","H1","H2","H3","U1"],client:["codex_cli","codex_desktop","claude_code","claude_desktop","hermes","unknown"],clientVersion:["0.165.0","0.166.0","unknown"],model:["gpt-6-luna","gpt-6.1-sol","gpt-6-astra","gpt-6.1-terra","unknown"],reasoningEffort:["low","medium","high","xhigh","max","ultra","unknown"],
};
const fieldPaths=["agentId","operationId","intentId","runId","taskIndex","actionId","command","command.kind","command.amount","command.recipient","command.route","answer","unknown_field"];
const byteLength = (v: unknown) => new TextEncoder().encode(JSON.stringify(v)).length;
function safeEnvelope(v: unknown): boolean {
  if (!object(v) || !keys(v,envelopeKeys) || byteLength(v)>2048) return false;
  for (const required of ["eventId","source","stage","tool","outcome","startedAt","completedAt","durationMs"]) if (v[required]===undefined) return false;
  for (const [key,value] of Object.entries(v)) {
    if (enums[key]) { if (typeof value!=="string" || !enums[key].includes(value)) return false; }
    else if (["eventId","traceId","actionId"].includes(key)) { if (typeof value!=="string" || !uuid.test(value)) return false; }
    else if (["callIdHash","operationIdHash","schemaHash","contractHash"].includes(key)) { if (typeof value!=="string" || !sha.test(value)) return false; }
    else if (["startedAt","completedAt","clientRunObservedAt"].includes(key)) { if (typeof value!=="string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) || Number.isNaN(Date.parse(value))) return false; }
    else if (key==="fieldPaths") { if (!Array.isArray(value) || value.length>8 || value.some(x=>typeof x!=="string" || !fieldPaths.includes(x))) return false; }
    else { if (!Number.isSafeInteger(value)) return false; const number=Number(value);
      if (key==="durationMs" && (number<0 || number>86400000) || key==="taskIndex" && (number<0 || number>11) || key==="httpStatus" && (number<100 || number>599) || key==="rpcCode" && (number< -2147483648 || number>2147483647)) return false;
    }
  }
  if (v.clientRunStatus!==undefined || v.clientRunObservedAt!==undefined) {
    if (v.clientRunStatus===undefined || v.clientRunObservedAt===undefined || v.source!=="client" || v.stage!=="client_runtime" || v.outcome!=="error") return false;
  }
  return v.outcome!=="error" || v.errorCode!==undefined;
}
/** AICODE-NOTE: Reject raw client logs and unknown fields before upload. Server remains authoritative for envelope semantics and original payload hashes. */
export function parseDiagnosticBundle(text: string): DiagnosticBundle {
  const invalid = () => { throw new Error("Select a bounded diagnostic helper export, not a raw client log."); };
  if (new TextEncoder().encode(text).length > 8 * 1024 * 1024) return invalid();
  let v: unknown;
  try { v = JSON.parse(text); } catch { return invalid(); }
  if (!object(v) || !keys(v,["schemaVersion","diagnosticSessionId","intentId","caseId","binding","segments"]) ||
      v.schemaVersion !== "w3bench-diagnostic-bundle/v1" || typeof v.diagnosticSessionId !== "string" || !uuid.test(v.diagnosticSessionId) ||
      !Array.isArray(v.segments) || !v.segments.length) return invalid();
  for (const field of ["intentId","caseId"]) if (v[field] !== undefined && (typeof v[field] !== "string" || !uuid.test(v[field] as string))) return invalid();
  if (v.binding !== undefined && (!object(v.binding) || !keys(v.binding,["agentId","connectionId"]) ||
      typeof v.binding.agentId !== "string" || !uuid.test(v.binding.agentId) || typeof v.binding.connectionId !== "string" || !uuid.test(v.binding.connectionId))) return invalid();
  if (!v.caseId && !v.binding) throw new Error("Export must include its saved case reference or owned agent/connection binding.");
  const seen = new Set<string>(); let count = 0;
  for (const segment of v.segments) {
    if (!object(segment) || !keys(segment,["segmentId","batches"]) || typeof segment.segmentId !== "string" || !uuid.test(segment.segmentId) || !Array.isArray(segment.batches)) return invalid();
    for (const batch of segment.batches) {
      if (!object(batch) || !keys(batch,["segmentId","batchSequence","payloadHash","events","completion"]) || batch.segmentId !== segment.segmentId ||
          !Number.isSafeInteger(batch.batchSequence) || Number(batch.batchSequence) < 0 || Number(batch.batchSequence) > 4095 ||
          typeof batch.payloadHash !== "string" || !sha.test(batch.payloadHash) || !Array.isArray(batch.events) || batch.events.length > 128 ||
          !["open","complete","partial"].includes(String(batch.completion))) return invalid();
      const key = `${batch.segmentId}:${batch.batchSequence}`;
      if (seen.has(key)) return invalid(); seen.add(key);
      for (const event of batch.events) if (!safeEnvelope(event)) return invalid();
      const body = {diagnosticSessionId:v.diagnosticSessionId,...(v.intentId ? {intentId:v.intentId}:{}),...(v.caseId ? {caseId:v.caseId}:{}),...(v.binding ? {binding:v.binding}:{}),batch};
      if (byteLength(body) > 64 * 1024) return invalid();
      count += batch.events.length;
    }
  }
  if (!seen.size || count > 4096) return invalid();
  return v as unknown as DiagnosticBundle;
}
export interface DiagnosticDetail {
  case: DiagnosticCaseView; events: DiagnosticEventView[]; segments: DiagnosticSegmentReceipt[];
}

const coverage: Record<DiagnosticCaptureState, string> = {
  open: "Collection is still open. Received data is not a complete error history.",
  complete: "The server marked this capture complete for its declared coverage.",
  partial: "Some diagnostic evidence is missing. Missing entries do not mean successful calls.",
  partial_quota: "A storage quota limited collection. Error counts cover only received data.",
  unavailable: "Diagnostic evidence is unavailable. Do not infer that the run had no errors.",
};
const trust: Record<DiagnosticSourceTrust, string> = {
  client_observed_unverified: "Client-observed evidence; responsibility is not independently confirmed.",
  server_observed: "Server-observed evidence. A server observation alone does not establish responsibility.",
  mixed: "Client and server observations are present. Responsibility requires their verified correlation.",
};
const responsibility: Record<DiagnosticResponsibility, string> = {
  unknown: "Unknown responsibility", client_contract: "Client contract violation", client_runtime: "Client runtime",
  platform_contract: "Platform contract mismatch", platform_runtime: "Platform runtime",
  external_dependency: "External dependency", expected_policy_denial: "Expected policy denial",
};
export function diagnosticCoverageText(value: DiagnosticCaptureState): string {
  return coverage[value] ?? coverage.unavailable;
}
export function diagnosticTrustText(value: DiagnosticSourceTrust): string {
  return trust[value] ?? trust.client_observed_unverified;
}
export function diagnosticResponsibilityText(value: DiagnosticResponsibility): string {
  return responsibility[value] ?? responsibility.unknown;
}

export function diagnosticSummary(value: Pick<DiagnosticCaseView, "captureState" | "eventCount" | "errorCount">): string {
  const countsValid = Number.isSafeInteger(value.eventCount) && value.eventCount >= 0 &&
    Number.isSafeInteger(value.errorCount) && value.errorCount >= 0 && value.errorCount <= value.eventCount;
  if (!countsValid) return "Diagnostic counts are unavailable.";
  const suffix = value.captureState === "complete" ? "in the declared capture" : "in received data; coverage is incomplete";
  return `${value.errorCount} error${value.errorCount === 1 ? "" : "s"} / ${value.eventCount} event${value.eventCount === 1 ? "" : "s"} ${suffix}.`;
}

export function isDiagnosticCallback(value: unknown): value is string {
  if (typeof value !== "string") return false;
  try {
    const u = new URL(value);
    return u.origin === "http://127.0.0.1:38766" && u.pathname === "/diagnostics/callback" &&
      !u.username && !u.password && !u.hash && [...u.searchParams.keys()].every(k => ["code", "state", "error"].includes(k)) &&
      u.searchParams.getAll("state").length === 1 && !!u.searchParams.get("state") &&
      ((u.searchParams.getAll("code").length === 1 && !!u.searchParams.get("code") && !u.searchParams.has("error")) ||
       (u.searchParams.getAll("error").length === 1 && !!u.searchParams.get("error") && !u.searchParams.has("code")));
  } catch { return false; }
}
