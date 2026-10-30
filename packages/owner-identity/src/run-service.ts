import { captureRankedVersionSnapshot } from './task-ranked-handoff.js';
import { createHash, randomUUID } from "node:crypto";
import { sql } from "drizzle-orm";
import type { OwnerDatabase } from "./db.js";
import { HttpError } from "./http-error.js";
import { lockBetaRunStartControl } from "./beta-operations-control.js";
import { readBetaStorageObservation } from "./beta-operations-observability.js";
import type {
  TaskReleaseProvider,
  RunAdmissionRelease as SealedAdmissionRelease,
  ValidatedTaskRelease,
  TaskExecutionReadinessProvider
} from "./task-release.js";
import { CURRENT_TRAINING_TASK_IDS, CURRENT_TRAINING_TASK_WEIGHTS, CURRENT_TRAINING_WEIGHT_SUM, type PublicTaskMetadata } from "./task-catalog.js";
import { insertTaskExecutionBindingInTransaction } from "./task-execution-binding.js";
import type { PreparedTaskStartPort, TaskPreparationRecord, TaskPreparationTarget } from "./task-preparation.js";

export type RunMode = "training" | "ranked";
export type RunIntentStatus = "pending" | "accepted" | "cancelled" | "expired";
export type RunStatus = "queued" | "preparing" | "running" | "cancellation_requested" | "cancelled" |
  "expired" | "completed" | "failed" | "unknown" | "disqualified";

export type RunAdmissionRelease = SealedAdmissionRelease;
export type RunReleaseProvider = TaskReleaseProvider;

export const SUCCESSOR_PREPARATION_POLICY_VERSION = "local-bef-successor-preparation/v1" as const;

export interface SuccessorPreparationPolicySnapshot {
  version: typeof SUCCESSOR_PREPARATION_POLICY_VERSION;
  timeoutSeconds: number;
}

/** Validate a stored snapshot without consulting the mutable server configuration. */
export function readSuccessorPreparationPolicySnapshot(version: unknown, timeoutSeconds: unknown): SuccessorPreparationPolicySnapshot | null {
  if (version !== SUCCESSOR_PREPARATION_POLICY_VERSION || !Number.isSafeInteger(timeoutSeconds) ||
      (timeoutSeconds as number) < 1 || (timeoutSeconds as number) > 3600) return null;
  return { version: SUCCESSOR_PREPARATION_POLICY_VERSION, timeoutSeconds: timeoutSeconds as number };
}

export type RunExecutionReadinessProvider = TaskExecutionReadinessProvider;

export interface RunReadiness {
  ready: boolean;
  executorId?: string;
  environmentId?: string;
  evidenceHash?: string;
  reason?: string;
}

export interface RunCatalogView {
  benchmarkVersion: string;
  manifestHash: string;
  benchmarkHash: string;
  policyHash: string;
  releaseIdentity: string;
  taskIds: string[];
  openTaskIds: string[];
  openTaskWeights: number[];
  openWeightSum: number;
  completeRankedRelease: boolean;
  precision: 6;
  rankedPrice: string;
  trainingPrice: string;
}

export interface RunCatalogResponse {
  status: "active" | "active_release_unavailable";
  activeRelease: RunCatalogView | null;
  taskCatalog: readonly PublicTaskMetadata[];
  readyToStart: boolean;
  readinessReason: string;
  intentCreationReady: boolean;
  intentCreationReason: string;
}

export interface RunServiceDependencies {
  db: OwnerDatabase;
  /** Configured persistent evidence/report volume; omitted in the non-beta reference adapter. */
  privateDataDir?: string;
  /** Enables durable beta pause/start barriers; absent means the non-beta reference behavior. */
  betaOperationsEnabled?: boolean;
  /** Beta cohort runs may debit only internal bonus sources, never inherited cash balances. */
  bonusOnly?: boolean;
  admissionReleaseProvider?: RunReleaseProvider | null;
  executionReadinessProvider?: RunExecutionReadinessProvider | null;
  /** Strict internal path for a specific durable first-task preparation. */
  preparedTaskStart?: PreparedTaskStartPort | null;
  intentTtlSeconds?: number;
  maxIntentTtlSeconds?: number;
  queueWaitSeconds?: number;
  maxQueueWaitSeconds?: number;
  executionCapacity?: number;
  maxPendingIntentsPerOwner?: number;
  maxPendingIntentsGlobal?: number;
  maxAcceptedRunsPerOwner?: number;
  maxAcceptedRunsGlobal?: number;
  trainingOverallTimeoutSeconds?: number;
  maxTrainingOverallTimeoutSeconds?: number;
  successorPreparationPolicyVersion?: string;
  successorPreparationTimeoutSeconds?: number;
}

export interface RunIntentView {
  id: string;
  agentId: string;
  mode: RunMode;
  taskIds: string[];
  benchmarkVersion: string;
  manifestHash: string;
  benchmarkHash: string;
  policyHash: string;
  successorPreparationPolicyVersion: string | null;
  successorPreparationTimeoutSeconds: number | null;
  quote: { price: string; precision: 6; token: "USDC" };
  cashCeiling: string;
  status: RunIntentStatus;
  createdAt: string;
  expiresAt: string;
  acceptedAt: string | null;
  runId: string | null;
  runStatus: RunStatus | null;
  queueDeadline: string | null;
  queueExpiryFencePending: boolean;
  terminalReason: string | null;
}

export interface RunView {
  id: string;
  intentId: string;
  agentId: string;
  mode: RunMode;
  taskIds: string[];
  benchmarkVersion: string;
  manifestHash: string;
  benchmarkHash: string;
  policyHash: string;
  successorPreparationPolicyVersion: string | null;
  successorPreparationTimeoutSeconds: number | null;
  quotePrice: string;
  cashCeiling: string;
  status: RunStatus;
  queuedAt: string;
  queueDeadline: string;
  startedAt: string | null;
  overallDeadline: string | null;
  finishedAt: string | null;
  terminalReason: string | null;
  cancellationReason: string | null;
  cancellationRequestedAt: string | null;
  cancellationEvidenceHash: string | null;
  queueExpiryFencePending: boolean;
}

export interface CreateLaunchIntentInput {
  ownerId: string;
  agentId: string;
  mode: RunMode;
  taskIds: string[];
  cashCeiling: string;
  expectedReleaseIdentity: string;
  expectedManifestHash: string;
  expectedQuotePrice: string;
  operationId: string;
}

export interface AcceptLaunchIntentInput {
  intentId: string;
  ownerId: string;
  agentId: string;
  accessGeneration: number;
  operationId: string;
  /** HTTP/MCP callers bind their resolved credential; internal fixture ports may omit it. */
  verifiedGrant?: { id: string; resource: string };
}

export interface AcceptedRunResult {
  run: RunView;
  replayed: boolean;
}

export interface CancellationExecutor {
  fenceAndStop(input: {
    runId: string; agentId: string; reason: string;
    /** Missing taskIndex is accepted only for historical task-0 cancellation outboxes. */
    taskPreparation?: { taskIndex?: number; preparationId: string; generationId: string | null };
  }): Promise<{
    fenced: true;
    evidenceHash: string;
    taskPreparation?: { taskIndex: number; preparationId: string; generationId: string | null };
  } | { fenced: false }>;
}

type RunTransaction = Parameters<Parameters<OwnerDatabase["transaction"]>[0]>[0];

interface DbIntentRow {
  id: string; owner_id: string; agent_id: string; operation_id: string; payload_hash: string; mode: RunMode;
  task_ids: string[]; release_identity: string; benchmark_version: string; manifest_hash: string; benchmark_hash: string; policy_hash: string;
  successor_preparation_policy_version: string | null; successor_preparation_timeout_seconds: number | null;
  quote_price_units: bigint | string; precision: number; cash_ceiling_units: bigint | string;
  owner_policy_revision: number; agent_policy_revision: number; status: RunIntentStatus; created_at: Date | string;
  expires_at: Date | string; accepted_at: Date | string | null; terminal_reason: string | null; run_id: string | null;
  run_status?: RunStatus | null; queue_deadline?: Date | string | null; expired_by_clock?: boolean;
  run_started_at?: Date | string | null; run_cancellation_reason?: string | null;
}

interface DbRunRow {
  id: string; intent_id: string; owner_id: string; agent_id: string; mode: RunMode; task_ids: string[];
  release_identity: string; benchmark_version: string; manifest_hash: string; benchmark_hash: string; policy_hash: string;
  successor_preparation_policy_version: string | null; successor_preparation_timeout_seconds: number | null;
  quote_price_units: bigint | string; cash_ceiling_units: bigint | string; access_generation: number; agent_policy_revision: number; status: RunStatus; queued_at: Date | string;
  queue_deadline: Date | string; started_at: Date | string | null; overall_deadline: Date | string | null; finished_at: Date | string | null;
  terminal_reason: string | null; cancellation_reason: string | null; cancellation_requested_at: Date | string | null;
  environment_evidence_hash: string | null; cancellation_evidence_hash: string | null;
}

const unitScale = 1_000_000n;
const maxInt64 = 9_223_372_036_854_775_807n;
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const operationIdPattern = /^[A-Za-z0-9_-]{12,128}$/;
const amountPattern = /^(0|[1-9][0-9]*)(?:\.([0-9]{1,6}))?$/;
const rankedTaskIds = ["S1", "S2", "S3", "S4", "M1", "M2", "M3", "M4", "H1", "H2", "H3", "U1"];
const openTrainingTaskIds: readonly string[] = CURRENT_TRAINING_TASK_IDS;

function configuredSuccessorPreparationPolicy(deps: RunServiceDependencies, required: boolean): SuccessorPreparationPolicySnapshot | null {
  const version = deps.successorPreparationPolicyVersion ?? null;
  const timeoutSeconds = deps.successorPreparationTimeoutSeconds ?? null;
  if (version === null && timeoutSeconds === null) {
    if (required) throw new HttpError(503, "RUN_POLICY_UNCONFIGURED", "A versioned successor-preparation timeout is required for multi-task runs");
    return null;
  }
  const snapshot = readSuccessorPreparationPolicySnapshot(version, timeoutSeconds);
  if (!snapshot) throw new HttpError(503, "RUN_POLICY_UNCONFIGURED", "The configured successor-preparation policy is unsupported or invalid");
  return snapshot;
}

function requireStoredSuccessorPreparationPolicy(taskIds: readonly string[], version: unknown, timeoutSeconds: unknown): void {
  if (taskIds.length > 1 && !readSuccessorPreparationPolicySnapshot(version, timeoutSeconds)) {
    throw new HttpError(409, "SUCCESSOR_PREPARATION_POLICY_UNAVAILABLE",
      "The multi-task run has no supported immutable successor-preparation policy snapshot");
  }
}

function record(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function storedJsonRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== "string") return record(value);
  try { return record(JSON.parse(value) as unknown); } catch { return {}; }
}

function validStoredPreparationFenceEvidence(value: unknown, row: {
  preparation_id: string; lease_id: string; environment_id: string; generation_id: string | null;
}): boolean {
  const fence = storedJsonRecord(value);
  const evidence = record(fence.evidence);
  const generation = fence.generationId;
  const generationMatches = row.generation_id === null
    ? generation === null
    : typeof generation === "string" && generation.toLowerCase() === row.generation_id.toLowerCase();
  return fence.confirmed === true && typeof fence.preparationId === "string" &&
    fence.preparationId.toLowerCase() === row.preparation_id.toLowerCase() &&
    typeof fence.leaseId === "string" && fence.leaseId.toLowerCase() === row.lease_id.toLowerCase() &&
    fence.environmentId === row.environment_id && generationMatches &&
    typeof evidence.path === "string" && evidence.path.trim() === evidence.path &&
    /^(?![A-Za-z]:)(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/-]{1,512}$/.test(evidence.path) &&
    typeof evidence.sha256 === "string" && /^[0-9a-f]{64}$/i.test(evidence.sha256) &&
    evidence.boundary === "actual_tool_http_x402_local_evm_application_store";
}

function parseUuid(value: unknown, field: string): string {
  if (typeof value !== "string" || !uuidPattern.test(value)) throw new HttpError(400, `INVALID_${field.toUpperCase()}`, `${field} must be a UUID`);
  return value;
}

function parseOperationId(value: unknown): string {
  if (typeof value !== "string" || !operationIdPattern.test(value)) {
    throw new HttpError(400, "INVALID_OPERATION_ID", "operationId must be a 12-128 character idempotency key");
  }
  return value;
}

function parseAmount(value: unknown, field: string, allowZero = true): bigint {
  if (typeof value !== "string") throw new HttpError(400, "INVALID_AMOUNT", `${field} must be a decimal string with up to 6 places`);
  const match = amountPattern.exec(value);
  if (!match) throw new HttpError(400, "INVALID_AMOUNT", `${field} must be a decimal string with up to 6 places`);
  const units = BigInt(match[1]!) * unitScale + BigInt((match[2] ?? "").padEnd(6, "0") || "0");
  if (units > maxInt64 || (!allowZero && units <= 0n)) throw new HttpError(400, "INVALID_AMOUNT", `${field} is outside the supported range`);
  return units;
}

function parseBaseUnits(value: unknown, field: string): bigint {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]{0,18})$/.test(value)) {
    throw new HttpError(503, "RELEASE_INVALID", `${field} must be an integer base-unit string`);
  }
  const units = BigInt(value);
  if (units > maxInt64) throw new HttpError(503, "RELEASE_INVALID", `${field} exceeds the supported range`);
  return units;
}

function toBigInt(value: bigint | string | number | null | undefined): bigint {
  if (typeof value === "bigint") return value;
  if (value === null || value === undefined) return 0n;
  return BigInt(value);
}

function formatUnits(value: bigint | string | number): string {
  const units = toBigInt(value);
  const whole = units / unitScale;
  const fraction = (units % unitScale).toString().padStart(6, "0");
  return `${whole}.${fraction}`;
}

function hashPayload(value: unknown): string {
  const canonical = (item: unknown): unknown => {
    if (Array.isArray(item)) return item.map(canonical);
    if (typeof item !== "object" || item === null) return item;
    return Object.fromEntries(Object.entries(item as Record<string, unknown>).sort(([left], [right]) => left.localeCompare(right))
      .map(([key, child]) => [key, canonical(child)]));
  };
  return createHash("sha256").update(JSON.stringify(canonical(value))).digest("hex");
}

function iso(value: Date | string | null | undefined): string | null {
  if (value === null || value === undefined) return null;
  const date = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(date.getTime())) throw new Error("Persisted run timestamp is invalid");
  return date.toISOString();
}

function rows<T>(result: unknown): T[] {
  if (!Array.isArray(result)) throw new Error("The PostgreSQL driver returned an unexpected result shape");
  return result as T[];
}

async function query<T>(tx: RunTransaction, statement: ReturnType<typeof sql>): Promise<T[]> {
  return rows<T>(await tx.execute(statement));
}

async function databaseNow(tx: RunTransaction): Promise<Date> {
  const result = await query<{ now: Date | string }>(tx, sql`SELECT clock_timestamp() AS now`);
  const value = result[0]?.now;
  const date = value instanceof Date ? value : new Date(String(value));
  if (!Number.isFinite(date.getTime())) throw new Error("PostgreSQL clock did not return a valid timestamp");
  return date;
}

async function lockOwner(tx: RunTransaction, ownerId: string): Promise<void> {
  const result = await query<{ id: string }>(tx, sql`SELECT id FROM oid_owner WHERE id=${ownerId} FOR NO KEY UPDATE`);
  if (!result.length) throw new HttpError(404, "OWNER_NOT_FOUND", "The owner does not exist");
}

async function lockOperation(tx: RunTransaction, ownerId: string, operationId: string): Promise<void> {
  const key = `${ownerId}\n${operationId}`;
  await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtextextended(${key}, 0))`);
}

async function existingOperation(
  tx: RunTransaction,
  ownerId: string,
  operationId: string,
  action: string,
  payloadHash: string,
  actorKind?: "owner" | "agent",
  actorAgentId?: string
): Promise<Record<string, unknown> | null> {
  const found = await query<{ action: string; payload_hash: string; response_json: unknown; actor_kind: string; actor_agent_id: string | null }>(tx, sql`
    SELECT action,payload_hash,response_json,actor_kind,actor_agent_id FROM oid_run_operation
    WHERE owner_id=${ownerId} AND operation_id=${operationId} LIMIT 1`);
  const row = found[0];
  if (!row) return null;
  if (row.action !== action || row.payload_hash !== payloadHash || (actorKind !== undefined && row.actor_kind !== actorKind) ||
    (actorAgentId !== undefined && row.actor_agent_id !== actorAgentId) || (actorKind === "owner" && row.actor_agent_id !== null)) {
    throw new HttpError(409, "IDEMPOTENCY_CONFLICT", "operationId was already used with a different request");
  }
  return record(row.response_json);
}

async function recordOperation(
  tx: RunTransaction,
  input: { ownerId: string; actorKind: "owner" | "agent"; actorAgentId?: string; operationId: string; action: string; payloadHash: string; response: Record<string, unknown> }
): Promise<void> {
  await tx.execute(sql`INSERT INTO oid_run_operation(
    id,owner_id,actor_kind,actor_agent_id,operation_id,action,payload_hash,response_json
  ) VALUES (
    ${randomUUID()},${input.ownerId},${input.actorKind},${input.actorAgentId ?? null},${input.operationId},
    ${input.action},${input.payloadHash},${JSON.stringify(input.response)}::jsonb
  )`);
}

function configuredSeconds(value: number | undefined, max: number | undefined, name: string): number {
  if (!Number.isSafeInteger(value) || value! < 1 || !Number.isSafeInteger(max) || max! < value!) {
    throw new HttpError(503, "RUN_POLICY_UNCONFIGURED", `${name} is not pinned to an approved bounded runtime value`);
  }
  return value!;
}

function validateMode(value: unknown): RunMode {
  if (value !== "training" && value !== "ranked") throw new HttpError(400, "INVALID_MODE", "mode must be training or ranked");
  return value;
}

function normalizeSelection(release: RunAdmissionRelease, requested: unknown): string[] {
  const expectedIds = release.mode === "training" ? openTrainingTaskIds : rankedTaskIds;
  const expectedWeights = release.mode === "training" ? CURRENT_TRAINING_TASK_WEIGHTS : [1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 5];
  if (release.precision !== 6 || !Array.isArray(release.taskIds) || release.taskIds.length !== expectedIds.length ||
    release.taskIds.some((id, index) => id !== expectedIds[index]) ||
    !Array.isArray(release.weights) || release.taskIds.length !== release.weights.length || new Set(release.taskIds).size !== release.taskIds.length ||
    release.taskIds.some((taskId) => typeof taskId !== "string" || !taskId) ||
    release.weights.some((weight, index) => weight !== expectedWeights[index])) {
    throw new HttpError(503, "RELEASE_INVALID", "The active release has an invalid ordered task inventory");
  }
  if (!Array.isArray(requested) || requested.length < 1 || requested.length > 12 || requested.some((value) => typeof value !== "string")) {
    throw new HttpError(400, "INVALID_TASK_SELECTION", "taskIds must be a nonempty array of known task IDs");
  }
  const selected = requested as string[];
  if (new Set(selected).size !== selected.length) throw new HttpError(400, "INVALID_TASK_SELECTION", "taskIds must not contain duplicates");
  const allowed: readonly string[] = release.mode === "training" ? openTrainingTaskIds : rankedTaskIds;
  const releaseTaskIds: readonly string[] = release.taskIds;
  if (release.mode === "ranked" && (release.taskIds.length !== rankedTaskIds.length ||
    rankedTaskIds.some((id, index) => release.taskIds[index] !== id))) {
    throw new HttpError(503, "RELEASE_INCOMPLETE", "A complete ordered twelve-task release is required for ranked admission");
  }
  if (selected.some((id) => !allowed.includes(id) || !releaseTaskIds.includes(id))) {
    throw new HttpError(400, "INVALID_TASK_SELECTION", "The selection contains an unknown or Training-ineligible task");
  }
  if (release.mode === "ranked" && (selected.length !== rankedTaskIds.length || selected.some((id, index) => id !== rankedTaskIds[index]))) {
    throw new HttpError(400, "INVALID_TASK_SELECTION", "Ranked runs must select the complete ordered twelve-task inventory");
  }
  const chosen = new Set(selected);
  return release.taskIds.filter((id) => chosen.has(id));
}

function quoteForSelection(release: RunAdmissionRelease, taskIds: string[]): bigint {
  const fullPrice = parseBaseUnits(release.priceUnits, "release price");
  if (release.mode === "ranked") return fullPrice;
  let selectedWeight = 0n;
  let totalWeight = 0n;
  for (let index = 0; index < release.taskIds.length; index += 1) {
    const weight = release.weights[index];
    if (!Number.isSafeInteger(weight) || weight! < 1 || weight! > 100) {
      throw new HttpError(503, "RELEASE_INVALID", "The active release contains an invalid task weight");
    }
    const weightUnits = BigInt(weight!);
    totalWeight += weightUnits;
    if (taskIds.includes(release.taskIds[index]!)) selectedWeight += weightUnits;
  }
  if (totalWeight !== BigInt(CURRENT_TRAINING_WEIGHT_SUM) || selectedWeight <= 0n) {
    throw new HttpError(503, "RELEASE_INVALID", "The open training release must pin the approved Training weight denominator of 6");
  }
  const numerator = fullPrice * selectedWeight;
  return (numerator + totalWeight - 1n) / totalWeight;
}

/** One validated selection/quote contract for intent creation, acceptance and start. */
export function quoteRunSelection(release: RunAdmissionRelease, requested: unknown): { taskIds: string[]; priceUnits: bigint } {
  const taskIds = normalizeSelection(release, requested);
  return { taskIds, priceUnits: quoteForSelection(release, taskIds) };
}

function parseRelease(release: RunAdmissionRelease | null, mode: RunMode): RunAdmissionRelease {
  if (!release) throw new HttpError(503, "RELEASE_UNAVAILABLE", "There is no active validated task release");
  if (release.mode !== mode || !release.releaseIdentity || !release.benchmarkVersion || !/^[0-9a-f]{64}$/.test(release.benchmarkHash) ||
    !/^[0-9a-f]{64}$/.test(release.policyHash) || !/^[0-9a-f]{64}$/.test(release.manifestHash)) {
    throw new HttpError(503, "RELEASE_INVALID", "The active task release identity or mode is invalid");
  }
  parseBaseUnits(release.priceUnits, "release price");
  return release;
}

function runView(row: DbRunRow, cancellationEvidenceHash: string | null = null): RunView {
  return {
    id: row.id,
    intentId: row.intent_id,
    agentId: row.agent_id,
    mode: row.mode,
    taskIds: row.task_ids,
    benchmarkVersion: row.benchmark_version,
    manifestHash: row.manifest_hash,
    benchmarkHash: row.benchmark_hash,
    policyHash: row.policy_hash,
    successorPreparationPolicyVersion: row.successor_preparation_policy_version,
    successorPreparationTimeoutSeconds: row.successor_preparation_timeout_seconds,
    quotePrice: formatUnits(row.quote_price_units),
    cashCeiling: formatUnits(row.cash_ceiling_units),
    status: row.status,
    queuedAt: iso(row.queued_at)!,
    queueDeadline: iso(row.queue_deadline)!,
    startedAt: iso(row.started_at),
    overallDeadline: iso(row.overall_deadline),
    finishedAt: iso(row.finished_at),
    terminalReason: row.terminal_reason,
    cancellationReason: row.cancellation_reason,
    cancellationRequestedAt: iso(row.cancellation_requested_at),
    cancellationEvidenceHash,
    queueExpiryFencePending: row.status === "cancellation_requested" && row.started_at === null &&
      row.cancellation_reason === "queue_deadline_expired"
  };
}

async function selectRun(tx: RunTransaction, runId: string, ownerId?: string, lock = false): Promise<DbRunRow | null> {
  const rowsFound = await query<DbRunRow>(tx, sql`
    SELECT r.* FROM oid_benchmark_run r WHERE r.id=${runId}
    ${ownerId ? sql`AND r.owner_id=${ownerId}` : sql``}
    LIMIT 1 ${lock ? sql`FOR UPDATE` : sql``}`);
  return rowsFound[0] ?? null;
}

async function selectIntent(tx: RunTransaction, intentId: string, ownerId?: string, lock = false): Promise<DbIntentRow | null> {
  const rowsFound = await query<DbIntentRow>(tx, sql`
    SELECT i.*,r.status AS run_status,r.queue_deadline,r.started_at AS run_started_at,r.cancellation_reason AS run_cancellation_reason
      ,(i.status='pending' AND i.expires_at<=clock_timestamp()) AS expired_by_clock
    FROM oid_run_launch_intent i LEFT JOIN oid_benchmark_run r ON r.id=i.run_id
    WHERE i.id=${intentId} ${ownerId ? sql`AND i.owner_id=${ownerId}` : sql``}
    LIMIT 1 ${lock ? sql`FOR UPDATE OF i` : sql``}`);
  return rowsFound[0] ?? null;
}

function intentView(row: DbIntentRow): RunIntentView {
  const expired = row.status === "pending" && row.expired_by_clock === true;
  const status: RunIntentStatus = expired ? "expired" : row.status;
  return {
    id: row.id,
    agentId: row.agent_id,
    mode: row.mode,
    taskIds: row.task_ids,
    benchmarkVersion: row.benchmark_version,
    manifestHash: row.manifest_hash,
    benchmarkHash: row.benchmark_hash,
    policyHash: row.policy_hash,
    successorPreparationPolicyVersion: row.successor_preparation_policy_version,
    successorPreparationTimeoutSeconds: row.successor_preparation_timeout_seconds,
    quote: { price: formatUnits(row.quote_price_units), precision: 6, token: "USDC" },
    cashCeiling: formatUnits(row.cash_ceiling_units),
    status,
    createdAt: iso(row.created_at)!,
    expiresAt: iso(row.expires_at)!,
    acceptedAt: iso(row.accepted_at),
    runId: row.run_id,
    runStatus: row.run_status ?? null,
    queueDeadline: iso(row.queue_deadline),
    queueExpiryFencePending: row.run_status === "cancellation_requested" && row.run_started_at == null &&
      row.run_cancellation_reason === "queue_deadline_expired",
    terminalReason: expired ? "intent_expired" : row.terminal_reason
  };
}

async function appendEvent(tx: RunTransaction, runId: string, source: string, eventType: string, payload: Record<string, unknown>): Promise<void> {
  const sequenceRows = await query<{ next_sequence: number }>(tx, sql`
    SELECT COALESCE(MAX(sequence),0)+1 AS next_sequence FROM oid_run_event WHERE run_id=${runId}`);
  const payloadText = JSON.stringify(payload);
  await tx.execute(sql`INSERT INTO oid_run_event(id,run_id,sequence,source,event_type,payload_hash,payload_json)
    VALUES (${randomUUID()},${runId},${sequenceRows[0]?.next_sequence ?? 1},${source},${eventType},
      ${hashPayload(payload)},${payloadText}::jsonb)`);
}

async function readFinancialPolicy(tx: RunTransaction, ownerId: string, agentId: string) {
  const found = await query<{
    allow_cash_shortfall: boolean; operation_limit_units: bigint | string | null; utc_day_limit_units: bigint | string | null;
    category_limits: { benchmark?: string | null; forum?: string | null } | null; revision: number;
  }>(tx, sql`SELECT allow_cash_shortfall,operation_limit_units,utc_day_limit_units,category_limits,revision
    FROM oid_agent_financial_policy WHERE owner_id=${ownerId} AND agent_id=${agentId} LIMIT 1`);
  const row = found[0];
  return row ? {
    allowCashShortfall: row.allow_cash_shortfall,
    operationLimit: row.operation_limit_units === null ? null : toBigInt(row.operation_limit_units),
    utcDayLimit: row.utc_day_limit_units === null ? null : toBigInt(row.utc_day_limit_units),
    categoryLimit: row.category_limits?.benchmark == null ? null : parseAmount(row.category_limits.benchmark, "category limit"),
    revision: row.revision
  } : { allowCashShortfall: false, operationLimit: 0n, utcDayLimit: 0n, categoryLimit: 0n, revision: 0 };
}

async function readAgent(tx: RunTransaction, ownerId: string, agentId: string, lock = false) {
  const found = await query<{
    id: string; owner_id: string; access_generation: number; access_revoked_at: Date | string | null;
    admission_status: string; training: boolean; ranked: boolean; policy_revision: number;
  }>(tx, sql`SELECT a.id,a.owner_id,a.access_generation,a.access_revoked_at,o.admission_status,
      p.training,p.ranked,p.revision AS policy_revision
    FROM oid_agent a JOIN oid_owner o ON o.id=a.owner_id
    JOIN oid_agent_policy p ON p.agent_id=a.id
    WHERE a.owner_id=${ownerId} AND a.id=${agentId} LIMIT 1 ${lock ? sql`FOR NO KEY UPDATE OF a` : sql``}`);
  const row = found[0];
  if (!row) throw new HttpError(404, "AGENT_NOT_FOUND", "The agent does not exist for this owner");
  if (row.admission_status !== "admitted") throw new HttpError(403, "OWNER_NOT_ADMITTED", "Owner admission is required");
  return row;
}

async function liveRunOr404(tx: RunTransaction, runId: string, ownerId: string, lock = false): Promise<DbRunRow> {
  const row = await selectRun(tx, runId, ownerId, lock);
  if (!row) throw new HttpError(404, "RUN_NOT_FOUND", "The run does not exist for this owner");
  return row;
}

export async function getRunCatalog(deps: RunServiceDependencies): Promise<RunCatalogResponse> {
  const provider = deps.admissionReleaseProvider;
  const configReady = [
    [deps.intentTtlSeconds, deps.maxIntentTtlSeconds],
    [deps.queueWaitSeconds, deps.maxQueueWaitSeconds]
  ].every(([value, max]) => Number.isSafeInteger(value) && value! > 0 && Number.isSafeInteger(max) && max! >= value!) &&
    Number.isSafeInteger(deps.executionCapacity) && deps.executionCapacity! > 0 &&
    Number.isSafeInteger(deps.maxPendingIntentsPerOwner) && deps.maxPendingIntentsPerOwner! > 0 &&
    Number.isSafeInteger(deps.maxPendingIntentsGlobal) && deps.maxPendingIntentsGlobal! > 0 &&
    ((deps.maxAcceptedRunsPerOwner === undefined && deps.maxAcceptedRunsGlobal === undefined) ||
      (Number.isSafeInteger(deps.maxAcceptedRunsPerOwner) && deps.maxAcceptedRunsPerOwner! > 0 &&
       Number.isSafeInteger(deps.maxAcceptedRunsGlobal) && deps.maxAcceptedRunsGlobal! > 0));
  const taskCatalog = provider?.getPublicCatalog() ?? [];
  if (!provider) return {
    status: "active_release_unavailable", activeRelease: null, readyToStart: false,
    readinessReason: "release_provider_unavailable", intentCreationReady: false,
    intentCreationReason: configReady ? "active_release_unavailable" : "run_policy_unconfigured", taskCatalog
  };
  const active = await deps.db.transaction(async (tx) => Promise.all([
    provider.getActiveAdmissionRelease("ranked", tx).catch(() => null),
    provider.getActiveAdmissionRelease("training", tx).catch(() => null)
  ]));
  const ranked = active[0];
  const training = active[1];
  if (!ranked || !training) return {
    status: "active_release_unavailable", activeRelease: null, readyToStart: false,
    readinessReason: "active_release_unavailable", intentCreationReady: false,
    intentCreationReason: configReady ? "active_release_unavailable" : "run_policy_unconfigured", taskCatalog
  };
  if (ranked.releaseIdentity !== training.releaseIdentity || ranked.manifestHash !== training.manifestHash ||
    ranked.benchmarkVersion !== training.benchmarkVersion || ranked.benchmarkHash !== training.benchmarkHash || ranked.policyHash !== training.policyHash) {
    return {
      status: "active_release_unavailable", activeRelease: null, readyToStart: false,
      readinessReason: "active_release_identity_mismatch", intentCreationReady: false,
      intentCreationReason: "active_release_identity_mismatch", taskCatalog
    };
  }
  try {
    quoteRunSelection(parseRelease(ranked, "ranked"), ranked.taskIds);
    quoteRunSelection(parseRelease(training, "training"), training.taskIds);
  } catch {
    return {
      status: "active_release_unavailable", activeRelease: null, readyToStart: false,
      readinessReason: "active_release_invalid", intentCreationReady: false,
      intentCreationReason: "active_release_invalid", taskCatalog
    };
  }
  const complete = ranked.taskIds.length === 12 && ranked.taskIds.every((id, index) => id === rankedTaskIds[index]);
  const readiness: RunReadiness = deps.executionReadinessProvider
    ? await deps.executionReadinessProvider.isPreparedForRelease(ranked.releaseIdentity, ranked.manifestHash).catch(() => ({ ready: false, reason: "readiness_observation_failed" }))
    : { ready: false, reason: "executor_readiness_unavailable" };
  return {
    status: "active",
    activeRelease: {
      benchmarkVersion: ranked.benchmarkVersion,
      manifestHash: ranked.manifestHash,
      benchmarkHash: ranked.benchmarkHash,
      policyHash: ranked.policyHash,
      releaseIdentity: ranked.releaseIdentity,
      taskIds: [...ranked.taskIds],
      openTaskIds: [...training.taskIds],
      openTaskWeights: [...training.weights],
      openWeightSum: training.weights.reduce((sum, weight) => sum + weight, 0),
      completeRankedRelease: complete,
      precision: 6,
      rankedPrice: formatUnits(ranked.priceUnits),
      trainingPrice: formatUnits(training.priceUnits)
    },
    taskCatalog,
    readyToStart: complete && readiness.ready && !!readiness.environmentId && /^[0-9a-f]{64}$/.test(readiness.evidenceHash ?? ""),
    readinessReason: readiness.ready ? "ready" : readiness.reason ?? "executor_not_ready",
    intentCreationReady: configReady && complete,
    intentCreationReason: !configReady ? "run_policy_unconfigured" : complete ? "ready" : "release_incomplete"
  };
}

export async function createLaunchIntent(deps: RunServiceDependencies, input: CreateLaunchIntentInput): Promise<{ intent: RunIntentView; replayed: boolean }> {
  const ownerId = parseUuid(input.ownerId, "ownerId");
  const agentId = parseUuid(input.agentId, "agentId");
  const operationId = parseOperationId(input.operationId);
  const mode = validateMode(input.mode);
  const cashCeilingUnits = parseAmount(input.cashCeiling, "cashCeiling");
  const expectedReleaseIdentity = typeof input.expectedReleaseIdentity === "string" ? input.expectedReleaseIdentity.trim() : "";
  const expectedManifestHash = typeof input.expectedManifestHash === "string" ? input.expectedManifestHash.trim() : "";
  if (!expectedReleaseIdentity || !/^[0-9a-f]{64}$/i.test(expectedManifestHash)) {
    throw new HttpError(400, "INVALID_RELEASE_EXPECTATION", "Expected active release identity and manifest hash are required");
  }
  const expectedQuoteUnits = parseAmount(input.expectedQuotePrice, "expectedQuotePrice");
  const hash = hashPayload({ action: "intent_create", agentId, mode, taskIds: input.taskIds, cashCeiling: formatUnits(cashCeilingUnits),
    expectedReleaseIdentity, expectedManifestHash, expectedQuotePrice: formatUnits(expectedQuoteUnits) });
  const created = await deps.db.transaction(async (tx) => {
    await lockOperation(tx, ownerId, operationId);
    const replay = await existingOperation(tx, ownerId, operationId, "intent_create", hash, "owner");
    if (replay) {
      const intentId = typeof replay.intentId === "string" ? replay.intentId : "";
      const row = await selectIntent(tx, intentId, ownerId);
      if (!row) throw new Error("Stored launch intent operation refers to a missing intent");
      return { row, replayed: true };
    }
    await lockOwner(tx, ownerId);
    await tx.execute(sql`SELECT pg_advisory_xact_lock(824731202, 21)`);
    const agent = await readAgent(tx, ownerId, agentId, true);
    if (agent.access_revoked_at) throw new HttpError(403, "AGENT_ACCESS_REVOKED", "The agent must be reauthorized before creating a run intent");
    const permission = mode === "training" ? agent.training : agent.ranked;
    if (!permission) throw new HttpError(403, "MODE_NOT_AUTHORIZED", `The owner has not enabled ${mode} for this agent`);

    // AICODE-NOTE: A restored API may serve authenticated reads and idempotent retries without
    // enabling new admissions. Resolve an existing operation before requiring live admission
    // policy or release-provider wiring; fresh requests still fail closed below.
    const ttlSeconds = configuredSeconds(deps.intentTtlSeconds, deps.maxIntentTtlSeconds, "intent TTL");
    const maxOwnerPending = configuredSeconds(deps.maxPendingIntentsPerOwner, deps.maxPendingIntentsPerOwner, "per-owner pending intent cap");
    const maxGlobalPending = configuredSeconds(deps.maxPendingIntentsGlobal, deps.maxPendingIntentsGlobal, "global pending intent cap");
    configuredSeconds(deps.queueWaitSeconds, deps.maxQueueWaitSeconds, "queue wait");
    if (!Number.isSafeInteger(deps.executionCapacity) || deps.executionCapacity! < 1) {
      throw new HttpError(503, "RUN_POLICY_UNCONFIGURED", "execution capacity is not pinned to an approved bounded runtime value");
    }
    const provider = deps.admissionReleaseProvider;
    if (!provider) throw new HttpError(503, "RELEASE_UNAVAILABLE", "There is no active validated task release");
    const release = parseRelease(await provider.getActiveAdmissionRelease(mode, tx), mode);
    const { taskIds, priceUnits } = quoteRunSelection(release, input.taskIds);
    const successorPolicy = configuredSuccessorPreparationPolicy(deps, taskIds.length > 1);
    if (release.releaseIdentity !== expectedReleaseIdentity || release.manifestHash !== expectedManifestHash || priceUnits !== expectedQuoteUnits) {
      throw new HttpError(409, "STALE_RUN_INTENT", "The active release or displayed quote changed; refresh the catalog and review the request again");
    }
    const now = await databaseNow(tx);
    const pendingCounts = await query<{ owner_pending: bigint | string; global_pending: bigint | string }>(tx, sql`
      SELECT
        (SELECT COUNT(*) FROM oid_run_launch_intent WHERE owner_id=${ownerId} AND status='pending' AND expires_at>${now.toISOString()}) AS owner_pending,
        (SELECT COUNT(*) FROM oid_run_launch_intent WHERE status='pending' AND expires_at>${now.toISOString()}) AS global_pending`);
    if (toBigInt(pendingCounts[0]?.owner_pending) >= BigInt(maxOwnerPending)) {
      throw new HttpError(429, "PENDING_INTENT_LIMIT", "The owner has reached the pending launch-intent limit");
    }
    if (toBigInt(pendingCounts[0]?.global_pending) >= BigInt(maxGlobalPending)) {
      throw new HttpError(503, "GLOBAL_INTENT_CAPACITY", "The shared pending launch-intent capacity is full");
    }
    if (deps.betaOperationsEnabled) await lockBetaRunStartControl(tx);
    const intentId = randomUUID();
    const expiresAt = new Date(now.getTime() + ttlSeconds * 1000);
    await tx.execute(sql`INSERT INTO oid_run_launch_intent(
      id,owner_id,agent_id,operation_id,payload_hash,mode,task_ids,release_identity,benchmark_version,
      manifest_hash,benchmark_hash,policy_hash,successor_preparation_policy_version,successor_preparation_timeout_seconds,
      quote_price_units,precision,cash_ceiling_units,owner_policy_revision,
      agent_policy_revision,status,created_at,expires_at
    ) VALUES (
      ${intentId},${ownerId},${agentId},${operationId},${hash},${mode},
      ARRAY(SELECT jsonb_array_elements_text(${JSON.stringify(taskIds)}::jsonb)),${release.releaseIdentity},
      ${release.benchmarkVersion},${release.manifestHash},${release.benchmarkHash},${release.policyHash},
      ${successorPolicy?.version ?? null},${successorPolicy?.timeoutSeconds ?? null},${priceUnits.toString()},6,
      ${cashCeilingUnits.toString()},${(await readFinancialPolicy(tx, ownerId, agentId)).revision},${agent.policy_revision},
      'pending',${now.toISOString()},${expiresAt.toISOString()}
    )`);
    await tx.execute(sql`INSERT INTO oid_ledger_audit(id,event_type,operation_id,actor_owner_id,subject_owner_id,metadata,created_at)
      VALUES (${randomUUID()},'run_intent_created',${operationId},${ownerId},${ownerId},
        ${JSON.stringify({ intentId, agentId, mode, benchmarkVersion: release.benchmarkVersion, taskIds, quote: formatUnits(priceUnits) })}::jsonb,${now.toISOString()})`);
    await recordOperation(tx, { ownerId, actorKind: "owner", operationId, action: "intent_create", payloadHash: hash, response: { intentId } });
    const row = await selectIntent(tx, intentId, ownerId);
    if (!row) throw new Error("Inserted launch intent could not be read back");
    return { row, replayed: false };
  });
  return { intent: intentView(created.row), replayed: created.replayed };
}

export async function getLaunchIntent(db: OwnerDatabase, ownerIdValue: string, intentIdValue: string): Promise<RunIntentView> {
  const ownerId = parseUuid(ownerIdValue, "ownerId");
  const intentId = parseUuid(intentIdValue, "intentId");
  return db.transaction(async (tx) => {
    const row = await selectIntent(tx, intentId, ownerId);
    if (!row) throw new HttpError(404, "RUN_INTENT_NOT_FOUND", "The launch intent does not exist for this owner");
    return intentView(row);
  });
}

export async function listLaunchIntents(db: OwnerDatabase, ownerIdValue: string, agentIdValue?: string): Promise<RunIntentView[]> {
  const ownerId = parseUuid(ownerIdValue, "ownerId");
  const agentId = agentIdValue === undefined ? undefined : parseUuid(agentIdValue, "agentId");
  return db.transaction(async (tx) => {
    const found = await query<DbIntentRow>(tx, sql`
      SELECT i.*,r.status AS run_status,r.queue_deadline,
        (i.status='pending' AND i.expires_at<=clock_timestamp()) AS expired_by_clock
      FROM oid_run_launch_intent i LEFT JOIN oid_benchmark_run r ON r.id=i.run_id
      WHERE i.owner_id=${ownerId} ${agentId ? sql`AND i.agent_id=${agentId}` : sql``}
      ORDER BY i.created_at DESC,i.id DESC LIMIT 100`);
    return found.map(intentView);
  });
}

export async function listOwnerRuns(db: OwnerDatabase, ownerIdValue: string): Promise<RunView[]> {
  const ownerId = parseUuid(ownerIdValue, "ownerId");
  return db.transaction(async (tx) => {
    const found = await query<DbRunRow>(tx, sql`SELECT * FROM oid_benchmark_run WHERE owner_id=${ownerId} ORDER BY queued_at DESC,id DESC LIMIT 100`);
    return found.map((row) => runView(row, row.cancellation_evidence_hash));
  });
}

async function allocateAndReserveSources(
  tx: RunTransaction,
  input: { ownerId: string; agentId: string; runId: string; amountUnits: bigint; cashCeilingUnits: bigint;
    allowCashShortfall: boolean; bonusOnly: boolean; operationId: string; now: Date }
): Promise<{ bonusUnits: bigint; cashUnits: bigint }> {
  let remaining = input.amountUnits;
  let bonusUnits = 0n;
  const grants = await query<{ grant_id: string; expires_at: Date | string | null }>(tx, sql`
    SELECT g.id AS grant_id,g.expires_at FROM oid_bonus_grant g
    WHERE g.owner_id=${input.ownerId} AND (g.expires_at IS NULL OR g.expires_at>${input.now.toISOString()})
    ORDER BY g.expires_at ASC NULLS LAST,g.id ASC FOR UPDATE OF g`);
  for (const grant of grants) {
    if (remaining <= 0n) break;
    const availableRows = await query<{ available_units: bigint | string }>(tx, sql`SELECT COALESCE(SUM(available_delta_units),0)::bigint AS available_units
      FROM oid_ledger_entry WHERE owner_id=${input.ownerId} AND bonus_grant_id=${grant.grant_id}`);
    const available = toBigInt(availableRows[0]?.available_units);
    const portion = available < remaining ? available : remaining;
    if (portion <= 0n) continue;
    const reservationId = randomUUID();
    await tx.execute(sql`INSERT INTO oid_run_reservation(id,run_id,owner_id,source_kind,bonus_grant_id,cash_provenance,amount_units,state,created_at)
      VALUES (${reservationId},${input.runId},${input.ownerId},'tester_bonus',${grant.grant_id},NULL,${portion.toString()},'held',${input.now.toISOString()})`);
    await tx.execute(sql`INSERT INTO oid_ledger_entry(
      id,owner_id,actor_owner_id,bonus_grant_id,operation_id,entry_type,source_kind,amount_units,
      available_delta_units,reserved_delta_units,expired_delta_units,cash_provenance,reason,created_at
    ) VALUES (${randomUUID()},${input.ownerId},${input.ownerId},${grant.grant_id},${input.operationId},'reserve','tester_bonus',
      ${portion.toString()},${(-portion).toString()},${portion.toString()},0,NULL,'benchmark run reservation',${input.now.toISOString()})`);
    remaining -= portion;
    bonusUnits += portion;
  }

  const cashUnits = remaining;
  if (cashUnits > 0n) {
    if (input.bonusOnly) {
      throw new HttpError(409, 'BETA_BONUS_BALANCE_REQUIRED', 'The beta run requires enough bonus credit; cash cannot cover a bonus shortfall');
    }
    if (!input.allowCashShortfall) throw new HttpError(409, "CASH_PERMISSION_REQUIRED", "The owner has not authorized cash spending for this agent");
    if (cashUnits > input.cashCeilingUnits) throw new HttpError(409, "CASH_CEILING_EXCEEDED", "The required cash portion exceeds the owner-approved ceiling");
    const cashBuckets = await query<{ cash_provenance: string; available_units: bigint | string }>(tx, sql`
      SELECT cash_provenance,COALESCE(SUM(available_delta_units),0)::bigint AS available_units
      FROM oid_ledger_entry WHERE owner_id=${input.ownerId} AND source_kind='cash_usdc'
      GROUP BY cash_provenance HAVING COALESCE(SUM(available_delta_units),0)>0
      ORDER BY MIN(created_at),cash_provenance`);
    let cashRemaining = cashUnits;
    for (const bucket of cashBuckets) {
      if (cashRemaining <= 0n) break;
      const available = toBigInt(bucket.available_units);
      const portion = available < cashRemaining ? available : cashRemaining;
      if (portion <= 0n) continue;
      const reservationId = randomUUID();
      await tx.execute(sql`INSERT INTO oid_run_reservation(id,run_id,owner_id,source_kind,bonus_grant_id,cash_provenance,amount_units,state,created_at)
        VALUES (${reservationId},${input.runId},${input.ownerId},'cash_usdc',NULL,${bucket.cash_provenance},${portion.toString()},'held',${input.now.toISOString()})`);
      await tx.execute(sql`INSERT INTO oid_ledger_entry(
        id,owner_id,actor_owner_id,bonus_grant_id,operation_id,entry_type,source_kind,amount_units,
        available_delta_units,reserved_delta_units,expired_delta_units,cash_provenance,reason,created_at
      ) VALUES (${randomUUID()},${input.ownerId},${input.ownerId},NULL,${input.operationId},'reserve','cash_usdc',
        ${portion.toString()},${(-portion).toString()},${portion.toString()},0,${bucket.cash_provenance},'benchmark run reservation',${input.now.toISOString()})`);
      cashRemaining -= portion;
    }
    if (cashRemaining > 0n) throw new HttpError(409, "INSUFFICIENT_FUNDS", "Available cash and bonus sources cannot fund this quote");
  }
  if (remaining > 0n && cashUnits === 0n) throw new HttpError(409, "INSUFFICIENT_FUNDS", "Available bonus sources cannot fund this quote");
  return { bonusUnits, cashUnits };
}

async function releaseRunHolds(tx: RunTransaction, run: DbRunRow, now: Date, reason: string): Promise<void> {
  const holds = await query<{
    id: string; source_kind: "cash_usdc" | "tester_bonus"; bonus_grant_id: string | null; cash_provenance: string | null;
    amount_units: bigint | string;
  }>(tx, sql`SELECT id,source_kind,bonus_grant_id,cash_provenance,amount_units FROM oid_run_reservation
    WHERE run_id=${run.id} AND state='held' ORDER BY source_kind,bonus_grant_id,cash_provenance FOR UPDATE`);
  for (const hold of holds) {
    const amount = toBigInt(hold.amount_units);
    await tx.execute(sql`INSERT INTO oid_ledger_entry(
      id,owner_id,actor_owner_id,bonus_grant_id,operation_id,entry_type,source_kind,amount_units,
      available_delta_units,reserved_delta_units,expired_delta_units,cash_provenance,reason,created_at
    ) VALUES (${randomUUID()},${run.owner_id},${run.owner_id},${hold.bonus_grant_id},${`runrel_${run.id.replaceAll("-", "")}`},
      'release',${hold.source_kind},${amount.toString()},${amount.toString()},${(-amount).toString()},0,${hold.cash_provenance},${reason},${now.toISOString()})`);
    await tx.execute(sql`UPDATE oid_run_reservation SET state='released',changed_at=${now.toISOString()}
      WHERE id=${hold.id} AND state='held'`);
  }
  await tx.execute(sql`UPDATE oid_run_budget_hold SET state='released',changed_at=${now.toISOString()}
    WHERE run_id=${run.id} AND state='held'`);
  await tx.execute(sql`DELETE FROM oid_run_execution_slot WHERE run_id=${run.id}`);
  await tx.execute(sql`UPDATE oid_run_dispatch_claim SET status='released',released_at=${now.toISOString()}
    WHERE run_id=${run.id} AND status='claimed'`);
}

export async function acceptLaunchIntent(deps: RunServiceDependencies, input: AcceptLaunchIntentInput): Promise<AcceptedRunResult> {
  const intentId = parseUuid(input.intentId, "intentId");
  const ownerId = parseUuid(input.ownerId, "ownerId");
  const agentId = parseUuid(input.agentId, "agentId");
  const operationId = parseOperationId(input.operationId);
  if (!Number.isSafeInteger(input.accessGeneration) || input.accessGeneration < 1) throw new HttpError(401, "UNAUTHORIZED", "The verified agent access generation is invalid");

  const accepted = await deps.db.transaction(async (tx) => {
    await lockOperation(tx, ownerId, operationId);
    const payloadHash = hashPayload({ action: "intent_accept", intentId, agentId, accessGeneration: input.accessGeneration });
    await lockOwner(tx, ownerId);
    const intent = await selectIntent(tx, intentId, ownerId, true);
    if (!intent) throw new HttpError(404, "RUN_INTENT_NOT_FOUND", "The launch intent does not exist for this owner");
    if (intent.agent_id !== agentId) throw new HttpError(404, "RUN_INTENT_NOT_FOUND", "The launch intent does not exist for this agent");
    const agent = await readAgent(tx, ownerId, agentId, true);
    if (agent.access_revoked_at || agent.access_generation !== input.accessGeneration) {
      throw new HttpError(403, "AGENT_ACCESS_REVOKED", "The agent access was revoked or rotated after this request was issued");
    }
    if (input.verifiedGrant) {
      const currentGrant = await query<{ id: string }>(tx, sql`SELECT id FROM oid_agent_access_grant
        WHERE id=${input.verifiedGrant.id} AND owner_id=${ownerId} AND agent_id=${agentId}
          AND resource=${input.verifiedGrant.resource} AND role='agent' AND access_generation=${input.accessGeneration}
          AND revoked_at IS NULL AND expires_at>clock_timestamp()`);
      if (!currentGrant.length) throw new HttpError(403, "AGENT_ACCESS_REVOKED", "The resolved agent grant is no longer active");
    }
    if (!(intent.mode === "training" ? agent.training : agent.ranked)) {
      throw new HttpError(403, "MODE_NOT_AUTHORIZED", `The owner has not enabled ${intent.mode} for this agent`);
    }
    const replay = await existingOperation(tx, ownerId, operationId, "intent_accept", payloadHash, "agent", agentId);
    if (replay) {
      const runId = typeof replay.runId === "string" ? replay.runId : "";
      const row = await selectRun(tx, runId, ownerId);
      if (!row) throw new Error("Stored launch acceptance refers to a missing run");
      return { row, replayed: true };
    }
    if (intent.status === "accepted" && intent.run_id) {
      const run = await selectRun(tx, intent.run_id, ownerId);
      if (!run) throw new Error("Accepted intent has no run binding");
      await recordOperation(tx, { ownerId, actorKind: "agent", actorAgentId: agentId, operationId, action: "intent_accept", payloadHash, response: { runId: run.id } });
      return { row: run, replayed: true };
    }
    if (intent.status !== "pending") throw new HttpError(409, "RUN_INTENT_TERMINAL", "The launch intent is no longer pending");
    const now = await databaseNow(tx);
    if (new Date(iso(intent.expires_at)!).getTime() <= now.getTime()) {
      throw new HttpError(410, "RUN_INTENT_EXPIRED", "The launch intent has expired");
    }
    if (agent.policy_revision !== intent.agent_policy_revision) throw new HttpError(409, "STALE_AGENT_POLICY", "Agent permissions changed after this launch intent was created");
    const financial = await readFinancialPolicy(tx, ownerId, agentId);
    if (financial.revision !== intent.owner_policy_revision) throw new HttpError(409, "STALE_OWNER_POLICY", "Owner financial limits changed after this launch intent was created");

    // AICODE-NOTE: Existing operation and already-accepted intent reads above are safe after
    // restore. Require current admission policy/provider only for a pending intent that creates a run.
    const queueWaitSeconds = configuredSeconds(deps.queueWaitSeconds, deps.maxQueueWaitSeconds, "queue wait");
    const provider = deps.admissionReleaseProvider;
    if (!provider) throw new HttpError(503, "RELEASE_UNAVAILABLE", "There is no active validated task release");
    await tx.execute(sql`SELECT pg_advisory_xact_lock(824731202, 21)`);
    if (deps.betaOperationsEnabled) await lockBetaRunStartControl(tx);
    if (deps.maxAcceptedRunsPerOwner !== undefined || deps.maxAcceptedRunsGlobal !== undefined) {
      const maxAcceptedPerOwner = configuredSeconds(deps.maxAcceptedRunsPerOwner,
        deps.maxAcceptedRunsPerOwner, "per-owner accepted queue cap");
      const maxAcceptedGlobal = configuredSeconds(deps.maxAcceptedRunsGlobal,
        deps.maxAcceptedRunsGlobal, "global accepted queue cap");
      const acceptedCounts = await query<{ owner_accepted: bigint | string; global_accepted: bigint | string }>(tx, sql`
        SELECT
          (SELECT COUNT(*) FROM oid_benchmark_run WHERE owner_id=${ownerId} AND started_at IS NULL
            AND status IN ('queued','preparing','cancellation_requested')) AS owner_accepted,
          (SELECT COUNT(*) FROM oid_benchmark_run WHERE started_at IS NULL
            AND status IN ('queued','preparing','cancellation_requested')) AS global_accepted`);
      if (toBigInt(acceptedCounts[0]?.owner_accepted) >= BigInt(maxAcceptedPerOwner)) {
        throw new HttpError(429, "ACCEPTED_QUEUE_OWNER_LIMIT", "The owner has reached the accepted unstarted run limit");
      }
      if (toBigInt(acceptedCounts[0]?.global_accepted) >= BigInt(maxAcceptedGlobal)) {
        throw new HttpError(503, "ACCEPTED_QUEUE_GLOBAL_CAPACITY", "The shared accepted run queue is full");
      }
    }
    const release = parseRelease(await provider.getActiveAdmissionRelease(intent.mode, tx), intent.mode);
    if (release.releaseIdentity !== intent.release_identity || release.benchmarkVersion !== intent.benchmark_version ||
      release.manifestHash !== intent.manifest_hash || release.benchmarkHash !== intent.benchmark_hash || release.policyHash !== intent.policy_hash) {
      throw new HttpError(409, "STALE_RUN_INTENT", "The active task release changed after this launch intent was created");
    }
    const { taskIds, priceUnits: quoteUnits } = quoteRunSelection(release, intent.task_ids);
    requireStoredSuccessorPreparationPolicy(taskIds, intent.successor_preparation_policy_version,
      intent.successor_preparation_timeout_seconds);
    if (quoteUnits !== toBigInt(intent.quote_price_units)) throw new HttpError(409, "STALE_RUN_INTENT", "The active quote changed after this launch intent was created");
    if (financial.operationLimit !== null && quoteUnits > financial.operationLimit) throw new HttpError(409, "AGENT_BUDGET_EXCEEDED", "The quote exceeds this agent's per-operation limit");

    const today = now.toISOString().slice(0, 10);
    const usageRows = await query<{ used_units: bigint | string }>(tx, sql`SELECT COALESCE(SUM(amount_units),0)::bigint AS used_units
      FROM oid_run_budget_hold WHERE agent_id=${agentId} AND utc_day=${today} AND state IN ('held','charged')`);
    const dayUsage = toBigInt(usageRows[0]?.used_units);
    const categoryRows = await query<{ category_units: bigint | string }>(tx, sql`SELECT COALESCE(SUM(amount_units),0)::bigint AS category_units
      FROM oid_run_budget_hold WHERE agent_id=${agentId} AND utc_day=${today} AND state IN ('held','charged')`);
    const currentCategoryUsage = toBigInt(categoryRows[0]?.category_units);
    if (financial.utcDayLimit !== null && dayUsage + quoteUnits > financial.utcDayLimit) throw new HttpError(409, "AGENT_BUDGET_EXCEEDED", "The quote exceeds this agent's UTC-day limit");
    if (financial.categoryLimit !== null && currentCategoryUsage + quoteUnits > financial.categoryLimit) throw new HttpError(409, "AGENT_BUDGET_EXCEEDED", "The quote exceeds this agent's benchmark-category limit");

    const runId = randomUUID();
    const queueDeadline = new Date(now.getTime() + queueWaitSeconds * 1000);
    await tx.execute(sql`INSERT INTO oid_benchmark_run(
      id,intent_id,owner_id,agent_id,mode,task_ids,release_identity,benchmark_version,manifest_hash,benchmark_hash,policy_hash,
      successor_preparation_policy_version,successor_preparation_timeout_seconds,quote_price_units,cash_ceiling_units,
      access_generation,agent_policy_revision,status,queued_at,queue_deadline
    ) VALUES (${runId},${intent.id},${ownerId},${agentId},${intent.mode},
      ARRAY(SELECT jsonb_array_elements_text(${JSON.stringify(taskIds)}::jsonb)),${intent.release_identity},
      ${intent.benchmark_version},${intent.manifest_hash},${intent.benchmark_hash},${intent.policy_hash},
      ${intent.successor_preparation_policy_version},${intent.successor_preparation_timeout_seconds},${quoteUnits.toString()},
      ${intent.cash_ceiling_units.toString()},${agent.access_generation},${agent.policy_revision},'queued',${now.toISOString()},${queueDeadline.toISOString()})`);
    if (intent.mode === 'ranked') await captureRankedVersionSnapshot(tx, {runId,ownerId,agentId}, now.toISOString());
    const allocation = await allocateAndReserveSources(tx, {
      ownerId, agentId, runId, amountUnits: quoteUnits,
      cashCeilingUnits: toBigInt(intent.cash_ceiling_units), allowCashShortfall: financial.allowCashShortfall,
      bonusOnly: deps.bonusOnly === true,
      operationId: `runacc_${runId.replaceAll("-", "")}`, now
    });
    await tx.execute(sql`INSERT INTO oid_run_budget_hold(run_id,owner_id,agent_id,mode,utc_day,amount_units,state,created_at)
      VALUES (${runId},${ownerId},${agentId},${intent.mode},${today},${quoteUnits.toString()},'held',${now.toISOString()})`);
    for (let index = 0; index < taskIds.length; index += 1) {
      await tx.execute(sql`INSERT INTO oid_run_task(run_id,task_index,task_id,status,snapshot_json)
        VALUES (${runId},${index},${taskIds[index]},'queued',${JSON.stringify({ taskId: taskIds[index], releaseIdentity: intent.release_identity, manifestHash: release.manifestHash })}::jsonb)`);
    }
    await tx.execute(sql`UPDATE oid_run_launch_intent SET status='accepted',accepted_at=${now.toISOString()},run_id=${runId}
      WHERE id=${intent.id} AND status='pending'`);
    await appendEvent(tx, runId, "agent", "run.accepted", {
      intentId: intent.id, operationId, mode: intent.mode, taskIds, quotePrice: formatUnits(quoteUnits),
      cashReserved: formatUnits(allocation.cashUnits), bonusReserved: formatUnits(allocation.bonusUnits), queueDeadline: queueDeadline.toISOString()
    });
    await tx.execute(sql`INSERT INTO oid_run_outbox(event_id,run_id,event_type,payload_json,status,created_at)
      VALUES (${randomUUID()},${runId},'run.queued',${JSON.stringify({ runId, ownerId, agentId, queueDeadline: queueDeadline.toISOString() })}::jsonb,'pending',${now.toISOString()})`);
    const response = { runId };
    await recordOperation(tx, { ownerId, actorKind: "agent", actorAgentId: agentId, operationId, action: "intent_accept", payloadHash, response });
    await tx.execute(sql`INSERT INTO oid_ledger_audit(id,event_type,operation_id,actor_owner_id,subject_owner_id,metadata,created_at)
      VALUES (${randomUUID()},'run_intent_accepted',${operationId},${ownerId},${ownerId},
        ${JSON.stringify({ intentId: intent.id, runId, cashReserved: formatUnits(allocation.cashUnits), bonusReserved: formatUnits(allocation.bonusUnits) })}::jsonb,${now.toISOString()})`);
    const row = await selectRun(tx, runId, ownerId);
    if (!row) throw new Error("Inserted run could not be read back");
    return { row, replayed: false };
  });
  return { run: runView(accepted.row), replayed: accepted.replayed };
}

export async function cancelLaunchIntent(
  deps: RunServiceDependencies,
  input: { ownerId: string; intentId: string; operationId: string }
): Promise<{ intent: RunIntentView; replayed: boolean }> {
  const ownerId = parseUuid(input.ownerId, "ownerId");
  const intentId = parseUuid(input.intentId, "intentId");
  const operationId = parseOperationId(input.operationId);
  const hash = hashPayload({ action: "intent_cancel", intentId });
  const result = await deps.db.transaction(async (tx) => {
    await lockOperation(tx, ownerId, operationId);
    const replay = await existingOperation(tx, ownerId, operationId, "intent_cancel", hash, "owner");
    if (replay) {
      const row = await selectIntent(tx, typeof replay.intentId === "string" ? replay.intentId : intentId, ownerId);
      if (!row) throw new Error("Stored launch cancellation refers to a missing intent");
      return { row, replayed: true };
    }
    await lockOwner(tx, ownerId);
    const intent = await selectIntent(tx, intentId, ownerId, true);
    if (!intent) throw new HttpError(404, "RUN_INTENT_NOT_FOUND", "The launch intent does not exist for this owner");
    const now = await databaseNow(tx);
    if (intent.status === "pending") {
      await tx.execute(sql`UPDATE oid_run_launch_intent SET status='cancelled',terminal_reason='owner_cancelled'
        WHERE id=${intent.id} AND status='pending'`);
      await tx.execute(sql`INSERT INTO oid_ledger_audit(id,event_type,operation_id,actor_owner_id,subject_owner_id,metadata,created_at)
        VALUES (${randomUUID()},'run_intent_cancelled',${operationId},${ownerId},${ownerId},
          ${JSON.stringify({ intentId, reason: "owner_cancelled" })}::jsonb,${now.toISOString()})`);
    } else if (intent.status === "accepted" && intent.run_id) {
      await requestRunCancellationInTransaction(tx, { ownerId, runId: intent.run_id, reason: "owner_voluntary", now });
    }
    await recordOperation(tx, { ownerId, actorKind: "owner", operationId, action: "intent_cancel", payloadHash: hash, response: { intentId } });
    const row = await selectIntent(tx, intentId, ownerId);
    if (!row) throw new Error("Launch intent disappeared during cancellation");
    return { row, replayed: false };
  });
  return { intent: intentView(result.row), replayed: result.replayed };
}

async function requestRunCancellationInTransaction(
  tx: RunTransaction,
  input: { ownerId: string; runId: string; reason: string; now: Date; actor?: "owner" | "coordinator" }
): Promise<DbRunRow> {
  const run = await liveRunOr404(tx, input.runId, input.ownerId, true);
  if (["cancelled", "expired", "completed", "failed", "unknown", "disqualified"].includes(run.status)) return run;
  if (run.status === "cancellation_requested") return run;
  // AICODE-NOTE: A preparing run or running successor with an allocated task
  // environment cannot release its lease or slot until the exact preparation
  // is fenced. Pin its task index and latest observed generation under the same
  // owner/run locks used by preparation callbacks and run start; null remains
  // null across retries, and multiple active leases fail closed as ambiguous.
  const preparationRows = run.status === "preparing" || run.status === "running"
    ? await query<{ task_index: number; preparation_id: string; generation_id: string | null }>(tx, sql`SELECT i.task_index,i.preparation_id,
        (SELECT o.generation_id FROM oid_task_preparation_observation o WHERE o.preparation_id=i.preparation_id
          ORDER BY o.revision DESC LIMIT 1) AS generation_id
      FROM oid_task_preparation_intent i JOIN oid_task_environment_lease l
        ON l.preparation_id=i.preparation_id AND l.lease_id=i.lease_id
      WHERE i.run_id=${run.id} AND i.task_index BETWEEN 0 AND 11 AND l.state='leased'
      ORDER BY i.task_index LIMIT 2 FOR UPDATE OF i,l`)
    : [];
  if (preparationRows.length > 1) {
    throw new HttpError(409, "TASK_PREPARATION_AMBIGUOUS", "More than one task environment lease is active for this run; cancellation is held for exact reconciliation");
  }
  let taskPreparation = preparationRows[0]
    ? { taskIndex: preparationRows[0].task_index, preparationId: preparationRows[0].preparation_id, generationId: preparationRows[0].generation_id }
    : null;

  // Between a task's confirmed fence/terminalization and creation of the next
  // preparation, a running training run has no leased preparation to pin. Reuse
  // the most recent exact stored fence only after every existing preparation
  // row for the run proves a complete, consistent fenced identity. This path
  // never derives a target from the compatibility environment pointer and never
  // asks the adapter to issue a second fence receipt.
  if (run.status === "running" && preparationRows.length === 0) {
    type FencedPreparationRow = {
      task_index: number; task_id: string; preparation_id: string; lease_id: string; environment_id: string;
      lease_id_found: string | null; lease_environment_id: string | null; lease_state: string | null;
      fence_evidence: unknown; observation_status: string | null; generation_id: string | null;
    };
    const existingPreparations = await query<FencedPreparationRow>(tx, sql`SELECT i.task_index,i.task_id,
        i.preparation_id::text AS preparation_id,i.lease_id::text AS lease_id,i.environment_id,
        l.lease_id::text AS lease_id_found,l.environment_id AS lease_environment_id,l.state AS lease_state,
        l.fence_evidence,o.status AS observation_status,o.generation_id::text AS generation_id
      FROM oid_task_preparation_intent i
      LEFT JOIN oid_task_environment_lease l ON l.preparation_id=i.preparation_id
      LEFT JOIN LATERAL (SELECT observation.status,observation.generation_id
        FROM oid_task_preparation_observation observation
        WHERE observation.preparation_id=i.preparation_id
        ORDER BY observation.revision DESC LIMIT 1) o ON TRUE
      WHERE i.run_id=${run.id}
      ORDER BY i.task_index FOR UPDATE OF i`);
    if (existingPreparations.length === 0) {
      // Historical single-task runs without preparation records retain their
      // existing generic cancellation boundary. Multi-task runs have no exact
      // predecessor fence to reuse and remain held for reconciliation.
      if (run.task_ids.length > 1) {
        throw new HttpError(409, "TASK_PREPARATION_AMBIGUOUS", "A multi-task run has no stored preparation fence to pin for cancellation");
      }
    } else {
      const exactRows = existingPreparations.every((row) => {
        const expectedTaskId = run.task_ids[row.task_index];
        return Number.isSafeInteger(row.task_index) && row.task_index >= 0 && row.task_index < run.task_ids.length &&
          expectedTaskId === row.task_id && uuidPattern.test(row.preparation_id) && uuidPattern.test(row.lease_id) &&
          /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(row.environment_id) &&
          row.lease_id_found?.toLowerCase() === row.lease_id.toLowerCase() &&
          row.lease_environment_id === row.environment_id && row.lease_state === "fenced" &&
          row.observation_status === "fenced" &&
          validStoredPreparationFenceEvidence(row.fence_evidence, row);
      });
      if (!exactRows) {
        throw new HttpError(409, "TASK_PREPARATION_AMBIGUOUS", "Existing task preparations do not prove one complete, exact fenced history; cancellation is held for reconciliation");
      }
      const mostRecent = existingPreparations.at(-1)!;
      taskPreparation = { taskIndex: mostRecent.task_index, preparationId: mostRecent.preparation_id,
        generationId: mostRecent.generation_id };
    }
  }
  const needsPreparationFence = run.status === "preparing" && taskPreparation !== null;
  if ((run.status === "queued" || run.status === "preparing") && !needsPreparationFence) {
    const queueExpired = input.reason === "queue_deadline_expired";
    await releaseRunHolds(tx, run, input.now, input.reason);
    await tx.execute(sql`UPDATE oid_benchmark_run SET status=${queueExpired ? "expired" : "cancelled"},finished_at=${input.now.toISOString()},
      terminal_reason=${input.reason},cancellation_reason=${input.reason} WHERE id=${run.id} AND status IN ('queued','preparing')`);
    await tx.execute(sql`UPDATE oid_run_launch_intent SET terminal_reason=${input.reason} WHERE id=${run.intent_id}`);
    await appendEvent(tx, run.id, queueExpired ? "coordinator" : (input.actor ?? "owner"),
      queueExpired ? "run.queue_expired" : "run.cancelled.before_start", { reason: input.reason });
    await tx.execute(sql`INSERT INTO oid_run_outbox(event_id,run_id,event_type,payload_json,status,created_at)
      VALUES (${randomUUID()},${run.id},${queueExpired ? "run.expired" : "run.cancelled"},
        ${JSON.stringify({ runId: run.id, reason: input.reason })}::jsonb,'pending',${input.now.toISOString()})
      ON CONFLICT (run_id,event_type) DO NOTHING`);
  } else {
    await tx.execute(sql`UPDATE oid_benchmark_run SET status='cancellation_requested',cancellation_requested_at=${input.now.toISOString()},
      cancellation_reason=${input.reason} WHERE id=${run.id} AND status IN ('preparing','running','cancellation_requested')`);
    const queueExpired = input.reason === "queue_deadline_expired";
    await appendEvent(tx, run.id, queueExpired ? "coordinator" : (input.actor ?? "owner"),
      queueExpired ? "run.queue_expiry_fence_requested" : "run.cancellation_requested", {
      reason: input.reason, ...(needsPreparationFence && taskPreparation ? {
        taskIndex: taskPreparation.taskIndex, preparationId: taskPreparation.preparationId, generationId: taskPreparation.generationId
      } : {})
    });
    await tx.execute(sql`INSERT INTO oid_run_outbox(event_id,run_id,event_type,payload_json,status,created_at)
      VALUES (${randomUUID()},${run.id},'run.cancel.requested',${JSON.stringify({
        runId: run.id, agentId: run.agent_id, reason: input.reason,
        ...(taskPreparation ? { taskPreparation } : {})
      })}::jsonb,'pending',${input.now.toISOString()})
      ON CONFLICT (run_id,event_type) DO NOTHING`);
  }
  const updated = await liveRunOr404(tx, run.id, input.ownerId);
  return updated;
}

export async function requestRunCancellation(
  depsOrDb: RunServiceDependencies | OwnerDatabase,
  input: { ownerId: string; runId: string; operationId: string; reason?: "owner_voluntary" }
): Promise<AcceptedRunResult> {
  const db = "db" in depsOrDb ? depsOrDb.db : depsOrDb;
  const ownerId = parseUuid(input.ownerId, "ownerId");
  const runId = parseUuid(input.runId, "runId");
  const operationId = parseOperationId(input.operationId);
  const reason = input.reason ?? "owner_voluntary";
  const hash = hashPayload({ action: "run_cancel", runId, reason });
  const result = await db.transaction(async (tx) => {
    await lockOperation(tx, ownerId, operationId);
    const replay = await existingOperation(tx, ownerId, operationId, "run_cancel", hash, "owner");
    if (replay) {
      const run = await selectRun(tx, typeof replay.runId === "string" ? replay.runId : runId, ownerId);
      if (!run) throw new Error("Stored run cancellation refers to a missing run");
      return { run, replayed: true };
    }
    await lockOwner(tx, ownerId);
    const now = await databaseNow(tx);
    const run = await requestRunCancellationInTransaction(tx, { ownerId, runId, reason, now });
    await recordOperation(tx, { ownerId, actorKind: "owner", operationId, action: "run_cancel", payloadHash: hash, response: { runId } });
    return { run, replayed: false };
  });
  return { run: runView(result.run), replayed: result.replayed };
}

/** Internal cancellation causes used by the guarded local/Beta coordinator. */
export type LocalCoordinatorCancellationReason =
  | "coordinator_preparation_failed"
  | "coordinator_interrupted_preparation"
  | "coordinator_executor_session_lost"
  | "coordinator_run_deadline"
  | "coordinator_platform_failure";

/**
 * Request cancellation from the local coordinator without impersonating an
 * owner action. This uses the same owner-before-run transaction helper and
 * pins any exact preparation generation in the durable cancellation outbox.
 * It is not registered as an HTTP or MCP operation.
 */
export async function requestRunCancellationFromCoordinator(
  db: OwnerDatabase,
  input: { runId: string; reason: LocalCoordinatorCancellationReason },
): Promise<RunStatus | null> {
  const runId = parseUuid(input.runId, "runId");
  if (!["coordinator_preparation_failed", "coordinator_interrupted_preparation", "coordinator_executor_session_lost", "coordinator_platform_failure", "coordinator_run_deadline"]
    .includes(input.reason)) {
    throw new HttpError(400, "INVALID_COORDINATOR_CANCELLATION", "The coordinator cancellation reason is not allowlisted");
  }
  const owners = await db.execute(sql`SELECT owner_id FROM oid_benchmark_run WHERE id=${runId} LIMIT 1`) as unknown as Array<{ owner_id: string }>;
  const ownerId = owners[0]?.owner_id;
  if (!ownerId) return null;
  return db.transaction(async (tx) => {
    await lockOwner(tx, ownerId);
    const now = await databaseNow(tx);
    if (input.reason === "coordinator_platform_failure") {
      const recovery = await tx.execute(sql`SELECT action_id FROM oid_run_platform_recovery
        WHERE run_id=${runId} AND owner_id=${ownerId} AND status IN ('recovering','unknown','exhausted')
          AND deadline_at<=${now.toISOString()} AND deadline_at=started_at+interval '180 seconds'
        LIMIT 1`) as unknown as Array<{ action_id: string }>;
      if (!recovery.length) throw new HttpError(409, "PLATFORM_RECOVERY_NOT_EXHAUSTED", "Platform cancellation requires the original exhausted server recovery");
    }
    const run = await requestRunCancellationInTransaction(tx, {
      ownerId, runId, reason: input.reason, now, actor: "coordinator",
    });
    return run.status;
  });
}

export async function expirePendingLaunchIntents(db: OwnerDatabase, limit = 100): Promise<number> {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000) throw new HttpError(400, "INVALID_LIMIT", "limit must be an integer from 1 to 1000");
  const candidates = await db.execute(sql`SELECT id,owner_id FROM oid_run_launch_intent
    WHERE status='pending' AND expires_at<=clock_timestamp()
    ORDER BY expires_at,id LIMIT ${limit}`) as unknown as Array<{ id: string; owner_id: string }>;
  let expired = 0;
  for (const candidate of candidates) {
    const changed = await db.transaction(async (tx) => {
      await lockOwner(tx, candidate.owner_id);
      const intent = await selectIntent(tx, candidate.id, candidate.owner_id, true);
      if (!intent || intent.status !== "pending") return false;
      const now = await databaseNow(tx);
      if (new Date(iso(intent.expires_at)!).getTime() > now.getTime()) return false;
      await tx.execute(sql`UPDATE oid_run_launch_intent SET status='expired',terminal_reason='intent_expired'
        WHERE id=${intent.id} AND status='pending'`);
      await tx.execute(sql`INSERT INTO oid_ledger_audit(id,event_type,operation_id,actor_owner_id,subject_owner_id,metadata,created_at)
        VALUES (${randomUUID()},'run_intent_expired',${`intent_exp_${intent.id.replaceAll("-", "")}`},${intent.owner_id},${intent.owner_id},
          ${JSON.stringify({ intentId: intent.id, reason: "intent_expired" })}::jsonb,${now.toISOString()})
        ON CONFLICT (actor_owner_id,operation_id,event_type) DO NOTHING`);
      return true;
    });
    if (changed) expired += 1;
  }
  return expired;
}

export async function expireQueuedRuns(db: OwnerDatabase, limit = 100): Promise<number> {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000) throw new HttpError(400, "INVALID_LIMIT", "limit must be an integer from 1 to 1000");
  const candidates = await db.execute(sql`SELECT id,owner_id FROM oid_benchmark_run
    WHERE status IN ('queued','preparing') AND queue_deadline<=clock_timestamp()
    ORDER BY queue_deadline,id LIMIT ${limit}`) as unknown as Array<{ id: string; owner_id: string }>;
  let expired = 0;
  for (const candidate of candidates) {
    const changed = await db.transaction(async (tx) => {
      await lockOwner(tx, candidate.owner_id);
      const run = await selectRun(tx, candidate.id, candidate.owner_id, true);
      if (!run || (run.status !== "queued" && run.status !== "preparing")) return false;
      const now = await databaseNow(tx);
      if (new Date(iso(run.queue_deadline)!).getTime() > now.getTime()) return false;
      const expired = await requestRunCancellationInTransaction(tx, {
        ownerId: candidate.owner_id, runId: candidate.id, reason: "queue_deadline_expired", now,
      });
      // A preparing run with a durable environment lease is only expiry-pending
      // until the exact preparation identity has been fenced by the outbox
      // consumer. Its holds and slot remain allocated while status is
      // cancellation_requested.
      return expired.status === "expired";
    });
    if (changed) expired += 1;
  }
  await expirePendingLaunchIntents(db, limit);
  return expired;
}

export async function claimNextQueuedRun(
  deps: RunServiceDependencies,
  input: { claimId?: string; maxCandidates?: number } = {}
): Promise<{ run: RunView; claimId: string; turnNumber: string } | null> {
  if (!Number.isSafeInteger(deps.executionCapacity) || deps.executionCapacity! < 1) {
    throw new HttpError(503, "RUN_POLICY_UNCONFIGURED", "execution capacity is not pinned to an approved bounded runtime value");
  }
  const maxCandidates = input.maxCandidates ?? 100;
  if (!Number.isSafeInteger(maxCandidates) || maxCandidates < 1 || maxCandidates > 1000) {
    throw new HttpError(400, "INVALID_CANDIDATE_LIMIT", "maxCandidates must be between 1 and 1000");
  }
  const claimId = input.claimId === undefined ? randomUUID() : parseUuid(input.claimId, "claimId");
  await expireQueuedRuns(deps.db, maxCandidates);
  if (deps.betaOperationsEnabled && deps.privateDataDir &&
      (await readBetaStorageObservation(deps.privateDataDir)).status !== 'ready') return null;
  return deps.db.transaction(async (tx) => {
    await tx.execute(sql`SELECT pg_advisory_xact_lock(824731202,22)`);
    const existing = await query<{ run_id: string; claim_id: string; turn_number: bigint | string }>(tx, sql`SELECT run_id,claim_id,turn_number
      FROM oid_run_dispatch_claim WHERE claim_id=${claimId} LIMIT 1`);
    if (existing[0]) {
      const run = await selectRun(tx, existing[0].run_id);
      if (!run) return null;
      return { run: runView(run), claimId: existing[0].claim_id, turnNumber: String(existing[0].turn_number) };
    }
    const stateRows = await query<{ last_owner_id: string | null; turn_number: bigint | string }>(tx, sql`SELECT last_owner_id,turn_number
      FROM oid_run_dispatch_state WHERE id=1 FOR UPDATE`);
    const state = stateRows[0];
    if (!state) throw new Error("Run dispatch state row is missing");
    const capacityRows = await query<{ active_count: bigint | string }>(tx, sql`SELECT COUNT(*)::bigint AS active_count
      FROM oid_run_execution_slot WHERE released_at IS NULL`);
    if (toBigInt(capacityRows[0]?.active_count) >= BigInt(deps.executionCapacity!)) return null;
    const candidates = await query<{ id: string; owner_id: string; agent_id: string; mode: RunMode; access_generation: number }>(tx, sql`
      WITH eligible AS (
        SELECT r.id,r.owner_id,r.agent_id,r.mode,r.queued_at,r.access_generation
        FROM oid_benchmark_run r
        JOIN oid_owner o ON o.id=r.owner_id
        JOIN oid_agent a ON a.id=r.agent_id AND a.owner_id=r.owner_id
        JOIN oid_agent_policy p ON p.agent_id=a.id
        WHERE r.status='queued' AND r.queue_deadline>clock_timestamp() AND o.admission_status='admitted'
          AND a.access_revoked_at IS NULL AND a.access_generation=r.access_generation
          AND ((r.mode='training' AND p.training=TRUE) OR (r.mode='ranked' AND p.ranked=TRUE))
          AND (cardinality(r.task_ids)<=1 OR
            (r.successor_preparation_policy_version=${SUCCESSOR_PREPARATION_POLICY_VERSION} AND
              r.successor_preparation_timeout_seconds BETWEEN 1 AND 3600))
          AND NOT EXISTS (SELECT 1 FROM oid_run_execution_slot s WHERE s.agent_id=r.agent_id AND s.released_at IS NULL)
      ), owner_heads AS (
        SELECT DISTINCT ON (owner_id) id,owner_id,agent_id,mode,queued_at,access_generation FROM eligible ORDER BY owner_id,queued_at,id
      ), owner_turns AS (
        SELECT owner_id,MAX(turn_number) AS last_turn FROM oid_run_dispatch_claim GROUP BY owner_id
      )
      SELECT h.id,h.owner_id,h.agent_id,h.mode,h.access_generation,COALESCE(t.last_turn,0)::bigint AS last_turn
      FROM owner_heads h LEFT JOIN owner_turns t ON t.owner_id=h.owner_id
      ORDER BY COALESCE(t.last_turn,0),h.queued_at,h.owner_id LIMIT ${maxCandidates}`);
    let candidate: typeof candidates[number] | undefined;
    let candidateRun: DbRunRow | undefined;
    let now = await databaseNow(tx);
    for (const next of candidates) {
      await lockOwner(tx, next.owner_id);
      const currentAgent = await readAgent(tx, next.owner_id, next.agent_id, true);
      const currentRun = await selectRun(tx, next.id, next.owner_id, true);
      if (!currentRun || currentRun.status !== "queued") continue;
      if (currentRun.task_ids.length > 1 &&
          !readSuccessorPreparationPolicySnapshot(currentRun.successor_preparation_policy_version,
            currentRun.successor_preparation_timeout_seconds)) continue;
      now = await databaseNow(tx);
      if (new Date(iso(currentRun.queue_deadline)!).getTime() <= now.getTime()) {
        await requestRunCancellationInTransaction(tx, {
          ownerId: currentRun.owner_id, runId: currentRun.id, reason: "queue_deadline_expired", now,
        });
        continue;
      }
      const enabled = currentRun.mode === "training" ? currentAgent.training : currentAgent.ranked;
      if (!enabled || currentAgent.access_revoked_at || currentAgent.access_generation !== currentRun.access_generation) continue;
      const slotRows = await query<{ has_slot: boolean }>(tx, sql`SELECT EXISTS(SELECT 1 FROM oid_run_execution_slot
        WHERE agent_id=${currentRun.agent_id} AND released_at IS NULL) AS has_slot`);
      if (slotRows[0]?.has_slot) continue;
      candidate = next;
      candidateRun = currentRun;
      break;
    }
    if (!candidate || !candidateRun) return null;
    // Match create/accept/start lock order: hold this candidate owner before taking the
    // shared operations-control barrier, so a queued administrator pause cannot form a
    // wait-queue cycle with a worker that already owns the candidate row.
    if (deps.betaOperationsEnabled) await lockBetaRunStartControl(tx);
    now = await databaseNow(tx);
    const nextTurn = toBigInt(state.turn_number) + 1n;
    const [claimed] = await tx.execute(sql`UPDATE oid_benchmark_run SET status='preparing'
      WHERE id=${candidate.id} AND status='queued' AND queue_deadline>${now.toISOString()} RETURNING *`) as unknown as DbRunRow[];
    if (!claimed) return null;
    await tx.execute(sql`INSERT INTO oid_run_dispatch_claim(run_id,owner_id,agent_id,claim_id,turn_number,status,claimed_at)
      VALUES (${candidate.id},${candidate.owner_id},${candidate.agent_id},${claimId},${nextTurn.toString()},'claimed',${now.toISOString()})`);
    await tx.execute(sql`INSERT INTO oid_run_execution_slot(agent_id,owner_id,run_id,claim_id,state,acquired_at)
      VALUES (${candidate.agent_id},${candidate.owner_id},${candidate.id},${claimId},'preparing',${now.toISOString()})`);
    await tx.execute(sql`UPDATE oid_run_dispatch_state SET last_owner_id=${candidate.owner_id},turn_number=${nextTurn.toString()},updated_at=${now.toISOString()} WHERE id=1`);
    await appendEvent(tx, candidate.id, "coordinator", "run.preparation_claimed", { claimId, turnNumber: nextTurn.toString(), ownerId: candidate.owner_id });
    const run = await selectRun(tx, candidate.id);
    if (!run) throw new Error("Claimed run could not be read back");
    return { run: runView(run), claimId, turnNumber: nextTurn.toString() };
  });
}

export async function startQueuedRun(
  deps: RunServiceDependencies,
  input: { runId: string; claimId: string; operationId: string }
): Promise<AcceptedRunResult> {
  const runId = parseUuid(input.runId, "runId");
  const claimId = parseUuid(input.claimId, "claimId");
  const operationId = parseOperationId(input.operationId);
  const provider = deps.admissionReleaseProvider;
  const readinessProvider = deps.executionReadinessProvider;
  const preparedTaskStart = deps.preparedTaskStart;
  if (!provider || (!readinessProvider && !preparedTaskStart)) {
    throw new HttpError(503, "EXECUTOR_NOT_READY", "Validated release and genuine executor readiness are required before start");
  }
  if (deps.betaOperationsEnabled && deps.privateDataDir &&
      (await readBetaStorageObservation(deps.privateDataDir)).status !== 'ready') {
    throw new HttpError(503, 'RUN_STORAGE_CAPACITY_LOW', 'Private storage capacity is below the safe start threshold');
  }
  const initial = await deps.db.transaction(async (tx) => {
    const found = await query<{ owner_id: string; agent_id: string; release_identity: string; manifest_hash: string; mode: RunMode; task_ids: string[];
      benchmark_version: string; benchmark_hash: string; policy_hash: string; status: RunStatus; quote_price_units: bigint | string;
      successor_preparation_policy_version: string | null; successor_preparation_timeout_seconds: number | null }>(tx, sql`SELECT r.owner_id,r.release_identity,r.manifest_hash,r.mode,r.task_ids,
        r.agent_id,r.benchmark_version,r.benchmark_hash,r.policy_hash,r.status,r.quote_price_units,
        r.successor_preparation_policy_version,r.successor_preparation_timeout_seconds
      FROM oid_benchmark_run r JOIN oid_run_launch_intent i ON i.id=r.intent_id WHERE r.id=${runId} LIMIT 1`);
    if (!found[0]) throw new HttpError(404, "RUN_NOT_FOUND", "The run does not exist");
    return found[0];
  });
  if (initial.status === "queued" || initial.status === "preparing") {
    requireStoredSuccessorPreparationPolicy(initial.task_ids, initial.successor_preparation_policy_version,
      initial.successor_preparation_timeout_seconds);
  }
  const target: TaskPreparationTarget = { runId, taskIndex: 0, claimId };
  const candidatePreparationId = preparedTaskStart
    ? await preparedTaskStart.readCandidatePreparationId(target)
    : null;
  if (preparedTaskStart && !candidatePreparationId) {
    throw new HttpError(409, "TASK_PREPARATION_NOT_READY", "The exact claimed first task has no durable preparation identity");
  }
  const [validated, readiness] = await Promise.all([
    provider.getValidatedRelease(initial.release_identity, initial.manifest_hash, initial.mode),
    preparedTaskStart ? Promise.resolve(null) : readinessProvider!.isPreparedForRelease(initial.release_identity, initial.manifest_hash)
  ]);
  const releaseTaskIds = validated ? validated.taskIds : [];
  const selectedAreValid = initial.mode === "ranked"
    ? initial.task_ids.length === rankedTaskIds.length && initial.task_ids.every((id, index) => id === rankedTaskIds[index])
    : initial.task_ids.every((id) => openTrainingTaskIds.includes(id)) &&
      initial.task_ids.every((id, index) => id === releaseTaskIds.filter((taskId) => initial.task_ids.includes(taskId))[index]);
  if (!validated || validated.releaseIdentity !== initial.release_identity || validated.manifestHash !== initial.manifest_hash ||
    validated.benchmarkVersion !== initial.benchmark_version || validated.benchmarkHash !== initial.benchmark_hash ||
    validated.policyHash !== initial.policy_hash || releaseTaskIds.length !== (initial.mode === "ranked" ? 12 : CURRENT_TRAINING_TASK_IDS.length) ||
    validated.mode !== initial.mode || !selectedAreValid) {
    throw new HttpError(503, "RELEASE_INCOMPLETE", "A complete validated twelve-task release is required before start");
  }
  const startQuote = quoteRunSelection({ ...validated, priceUnits: validated.pricing.priceUnits, precision: validated.pricing.precision }, initial.task_ids);
  if (startQuote.priceUnits !== toBigInt(initial.quote_price_units)) {
    throw new HttpError(503, "RELEASE_INVALID", "The stored run quote does not match its validated selection");
  }
  const taskTimeoutSeconds = validated.taskDeadlines.find((task) => task.taskId === initial.task_ids[0])?.timeoutSeconds;
  const overallTimeoutSeconds = validated.overallTimeoutSeconds;
  if (typeof taskTimeoutSeconds !== "number" || !Number.isSafeInteger(taskTimeoutSeconds) || taskTimeoutSeconds < 1 || !Number.isSafeInteger(overallTimeoutSeconds) ||
    overallTimeoutSeconds < taskTimeoutSeconds!) {
    throw new HttpError(503, "RUN_POLICY_UNCONFIGURED", "The selected mode's task and overall deadlines are not pinned");
  }
  if (!preparedTaskStart && (!readiness?.ready || !readiness.environmentId || !/^[0-9a-f]{64}$/.test(readiness.evidenceHash ?? ""))) {
    throw new HttpError(503, "EXECUTOR_NOT_READY", readiness?.reason ?? "The executor has not provided genuine preparation evidence");
  }
  const payloadHash = hashPayload(preparedTaskStart
    ? { action: "run_start", runId, claimId, releaseIdentity: initial.release_identity, preparationId: candidatePreparationId }
    : { action: "run_start", runId, claimId, releaseIdentity: initial.release_identity, evidenceHash: readiness!.evidenceHash });
  let preparedSessionValidUntil: string | undefined;
  let result: { run: DbRunRow; replayed: boolean; preparedPreparation: TaskPreparationRecord | undefined };
  try {
    result = await deps.db.transaction(async (tx) => {
    await lockOperation(tx, initial.owner_id, operationId);
    const replay = await existingOperation(tx, initial.owner_id, operationId, "run_start", payloadHash, "owner");
    if (replay) {
      const run = await selectRun(tx, typeof replay.runId === "string" ? replay.runId : runId, initial.owner_id);
      if (!run) throw new Error("Stored start receipt refers to a missing run");
      return { run, replayed: true, preparedPreparation: undefined as TaskPreparationRecord | undefined };
    }
    await lockOwner(tx, initial.owner_id);
    const strictAgent = preparedTaskStart ? await readAgent(tx, initial.owner_id, initial.agent_id, true) : null;
    const run = await liveRunOr404(tx, runId, initial.owner_id, true);
    if (deps.betaOperationsEnabled) await lockBetaRunStartControl(tx);
    if (run.status !== "preparing") throw new HttpError(409, "RUN_NOT_PREPARING", "The run does not hold a preparation claim");
    requireStoredSuccessorPreparationPolicy(run.task_ids, run.successor_preparation_policy_version,
      run.successor_preparation_timeout_seconds);
    const claimRows = await query<{ claim_id: string; status: string }>(tx, sql`SELECT claim_id,status FROM oid_run_dispatch_claim WHERE run_id=${runId} LIMIT 1 FOR UPDATE`);
    const slotRows = await query<{ claim_id: string; state: string }>(tx, sql`SELECT claim_id,state FROM oid_run_execution_slot WHERE run_id=${runId} AND released_at IS NULL LIMIT 1 FOR UPDATE`);
    if (claimRows[0]?.claim_id !== claimId || claimRows[0]?.status !== "claimed" || slotRows[0]?.claim_id !== claimId) {
      throw new HttpError(409, "STALE_RUN_CLAIM", "The preparation claim is no longer current");
    }
    const now = await databaseNow(tx);
    if (new Date(iso(run.queue_deadline)!).getTime() <= now.getTime()) {
      const expired = await requestRunCancellationInTransaction(tx, {
        ownerId: initial.owner_id, runId: run.id, reason: "queue_deadline_expired", now,
      });
      return { run: expired, replayed: false, preparedPreparation: undefined as TaskPreparationRecord | undefined };
    }
    const agent = strictAgent ?? await readAgent(tx, initial.owner_id, run.agent_id, true);
    const permission = run.mode === "training" ? agent.training : agent.ranked;
    // AICODE-NOTE: Re-enabling a mode authorizes successor runs; it never revives an older run while its cancellation outbox is still pending.
    const historicalModeRemoval = await query<{ exists: boolean }>(tx, sql`SELECT EXISTS(
      SELECT 1 FROM oid_run_mode_cancellation_outbox WHERE owner_id=${run.owner_id} AND agent_id=${run.agent_id}
        AND mode=${run.mode} AND policy_revision>${run.agent_policy_revision}) AS exists`);
    if (!permission || agent.access_revoked_at || agent.access_generation !== run.access_generation || historicalModeRemoval[0]?.exists) {
      await releaseRunHolds(tx, run, now, "current_access_denied");
      await tx.execute(sql`UPDATE oid_benchmark_run SET status='cancelled',finished_at=${now.toISOString()},terminal_reason='current_access_denied' WHERE id=${run.id}`);
      await appendEvent(tx, run.id, "coordinator", "run.start_rejected", { reason: "current_access_denied" });
      return { run: await liveRunOr404(tx, run.id, initial.owner_id), replayed: false, preparedPreparation: undefined as TaskPreparationRecord | undefined };
    }
    const financial = await readFinancialPolicy(tx, initial.owner_id, run.agent_id);
    const price = toBigInt(run.quote_price_units);
    if (financial.operationLimit !== null && price > financial.operationLimit) {
      await releaseRunHolds(tx, run, now, "current_operation_limit_exceeded");
      await tx.execute(sql`UPDATE oid_benchmark_run SET status='cancelled',finished_at=${now.toISOString()},terminal_reason='current_operation_limit_exceeded' WHERE id=${run.id}`);
      await appendEvent(tx, run.id, "coordinator", "run.start_rejected", { reason: "current_operation_limit_exceeded" });
      return { run: await liveRunOr404(tx, run.id, initial.owner_id), replayed: false, preparedPreparation: undefined as TaskPreparationRecord | undefined };
    }
    const cashRows = await query<{ cash_units: bigint | string }>(tx, sql`SELECT COALESCE(SUM(amount_units),0)::bigint AS cash_units
      FROM oid_run_reservation WHERE run_id=${run.id} AND source_kind='cash_usdc' AND state='held'`);
    if (toBigInt(cashRows[0]?.cash_units) > 0n && (deps.bonusOnly || !financial.allowCashShortfall)) {
      const reason = deps.bonusOnly ? 'beta_bonus_only_policy' : 'cash_permission_revoked';
      await releaseRunHolds(tx, run, now, reason);
      await tx.execute(sql`UPDATE oid_benchmark_run SET status='cancelled',finished_at=${now.toISOString()},terminal_reason=${reason} WHERE id=${run.id}`);
      await appendEvent(tx, run.id, "coordinator", "run.start_rejected", { reason });
      return { run: await liveRunOr404(tx, run.id, initial.owner_id), replayed: false, preparedPreparation: undefined as TaskPreparationRecord | undefined };
    }
    const expiredBonus = await query<{ exists: boolean }>(tx, sql`SELECT EXISTS(
      SELECT 1 FROM oid_run_reservation rr JOIN oid_bonus_grant g ON g.id=rr.bonus_grant_id
      WHERE rr.run_id=${run.id} AND rr.state='held' AND g.expires_at IS NOT NULL AND g.expires_at<=${now.toISOString()}) AS exists`);
    if (expiredBonus[0]?.exists) {
      await releaseRunHolds(tx, run, now, "allocated_bonus_expired");
      await tx.execute(sql`UPDATE oid_benchmark_run SET status='cancelled',finished_at=${now.toISOString()},terminal_reason='allocated_bonus_expired' WHERE id=${run.id}`);
      await appendEvent(tx, run.id, "coordinator", "run.start_rejected", { reason: "allocated_bonus_expired" });
      return { run: await liveRunOr404(tx, run.id, initial.owner_id), replayed: false, preparedPreparation: undefined as TaskPreparationRecord | undefined };
    }
    const today = now.toISOString().slice(0, 10);
    const daily = await query<{ used: bigint | string }>(tx, sql`SELECT COALESCE(SUM(amount_units),0)::bigint AS used FROM oid_run_budget_hold
      WHERE agent_id=${run.agent_id} AND utc_day=${today} AND state IN ('held','charged') AND run_id<>${run.id}`);
    const currentDayUsed = toBigInt(daily[0]?.used);
    if ((financial.utcDayLimit !== null && currentDayUsed + price > financial.utcDayLimit) ||
      (financial.categoryLimit !== null && currentDayUsed + price > financial.categoryLimit)) {
      await releaseRunHolds(tx, run, now, "current_utc_budget_exceeded");
      await tx.execute(sql`UPDATE oid_benchmark_run SET status='cancelled',finished_at=${now.toISOString()},terminal_reason='current_utc_budget_exceeded' WHERE id=${run.id}`);
      await appendEvent(tx, run.id, "coordinator", "run.start_rejected", { reason: "current_utc_budget_exceeded", utcDay: today });
      return { run: await liveRunOr404(tx, run.id, initial.owner_id), replayed: false, preparedPreparation: undefined as TaskPreparationRecord | undefined };
    }
    const firstTaskDeadline = new Date(now.getTime() + taskTimeoutSeconds * 1000);
    if (preparedTaskStart) preparedSessionValidUntil = firstTaskDeadline.toISOString();
    let preparedPreparation: TaskPreparationRecord | undefined;
    let startEnvironmentId = readiness?.environmentId ?? "";
    let startEvidenceHash = readiness?.evidenceHash ?? "";
    if (preparedTaskStart) {
      preparedPreparation = await preparedTaskStart.assertReadyInTransaction(
        tx, target, candidatePreparationId!, firstTaskDeadline.toISOString(),
      );
      if (preparedPreparation.intent.preparationId !== candidatePreparationId ||
          preparedPreparation.intent.claimId !== claimId || preparedPreparation.intent.runId !== runId ||
          preparedPreparation.observation.status !== "ready" || !preparedPreparation.observation.generationId) {
        throw new HttpError(409, "TASK_PREPARATION_NOT_READY", "The durable preparation changed before atomic start");
      }
      startEnvironmentId = preparedPreparation.intent.environmentId;
      startEvidenceHash = hashPayload({
        preparationId: preparedPreparation.intent.preparationId,
        leaseId: preparedPreparation.intent.leaseId,
        runId: preparedPreparation.intent.runId,
        taskIndex: preparedPreparation.intent.taskIndex,
        claimId: preparedPreparation.intent.claimId,
        releaseIdentity: preparedPreparation.intent.releaseIdentity,
        manifestHash: preparedPreparation.intent.manifestHash,
        taskId: preparedPreparation.intent.taskId,
        caseId: preparedPreparation.intent.caseId,
        caseHash: preparedPreparation.intent.caseHash,
        initialStateSha256: preparedPreparation.intent.initialStateSha256,
        executionIdentityHash: preparedPreparation.intent.executionIdentityHash,
        environmentManifestSha256: preparedPreparation.intent.environmentManifestSha256,
        applicationSourceHash: preparedPreparation.intent.applicationSourceHash,
        generationId: preparedPreparation.observation.generationId,
        baselineStateSha256: preparedPreparation.observation.baselineStateSha256,
        fixtureEvidence: preparedPreparation.observation.fixtureEvidence,
        baselineEvidence: preparedPreparation.observation.baselineEvidence,
      });
    }
    if (run.mode === 'ranked') await captureRankedVersionSnapshot(tx, {runId:run.id,ownerId:run.owner_id,agentId:run.agent_id}, now.toISOString());
    const holds = await query<{ id: string; source_kind: string; bonus_grant_id: string | null; cash_provenance: string | null; amount_units: bigint | string }>(tx, sql`SELECT id,source_kind,bonus_grant_id,cash_provenance,amount_units
      FROM oid_run_reservation WHERE run_id=${run.id} AND state='held' ORDER BY source_kind,bonus_grant_id,cash_provenance FOR UPDATE`);
    for (const hold of holds) {
      const amount = toBigInt(hold.amount_units);
      const operation = `rundeb_${run.id.replaceAll("-", "")}`;
      await tx.execute(sql`INSERT INTO oid_ledger_entry(
        id,owner_id,actor_owner_id,bonus_grant_id,operation_id,entry_type,source_kind,amount_units,
        available_delta_units,reserved_delta_units,expired_delta_units,cash_provenance,reason,created_at
      ) VALUES (${randomUUID()},${run.owner_id},${run.owner_id},${hold.bonus_grant_id},${operation},'debit',${hold.source_kind},
        ${amount.toString()},0,${(-amount).toString()},0,${hold.cash_provenance},'benchmark run start',${now.toISOString()})`);
      await tx.execute(sql`UPDATE oid_run_reservation SET state='debited',changed_at=${now.toISOString()} WHERE id=${hold.id} AND state='held'`);
    }
    await tx.execute(sql`UPDATE oid_run_budget_hold SET state='charged',utc_day=${today},changed_at=${now.toISOString()} WHERE run_id=${run.id} AND state='held'`);
    const overallDeadline = new Date(now.getTime() + overallTimeoutSeconds! * 1000);
    await tx.execute(sql`UPDATE oid_run_task SET status='active',started_at=${now.toISOString()},deadline_at=${firstTaskDeadline.toISOString()},
      snapshot_json=${JSON.stringify({ taskId: initial.task_ids[0], releaseIdentity: validated.releaseIdentity, manifestHash: validated.manifestHash })}::jsonb
      WHERE run_id=${run.id} AND task_index=0 AND task_id=${initial.task_ids[0]}`);
    await tx.execute(sql`UPDATE oid_benchmark_run SET status='running',started_at=${now.toISOString()},overall_deadline=${overallDeadline.toISOString()},environment_id=${startEnvironmentId},
      environment_evidence_hash=${startEvidenceHash} WHERE id=${run.id} AND status='preparing'`);
    await tx.execute(sql`UPDATE oid_run_execution_slot SET state='running' WHERE run_id=${run.id} AND claim_id=${claimId} AND released_at IS NULL`);
    if (preparedPreparation) {
      const insertedBinding = await insertTaskExecutionBindingInTransaction(tx, {
        runId: preparedPreparation.intent.runId,
        taskIndex: preparedPreparation.intent.taskIndex,
        envId: preparedPreparation.intent.environmentId,
        generationId: preparedPreparation.observation.generationId!,
        manifestHash: preparedPreparation.intent.environmentManifestSha256,
        applicationSourceHash: preparedPreparation.intent.applicationSourceHash,
        ...(preparedPreparation.observation.participantId ? { participantId: preparedPreparation.observation.participantId } : {}),
        ...(preparedPreparation.observation.payerAddress ? { payerAddress: preparedPreparation.observation.payerAddress } : {}),
      });
      if (!insertedBinding.inserted) {
        throw new HttpError(409, "TASK_EXECUTION_BINDING_ALREADY_EXISTS", "The first task already has a durable execution identity");
      }
    }
    await appendEvent(tx, run.id, "coordinator", "run.started", {
      startedAt: now.toISOString(), taskId: initial.task_ids[0], taskDeadline: firstTaskDeadline.toISOString(), overallDeadline: overallDeadline.toISOString(),
      environmentId: startEnvironmentId, readinessEvidenceHash: startEvidenceHash
    });
    await tx.execute(sql`INSERT INTO oid_run_outbox(event_id,run_id,event_type,payload_json,status,created_at)
      VALUES (${randomUUID()},${run.id},'run.started',${JSON.stringify({ runId: run.id, environmentId: startEnvironmentId, taskId: initial.task_ids[0], overallDeadline: overallDeadline.toISOString() })}::jsonb,'pending',${now.toISOString()})
      ON CONFLICT (run_id,event_type) DO NOTHING`);
    await recordOperation(tx, { ownerId: initial.owner_id, actorKind: "owner", operationId, action: "run_start", payloadHash, response: { runId } });
    const started = await liveRunOr404(tx, run.id, initial.owner_id);
    if (preparedPreparation && !preparedTaskStart!.hasUsableStartSession(preparedPreparation, firstTaskDeadline.toISOString())) {
      throw new HttpError(409, "TASK_PREPARATION_SESSION_UNAVAILABLE", "The original RAM session expired before atomic start committed");
    }
    await preparedTaskStart?.assertLeaseHeld?.();
    return { run: started, replayed: false, preparedPreparation };
    });
  } catch (error) {
    if (preparedTaskStart && error && typeof error === "object" && "code" in error &&
        (error.code === "TASK_PREPARATION_SESSION_UNAVAILABLE" || error.code === "TASK_PREPARATION_FENCED")) {
      // A durable ready row after RAM loss/expiry is not sufficient to charge.
      // Request the exact preparation fence after rolling back the start tx.
      await requestPreparedStartHandoffCancellation(deps.db, initial.owner_id, runId);
    }
    throw error;
  }
  if (!result.replayed && result.run.status === "running" && result.preparedPreparation && preparedTaskStart) {
    try {
      if (!preparedSessionValidUntil) throw new Error("prepared_start_deadline_missing");
      await preparedTaskStart.attachStartedSession(result.preparedPreparation, preparedSessionValidUntil);
    } catch {
      await requestPreparedStartHandoffCancellation(deps.db, initial.owner_id, runId);
      throw new HttpError(503, "PREPARED_EXECUTOR_HANDOFF_FAILED", "The run start committed but its executor session could not be attached; cancellation and fencing were requested");
    }
  }
  return { run: runView(result.run), replayed: result.replayed };
}

async function requestPreparedStartHandoffCancellation(db: OwnerDatabase, ownerId: string, runId: string): Promise<void> {
  await db.transaction(async (tx) => {
    await lockOwner(tx, ownerId);
    const now = await databaseNow(tx);
    await requestRunCancellationInTransaction(tx, {
      ownerId, runId, reason: "prepared_executor_handoff_failed", now,
    });
  });
}

type CancellationSourceEvent = {
  eventId: string;
  ownerId: string;
  agentId: string;
  sourceKind: "agent_access_revoked";
  accessGeneration: number;
  reason: string;
} | {
  eventId: string;
  ownerId: string;
  agentId: string;
  sourceKind: "mode_removed";
  mode: RunMode;
  policyRevision: number;
  reason: string;
};

function cancellationRunModePredicate(source: CancellationSourceEvent) {
  return source.sourceKind === "mode_removed" ? sql`AND mode=${source.mode}` : sql``;
}

function cancellationAdmissionCutoff(source: CancellationSourceEvent) {
  return source.sourceKind === "agent_access_revoked"
    ? sql`AND access_generation < ${source.accessGeneration}`
    : sql`AND agent_policy_revision < ${source.policyRevision}`;
}

async function loadCancellationSources(db: OwnerDatabase, limit: number): Promise<CancellationSourceEvent[]> {
  const [globalRows, modeRows] = await Promise.all([
    db.execute(sql`SELECT o.event_id,o.owner_id,o.agent_id,o.access_generation
      FROM oid_agent_cancellation_outbox o
      LEFT JOIN oid_run_cancellation_receipt r ON r.source_event_id=o.event_id
      WHERE o.status='pending' AND (r.source_event_id IS NULL OR r.completed_at IS NULL)
      ORDER BY o.created_at,o.event_id LIMIT ${limit}`) as Promise<unknown>,
    db.execute(sql`SELECT o.event_id,o.owner_id,o.agent_id,o.mode,o.policy_revision
      FROM oid_run_mode_cancellation_outbox o
      LEFT JOIN oid_run_cancellation_receipt r ON r.source_event_id=o.event_id
      WHERE o.status='pending' AND (r.source_event_id IS NULL OR r.completed_at IS NULL)
      ORDER BY o.created_at,o.event_id LIMIT ${limit}`) as Promise<unknown>
  ]);
  const globalEvents = rows<{ event_id: string; owner_id: string; agent_id: string; access_generation: number }>(globalRows).map((row) => ({
    eventId: row.event_id, ownerId: row.owner_id, agentId: row.agent_id,
    sourceKind: "agent_access_revoked" as const, accessGeneration: row.access_generation, reason: "owner_global_revoke"
  }));
  const modeEvents = rows<{ event_id: string; owner_id: string; agent_id: string; mode: RunMode; policy_revision: number }>(modeRows).map((row) => ({
    eventId: row.event_id, ownerId: row.owner_id, agentId: row.agent_id, mode: row.mode,
    sourceKind: "mode_removed" as const, policyRevision: row.policy_revision, reason: `owner_${row.mode}_permission_removed`
  }));
  return [...globalEvents, ...modeEvents].sort((left, right) => left.eventId.localeCompare(right.eventId)).slice(0, limit);
}

async function stageCancellationSource(db: OwnerDatabase, source: CancellationSourceEvent): Promise<{
  affectedRunIds: string[]; waitingRunIds: string[]; alreadyComplete: boolean;
}> {
  return db.transaction(async (tx) => {
    await lockOwner(tx, source.ownerId);
    const receiptRows = await query<{ source_event_id: string; cancelled_run_ids: string[]; pending_run_ids: string[];
      completed_at: Date | string | null }>(tx, sql`SELECT source_event_id,cancelled_run_ids,pending_run_ids,completed_at
      FROM oid_run_cancellation_receipt WHERE source_event_id=${source.eventId} LIMIT 1 FOR UPDATE`);
    const priorReceipt = receiptRows[0];
    if (priorReceipt?.completed_at) return { affectedRunIds: [], waitingRunIds: [], alreadyComplete: true };
    if (source.sourceKind === "mode_removed") {
      const locked = await query<{ event_id: string; status: string }>(tx, sql`SELECT event_id,status FROM oid_run_mode_cancellation_outbox
        WHERE event_id=${source.eventId} AND policy_revision=${source.policyRevision} AND status='pending' LIMIT 1 FOR UPDATE`);
      if (!locked.length) return { affectedRunIds: [], waitingRunIds: [], alreadyComplete: true };
    } else {
      const locked = await query<{ event_id: string; status: string }>(tx, sql`SELECT event_id,status FROM oid_agent_cancellation_outbox
        WHERE event_id=${source.eventId} AND access_generation=${source.accessGeneration} AND status='pending' LIMIT 1 FOR UPDATE`);
      if (!locked.length) return { affectedRunIds: [], waitingRunIds: [], alreadyComplete: true };
    }
    const activeRows = await query<{ id: string; status: RunStatus }>(tx, sql`SELECT id,status FROM oid_benchmark_run
      WHERE owner_id=${source.ownerId} AND agent_id=${source.agentId}
        AND status IN ('queued','preparing','running','cancellation_requested')
        ${cancellationRunModePredicate(source)}
        ${cancellationAdmissionCutoff(source)}
      ORDER BY queued_at,id`);
    const now = await databaseNow(tx);
    for (const active of activeRows) {
      await requestRunCancellationInTransaction(tx, { ownerId: source.ownerId, runId: active.id, reason: source.reason, now });
    }
    const affectedRunIds = [...new Set([
      ...(priorReceipt?.cancelled_run_ids ?? []),
      ...(priorReceipt?.pending_run_ids ?? []),
      ...activeRows.map((row) => row.id)
    ])];
    const statusRows = affectedRunIds.length === 0 ? [] : await query<{ id: string; status: RunStatus }>(tx, sql`SELECT id,status
      FROM oid_benchmark_run WHERE owner_id=${source.ownerId} AND agent_id=${source.agentId}
        AND id=ANY(ARRAY(SELECT jsonb_array_elements_text(${JSON.stringify(affectedRunIds)}::jsonb)::uuid))
        ${cancellationRunModePredicate(source)}
        ${cancellationAdmissionCutoff(source)}
      ORDER BY queued_at,id`);
    const cancelledRunIds = statusRows.filter((row) => row.status === "cancelled").map((row) => row.id);
    const waitingRunIds = statusRows.filter((row) => row.status === "running" || row.status === "cancellation_requested").map((row) => row.id);
    await tx.execute(sql`INSERT INTO oid_run_cancellation_receipt(
        source_event_id,source_kind,cancelled_run_ids,pending_run_ids,evidence_hash,completed_at
      ) VALUES (${source.eventId},${source.sourceKind},
        ARRAY(SELECT jsonb_array_elements_text(${JSON.stringify(cancelledRunIds)}::jsonb)::uuid),
        ARRAY(SELECT jsonb_array_elements_text(${JSON.stringify(waitingRunIds)}::jsonb)::uuid),NULL,NULL)
      ON CONFLICT (source_event_id) DO UPDATE SET
        source_kind=EXCLUDED.source_kind,
        cancelled_run_ids=EXCLUDED.cancelled_run_ids,
        pending_run_ids=EXCLUDED.pending_run_ids`);
    return {
      affectedRunIds,
      waitingRunIds,
      alreadyComplete: false
    };
  });
}

type CancellationTaskPreparationPin = { taskIndex?: number; preparationId: string; generationId: string | null };
type ParsedCancellationTaskPreparationPin =
  | { status: "none" }
  | { status: "valid"; value: CancellationTaskPreparationPin }
  | { status: "invalid" };

function cancellationTaskPreparationPin(payload: unknown): ParsedCancellationTaskPreparationPin {
  const body = record(payload);
  if (!Object.prototype.hasOwnProperty.call(body, "taskPreparation")) return { status: "none" };
  const value = record(body.taskPreparation);
  const hasTaskIndex = Object.prototype.hasOwnProperty.call(value, "taskIndex");
  if ((hasTaskIndex && (!Number.isSafeInteger(value.taskIndex) || (value.taskIndex as number) < 0 || (value.taskIndex as number) > 11)) ||
      typeof value.preparationId !== "string" || !uuidPattern.test(value.preparationId) ||
      !(value.generationId === null || (typeof value.generationId === "string" && uuidPattern.test(value.generationId)))) {
    return { status: "invalid" };
  }
  return { status: "valid", value: {
    ...(hasTaskIndex ? { taskIndex: value.taskIndex as number } : {}),
    preparationId: value.preparationId.toLowerCase(),
    generationId: typeof value.generationId === "string" ? value.generationId.toLowerCase() : null,
  } };
}

function fenceConfirmsTaskPreparation(
  result: { fenced: true; taskPreparation?: { taskIndex: number; preparationId: string; generationId: string | null } } | { fenced: false },
  expected: ParsedCancellationTaskPreparationPin,
): boolean {
  if (expected.status !== "valid") return true;
  if (!result.fenced || !result.taskPreparation) return false;
  const actual = result.taskPreparation;
  const expectedTaskIndex = expected.value.taskIndex ?? 0;
  if (!Number.isSafeInteger(actual.taskIndex) || actual.taskIndex < 0 || actual.taskIndex > 11 ||
      actual.taskIndex !== expectedTaskIndex || !uuidPattern.test(actual.preparationId) ||
      !(actual.generationId === null || (typeof actual.generationId === "string" && uuidPattern.test(actual.generationId)))) return false;
  const generationId = typeof actual.generationId === "string" ? actual.generationId.toLowerCase() : null;
  return actual.preparationId.toLowerCase() === expected.value.preparationId && generationId === expected.value.generationId;
}

async function finalizeFencedCancellation(
  db: OwnerDatabase,
  input: { ownerId: string; runId: string; evidenceHash: string }
): Promise<boolean> {
  if (!/^[0-9a-f]{64}$/i.test(input.evidenceHash)) return false;
  return db.transaction(async (tx) => {
    await lockOwner(tx, input.ownerId);
    const run = await selectRun(tx, input.runId, input.ownerId, true);
    if (!run || run.status !== "cancellation_requested") return false;
    const now = await databaseNow(tx);
    const beforeStart = run.started_at === null;
    const queueExpired = beforeStart && run.cancellation_reason === "queue_deadline_expired";
    if (beforeStart) await releaseRunHolds(tx, run, now, run.cancellation_reason ?? "owner_cancelled");
    await tx.execute(sql`UPDATE oid_benchmark_run SET status=${queueExpired ? "expired" : "cancelled"},finished_at=${now.toISOString()},
      terminal_reason=${run.cancellation_reason ?? 'owner_revoked'},cancellation_evidence_hash=${input.evidenceHash}
      WHERE id=${run.id} AND status='cancellation_requested'`);
    if (!beforeStart) {
      await tx.execute(sql`DELETE FROM oid_run_execution_slot WHERE run_id=${run.id}`);
      await tx.execute(sql`UPDATE oid_run_dispatch_claim SET status='released',released_at=${now.toISOString()}
        WHERE run_id=${run.id} AND status='claimed'`);
    } else {
      await tx.execute(sql`UPDATE oid_run_launch_intent SET terminal_reason=${run.cancellation_reason ?? 'owner_cancelled'}
        WHERE id=${run.intent_id}`);
    }
    await tx.execute(sql`UPDATE oid_run_outbox SET status='delivered',delivered_at=${now.toISOString()}
      WHERE run_id=${run.id} AND event_type='run.cancel.requested' AND status='pending'`);
    await appendEvent(tx, run.id, queueExpired ? "coordinator" : "executor",
      queueExpired ? "run.queue_expired" : beforeStart ? "run.cancelled.before_start" : "run.cancelled.after_start", {
      reason: run.cancellation_reason ?? "owner_revoked", fenceEvidenceHash: input.evidenceHash, finishedAt: now.toISOString()
    });
    if (queueExpired) {
      await tx.execute(sql`INSERT INTO oid_run_outbox(event_id,run_id,event_type,payload_json,status,created_at)
        VALUES (${randomUUID()},${run.id},'run.expired',${JSON.stringify({ runId: run.id, reason: "queue_deadline_expired" })}::jsonb,'pending',${now.toISOString()})
        ON CONFLICT (run_id,event_type) DO NOTHING`);
    }
    return true;
  });
}

async function consumeDirectRunCancellationCommands(
  db: OwnerDatabase,
  executor: CancellationExecutor | undefined,
  limit: number,
  skipRunIds: Set<string>
): Promise<number> {
  const commands = await db.execute(sql`SELECT r.id AS run_id,r.owner_id,r.agent_id,r.cancellation_reason,r.status,o.payload_json
    FROM oid_run_outbox o JOIN oid_benchmark_run r ON r.id=o.run_id
    WHERE o.event_type='run.cancel.requested' AND o.status='pending' AND r.status='cancellation_requested'
    ORDER BY o.created_at,o.event_id LIMIT ${limit}`) as unknown as Array<{
      run_id: string; owner_id: string; agent_id: string; cancellation_reason: string | null; status: string; payload_json: unknown;
    }>;
  let awaiting = 0;
  for (const command of commands) {
    if (skipRunIds.has(command.run_id)) continue;
    if (!executor) { awaiting += 1; continue; }
    const preparationPin = cancellationTaskPreparationPin(command.payload_json);
    if (preparationPin.status === "invalid") { awaiting += 1; continue; }
    let fence: { fenced: true; evidenceHash: string; taskPreparation?: { taskIndex: number; preparationId: string; generationId: string | null } } | { fenced: false };
    try {
      fence = await executor.fenceAndStop({
        runId: command.run_id, agentId: command.agent_id,
        reason: command.cancellation_reason ?? "owner_voluntary",
        ...(preparationPin.status === "valid" ? { taskPreparation: preparationPin.value } : {})
      });
    } catch {
      fence = { fenced: false };
    }
    if (!fence.fenced || !/^[0-9a-f]{64}$/i.test(fence.evidenceHash) || !fenceConfirmsTaskPreparation(fence, preparationPin)) {
      awaiting += 1; continue;
    }
    await finalizeFencedCancellation(db, { ownerId: command.owner_id, runId: command.run_id, evidenceHash: fence.evidenceHash });
  }
  return awaiting;
}

async function completeCancellationSource(
  db: OwnerDatabase,
  source: CancellationSourceEvent
): Promise<boolean> {
  return db.transaction(async (tx) => {
    await lockOwner(tx, source.ownerId);
    const receiptRows = await query<{ source_event_id: string; cancelled_run_ids: string[]; pending_run_ids: string[];
      completed_at: Date | string | null }>(tx, sql`SELECT source_event_id,cancelled_run_ids,pending_run_ids,completed_at
      FROM oid_run_cancellation_receipt WHERE source_event_id=${source.eventId} LIMIT 1 FOR UPDATE`);
    const receipt = receiptRows[0];
    if (!receipt) throw new Error("Cancellation source completion has no durable staging receipt");
    if (receipt.completed_at) return true;
    const pending = await query<{ id: string; status: RunStatus }>(tx, sql`SELECT id,status FROM oid_benchmark_run
      WHERE owner_id=${source.ownerId} AND agent_id=${source.agentId}
        AND status IN ('running','cancellation_requested')
        ${cancellationRunModePredicate(source)}
        ${cancellationAdmissionCutoff(source)}
      ORDER BY queued_at,id`);
    const trackedRunIds = [...new Set([...(receipt.cancelled_run_ids ?? []), ...(receipt.pending_run_ids ?? []), ...pending.map((row) => row.id)])];
    const trackedRows = trackedRunIds.length === 0 ? [] : await query<{ id: string; status: RunStatus; cancellation_evidence_hash: string | null }>(tx, sql`SELECT id,status,cancellation_evidence_hash
      FROM oid_benchmark_run WHERE owner_id=${source.ownerId} AND agent_id=${source.agentId}
        AND id=ANY(ARRAY(SELECT jsonb_array_elements_text(${JSON.stringify(trackedRunIds)}::jsonb)::uuid))
        ${cancellationRunModePredicate(source)}
        ${cancellationAdmissionCutoff(source)}
      ORDER BY queued_at,id`);
    const cancelledRunIds = trackedRows.filter((row) => row.status === "cancelled").map((row) => row.id);
    const pendingRunIds = trackedRows.filter((row) => row.status === "running" || row.status === "cancellation_requested").map((row) => row.id);
    if (pendingRunIds.length > 0) {
      await tx.execute(sql`UPDATE oid_run_cancellation_receipt SET
          cancelled_run_ids=ARRAY(SELECT jsonb_array_elements_text(${JSON.stringify(cancelledRunIds)}::jsonb)::uuid),
          pending_run_ids=ARRAY(SELECT jsonb_array_elements_text(${JSON.stringify(pendingRunIds)}::jsonb)::uuid),
          evidence_hash=NULL,completed_at=NULL
        WHERE source_event_id=${source.eventId} AND completed_at IS NULL`);
      return false;
    }
    const evidenceEntries = trackedRows.filter((row) => row.status === "cancelled" && row.cancellation_evidence_hash)
      .map((row) => [row.id, row.cancellation_evidence_hash] as const)
      .sort(([left], [right]) => left.localeCompare(right));
    const evidenceHash = evidenceEntries.length ? hashPayload(evidenceEntries) : null;
    const completedAt = await databaseNow(tx);
    await tx.execute(sql`UPDATE oid_run_cancellation_receipt SET
        cancelled_run_ids=ARRAY(SELECT jsonb_array_elements_text(${JSON.stringify(cancelledRunIds)}::jsonb)::uuid),
        pending_run_ids='{}'::uuid[],evidence_hash=${evidenceHash},completed_at=${completedAt.toISOString()}
      WHERE source_event_id=${source.eventId} AND completed_at IS NULL`);
    // AICODE-NOTE: The existing agent-revocation outbox has an immutable
    // status='pending' constraint. A receipt with completed_at set is its
    // durable ACK; incomplete receipts retain cancelled and pending run IDs
    // across worker retries. Mode-removal events also transition to delivered.
    if (source.sourceKind === "mode_removed") {
      const deliveredAt = await databaseNow(tx);
      await tx.execute(sql`UPDATE oid_run_mode_cancellation_outbox SET status='delivered',delivered_at=${deliveredAt.toISOString()}
        WHERE event_id=${source.eventId} AND status='pending'`);
    }
    return true;
  });
}

/**
 * Consume durable owner revocation and run-mode removal events. Started runs
 * remain cancellation_requested until the executor positively fences/stops the
 * exact run and supplies a durable evidence hash.
 */
export async function consumeRunCancellationOutbox(
  db: OwnerDatabase,
  executor?: CancellationExecutor,
  limit = 50
): Promise<{ processed: number; awaitingExecutor: number }> {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 500) throw new HttpError(400, "INVALID_LIMIT", "limit must be an integer from 1 to 500");
  const sources = await loadCancellationSources(db, limit);
  let processed = 0;
  let awaitingExecutor = 0;
  const attemptedRunIds = new Set<string>();
  for (const source of sources) {
    const staged = await stageCancellationSource(db, source);
    if (staged.alreadyComplete) { processed += 1; continue; }
    for (const runId of staged.waitingRunIds) {
      if (attemptedRunIds.has(runId)) continue;
      attemptedRunIds.add(runId);
      if (!executor) { awaitingExecutor += 1; continue; }
      const run = await db.transaction(async (tx) => {
        const found = await query<{ agent_id: string; status: string; payload_json: unknown }>(tx, sql`SELECT r.agent_id,r.status,o.payload_json
          FROM oid_benchmark_run r LEFT JOIN oid_run_outbox o ON o.run_id=r.id AND o.event_type='run.cancel.requested'
          WHERE r.id=${runId} AND r.owner_id=${source.ownerId} LIMIT 1`);
        return found[0];
      });
      if (!run || run.status !== "cancellation_requested") continue;
      const preparationPin = cancellationTaskPreparationPin(run.payload_json);
      if (preparationPin.status === "invalid") { awaitingExecutor += 1; continue; }
      let fence: { fenced: true; evidenceHash: string; taskPreparation?: { taskIndex: number; preparationId: string; generationId: string | null } } | { fenced: false };
      try {
        fence = await executor.fenceAndStop({ runId, agentId: run.agent_id, reason: source.reason,
          ...(preparationPin.status === "valid" ? { taskPreparation: preparationPin.value } : {}) });
      }
      catch { fence = { fenced: false }; }
      if (!fence.fenced || !/^[0-9a-f]{64}$/i.test(fence.evidenceHash) || !fenceConfirmsTaskPreparation(fence, preparationPin)) {
        awaitingExecutor += 1; continue;
      }
      const finalized = await finalizeFencedCancellation(db, { ownerId: source.ownerId, runId, evidenceHash: fence.evidenceHash });
      if (!finalized) awaitingExecutor += 1;
    }
    const complete = await completeCancellationSource(db, source);
    if (complete) processed += 1;
  }
  awaitingExecutor += await consumeDirectRunCancellationCommands(db, executor, limit, attemptedRunIds);
  return { processed, awaitingExecutor };
}
