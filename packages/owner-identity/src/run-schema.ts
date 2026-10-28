import { sql } from "drizzle-orm";
import {
  bigint,
  check,
  foreignKey,
  index,
  integer,
  jsonb,
  pgTable,
  primaryKey,
  text,
  timestamp,
  uniqueIndex,
  uuid
} from "drizzle-orm/pg-core";
import { agentProfiles, owners } from "./schema.js";
import { bonusGrants } from "./ledger-schema.js";

const time = (name: string) => timestamp(name, { withTimezone: true, mode: "date" });

export const runLaunchIntents = pgTable("oid_run_launch_intent", {
  id: uuid("id").primaryKey(),
  ownerId: uuid("owner_id").notNull(),
  agentId: uuid("agent_id").notNull(),
  operationId: text("operation_id").notNull(),
  payloadHash: text("payload_hash").notNull(),
  mode: text("mode").notNull(),
  taskIds: text("task_ids").array().notNull(),
  releaseIdentity: text("release_identity").notNull(),
  benchmarkVersion: text("benchmark_version").notNull(),
  manifestHash: text("manifest_hash").notNull(),
  benchmarkHash: text("benchmark_hash").notNull(),
  policyHash: text("policy_hash").notNull(),
  successorPreparationPolicyVersion: text("successor_preparation_policy_version"),
  successorPreparationTimeoutSeconds: integer("successor_preparation_timeout_seconds"),
  quotePriceUnits: bigint("quote_price_units", { mode: "bigint" }).notNull(),
  precision: integer("precision").notNull().default(6),
  cashCeilingUnits: bigint("cash_ceiling_units", { mode: "bigint" }).notNull(),
  ownerPolicyRevision: integer("owner_policy_revision").notNull(),
  agentPolicyRevision: integer("agent_policy_revision").notNull(),
  status: text("status").notNull().default("pending"),
  createdAt: time("created_at").notNull().defaultNow(),
  expiresAt: time("expires_at").notNull(),
  acceptedAt: time("accepted_at"),
  terminalReason: text("terminal_reason"),
  runId: uuid("run_id")
}, (table) => [
  foreignKey({ columns: [table.ownerId], foreignColumns: [owners.id], name: "oid_run_intent_owner_fk" }).onDelete("restrict"),
  foreignKey({ columns: [table.ownerId, table.agentId], foreignColumns: [agentProfiles.ownerId, agentProfiles.id], name: "oid_run_intent_agent_owner_fk" }).onDelete("restrict"),
  uniqueIndex("oid_run_intent_owner_operation_uq").on(table.ownerId, table.operationId),
  index("oid_run_intent_owner_created_idx").on(table.ownerId, table.createdAt),
  index("oid_run_intent_agent_status_idx").on(table.agentId, table.status, table.createdAt),
  check("oid_run_intent_mode_check", sql`${table.mode} IN ('training','ranked')`),
  check("oid_run_intent_status_check", sql`${table.status} IN ('pending','accepted','cancelled','expired')`),
  check("oid_run_intent_price_check", sql`${table.quotePriceUnits} >= 0 AND ${table.cashCeilingUnits} >= 0 AND ${table.precision} = 6`),
  check("oid_run_intent_hash_check", sql`${table.payloadHash} ~ '^[0-9a-f]{64}$' AND ${table.benchmarkHash} ~ '^[0-9a-f]{64}$' AND ${table.policyHash} ~ '^[0-9a-f]{64}$'`),
  check("oid_run_intent_successor_preparation_policy_pair_ck", sql`(${table.successorPreparationPolicyVersion} IS NULL AND ${table.successorPreparationTimeoutSeconds} IS NULL) OR (${table.successorPreparationPolicyVersion} IS NOT NULL AND ${table.successorPreparationTimeoutSeconds} IS NOT NULL AND ${table.successorPreparationPolicyVersion} ~ '^[a-z0-9][a-z0-9._/-]{0,100}/v[1-9][0-9]*$' AND ${table.successorPreparationTimeoutSeconds} BETWEEN 1 AND 3600)`),
  check("oid_run_intent_operation_check", sql`${table.operationId} ~ '^[A-Za-z0-9_-]{12,128}$'`),
  check("oid_run_intent_task_ids_check", sql`cardinality(${table.taskIds}) > 0 AND array_position(${table.taskIds}, NULL) IS NULL`)
]);

export const benchmarkRuns = pgTable("oid_benchmark_run", {
  id: uuid("id").primaryKey(),
  intentId: uuid("intent_id").notNull().unique(),
  ownerId: uuid("owner_id").notNull(),
  agentId: uuid("agent_id").notNull(),
  mode: text("mode").notNull(),
  taskIds: text("task_ids").array().notNull(),
  releaseIdentity: text("release_identity").notNull(),
  benchmarkVersion: text("benchmark_version").notNull(),
  manifestHash: text("manifest_hash").notNull(),
  benchmarkHash: text("benchmark_hash").notNull(),
  policyHash: text("policy_hash").notNull(),
  successorPreparationPolicyVersion: text("successor_preparation_policy_version"),
  successorPreparationTimeoutSeconds: integer("successor_preparation_timeout_seconds"),
  quotePriceUnits: bigint("quote_price_units", { mode: "bigint" }).notNull(),
  cashCeilingUnits: bigint("cash_ceiling_units", { mode: "bigint" }).notNull(),
  accessGeneration: integer("access_generation").notNull(),
  agentPolicyRevision: integer("agent_policy_revision").notNull(),
  status: text("status").notNull().default("queued"),
  queuedAt: time("queued_at").notNull().defaultNow(),
  queueDeadline: time("queue_deadline").notNull(),
  startedAt: time("started_at"),
  overallDeadline: time("overall_deadline"),
  finishedAt: time("finished_at"),
  terminalReason: text("terminal_reason"),
  cancellationReason: text("cancellation_reason"),
  cancellationRequestedAt: time("cancellation_requested_at"),
  environmentId: text("environment_id"),
  environmentEvidenceHash: text("environment_evidence_hash")
}, (table) => [
  foreignKey({ columns: [table.intentId], foreignColumns: [runLaunchIntents.id], name: "oid_benchmark_run_intent_fk" }).onDelete("restrict"),
  foreignKey({ columns: [table.ownerId], foreignColumns: [owners.id], name: "oid_benchmark_run_owner_fk" }).onDelete("restrict"),
  foreignKey({ columns: [table.ownerId, table.agentId], foreignColumns: [agentProfiles.ownerId, agentProfiles.id], name: "oid_benchmark_run_agent_owner_fk" }).onDelete("restrict"),
  index("oid_benchmark_run_owner_created_idx").on(table.ownerId, table.queuedAt),
  index("oid_benchmark_run_queue_idx").on(table.status, table.queueDeadline, table.queuedAt),
  index("oid_benchmark_run_agent_idx").on(table.agentId, table.status),
  check("oid_benchmark_run_mode_check", sql`${table.mode} IN ('training','ranked')`),
  check("oid_benchmark_run_status_check", sql`${table.status} IN ('queued','preparing','running','cancellation_requested','cancelled','expired','completed','failed','unknown','disqualified')`),
  check("oid_benchmark_run_quote_check", sql`${table.quotePriceUnits} >= 0 AND ${table.cashCeilingUnits} >= 0`),
  check("oid_benchmark_run_hash_check", sql`${table.benchmarkHash} ~ '^[0-9a-f]{64}$' AND ${table.policyHash} ~ '^[0-9a-f]{64}$'`),
  check("oid_benchmark_run_successor_preparation_policy_pair_ck", sql`(${table.successorPreparationPolicyVersion} IS NULL AND ${table.successorPreparationTimeoutSeconds} IS NULL) OR (${table.successorPreparationPolicyVersion} IS NOT NULL AND ${table.successorPreparationTimeoutSeconds} IS NOT NULL AND ${table.successorPreparationPolicyVersion} ~ '^[a-z0-9][a-z0-9._/-]{0,100}/v[1-9][0-9]*$' AND ${table.successorPreparationTimeoutSeconds} BETWEEN 1 AND 3600)`)
]);

export const runReservations = pgTable("oid_run_reservation", {
  id: uuid("id").primaryKey(),
  runId: uuid("run_id").notNull(),
  ownerId: uuid("owner_id").notNull(),
  sourceKind: text("source_kind").notNull(),
  bonusGrantId: uuid("bonus_grant_id"),
  cashProvenance: text("cash_provenance"),
  amountUnits: bigint("amount_units", { mode: "bigint" }).notNull(),
  state: text("state").notNull().default("held"),
  createdAt: time("created_at").notNull().defaultNow(),
  changedAt: time("changed_at")
}, (table) => [
  foreignKey({ columns: [table.runId], foreignColumns: [benchmarkRuns.id], name: "oid_run_reservation_run_fk" }).onDelete("restrict"),
  foreignKey({ columns: [table.ownerId], foreignColumns: [owners.id], name: "oid_run_reservation_owner_fk" }).onDelete("restrict"),
  foreignKey({ columns: [table.ownerId, table.bonusGrantId], foreignColumns: [bonusGrants.ownerId, bonusGrants.id], name: "oid_run_reservation_bonus_fk" }).onDelete("restrict"),
  uniqueIndex("oid_run_reservation_run_source_uq").on(table.runId, table.sourceKind, table.bonusGrantId, table.cashProvenance),
  index("oid_run_reservation_owner_state_idx").on(table.ownerId, table.state),
  check("oid_run_reservation_source_check", sql`${table.sourceKind} IN ('cash_usdc','tester_bonus')`),
  check("oid_run_reservation_state_check", sql`${table.state} IN ('held','released','debited')`),
  check("oid_run_reservation_amount_check", sql`${table.amountUnits} > 0`),
  check("oid_run_reservation_source_shape_check", sql`(${table.sourceKind} = 'tester_bonus' AND ${table.bonusGrantId} IS NOT NULL AND ${table.cashProvenance} IS NULL) OR (${table.sourceKind} = 'cash_usdc' AND ${table.bonusGrantId} IS NULL AND ${table.cashProvenance} IS NOT NULL AND char_length(${table.cashProvenance}) BETWEEN 1 AND 120)`)
]);

export const runBudgetHolds = pgTable("oid_run_budget_hold", {
  runId: uuid("run_id").notNull(),
  ownerId: uuid("owner_id").notNull(),
  agentId: uuid("agent_id").notNull(),
  mode: text("mode").notNull(),
  utcDay: text("utc_day").notNull(),
  amountUnits: bigint("amount_units", { mode: "bigint" }).notNull(),
  state: text("state").notNull().default("held"),
  createdAt: time("created_at").notNull().defaultNow(),
  changedAt: time("changed_at")
}, (table) => [
  primaryKey({ columns: [table.runId], name: "oid_run_budget_hold_pk" }),
  foreignKey({ columns: [table.runId], foreignColumns: [benchmarkRuns.id], name: "oid_run_budget_hold_run_fk" }).onDelete("restrict"),
  foreignKey({ columns: [table.ownerId], foreignColumns: [owners.id], name: "oid_run_budget_hold_owner_fk" }).onDelete("restrict"),
  foreignKey({ columns: [table.ownerId, table.agentId], foreignColumns: [agentProfiles.ownerId, agentProfiles.id], name: "oid_run_budget_hold_agent_fk" }).onDelete("restrict"),
  index("oid_run_budget_hold_agent_day_idx").on(table.agentId, table.utcDay, table.state),
  check("oid_run_budget_hold_mode_check", sql`${table.mode} IN ('training','ranked')`),
  check("oid_run_budget_hold_state_check", sql`${table.state} IN ('held','charged','released')`),
  check("oid_run_budget_hold_amount_check", sql`${table.amountUnits} >= 0`),
  check("oid_run_budget_hold_day_check", sql`${table.utcDay} ~ '^\\d{4}-\\d{2}-\\d{2}$'`)
]);

export const runOperations = pgTable("oid_run_operation", {
  id: uuid("id").primaryKey(),
  ownerId: uuid("owner_id").notNull(),
  actorKind: text("actor_kind").notNull(),
  actorAgentId: uuid("actor_agent_id"),
  operationId: text("operation_id").notNull(),
  action: text("action").notNull(),
  payloadHash: text("payload_hash").notNull(),
  responseJson: jsonb("response_json").$type<Record<string, unknown>>().notNull(),
  createdAt: time("created_at").notNull().defaultNow()
}, (table) => [
  foreignKey({ columns: [table.ownerId], foreignColumns: [owners.id], name: "oid_run_operation_owner_fk" }).onDelete("restrict"),
  foreignKey({ columns: [table.ownerId, table.actorAgentId], foreignColumns: [agentProfiles.ownerId, agentProfiles.id], name: "oid_run_operation_actor_agent_fk" }).onDelete("restrict"),
  uniqueIndex("oid_run_operation_owner_operation_uq").on(table.ownerId, table.operationId),
  index("oid_run_operation_agent_created_idx").on(table.actorAgentId, table.createdAt),
  check("oid_run_operation_actor_check", sql`(${table.actorKind} = 'owner' AND ${table.actorAgentId} IS NULL) OR (${table.actorKind} = 'agent' AND ${table.actorAgentId} IS NOT NULL)`),
  check("oid_run_operation_action_check", sql`${table.action} IN ('intent_create','intent_cancel','intent_accept','run_start','run_cancel')`),
  check("oid_run_operation_payload_hash_check", sql`${table.payloadHash} ~ '^[0-9a-f]{64}$'`),
  check("oid_run_operation_operation_id_check", sql`${table.operationId} ~ '^[A-Za-z0-9_-]{12,128}$'`)
]);

export const runEvents = pgTable("oid_run_event", {
  id: uuid("id").primaryKey(),
  runId: uuid("run_id").notNull(),
  sequence: integer("sequence").notNull(),
  source: text("source").notNull(),
  eventType: text("event_type").notNull(),
  payloadHash: text("payload_hash").notNull(),
  payloadJson: jsonb("payload_json").$type<Record<string, unknown>>().notNull(),
  createdAt: time("created_at").notNull().defaultNow()
}, (table) => [
  foreignKey({ columns: [table.runId], foreignColumns: [benchmarkRuns.id], name: "oid_run_event_run_fk" }).onDelete("restrict"),
  uniqueIndex("oid_run_event_run_sequence_uq").on(table.runId, table.sequence),
  index("oid_run_event_run_created_idx").on(table.runId, table.createdAt),
  check("oid_run_event_sequence_check", sql`${table.sequence} > 0`),
  check("oid_run_event_source_check", sql`${table.source} IN ('owner','agent','coordinator','worker','executor')`),
  check("oid_run_event_payload_hash_check", sql`${table.payloadHash} ~ '^[0-9a-f]{64}$'`)
]);

export const runOutbox = pgTable("oid_run_outbox", {
  eventId: uuid("event_id").primaryKey(),
  runId: uuid("run_id").notNull(),
  eventType: text("event_type").notNull(),
  payloadJson: jsonb("payload_json").$type<Record<string, unknown>>().notNull(),
  status: text("status").notNull().default("pending"),
  createdAt: time("created_at").notNull().defaultNow(),
  deliveredAt: time("delivered_at")
}, (table) => [
  foreignKey({ columns: [table.runId], foreignColumns: [benchmarkRuns.id], name: "oid_run_outbox_run_fk" }).onDelete("restrict"),
  uniqueIndex("oid_run_outbox_run_type_uq").on(table.runId, table.eventType),
  index("oid_run_outbox_status_created_idx").on(table.status, table.createdAt),
  check("oid_run_outbox_status_check", sql`${table.status} IN ('pending','delivered')`)
]);

export const runExecutionSlots = pgTable("oid_run_execution_slot", {
  agentId: uuid("agent_id").primaryKey(),
  ownerId: uuid("owner_id").notNull(),
  runId: uuid("run_id").notNull().unique(),
  claimId: uuid("claim_id").notNull().unique(),
  state: text("state").notNull().default("preparing"),
  acquiredAt: time("acquired_at").notNull().defaultNow(),
  releasedAt: time("released_at")
}, (table) => [
  foreignKey({ columns: [table.ownerId, table.agentId], foreignColumns: [agentProfiles.ownerId, agentProfiles.id], name: "oid_run_execution_slot_agent_fk" }).onDelete("restrict"),
  foreignKey({ columns: [table.runId], foreignColumns: [benchmarkRuns.id], name: "oid_run_execution_slot_run_fk" }).onDelete("restrict"),
  check("oid_run_execution_slot_state_check", sql`${table.state} IN ('preparing','running')`)
]);

export const runDispatchState = pgTable("oid_run_dispatch_state", {
  id: integer("id").primaryKey(),
  lastOwnerId: uuid("last_owner_id"),
  turnNumber: bigint("turn_number", { mode: "bigint" }).notNull().default(0n),
  updatedAt: time("updated_at").notNull().defaultNow()
}, (table) => [
  foreignKey({ columns: [table.lastOwnerId], foreignColumns: [owners.id], name: "oid_run_dispatch_state_owner_fk" }).onDelete("set null"),
  check("oid_run_dispatch_state_id_check", sql`${table.id} = 1`)
]);

export const runDispatchClaims = pgTable("oid_run_dispatch_claim", {
  runId: uuid("run_id").primaryKey(),
  ownerId: uuid("owner_id").notNull(),
  agentId: uuid("agent_id").notNull(),
  claimId: uuid("claim_id").notNull().unique(),
  turnNumber: bigint("turn_number", { mode: "bigint" }).notNull(),
  status: text("status").notNull().default("claimed"),
  claimedAt: time("claimed_at").notNull().defaultNow(),
  releasedAt: time("released_at")
}, (table) => [
  foreignKey({ columns: [table.runId], foreignColumns: [benchmarkRuns.id], name: "oid_run_dispatch_claim_run_fk" }).onDelete("restrict"),
  foreignKey({ columns: [table.ownerId], foreignColumns: [owners.id], name: "oid_run_dispatch_claim_owner_fk" }).onDelete("restrict"),
  foreignKey({ columns: [table.ownerId, table.agentId], foreignColumns: [agentProfiles.ownerId, agentProfiles.id], name: "oid_run_dispatch_claim_agent_fk" }).onDelete("restrict"),
  index("oid_run_dispatch_claim_owner_turn_idx").on(table.ownerId, table.turnNumber),
  check("oid_run_dispatch_claim_status_check", sql`${table.status} IN ('claimed','released')`)
]);

export const runModeCancellationOutbox = pgTable("oid_run_mode_cancellation_outbox", {
  eventId: uuid("event_id").primaryKey(),
  ownerId: uuid("owner_id").notNull(),
  agentId: uuid("agent_id").notNull(),
  mode: text("mode").notNull(),
  policyRevision: integer("policy_revision").notNull(),
  status: text("status").notNull().default("pending"),
  createdAt: time("created_at").notNull().defaultNow(),
  deliveredAt: time("delivered_at")
}, (table) => [
  foreignKey({ columns: [table.ownerId, table.agentId], foreignColumns: [agentProfiles.ownerId, agentProfiles.id], name: "oid_run_mode_cancellation_agent_fk" }).onDelete("restrict"),
  uniqueIndex("oid_run_mode_cancellation_mode_revision_uq").on(table.agentId, table.mode, table.policyRevision),
  index("oid_run_mode_cancellation_status_created_idx").on(table.status, table.createdAt),
  check("oid_run_mode_cancellation_mode_check", sql`${table.mode} IN ('training','ranked')`),
  check("oid_run_mode_cancellation_status_check", sql`${table.status} IN ('pending','delivered')`)
]);

export const runCancellationReceipts = pgTable("oid_run_cancellation_receipt", {
  sourceEventId: uuid("source_event_id").primaryKey(),
  sourceKind: text("source_kind").notNull(),
  cancelledRunIds: uuid("cancelled_run_ids").array().notNull().default([]),
  pendingRunIds: uuid("pending_run_ids").array().notNull().default([]),
  evidenceHash: text("evidence_hash"),
  createdAt: time("created_at").notNull().defaultNow(),
  completedAt: time("completed_at")
}, (table) => [
  check("oid_run_cancellation_receipt_source_check", sql`${table.sourceKind} IN ('agent_access_revoked','mode_removed')`),
  check("oid_run_cancellation_receipt_evidence_hash_check", sql`${table.evidenceHash} IS NULL OR ${table.evidenceHash} ~ '^[0-9a-f]{64}$'`)
]);

export const runSchema = {
  runLaunchIntents,
  benchmarkRuns,
  runReservations,
  runBudgetHolds,
  runOperations,
  runEvents,
  runOutbox,
  runExecutionSlots,
  runDispatchState,
  runDispatchClaims,
  runModeCancellationOutbox,
  runCancellationReceipts
};
