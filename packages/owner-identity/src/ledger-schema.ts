import { sql } from "drizzle-orm";
import {
  bigint,
  boolean,
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

export type LedgerCategoryLimits = {
  benchmark: string | null;
  forum: string | null;
};

export const ledgerOperations = pgTable("oid_ledger_operation", {
  id: uuid("id").primaryKey(),
  actorOwnerId: uuid("actor_owner_id").notNull(),
  subjectOwnerId: uuid("subject_owner_id").notNull(),
  operationId: text("operation_id").notNull(),
  action: text("action").notNull(),
  payloadHash: text("payload_hash").notNull(),
  responseJson: jsonb("response_json").$type<Record<string, unknown>>().notNull(),
  createdAt: timestamp("created_at", { withTimezone: true, mode: "date" }).notNull().defaultNow()
}, (table) => [
  foreignKey({
    columns: [table.actorOwnerId],
    foreignColumns: [owners.id],
    name: "oid_ledger_operation_actor_fk"
  }).onDelete("restrict"),
  foreignKey({
    columns: [table.subjectOwnerId],
    foreignColumns: [owners.id],
    name: "oid_ledger_operation_subject_fk"
  }).onDelete("restrict"),
  uniqueIndex("oid_ledger_operation_actor_operation_uq").on(table.actorOwnerId, table.operationId),
  index("oid_ledger_operation_subject_created_idx").on(table.subjectOwnerId, table.createdAt),
  check("oid_ledger_operation_id_check", sql`${table.operationId} ~ '^[A-Za-z0-9_-]{12,128}$'`),
  check("oid_ledger_operation_action_check", sql`${table.action} IN ('bonus_grant', 'agent_financial_policy_update')`),
  check("oid_ledger_operation_payload_hash_check", sql`${table.payloadHash} ~ '^[0-9a-f]{64}$'`)
]);

export const bonusGrants = pgTable("oid_bonus_grant", {
  id: uuid("id").primaryKey(),
  ownerId: uuid("owner_id").notNull(),
  amountUnits: bigint("amount_units", { mode: "bigint" }).notNull(),
  issuedByOwnerId: uuid("issued_by_owner_id").notNull(),
  reason: text("reason").notNull(),
  operationId: text("operation_id").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true, mode: "date" }).notNull().defaultNow(),
  expiresAt: timestamp("expires_at", { withTimezone: true, mode: "date" })
}, (table) => [
  foreignKey({
    columns: [table.ownerId],
    foreignColumns: [owners.id],
    name: "oid_bonus_grant_owner_fk"
  }).onDelete("restrict"),
  foreignKey({
    columns: [table.issuedByOwnerId],
    foreignColumns: [owners.id],
    name: "oid_bonus_grant_issuer_fk"
  }).onDelete("restrict"),
  uniqueIndex("oid_bonus_grant_issuer_operation_uq").on(table.issuedByOwnerId, table.operationId),
  uniqueIndex("oid_bonus_grant_owner_id_uq").on(table.ownerId, table.id),
  index("oid_bonus_grant_owner_created_idx").on(table.ownerId, table.createdAt, table.id),
  check("oid_bonus_grant_positive_amount_check", sql`${table.amountUnits} > 0`),
  check("oid_bonus_grant_reason_check", sql`char_length(${table.reason}) BETWEEN 1 AND 500`),
  check("oid_bonus_grant_expiry_check", sql`${table.expiresAt} IS NULL OR ${table.expiresAt} > ${table.createdAt}`),
  check("oid_bonus_grant_operation_id_check", sql`${table.operationId} ~ '^[A-Za-z0-9_-]{12,128}$'`)
]);

export const ledgerEntries = pgTable("oid_ledger_entry", {
  id: uuid("id").primaryKey(),
  ownerId: uuid("owner_id").notNull(),
  actorOwnerId: uuid("actor_owner_id"),
  bonusGrantId: uuid("bonus_grant_id"),
  operationId: text("operation_id").notNull(),
  entryType: text("entry_type").notNull(),
  sourceKind: text("source_kind").notNull(),
  amountUnits: bigint("amount_units", { mode: "bigint" }).notNull(),
  availableDeltaUnits: bigint("available_delta_units", { mode: "bigint" }).notNull().default(0n),
  reservedDeltaUnits: bigint("reserved_delta_units", { mode: "bigint" }).notNull().default(0n),
  expiredDeltaUnits: bigint("expired_delta_units", { mode: "bigint" }).notNull().default(0n),
  cashProvenance: text("cash_provenance"),
  reason: text("reason"),
  createdAt: timestamp("created_at", { withTimezone: true, mode: "date" }).notNull().defaultNow()
}, (table) => [
  foreignKey({
    columns: [table.ownerId],
    foreignColumns: [owners.id],
    name: "oid_ledger_entry_owner_fk"
  }).onDelete("restrict"),
  foreignKey({
    columns: [table.actorOwnerId],
    foreignColumns: [owners.id],
    name: "oid_ledger_entry_actor_fk"
  }).onDelete("restrict"),
  foreignKey({
    columns: [table.ownerId, table.bonusGrantId],
    foreignColumns: [bonusGrants.ownerId, bonusGrants.id],
    name: "oid_ledger_entry_owner_bonus_grant_fk"
  }).onDelete("restrict"),
  index("oid_ledger_entry_owner_created_idx").on(table.ownerId, table.createdAt, table.id),
  index("oid_ledger_entry_operation_idx").on(table.operationId),
  uniqueIndex("oid_ledger_entry_grant_event_uq").on(table.bonusGrantId).where(sql`${table.entryType} = 'bonus_grant' AND ${table.bonusGrantId} IS NOT NULL`),
  check("oid_ledger_entry_source_check", sql`${table.sourceKind} IN ('cash_usdc', 'tester_bonus')`),
  check("oid_ledger_entry_type_check", sql`${table.entryType} IN ('bonus_grant', 'cash_credit', 'reserve', 'release', 'debit', 'refund', 'expiry')`),
  check("oid_ledger_entry_positive_amount_check", sql`${table.amountUnits} > 0`),
  check(
    "oid_ledger_entry_delta_check",
    sql`${table.availableDeltaUnits} <> 0 OR ${table.reservedDeltaUnits} <> 0 OR ${table.expiredDeltaUnits} <> 0`
  ),
  check(
    "oid_ledger_entry_bonus_grant_check",
    sql`(${table.sourceKind} = 'tester_bonus' AND ${table.bonusGrantId} IS NOT NULL) OR (${table.sourceKind} = 'cash_usdc' AND ${table.bonusGrantId} IS NULL)`
  ),
  check(
    "oid_ledger_entry_cash_provenance_check",
    sql`(${table.sourceKind} = 'cash_usdc' AND ${table.cashProvenance} IS NOT NULL AND char_length(${table.cashProvenance}) BETWEEN 1 AND 120) OR (${table.sourceKind} = 'tester_bonus' AND ${table.cashProvenance} IS NULL)`
  ),
  check("oid_ledger_entry_operation_id_check", sql`${table.operationId} ~ '^[A-Za-z0-9_-]{12,128}$'`)
]);

export const ledgerAudit = pgTable("oid_ledger_audit", {
  id: uuid("id").primaryKey(),
  eventType: text("event_type").notNull(),
  operationId: text("operation_id").notNull(),
  actorOwnerId: uuid("actor_owner_id").notNull(),
  subjectOwnerId: uuid("subject_owner_id"),
  metadata: jsonb("metadata").$type<Record<string, unknown>>().notNull().default({}),
  createdAt: timestamp("created_at", { withTimezone: true, mode: "date" }).notNull().defaultNow()
}, (table) => [
  foreignKey({
    columns: [table.actorOwnerId],
    foreignColumns: [owners.id],
    name: "oid_ledger_audit_actor_fk"
  }).onDelete("restrict"),
  foreignKey({
    columns: [table.subjectOwnerId],
    foreignColumns: [owners.id],
    name: "oid_ledger_audit_subject_fk"
  }).onDelete("restrict"),
  uniqueIndex("oid_ledger_audit_actor_operation_event_uq").on(table.actorOwnerId, table.operationId, table.eventType),
  index("oid_ledger_audit_type_created_idx").on(table.eventType, table.createdAt),
  check("oid_ledger_audit_operation_id_check", sql`${table.operationId} ~ '^[A-Za-z0-9_-]{12,128}$'`)
]);

export const agentFinancialPolicies = pgTable("oid_agent_financial_policy", {
  ownerId: uuid("owner_id").notNull(),
  agentId: uuid("agent_id").notNull(),
  allowCashShortfall: boolean("allow_cash_shortfall").notNull().default(false),
  operationLimitUnits: bigint("operation_limit_units", { mode: "bigint" }).default(0n),
  utcDayLimitUnits: bigint("utc_day_limit_units", { mode: "bigint" }).default(0n),
  categoryLimits: jsonb("category_limits").$type<LedgerCategoryLimits>().notNull().default({ benchmark: "0.000000", forum: "0.000000" }),
  revision: integer("revision").notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" }).notNull().defaultNow()
}, (table) => [
  primaryKey({ columns: [table.ownerId, table.agentId], name: "oid_agent_financial_policy_owner_agent_pk" }),
  foreignKey({
    columns: [table.ownerId, table.agentId],
    foreignColumns: [agentProfiles.ownerId, agentProfiles.id],
    name: "oid_agent_financial_policy_agent_owner_fk"
  }).onDelete("cascade"),
  check("oid_agent_financial_policy_operation_limit_check", sql`${table.operationLimitUnits} IS NULL OR ${table.operationLimitUnits} >= 0`),
  check("oid_agent_financial_policy_utc_day_limit_check", sql`${table.utcDayLimitUnits} IS NULL OR ${table.utcDayLimitUnits} >= 0`),
  check("oid_agent_financial_policy_revision_check", sql`${table.revision} > 0`),
  check(
    "oid_agent_financial_policy_category_shape_check",
    sql`jsonb_typeof(${table.categoryLimits}) = 'object'
      AND ${table.categoryLimits} ? 'benchmark' AND ${table.categoryLimits} ? 'forum'
      AND (${table.categoryLimits} - 'benchmark' - 'forum') = '{}'::jsonb
      AND (${table.categoryLimits}->'benchmark' = 'null'::jsonb OR (jsonb_typeof(${table.categoryLimits}->'benchmark') = 'string' AND ${table.categoryLimits}->>'benchmark' ~ '^(0|[1-9][0-9]*)[.][0-9]{6}$'))
      AND (${table.categoryLimits}->'forum' = 'null'::jsonb OR (jsonb_typeof(${table.categoryLimits}->'forum') = 'string' AND ${table.categoryLimits}->>'forum' ~ '^(0|[1-9][0-9]*)[.][0-9]{6}$'))`
  )
]);

export const ledgerSchema = {
  ledgerOperations,
  bonusGrants,
  ledgerEntries,
  ledgerAudit,
  agentFinancialPolicies
};
