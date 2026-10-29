import { sql } from "drizzle-orm";
import {
  bigint,
  check,
  foreignKey,
  index,
  integer,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
  uuid
} from "drizzle-orm/pg-core";
import { owners } from "./schema.js";
import { bonusGrants } from "./ledger-schema.js";

const time = (name: string) => timestamp(name, { withTimezone: true, mode: "date" });

export const bonusCodes = pgTable("oid_bonus_code", {
  id: uuid("id").primaryKey(),
  issuerOwnerId: uuid("issuer_owner_id").notNull(),
  label: text("label").notNull(),
  kind: text("kind").notNull(),
  amountUnits: bigint("amount_units", { mode: "bigint" }).notNull(),
  maximumUses: integer("maximum_uses").notNull(),
  usedCount: integer("used_count").notNull().default(0),
  verifierHash: text("verifier_hash").notNull(),
  issueOperationId: text("issue_operation_id").notNull(),
  issuePayloadHash: text("issue_payload_hash").notNull(),
  issuedAt: time("issued_at").notNull().defaultNow(),
  disabledAt: time("disabled_at"),
  disableOperationId: text("disable_operation_id"),
  disablePayloadHash: text("disable_payload_hash")
}, (table) => [
  foreignKey({
    columns: [table.issuerOwnerId],
    foreignColumns: [owners.id],
    name: "oid_bonus_code_issuer_fk"
  }).onDelete("restrict"),
  uniqueIndex("oid_bonus_code_verifier_uq").on(table.verifierHash),
  uniqueIndex("oid_bonus_code_issuer_operation_uq").on(table.issuerOwnerId, table.issueOperationId),
  index("oid_bonus_code_issuer_issued_idx").on(table.issuerOwnerId, table.issuedAt, table.id),
  check("oid_bonus_code_label_check", sql`char_length(${table.label}) BETWEEN 1 AND 100`),
  check("oid_bonus_code_kind_check", sql`${table.kind} IN ('group', 'single_use')`),
  check("oid_bonus_code_amount_check", sql`${table.amountUnits} > 0`),
  check("oid_bonus_code_maximum_uses_check", sql`${table.maximumUses} > 0`),
  check("oid_bonus_code_used_count_check", sql`${table.usedCount} >= 0 AND ${table.usedCount} <= ${table.maximumUses}`),
  check("oid_bonus_code_single_use_check", sql`${table.kind} <> 'single_use' OR ${table.maximumUses} = 1`),
  check("oid_bonus_code_verifier_hash_check", sql`${table.verifierHash} ~ '^[0-9a-f]{64}$'`),
  check("oid_bonus_code_issue_operation_id_check", sql`${table.issueOperationId} ~ '^[A-Za-z0-9_-]{12,128}$'`),
  check("oid_bonus_code_issue_payload_hash_check", sql`${table.issuePayloadHash} ~ '^[0-9a-f]{64}$'`),
  check("oid_bonus_code_disable_operation_id_check", sql`${table.disableOperationId} IS NULL OR ${table.disableOperationId} ~ '^[A-Za-z0-9_-]{12,128}$'`),
  check("oid_bonus_code_disable_payload_hash_check", sql`${table.disablePayloadHash} IS NULL OR ${table.disablePayloadHash} ~ '^[0-9a-f]{64}$'`),
  check("oid_bonus_code_disable_fields_check", sql`(${table.disabledAt} IS NULL AND ${table.disableOperationId} IS NULL AND ${table.disablePayloadHash} IS NULL) OR (${table.disabledAt} IS NOT NULL AND ${table.disableOperationId} IS NOT NULL AND ${table.disablePayloadHash} IS NOT NULL)`)
]);

export const bonusCodeRedemptions = pgTable("oid_bonus_code_redemption", {
  id: uuid("id").primaryKey(),
  codeId: uuid("code_id").notNull(),
  ownerId: uuid("owner_id").notNull(),
  bonusGrantId: uuid("bonus_grant_id").notNull(),
  financialOperationId: text("financial_operation_id").notNull(),
  createdAt: time("created_at").notNull().defaultNow()
}, (table) => [
  foreignKey({
    columns: [table.codeId],
    foreignColumns: [bonusCodes.id],
    name: "oid_bonus_code_redemption_code_fk"
  }).onDelete("restrict"),
  foreignKey({
    columns: [table.ownerId],
    foreignColumns: [owners.id],
    name: "oid_bonus_code_redemption_owner_fk"
  }).onDelete("restrict"),
  foreignKey({
    columns: [table.ownerId, table.bonusGrantId],
    foreignColumns: [bonusGrants.ownerId, bonusGrants.id],
    name: "oid_bonus_code_redemption_grant_fk"
  }).onDelete("restrict"),
  uniqueIndex("oid_bonus_code_redemption_code_owner_uq").on(table.codeId, table.ownerId),
  uniqueIndex("oid_bonus_code_redemption_grant_uq").on(table.bonusGrantId),
  uniqueIndex("oid_bonus_code_redemption_financial_operation_uq").on(table.financialOperationId),
  index("oid_bonus_code_redemption_owner_created_idx").on(table.ownerId, table.createdAt, table.id),
  check("oid_bonus_code_redemption_financial_operation_id_check", sql`${table.financialOperationId} ~ '^[A-Za-z0-9_-]{12,128}$'`)
]);

export const bonusCodeClaimOperations = pgTable("oid_bonus_code_claim_operation", {
  ownerId: uuid("owner_id").notNull(),
  operationId: text("operation_id").notNull(),
  codeId: uuid("code_id").notNull(),
  redemptionId: uuid("redemption_id").notNull(),
  payloadHash: text("payload_hash").notNull(),
  createdAt: time("created_at").notNull().defaultNow()
}, (table) => [
  foreignKey({
    columns: [table.ownerId],
    foreignColumns: [owners.id],
    name: "oid_bonus_code_claim_operation_owner_fk"
  }).onDelete("restrict"),
  foreignKey({
    columns: [table.codeId],
    foreignColumns: [bonusCodes.id],
    name: "oid_bonus_code_claim_operation_code_fk"
  }).onDelete("restrict"),
  foreignKey({
    columns: [table.redemptionId],
    foreignColumns: [bonusCodeRedemptions.id],
    name: "oid_bonus_code_claim_operation_redemption_fk"
  }).onDelete("restrict"),
  uniqueIndex("oid_bonus_code_claim_operation_owner_key_uq").on(table.ownerId, table.operationId),
  index("oid_bonus_code_claim_operation_redemption_idx").on(table.redemptionId),
  check("oid_bonus_code_claim_operation_id_check", sql`${table.operationId} ~ '^[A-Za-z0-9_-]{12,128}$'`),
  check("oid_bonus_code_claim_operation_payload_hash_check", sql`${table.payloadHash} ~ '^[0-9a-f]{64}$'`)
]);

export const bonusCodeSchema = {
  bonusCodes,
  bonusCodeRedemptions,
  bonusCodeClaimOperations
};
