import { createHash, randomUUID } from "node:crypto";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { and, desc, eq, sql } from "drizzle-orm";
import type { OwnerDatabase } from "./db.js";
import { HttpError } from "./http-error.js";
import { owners } from "./schema.js";
import {
  agentFinancialPolicies,
  bonusGrants,
  ledgerAudit,
  ledgerEntries,
  ledgerOperations,
  type LedgerCategoryLimits
} from "./ledger-schema.js";

const unitScale = 1_000_000n;
const maxInt64 = 9_223_372_036_854_775_807n;
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const operationIdPattern = /^[A-Za-z0-9_-]{12,128}$/;
const amountPattern = /^(0|[1-9][0-9]*)(?:\.([0-9]{1,6}))?$/;
const expiryPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})$/i;

type LedgerTransaction = Parameters<Parameters<OwnerDatabase["transaction"]>[0]>[0];

export interface LedgerOwnerContext {
  owner: { id: string };
}

export interface LedgerAdminContext {
  context: LedgerOwnerContext;
}

export interface LedgerRouteDependencies {
  db: OwnerDatabase;
  resolveOwner(request: FastifyRequest): Promise<LedgerOwnerContext>;
  requireAdmin(request: FastifyRequest): Promise<LedgerAdminContext>;
  rateLimit(request: FastifyRequest, group: string, limit: number): Promise<void>;
  rateLimitMax: number;
  requireOrigin(request: FastifyRequest): Promise<void>;
}

export interface BonusGrantView {
  id: string;
  ownerId: string;
  amount: string;
  reason: string;
  createdAt: string;
  expiresAt: string | null;
}

export interface BonusGrantCommand {
  actorOwnerId: string;
  ownerId: string;
  operationId: string;
  amount: string;
  reason: string;
  expiresAt?: string;
}

export interface BonusGrantResult {
  grant: BonusGrantView;
  replayed: boolean;
  operationId: string;
}

export interface AgentFinancialPolicy {
  revision: number;
  allowCashShortfall: boolean;
  operationLimit: string | null;
  utcDayLimit: string | null;
  categoryLimits: LedgerCategoryLimits;
}

export interface UpdateAgentFinancialPolicyCommand {
  allowCashShortfall: boolean;
  operationLimit: string | null;
  utcDayLimit: string | null;
  categoryLimits: LedgerCategoryLimits;
  operationId: string;
  expectedRevision: number;
}

function asRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return {};
  return value as Record<string, unknown>;
}

function isUuid(value: unknown): value is string {
  return typeof value === "string" && uuidPattern.test(value);
}

function parseOperationId(value: unknown): string {
  if (typeof value !== "string" || !operationIdPattern.test(value)) {
    throw new HttpError(400, "INVALID_OPERATION_ID", "operationId must be a 12-128 character idempotency key");
  }
  return value;
}

function parseUuid(value: unknown, code: string, message: string): string {
  if (!isUuid(value)) throw new HttpError(400, code, message);
  return value;
}

function parseMoneyUnits(value: unknown, fieldName: string, allowNull = false): bigint | null {
  if (allowNull && value === null) return null;
  if (typeof value !== "string") {
    throw new HttpError(400, "INVALID_AMOUNT", `${fieldName} must be a decimal string${allowNull ? " or null" : ""}`);
  }
  const match = amountPattern.exec(value);
  if (!match) throw new HttpError(400, "INVALID_AMOUNT", `${fieldName} must have no more than 6 decimal places`);
  const whole = BigInt(match[1]!);
  const fraction = BigInt((match[2] ?? "").padEnd(6, "0") || "0");
  const units = whole * unitScale + fraction;
  if (units > maxInt64 || (!allowNull && units <= 0n)) {
    throw new HttpError(400, "INVALID_AMOUNT", `${fieldName} is outside the supported positive range`);
  }
  return units;
}

function formatUnits(value: bigint): string {
  if (value < 0n) throw new Error("Ledger invariant violation: negative source balance");
  const whole = value / unitScale;
  const fraction = (value % unitScale).toString().padStart(6, "0");
  return `${whole}.${fraction}`;
}

function toBigInt(value: bigint | string | number): bigint {
  return typeof value === "bigint" ? value : BigInt(value);
}

function parseReason(value: unknown): string {
  if (typeof value !== "string") throw new HttpError(400, "INVALID_REASON", "reason must be nonempty text");
  const reason = value.trim();
  if (reason.length < 1 || reason.length > 500 || /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/.test(reason)) {
    throw new HttpError(400, "INVALID_REASON", "reason must contain 1-500 safe text characters");
  }
  return reason;
}

function parseExpiry(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || !expiryPattern.test(value)) {
    throw new HttpError(400, "INVALID_EXPIRY", "expiresAt must be a timezone-qualified RFC3339 timestamp");
  }
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?(Z|[+-]\d{2}:\d{2})$/i.exec(value);
  if (!match) throw new HttpError(400, "INVALID_EXPIRY", "expiresAt must be a timezone-qualified RFC3339 timestamp");
  const [, yearText, monthText, dayText, hourText, minuteText, secondText, fractionText, zoneText] = match;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = Number(secondText);
  const millis = Number((fractionText ?? "").padEnd(3, "0"));
  if (
    year < 1 || month < 1 || month > 12 || day < 1 || hour > 23 || minute > 59 || second > 59 ||
    (zoneText !== undefined && zoneText.toUpperCase() !== "Z" &&
      (zoneText === "-00:00" || Number(zoneText.slice(1, 3)) > 23 || Number(zoneText.slice(4, 6)) > 59))
  ) {
    throw new HttpError(400, "INVALID_EXPIRY", "expiresAt must be a valid absolute RFC3339 timestamp");
  }
  const calendar = new Date(0);
  calendar.setUTCFullYear(year, month - 1, day);
  calendar.setUTCHours(hour, minute, second, millis);
  if (
    calendar.getUTCFullYear() !== year || calendar.getUTCMonth() !== month - 1 || calendar.getUTCDate() !== day ||
    !Number.isFinite(calendar.getTime())
  ) {
    throw new HttpError(400, "INVALID_EXPIRY", "expiresAt must be a valid absolute RFC3339 timestamp");
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) throw new HttpError(400, "INVALID_EXPIRY", "expiresAt must be a valid absolute RFC3339 timestamp");
  return parsed.toISOString();
}

function payloadHash(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

async function lockOwner(tx: LedgerTransaction, ownerId: string): Promise<boolean> {
  // AICODE-NOTE: Preserve FK key-share compatibility: cross-owner grants also
  // reference the issuer, so FOR UPDATE can deadlock reciprocal grants.
  const result = await tx.execute(sql`SELECT id FROM oid_owner WHERE id=${ownerId} FOR NO KEY UPDATE`);
  return result.length > 0;
}

async function lockIdempotencyKey(tx: LedgerTransaction, actorOwnerId: string, operationId: string): Promise<void> {
  const key = `${actorOwnerId}\n${operationId}`;
  await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtextextended(${key}, 0))`);
}

async function databaseNow(tx: LedgerTransaction): Promise<Date> {
  const rows = await tx.execute(sql`SELECT clock_timestamp() AS observed_at`);
  const raw = (rows[0] as { observed_at?: Date | string } | undefined)?.observed_at;
  const observedAt = raw instanceof Date ? raw : new Date(String(raw));
  if (Number.isNaN(observedAt.getTime())) throw new Error("Database clock did not return a valid timestamp");
  return observedAt;
}

function grantDtoFromReceipt(value: unknown): BonusGrantResult {
  const record = asRecord(value);
  const grant = asRecord(record.grant);
  if (typeof grant.id !== "string" || typeof grant.ownerId !== "string" || typeof grant.amount !== "string" ||
    typeof grant.reason !== "string" || typeof grant.createdAt !== "string" ||
    !(typeof grant.expiresAt === "string" || grant.expiresAt === null) || typeof record.operationId !== "string") {
    throw new Error("Stored ledger operation has an invalid bonus grant response");
  }
  return {
    grant: {
      id: grant.id,
      ownerId: grant.ownerId,
      amount: grant.amount,
      reason: grant.reason,
      createdAt: grant.createdAt,
      expiresAt: grant.expiresAt
    },
    replayed: true,
    operationId: record.operationId
  };
}

function policyFromReceipt(value: unknown): AgentFinancialPolicy {
  const row = asRecord(value);
  const categoryLimits = asRecord(row.categoryLimits);
  if (!Number.isInteger(row.revision) || typeof row.allowCashShortfall !== "boolean" ||
    !(typeof row.operationLimit === "string" || row.operationLimit === null) ||
    !(typeof row.utcDayLimit === "string" || row.utcDayLimit === null) ||
    !(typeof categoryLimits.benchmark === "string" || categoryLimits.benchmark === null) ||
    !(typeof categoryLimits.forum === "string" || categoryLimits.forum === null)) {
    throw new Error("Stored ledger operation has an invalid financial policy response");
  }
  return {
    revision: row.revision as number,
    allowCashShortfall: row.allowCashShortfall,
    operationLimit: row.operationLimit,
    utcDayLimit: row.utcDayLimit,
    categoryLimits: {
      benchmark: categoryLimits.benchmark,
      forum: categoryLimits.forum
    }
  };
}

export async function issueBonusGrant(db: OwnerDatabase, input: BonusGrantCommand): Promise<BonusGrantResult> {
  const actorOwnerId = parseUuid(input.actorOwnerId, "INVALID_ACTOR", "A verified admin owner is required");
  const ownerId = parseUuid(input.ownerId, "INVALID_OWNER_ID", "ownerId must be a UUID");
  const operationId = parseOperationId(input.operationId);
  const amountUnits = parseMoneyUnits(input.amount, "amount")!;
  const reason = parseReason(input.reason);
  const expiresAtText = parseExpiry(input.expiresAt);
  const expiresAt = expiresAtText ? new Date(expiresAtText) : null;
  const amount = formatUnits(amountUnits);
  const hash = payloadHash({ action: "bonus_grant", ownerId, amount, reason, expiresAt: expiresAtText ?? null });

  return db.transaction(async (tx) => {
    await lockIdempotencyKey(tx, actorOwnerId, operationId);
    const existingRows = await tx.select().from(ledgerOperations).where(and(
      eq(ledgerOperations.actorOwnerId, actorOwnerId),
      eq(ledgerOperations.operationId, operationId)
    )).limit(1);
    const existing = existingRows[0];
    if (existing) {
      if (existing.action !== "bonus_grant" || existing.payloadHash !== hash) {
        throw new HttpError(409, "IDEMPOTENCY_CONFLICT", "operationId was already used with a different request");
      }
      return grantDtoFromReceipt(existing.responseJson);
    }

    if (!(await lockOwner(tx, ownerId))) throw new HttpError(404, "OWNER_NOT_FOUND", "The target owner does not exist");
    const now = await databaseNow(tx);
    if (expiresAt && expiresAt.getTime() <= now.getTime()) {
      throw new HttpError(409, "EXPIRY_NOT_FUTURE", "expiresAt must be later than the database commit time");
    }

    const id = randomUUID();
    const createdAt = now.toISOString();
    const grant: BonusGrantView = { id, ownerId, amount, reason, createdAt, expiresAt: expiresAtText ?? null };
    const responseJson = { grant, operationId };
    await tx.insert(bonusGrants).values({
      id,
      ownerId,
      amountUnits,
      issuedByOwnerId: actorOwnerId,
      reason,
      operationId,
      createdAt: now,
      expiresAt
    });
    await tx.insert(ledgerEntries).values({
      id: randomUUID(),
      ownerId,
      actorOwnerId,
      bonusGrantId: id,
      operationId,
      entryType: "bonus_grant",
      sourceKind: "tester_bonus",
      amountUnits,
      availableDeltaUnits: amountUnits,
      reservedDeltaUnits: 0n,
      expiredDeltaUnits: 0n,
      reason,
      createdAt: now
    });
    await tx.insert(ledgerAudit).values({
      id: randomUUID(),
      eventType: "bonus_grant_issued",
      operationId,
      actorOwnerId,
      subjectOwnerId: ownerId,
      metadata: { grantId: id, amount, reason, expiresAt: expiresAtText ?? null, source: "tester_bonus" },
      createdAt: now
    });
    await tx.insert(ledgerOperations).values({
      id: randomUUID(),
      actorOwnerId,
      subjectOwnerId: ownerId,
      operationId,
      action: "bonus_grant",
      payloadHash: hash,
      responseJson,
      createdAt: now
    });
    return { grant, replayed: false, operationId };
  });
}

export interface BonusGrantRejectionAudit {
  actorOwnerId: string;
  subjectOwnerId?: string | null;
  operationId?: string;
  grantId?: string;
  reasonCode: string;
}

export async function auditBonusGrantRejection(db: OwnerDatabase, input: BonusGrantRejectionAudit): Promise<void> {
  const actorOwnerId = parseUuid(input.actorOwnerId, "INVALID_ACTOR", "A verified owner is required for audit");
  const operationId = typeof input.operationId === "string" && operationIdPattern.test(input.operationId)
    ? input.operationId
    : `reject_${randomUUID().replaceAll("-", "")}`;
  const reasonCode = /^[A-Z][A-Z0-9_]{1,63}$/.test(input.reasonCode) ? input.reasonCode : "REQUEST_REJECTED";
  let subjectOwnerId: string | null = null;
  let grantId: string | null = null;

  if (input.grantId && isUuid(input.grantId)) {
    const grantRows = await db.select({ id: bonusGrants.id, ownerId: bonusGrants.ownerId })
      .from(bonusGrants).where(eq(bonusGrants.id, input.grantId)).limit(1);
    const grant = grantRows[0];
    if (grant) {
      subjectOwnerId = grant.ownerId;
      grantId = grant.id;
    }
  }
  if (!subjectOwnerId && input.subjectOwnerId && isUuid(input.subjectOwnerId)) {
    const ownerRows = await db.select({ id: owners.id }).from(owners).where(eq(owners.id, input.subjectOwnerId)).limit(1);
    subjectOwnerId = ownerRows[0]?.id ?? null;
  }

  await db.insert(ledgerAudit).values({
    id: randomUUID(),
    eventType: "bonus_grant_rejected",
    operationId,
    actorOwnerId,
    subjectOwnerId,
    metadata: { reasonCode, ...(grantId ? { grantId } : {}) }
  }).onConflictDoNothing();
}

export interface BillingHistoryItem {
  id: string;
  type: string;
  source: "cash_usdc" | "tester_bonus";
  amount: string;
  createdAt: string;
  expiresAt?: string | null;
  reason?: string;
  status?: string;
}

export interface OwnerBillingView {
  cash: { available: string; reserved: string };
  bonus: { available: string; reserved: string; expired: string };
  grants: Array<{
    id: string;
    amount: string;
    available: string;
    reserved: string;
    expired: string;
    createdAt: string;
    expiresAt: string | null;
    reason: string;
    status: "available" | "partially_reserved" | "reserved" | "expired" | "spent";
  }>;
  history: BillingHistoryItem[];
  observedAt: string;
  nextUtcResetAt: string;
}

export async function readOwnerBilling(db: OwnerDatabase, ownerIdValue: string): Promise<OwnerBillingView> {
  const ownerId = parseUuid(ownerIdValue, "INVALID_OWNER_ID", "A verified owner is required");
  return db.transaction(async (tx) => {
    await tx.execute(sql`SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY`);
    const observedAtDate = await databaseNow(tx);
    const grantRows = await tx.select().from(bonusGrants).where(eq(bonusGrants.ownerId, ownerId))
      .orderBy(desc(bonusGrants.createdAt), desc(bonusGrants.id));
    const entryRows = await tx.select().from(ledgerEntries).where(eq(ledgerEntries.ownerId, ownerId))
      .orderBy(desc(ledgerEntries.createdAt), desc(ledgerEntries.id));
    const balancesByGrant = new Map<string, { available: bigint; reserved: bigint; expired: bigint }>();
    let cashAvailable = 0n;
    let cashReserved = 0n;
    for (const entry of entryRows) {
      const availableDelta = toBigInt(entry.availableDeltaUnits);
      const reservedDelta = toBigInt(entry.reservedDeltaUnits);
      const expiredDelta = toBigInt(entry.expiredDeltaUnits);
      if (entry.sourceKind === "cash_usdc") {
        cashAvailable += availableDelta;
        cashReserved += reservedDelta;
      } else if (entry.bonusGrantId) {
        const prior = balancesByGrant.get(entry.bonusGrantId) ?? { available: 0n, reserved: 0n, expired: 0n };
        balancesByGrant.set(entry.bonusGrantId, {
          available: prior.available + availableDelta,
          reserved: prior.reserved + reservedDelta,
          expired: prior.expired + expiredDelta
        });
      }
    }
    if (cashAvailable < 0n || cashReserved < 0n) throw new Error("Ledger invariant violation: negative cash balance");

    let bonusAvailable = 0n;
    let bonusReserved = 0n;
    let bonusExpired = 0n;
    const observedAtMs = observedAtDate.getTime();
    const grants = grantRows.map((grant) => {
      const balances = balancesByGrant.get(grant.id) ?? { available: 0n, reserved: 0n, expired: 0n };
      let available = balances.available;
      let reserved = balances.reserved;
      let expired = balances.expired;
      if (grant.expiresAt && grant.expiresAt.getTime() <= observedAtMs) {
        expired += available;
        available = 0n;
      }
      const issued = toBigInt(grant.amountUnits);
      if (available < 0n || reserved < 0n || expired < 0n) throw new Error("Ledger invariant violation: negative bonus lot balance");
      if (available + reserved + expired > issued) throw new Error("Ledger invariant violation: bonus lot exceeds its issued amount");
      bonusAvailable += available;
      bonusReserved += reserved;
      bonusExpired += expired;
      const status: OwnerBillingView["grants"][number]["status"] = expired > 0n && available === 0n
        ? "expired"
        : reserved > 0n && available > 0n
          ? "partially_reserved"
          : reserved > 0n
            ? "reserved"
            : available > 0n
              ? "available"
              : "spent";
      return {
        id: grant.id,
        amount: formatUnits(issued),
        available: formatUnits(available),
        reserved: formatUnits(reserved),
        expired: formatUnits(expired),
        createdAt: grant.createdAt.toISOString(),
        expiresAt: grant.expiresAt?.toISOString() ?? null,
        reason: grant.reason,
        status
      };
    });
    const grantsById = new Map(grantRows.map((grant) => [grant.id, grant]));
    const history: BillingHistoryItem[] = entryRows.map((entry) => {
      const grant = entry.bonusGrantId ? grantsById.get(entry.bonusGrantId) : undefined;
      const type = entry.entryType === "bonus_grant" ? "grant" : entry.entryType;
      return {
        id: entry.id,
        type,
        source: entry.sourceKind as "cash_usdc" | "tester_bonus",
        amount: formatUnits(toBigInt(entry.amountUnits)),
        createdAt: entry.createdAt.toISOString(),
        ...(grant ? { expiresAt: grant.expiresAt?.toISOString() ?? null, reason: entry.reason ?? grant.reason } : entry.reason ? { reason: entry.reason } : {}),
        ...(entry.entryType === "bonus_grant" ? { status: "issued" } : {})
      };
    });
    const nextUtcResetAt = new Date(Date.UTC(
      observedAtDate.getUTCFullYear(), observedAtDate.getUTCMonth(), observedAtDate.getUTCDate() + 1
    )).toISOString();
    return {
      cash: { available: formatUnits(cashAvailable), reserved: formatUnits(cashReserved) },
      bonus: {
        available: formatUnits(bonusAvailable),
        reserved: formatUnits(bonusReserved),
        expired: formatUnits(bonusExpired)
      },
      grants,
      history,
      observedAt: observedAtDate.toISOString(),
      nextUtcResetAt
    };
  });
}

function parseLimit(value: unknown, name: string): bigint | null {
  return parseMoneyUnits(value, name, true);
}

function normalizeCategoryLimits(value: unknown): LedgerCategoryLimits {
  const record = asRecord(value);
  const keys = Object.keys(record).sort();
  if (keys.length !== 2 || keys[0] !== "benchmark" || keys[1] !== "forum") {
    throw new HttpError(400, "INVALID_CATEGORY_LIMITS", "categoryLimits must contain exactly benchmark and forum");
  }
  const benchmark = parseLimit(record.benchmark, "categoryLimits.benchmark");
  const forum = parseLimit(record.forum, "categoryLimits.forum");
  return {
    benchmark: benchmark === null ? null : formatUnits(benchmark),
    forum: forum === null ? null : formatUnits(forum)
  };
}

function policyViewFromRow(row: typeof agentFinancialPolicies.$inferSelect): AgentFinancialPolicy {
  const categoryLimits = row.categoryLimits;
  return {
    revision: row.revision,
    allowCashShortfall: row.allowCashShortfall,
    operationLimit: row.operationLimitUnits === null ? null : formatUnits(toBigInt(row.operationLimitUnits)),
    utcDayLimit: row.utcDayLimitUnits === null ? null : formatUnits(toBigInt(row.utcDayLimitUnits)),
    categoryLimits: {
      benchmark: categoryLimits.benchmark,
      forum: categoryLimits.forum
    }
  };
}

const defaultPolicy = (): AgentFinancialPolicy => ({
  revision: 0,
  allowCashShortfall: false,
  operationLimit: "0.000000",
  utcDayLimit: "0.000000",
  categoryLimits: { benchmark: "0.000000", forum: "0.000000" }
});

async function requireOwnedAgent(tx: LedgerTransaction, ownerId: string, agentId: string): Promise<boolean> {
  const result = await tx.execute(sql`SELECT id FROM oid_agent WHERE owner_id=${ownerId} AND id=${agentId}`);
  return result.length > 0;
}

export async function readAgentFinancialPolicy(db: OwnerDatabase, ownerIdValue: string, agentIdValue: string): Promise<AgentFinancialPolicy> {
  const ownerId = parseUuid(ownerIdValue, "INVALID_OWNER_ID", "A verified owner is required");
  const agentId = parseUuid(agentIdValue, "INVALID_AGENT_ID", "agentId must be a UUID");
  return db.transaction(async (tx) => {
    if (!(await requireOwnedAgent(tx, ownerId, agentId))) throw new HttpError(404, "AGENT_NOT_FOUND", "The agent does not exist for this owner");
    const rows = await tx.select().from(agentFinancialPolicies).where(and(
      eq(agentFinancialPolicies.ownerId, ownerId),
      eq(agentFinancialPolicies.agentId, agentId)
    )).limit(1);
    return rows[0] ? policyViewFromRow(rows[0]) : defaultPolicy();
  });
}

export async function updateAgentFinancialPolicy(
  db: OwnerDatabase,
  ownerIdValue: string,
  agentIdValue: string,
  input: UpdateAgentFinancialPolicyCommand
): Promise<AgentFinancialPolicy> {
  const ownerId = parseUuid(ownerIdValue, "INVALID_OWNER_ID", "A verified owner is required");
  const agentId = parseUuid(agentIdValue, "INVALID_AGENT_ID", "agentId must be a UUID");
  const operationId = parseOperationId(input.operationId);
  if (!Number.isSafeInteger(input.expectedRevision) || input.expectedRevision < 0) {
    throw new HttpError(400, "INVALID_REVISION", "expectedRevision must be a nonnegative integer");
  }
  if (typeof input.allowCashShortfall !== "boolean") {
    throw new HttpError(400, "INVALID_CASH_POLICY", "allowCashShortfall must be a boolean");
  }
  const operationLimitUnits = parseLimit(input.operationLimit, "operationLimit");
  const utcDayLimitUnits = parseLimit(input.utcDayLimit, "utcDayLimit");
  const category = normalizeCategoryLimits(input.categoryLimits);
  const normalized: AgentFinancialPolicy = {
    revision: input.expectedRevision + 1,
    allowCashShortfall: input.allowCashShortfall,
    operationLimit: operationLimitUnits === null ? null : formatUnits(operationLimitUnits),
    utcDayLimit: utcDayLimitUnits === null ? null : formatUnits(utcDayLimitUnits),
    categoryLimits: category
  };
  const hash = payloadHash({
    action: "agent_financial_policy_update",
    ownerId,
    agentId,
    expectedRevision: input.expectedRevision,
    allowCashShortfall: normalized.allowCashShortfall,
    operationLimit: normalized.operationLimit,
    utcDayLimit: normalized.utcDayLimit,
    categoryLimits: normalized.categoryLimits
  });

  return db.transaction(async (tx) => {
    await lockIdempotencyKey(tx, ownerId, operationId);
    const existingRows = await tx.select().from(ledgerOperations).where(and(
      eq(ledgerOperations.actorOwnerId, ownerId),
      eq(ledgerOperations.operationId, operationId)
    )).limit(1);
    const existing = existingRows[0];
    if (existing) {
      if (existing.action !== "agent_financial_policy_update" || existing.payloadHash !== hash) {
        throw new HttpError(409, "IDEMPOTENCY_CONFLICT", "operationId was already used with a different request");
      }
      return policyFromReceipt(existing.responseJson);
    }

    if (!(await lockOwner(tx, ownerId))) throw new HttpError(404, "OWNER_NOT_FOUND", "The owner does not exist");
    if (!(await requireOwnedAgent(tx, ownerId, agentId))) throw new HttpError(404, "AGENT_NOT_FOUND", "The agent does not exist for this owner");
    const currentRows = await tx.select().from(agentFinancialPolicies).where(and(
      eq(agentFinancialPolicies.ownerId, ownerId),
      eq(agentFinancialPolicies.agentId, agentId)
    )).limit(1);
    const current = currentRows[0];
    const currentRevision = current?.revision ?? 0;
    if (currentRevision !== input.expectedRevision) {
      throw new HttpError(409, "REVISION_CONFLICT", "The financial policy changed; reload it before retrying");
    }

    const now = await databaseNow(tx);
    const values = {
      ownerId,
      agentId,
      allowCashShortfall: normalized.allowCashShortfall,
      operationLimitUnits,
      utcDayLimitUnits,
      categoryLimits: category,
      revision: currentRevision + 1,
      updatedAt: now
    };
    if (current) {
      await tx.update(agentFinancialPolicies).set(values).where(and(
        eq(agentFinancialPolicies.ownerId, ownerId),
        eq(agentFinancialPolicies.agentId, agentId),
        eq(agentFinancialPolicies.revision, currentRevision)
      ));
    } else {
      await tx.insert(agentFinancialPolicies).values(values);
    }
    const response: AgentFinancialPolicy = { ...normalized, revision: currentRevision + 1 };
    await tx.insert(ledgerAudit).values({
      id: randomUUID(),
      eventType: "agent_financial_policy_updated",
      operationId,
      actorOwnerId: ownerId,
      subjectOwnerId: ownerId,
      metadata: {
        agentId,
        revision: response.revision,
        allowCashShortfall: response.allowCashShortfall,
        operationLimit: response.operationLimit,
        utcDayLimit: response.utcDayLimit,
        categoryLimits: response.categoryLimits
      },
      createdAt: now
    });
    await tx.insert(ledgerOperations).values({
      id: randomUUID(),
      actorOwnerId: ownerId,
      subjectOwnerId: ownerId,
      operationId,
      action: "agent_financial_policy_update",
      payloadHash: hash,
      responseJson: {
        revision: response.revision,
        allowCashShortfall: response.allowCashShortfall,
        operationLimit: response.operationLimit,
        utcDayLimit: response.utcDayLimit,
        categoryLimits: response.categoryLimits
      },
      createdAt: now
    });
    return response;
  });
}

function toBonusGrantCommand(actorOwnerId: string, value: unknown): BonusGrantCommand {
  const body = asRecord(value);
  const allowedKeys = new Set(["operationId", "ownerId", "amount", "reason", "expiresAt"]);
  if (Object.keys(body).some((key) => !allowedKeys.has(key))) {
    throw new HttpError(400, "INVALID_REQUEST", "The request contains unsupported fields");
  }
  return {
    actorOwnerId,
    operationId: parseOperationId(body.operationId),
    ownerId: parseUuid(body.ownerId, "INVALID_OWNER_ID", "ownerId must be a UUID"),
    amount: typeof body.amount === "string" ? body.amount : "",
    reason: typeof body.reason === "string" ? body.reason : "",
    ...(body.expiresAt === undefined ? {} : { expiresAt: typeof body.expiresAt === "string" ? body.expiresAt : "" })
  };
}

function toPolicyCommand(value: unknown): UpdateAgentFinancialPolicyCommand {
  const body = asRecord(value);
  const allowedKeys = new Set([
    "operationId", "expectedRevision", "allowCashShortfall", "operationLimit", "utcDayLimit", "categoryLimits"
  ]);
  if (Object.keys(body).some((key) => !allowedKeys.has(key))) {
    throw new HttpError(400, "INVALID_REQUEST", "The request contains unsupported fields");
  }
  if (typeof body.expectedRevision !== "number") throw new HttpError(400, "INVALID_REVISION", "expectedRevision must be an integer");
  return {
    operationId: parseOperationId(body.operationId),
    expectedRevision: body.expectedRevision,
    allowCashShortfall: body.allowCashShortfall as boolean,
    operationLimit: body.operationLimit as string | null,
    utcDayLimit: body.utcDayLimit as string | null,
    categoryLimits: body.categoryLimits as LedgerCategoryLimits
  };
}

function sendError(reply: FastifyReply, error: unknown) {
  if (error instanceof HttpError) {
    return reply.code(error.status).header("Cache-Control", "no-store").send({ error: { code: error.code, message: error.message } });
  }
  return reply.code(500).header("Cache-Control", "no-store").send({
    error: { code: "INTERNAL_ERROR", message: "The request could not be completed" }
  });
}

function operationIdFromBody(value: unknown): string | undefined {
  const candidate = asRecord(value).operationId;
  return typeof candidate === "string" && operationIdPattern.test(candidate) ? candidate : undefined;
}

const grantRejectionCodes = new Set([
  "INVALID_REQUEST", "INVALID_OPERATION_ID", "INVALID_OWNER_ID", "INVALID_AMOUNT", "INVALID_REASON", "INVALID_EXPIRY",
  "OWNER_NOT_FOUND", "IDEMPOTENCY_CONFLICT", "EXPIRY_NOT_FUTURE", "INVALID_GRANT_ID", "GRANT_NOT_FOUND", "IMMUTABLE_GRANT"
]);

async function auditRejectedAdminAttempt(
  dependencies: LedgerRouteDependencies,
  request: FastifyRequest,
  error: unknown,
  grantId?: string
): Promise<void> {
  if (!(error instanceof HttpError)) return;
  let actorOwnerId: string | undefined;
  try {
    if (error.status === 403) actorOwnerId = (await dependencies.resolveOwner(request)).owner.id;
    if (!actorOwnerId) return;
    const body = asRecord(request.body);
    const operationId = operationIdFromBody(request.body);
    await auditBonusGrantRejection(dependencies.db, {
      actorOwnerId,
      ...(isUuid(body.ownerId) ? { subjectOwnerId: body.ownerId } : {}),
      ...(operationId ? { operationId } : {}),
      ...(grantId ? { grantId } : {}),
      reasonCode: grantRejectionCodes.has(error.code) ? error.code : "FORBIDDEN"
    });
  } catch {
    // A rejected command must never be converted into a grant by an audit failure.
  }
}

export function registerLedgerRoutes(app: FastifyInstance, dependencies: LedgerRouteDependencies): void {
  app.post("/api/admin/bonus-grants", async (request, reply) => {
    let actorOwnerId: string | undefined;
    try {
      await dependencies.rateLimit(request, "bonus-grants", dependencies.rateLimitMax);
      await dependencies.requireOrigin(request);
      const auth = await dependencies.requireAdmin(request);
      actorOwnerId = auth.context.owner.id;
      const command = toBonusGrantCommand(actorOwnerId, request.body);
      const result = await issueBonusGrant(dependencies.db, command);
      return reply.code(200).header("Cache-Control", "no-store").send(result);
    } catch (error) {
      if (actorOwnerId && error instanceof HttpError && grantRejectionCodes.has(error.code)) {
        const operationId = operationIdFromBody(request.body);
        await auditBonusGrantRejection(dependencies.db, {
          actorOwnerId,
          ...(isUuid(asRecord(request.body).ownerId) ? { subjectOwnerId: asRecord(request.body).ownerId as string } : {}),
          ...(operationId ? { operationId } : {}),
          reasonCode: error.code
        }).catch(() => undefined);
      } else if (!actorOwnerId) {
        await auditRejectedAdminAttempt(dependencies, request, error);
      }
      return sendError(reply, error);
    }
  });

  const rejectGrantEdit = async (request: FastifyRequest<{ Params: { grantId: string } }>, reply: FastifyReply) => {
    let actorOwnerId: string | undefined;
    let grantId: string | undefined;
    try {
      await dependencies.rateLimit(request, "bonus-grants", dependencies.rateLimitMax);
      await dependencies.requireOrigin(request);
      const auth = await dependencies.requireAdmin(request);
      actorOwnerId = auth.context.owner.id;
      grantId = parseUuid(request.params.grantId, "INVALID_GRANT_ID", "grantId must be a UUID");
      const rows = await dependencies.db.select({ id: bonusGrants.id, ownerId: bonusGrants.ownerId })
        .from(bonusGrants).where(eq(bonusGrants.id, grantId)).limit(1);
      const grant = rows[0];
      if (!grant) throw new HttpError(404, "GRANT_NOT_FOUND", "The bonus grant does not exist");
      const operationId = operationIdFromBody(request.body);
      await auditBonusGrantRejection(dependencies.db, {
        actorOwnerId,
        subjectOwnerId: grant.ownerId,
        grantId: grant.id,
        ...(operationId ? { operationId } : {}),
        reasonCode: "IMMUTABLE_GRANT"
      });
      throw new HttpError(409, "IMMUTABLE_GRANT", "Bonus grant terms are immutable");
    } catch (error) {
      if (!actorOwnerId) await auditRejectedAdminAttempt(dependencies, request, error, grantId);
      else if (error instanceof HttpError && grantRejectionCodes.has(error.code) && error.code !== "IMMUTABLE_GRANT") {
        const operationId = operationIdFromBody(request.body);
        await auditBonusGrantRejection(dependencies.db, {
          actorOwnerId,
          ...(grantId ? { grantId } : {}),
          ...(operationId ? { operationId } : {}),
          reasonCode: error.code
        }).catch(() => undefined);
      }
      return sendError(reply, error);
    }
  };

  app.put<{ Params: { grantId: string } }>("/api/admin/bonus-grants/:grantId", rejectGrantEdit);
  app.patch<{ Params: { grantId: string } }>("/api/admin/bonus-grants/:grantId", rejectGrantEdit);

  app.get("/api/owner/billing", async (request, reply) => {
    try {
      await dependencies.rateLimit(request, "owner-billing", dependencies.rateLimitMax);
      const owner = await dependencies.resolveOwner(request);
      const billing = await readOwnerBilling(dependencies.db, owner.owner.id);
      return reply.header("Cache-Control", "no-store").send(billing);
    } catch (error) {
      return sendError(reply, error);
    }
  });

  app.get<{ Params: { id: string } }>("/api/owner/agents/:id/financial-policy", async (request, reply) => {
    try {
      await dependencies.rateLimit(request, "owner-financial-policy", dependencies.rateLimitMax);
      const owner = await dependencies.resolveOwner(request);
      const policy = await readAgentFinancialPolicy(dependencies.db, owner.owner.id, request.params.id);
      return reply.header("Cache-Control", "no-store").send(policy);
    } catch (error) {
      return sendError(reply, error);
    }
  });

  app.put<{ Params: { id: string } }>("/api/owner/agents/:id/financial-policy", async (request, reply) => {
    let ownerId: string | undefined;
    try {
      await dependencies.rateLimit(request, "owner-financial-policy", dependencies.rateLimitMax);
      await dependencies.requireOrigin(request);
      const owner = await dependencies.resolveOwner(request);
      ownerId = owner.owner.id;
      const command = toPolicyCommand(request.body);
      const policy = await updateAgentFinancialPolicy(dependencies.db, ownerId, request.params.id, command);
      return reply.header("Cache-Control", "no-store").send(policy);
    } catch (error) {
      return sendError(reply, error);
    }
  });
}
