import { createHash, createHmac, randomBytes, randomUUID } from "node:crypto";
import { and, desc, eq, inArray } from "drizzle-orm";
import { sql } from "drizzle-orm";
import type { OwnerDatabase } from "./db.js";
import { bonusCodeClaimOperations, bonusCodes, bonusCodeRedemptions } from "./bonus-code-schema.js";
import { HttpError } from "./http-error.js";
import { ledgerAudit } from "./ledger-schema.js";
import { issueBonusGrantInTransaction, lockLedgerOperationKey, lockLedgerOwner, type LedgerTransaction } from "./ledger.js";

const unitScale = 1_000_000n;
const maxInt64 = 9_223_372_036_854_775_807n;
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const operationIdPattern = /^[A-Za-z0-9_-]{12,128}$/;
const amountPattern = /^(0|[1-9][0-9]*)(?:\.([0-9]{1,6}))?$/;
const codePattern = /^BPC-[A-Za-z0-9_-]{43}$/;

type CodeRow = {
  id: string;
  issuerOwnerId: string;
  label: string;
  kind: "group" | "single_use";
  amountUnits: bigint;
  maximumUses: number;
  usedCount: number;
  issuedAt: Date;
  disabledAt: Date | null;
  disableOperationId: string | null;
  disablePayloadHash: string | null;
};

export interface BonusCodeView {
  id: string;
  label: string;
  kind: "group" | "single_use";
  amount: string;
  maximumUses: number;
  usedCount: number;
  issuedAt: string;
  disabledAt: string | null;
}

export interface IssueBonusCodeCommand {
  issuerOwnerId: string;
  codeVerifierSecret: string;
  operationId: string;
  label: string;
  kind: "group" | "single_use";
  amount: string;
  maximumUses: number;
}

export interface IssueBonusCodeResult {
  code: BonusCodeView;
  operationId: string;
  replayed: boolean;
  secret: string | null;
}

export interface BonusCodeRedemptionView {
  id: string;
  codeId: string;
  label: string;
  kind: "group" | "single_use";
  amount: string;
  grantId: string;
  createdAt: string;
}

export interface RedeemBonusCodeResult {
  redemption: BonusCodeRedemptionView;
  operationId: string;
  replayed: boolean;
}

export interface DisableBonusCodeResult {
  code: BonusCodeView;
  operationId: string | null;
  replayed: boolean;
}

function asRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return {};
  return value as Record<string, unknown>;
}

function parseUuid(value: unknown, code: string, message: string): string {
  if (typeof value !== "string" || !uuidPattern.test(value)) throw new HttpError(400, code, message);
  return value;
}

function parseOperationId(value: unknown): string {
  if (typeof value !== "string" || !operationIdPattern.test(value)) {
    throw new HttpError(400, "INVALID_OPERATION_ID", "operationId must be a 12-128 character idempotency key");
  }
  return value;
}

function parseMoneyUnits(value: unknown): bigint {
  if (typeof value !== "string") throw new HttpError(400, "INVALID_AMOUNT", "amount must be a decimal string");
  const match = amountPattern.exec(value);
  if (!match) throw new HttpError(400, "INVALID_AMOUNT", "amount must have no more than 6 decimal places");
  const units = BigInt(match[1]!) * unitScale + BigInt((match[2] ?? "").padEnd(6, "0") || "0");
  if (units <= 0n || units > maxInt64) {
    throw new HttpError(400, "INVALID_AMOUNT", "amount is outside the supported positive range");
  }
  return units;
}

function formatUnits(value: bigint): string {
  if (value <= 0n) throw new Error("Bonus-code invariant violation: amount must be positive");
  return `${value / unitScale}.${(value % unitScale).toString().padStart(6, "0")}`;
}

function parseLabel(value: unknown): string {
  if (typeof value !== "string") throw new HttpError(400, "INVALID_LABEL", "label must be nonempty text");
  const label = value.trim();
  if (label.length < 1 || label.length > 100 || /[\u0000-\u001F\u007F]/.test(label)) {
    throw new HttpError(400, "INVALID_LABEL", "label must contain 1-100 safe text characters");
  }
  return label;
}

function parseKind(value: unknown): "group" | "single_use" {
  if (value !== "group" && value !== "single_use") throw new HttpError(400, "INVALID_KIND", "kind must be group or single_use");
  return value;
}

function parseMaximum(value: unknown, kind: "group" | "single_use"): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > 2_147_483_647) {
    throw new HttpError(400, "INVALID_MAXIMUM", "maximumUses must be a positive 32-bit integer");
  }
  const maximumUses = value as number;
  if (kind === "single_use" && maximumUses !== 1) {
    throw new HttpError(400, "INVALID_MAXIMUM", "single_use codes must have maximumUses equal to one");
  }
  return maximumUses;
}

function assertVerifierSecret(value: unknown): asserts value is string {
  if (typeof value !== "string" || Buffer.byteLength(value, "utf8") < 32) {
    throw new Error("Bonus-code verifier secret must contain at least 32 bytes");
  }
}

function payloadHash(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function verifierFor(secret: string, plaintextCode: string): string {
  assertVerifierSecret(secret);
  return createHmac("sha256", secret).update("web-agent-bench/bonus-code/v1\0").update(plaintextCode).digest("hex");
}

function normalizePlaintextCode(value: unknown): string {
  if (typeof value !== "string") throw new HttpError(400, "INVALID_CODE", "Enter a valid bonus code");
  const code = value.trim();
  if (!codePattern.test(code)) throw new HttpError(404, "BONUS_CODE_INVALID", "This bonus code is not valid");
  return code;
}

function parseDate(value: unknown, field: string): Date {
  const date = value instanceof Date ? value : new Date(String(value));
  if (Number.isNaN(date.getTime())) throw new Error(`Stored bonus-code ${field} is invalid`);
  return date;
}

function codeView(row: CodeRow): BonusCodeView {
  return {
    id: row.id,
    label: row.label,
    kind: row.kind,
    amount: formatUnits(row.amountUnits),
    maximumUses: row.maximumUses,
    usedCount: row.usedCount,
    issuedAt: row.issuedAt.toISOString(),
    disabledAt: row.disabledAt?.toISOString() ?? null
  };
}

function codeRow(row: Record<string, unknown>): CodeRow {
  const kind = row.kind;
  if (kind !== "group" && kind !== "single_use") throw new Error("Stored bonus-code kind is invalid");
  const amountUnits = typeof row.amount_units === "bigint" ? row.amount_units : BigInt(String(row.amount_units));
  const maximumUses = Number(row.maximum_uses);
  const usedCount = Number(row.used_count);
  if (!Number.isSafeInteger(maximumUses) || !Number.isSafeInteger(usedCount)) throw new Error("Stored bonus-code usage is invalid");
  return {
    id: String(row.id),
    issuerOwnerId: String(row.issuer_owner_id),
    label: String(row.label),
    kind,
    amountUnits,
    maximumUses,
    usedCount,
    issuedAt: parseDate(row.issued_at, "issued_at"),
    disabledAt: row.disabled_at === null || row.disabled_at === undefined ? null : parseDate(row.disabled_at, "disabled_at"),
    disableOperationId: row.disable_operation_id === null || row.disable_operation_id === undefined ? null : String(row.disable_operation_id),
    disablePayloadHash: row.disable_payload_hash === null || row.disable_payload_hash === undefined ? null : String(row.disable_payload_hash)
  };
}

function dbCodeRow(row: {
  id: string;
  issuerOwnerId: string;
  label: string;
  kind: string;
  amountUnits: bigint;
  maximumUses: number;
  usedCount: number;
  issuedAt: Date;
  disabledAt: Date | null;
  disableOperationId: string | null;
  disablePayloadHash: string | null;
}): CodeRow {
  if (row.kind !== "group" && row.kind !== "single_use") throw new Error("Stored bonus-code kind is invalid");
  return { ...row, kind: row.kind };
}

async function databaseNow(tx: LedgerTransaction): Promise<Date> {
  const rows = await tx.execute(sql`SELECT clock_timestamp() AS observed_at`);
  const raw = asRecord(rows[0]).observed_at;
  return parseDate(raw, "database clock");
}

async function lockAdminCodeOperation(tx: LedgerTransaction, issuerOwnerId: string, operationId: string): Promise<void> {
  const key = `${issuerOwnerId}\nbonus-code-admin\n${operationId}`;
  await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtextextended(${key}, 0))`);
}

async function readAdminCodeOperation(
  tx: LedgerTransaction,
  actorOwnerId: string,
  operationId: string
): Promise<{ eventType: string; metadata: Record<string, unknown> } | null> {
  const rows = await tx.select({ eventType: ledgerAudit.eventType, metadata: ledgerAudit.metadata })
    .from(ledgerAudit)
    .where(and(
      eq(ledgerAudit.actorOwnerId, actorOwnerId),
      eq(ledgerAudit.operationId, operationId),
      inArray(ledgerAudit.eventType, ["bonus_code_issued", "bonus_code_disabled"])
    )).limit(1);
  const row = rows[0];
  return row ? { eventType: row.eventType, metadata: asRecord(row.metadata) } : null;
}

async function lockCodeById(tx: LedgerTransaction, codeId: string): Promise<CodeRow | null> {
  const rows = await tx.execute(sql`SELECT id::text AS id, issuer_owner_id::text AS issuer_owner_id,
      label, kind, amount_units, maximum_uses, used_count, issued_at, disabled_at,
      disable_operation_id, disable_payload_hash
    FROM oid_bonus_code WHERE id=${codeId} FOR UPDATE`);
  const row = rows[0] as Record<string, unknown> | undefined;
  return row ? codeRow(row) : null;
}

async function lockCodeByVerifier(tx: LedgerTransaction, verifierHash: string): Promise<CodeRow | null> {
  const rows = await tx.execute(sql`SELECT id::text AS id, issuer_owner_id::text AS issuer_owner_id,
      label, kind, amount_units, maximum_uses, used_count, issued_at, disabled_at,
      disable_operation_id, disable_payload_hash
    FROM oid_bonus_code WHERE verifier_hash=${verifierHash} FOR UPDATE`);
  const row = rows[0] as Record<string, unknown> | undefined;
  return row ? codeRow(row) : null;
}

function redemptionView(row: {
  id: string;
  codeId: string;
  label: string;
  kind: string;
  amountUnits: bigint;
  bonusGrantId: string;
  createdAt: Date;
}): BonusCodeRedemptionView {
  if (row.kind !== "group" && row.kind !== "single_use") throw new Error("Stored bonus-code redemption kind is invalid");
  return {
    id: row.id,
    codeId: row.codeId,
    label: row.label,
    kind: row.kind,
    amount: formatUnits(row.amountUnits),
    grantId: row.bonusGrantId,
    createdAt: row.createdAt.toISOString()
  };
}

function redemptionFromReceipt(value: unknown): RedeemBonusCodeResult {
  const record = asRecord(value);
  const redemption = asRecord(record.redemption);
  if (typeof redemption.id !== "string" || typeof redemption.codeId !== "string" ||
    typeof redemption.label !== "string" || (redemption.kind !== "group" && redemption.kind !== "single_use") ||
    typeof redemption.amount !== "string" || typeof redemption.grantId !== "string" ||
    typeof redemption.createdAt !== "string" || typeof record.operationId !== "string") {
    throw new Error("Stored bonus-code claim operation has an invalid receipt");
  }
  return {
    redemption: {
      id: redemption.id,
      codeId: redemption.codeId,
      label: redemption.label,
      kind: redemption.kind,
      amount: redemption.amount,
      grantId: redemption.grantId,
      createdAt: redemption.createdAt
    },
    operationId: record.operationId,
    replayed: true
  };
}

async function loadRedemption(tx: LedgerTransaction, redemptionId: string): Promise<RedeemBonusCodeResult> {
  const rows = await tx.select({
    id: bonusCodeRedemptions.id,
    codeId: bonusCodeRedemptions.codeId,
    label: bonusCodes.label,
    kind: bonusCodes.kind,
    amountUnits: bonusCodes.amountUnits,
    bonusGrantId: bonusCodeRedemptions.bonusGrantId,
    createdAt: bonusCodeRedemptions.createdAt
  }).from(bonusCodeRedemptions)
    .innerJoin(bonusCodes, eq(bonusCodes.id, bonusCodeRedemptions.codeId))
    .where(eq(bonusCodeRedemptions.id, redemptionId)).limit(1);
  const row = rows[0];
  if (!row) throw new Error("Stored bonus-code redemption receipt is missing");
  return {
    redemption: redemptionView(row),
    operationId: "",
    replayed: true
  };
}

export async function issueBonusCode(db: OwnerDatabase, input: IssueBonusCodeCommand): Promise<IssueBonusCodeResult> {
  const issuerOwnerId = parseUuid(input.issuerOwnerId, "INVALID_ISSUER", "A verified administrator is required");
  const operationId = parseOperationId(input.operationId);
  const label = parseLabel(input.label);
  const kind = parseKind(input.kind);
  const amountUnits = parseMoneyUnits(input.amount);
  const maximumUses = parseMaximum(input.maximumUses, kind);
  assertVerifierSecret(input.codeVerifierSecret);
  const amount = formatUnits(amountUnits);
  const hash = payloadHash({ action: "bonus_code_issue", label, kind, amount, maximumUses });

  return db.transaction(async (tx) => {
    await lockAdminCodeOperation(tx, issuerOwnerId, operationId);
    const existingRows = await tx.select().from(bonusCodes).where(and(
      eq(bonusCodes.issuerOwnerId, issuerOwnerId),
      eq(bonusCodes.issueOperationId, operationId)
    )).limit(1);
    const existing = existingRows[0];
    if (existing) {
      const row = dbCodeRow(existing);
      const stored = existing.issuePayloadHash;
      if (stored !== hash) throw new HttpError(409, "IDEMPOTENCY_CONFLICT", "operationId was already used with a different request");
      const priorAudit = await readAdminCodeOperation(tx, issuerOwnerId, operationId);
      if (!priorAudit || priorAudit.eventType !== "bonus_code_issued" || priorAudit.metadata.codeId !== row.id) {
        throw new HttpError(409, "IDEMPOTENCY_CONFLICT", "operationId is already bound to another administrator action");
      }
      return { code: codeView(row), operationId, replayed: true, secret: null };
    }
    if (await readAdminCodeOperation(tx, issuerOwnerId, operationId)) {
      throw new HttpError(409, "IDEMPOTENCY_CONFLICT", "operationId is already bound to another administrator action");
    }
    if (!(await lockLedgerOwner(tx, issuerOwnerId))) throw new HttpError(404, "OWNER_NOT_FOUND", "The administrator account does not exist");

    const id = randomUUID();
    const secret = `BPC-${randomBytes(32).toString("base64url")}`;
    const now = await databaseNow(tx);
    const verifierHash = verifierFor(input.codeVerifierSecret, secret);
    const row: CodeRow = {
      id, issuerOwnerId, label, kind, amountUnits, maximumUses, usedCount: 0,
      issuedAt: now, disabledAt: null, disableOperationId: null, disablePayloadHash: null
    };
    await tx.insert(bonusCodes).values({
      id,
      issuerOwnerId,
      label,
      kind,
      amountUnits,
      maximumUses,
      usedCount: 0,
      verifierHash,
      issueOperationId: operationId,
      issuePayloadHash: hash,
      issuedAt: now
    });
    await tx.insert(ledgerAudit).values({
      id: randomUUID(),
      eventType: "bonus_code_issued",
      operationId,
      actorOwnerId: issuerOwnerId,
      subjectOwnerId: issuerOwnerId,
      metadata: { codeId: id, label, kind, amount, maximumUses },
      createdAt: now
    });
    return { code: codeView(row), operationId, replayed: false, secret };
  });
}

export async function listBonusCodes(db: OwnerDatabase): Promise<{ codes: BonusCodeView[] }> {
  const rows = await db.select().from(bonusCodes).orderBy(desc(bonusCodes.issuedAt), desc(bonusCodes.id));
  return { codes: rows.map((row) => codeView(dbCodeRow(row))) };
}

export async function disableBonusCode(
  db: OwnerDatabase,
  input: { actorOwnerId: string; codeId: string; operationId: string }
): Promise<DisableBonusCodeResult> {
  const actorOwnerId = parseUuid(input.actorOwnerId, "INVALID_ACTOR", "A verified administrator is required");
  const codeId = parseUuid(input.codeId, "INVALID_CODE_ID", "codeId must be a UUID");
  const operationId = parseOperationId(input.operationId);

  return db.transaction(async (tx) => {
    await lockAdminCodeOperation(tx, actorOwnerId, operationId);
    const code = await lockCodeById(tx, codeId);
    if (!code) throw new HttpError(404, "BONUS_CODE_NOT_FOUND", "The bonus code does not exist");
    const payload = payloadHash({ action: "bonus_code_disable", codeId });
    const priorAudit = await readAdminCodeOperation(tx, actorOwnerId, operationId);
    if (priorAudit) {
      if (priorAudit.eventType !== "bonus_code_disabled" || priorAudit.metadata.codeId !== codeId) {
        throw new HttpError(409, "IDEMPOTENCY_CONFLICT", "operationId is already bound to another administrator action");
      }
      return { code: codeView(code), operationId, replayed: true };
    }
    if (code.disabledAt) {
      if (code.disableOperationId === operationId && code.disablePayloadHash !== payload) {
        throw new HttpError(409, "IDEMPOTENCY_CONFLICT", "operationId was already used with a different request");
      }
      return { code: codeView(code), operationId: code.disableOperationId, replayed: true };
    }
    if (!(await lockLedgerOwner(tx, actorOwnerId))) throw new HttpError(404, "OWNER_NOT_FOUND", "The administrator account does not exist");

    const now = await databaseNow(tx);
    await tx.update(bonusCodes).set({
      disabledAt: now,
      disableOperationId: operationId,
      disablePayloadHash: payload
    }).where(eq(bonusCodes.id, codeId));
    await tx.insert(ledgerAudit).values({
      id: randomUUID(),
      eventType: "bonus_code_disabled",
      operationId,
      actorOwnerId,
      subjectOwnerId: code.issuerOwnerId,
      metadata: { codeId, usedCount: code.usedCount, maximumUses: code.maximumUses },
      createdAt: now
    });
    return { code: { ...codeView(code), disabledAt: now.toISOString() }, operationId, replayed: false };
  });
}

export async function redeemBonusCode(
  db: OwnerDatabase,
  input: { ownerId: string; codeVerifierSecret: string; plaintextCode: string; operationId: string }
): Promise<RedeemBonusCodeResult> {
  const ownerId = parseUuid(input.ownerId, "INVALID_OWNER_ID", "A verified owner is required");
  const operationId = parseOperationId(input.operationId);
  const plaintextCode = normalizePlaintextCode(input.plaintextCode);
  assertVerifierSecret(input.codeVerifierSecret);
  const verifierHash = verifierFor(input.codeVerifierSecret, plaintextCode);

  return db.transaction(async (tx) => {
    // AICODE-NOTE: Code row -> ledger operation key -> owner-ledger row is the shared grant lock order. Recheck committed claims before disabled/capacity so retries survive later disable/exhaustion.
    const code = await lockCodeByVerifier(tx, verifierHash);
    if (!code) throw new HttpError(404, "BONUS_CODE_INVALID", "This bonus code is not valid");
    const requestHash = payloadHash({ action: "bonus_code_redeem", codeId: code.id });
    const operationRows = await tx.select().from(bonusCodeClaimOperations).where(and(
      eq(bonusCodeClaimOperations.ownerId, ownerId),
      eq(bonusCodeClaimOperations.operationId, operationId)
    )).limit(1);
    const priorOperation = operationRows[0];
    if (priorOperation) {
      if (priorOperation.codeId !== code.id || priorOperation.payloadHash !== requestHash) {
        throw new HttpError(409, "IDEMPOTENCY_CONFLICT", "operationId was already used with a different request");
      }
      const replay = await loadRedemption(tx, priorOperation.redemptionId);
      return { ...replay, operationId, replayed: true };
    }

    const priorRedemptions = await tx.select().from(bonusCodeRedemptions).where(and(
      eq(bonusCodeRedemptions.codeId, code.id),
      eq(bonusCodeRedemptions.ownerId, ownerId)
    )).limit(1);
    const priorRedemption = priorRedemptions[0];
    if (priorRedemption) {
      if (!(await lockLedgerOwner(tx, ownerId))) throw new HttpError(404, "OWNER_NOT_FOUND", "The owner account does not exist");
      const concurrentOperationRows = await tx.select().from(bonusCodeClaimOperations).where(and(
        eq(bonusCodeClaimOperations.ownerId, ownerId),
        eq(bonusCodeClaimOperations.operationId, operationId)
      )).limit(1);
      const concurrentOperation = concurrentOperationRows[0];
      if (concurrentOperation && (concurrentOperation.codeId !== code.id || concurrentOperation.payloadHash !== requestHash)) {
        throw new HttpError(409, "IDEMPOTENCY_CONFLICT", "operationId was already used with a different request");
      }
      if (concurrentOperation) {
        const replay = await loadRedemption(tx, concurrentOperation.redemptionId);
        return { ...replay, operationId, replayed: true };
      }
      const replay = await loadRedemption(tx, priorRedemption.id);
      await tx.insert(bonusCodeClaimOperations).values({
        ownerId,
        operationId,
        codeId: code.id,
        redemptionId: priorRedemption.id,
        payloadHash: requestHash
      });
      return { ...replay, operationId, replayed: true };
    }

    if (code.disabledAt) throw new HttpError(409, "BONUS_CODE_DISABLED", "This bonus code no longer accepts new claims");
    if (code.usedCount >= code.maximumUses) throw new HttpError(409, "BONUS_CODE_EXHAUSTED", "This bonus code has no uses remaining");

    const grantOperationId = `bcg_${createHash("sha256").update(`${code.id}\0${ownerId}`).digest("hex")}`;
    await lockLedgerOperationKey(tx, code.issuerOwnerId, grantOperationId);
    if (!(await lockLedgerOwner(tx, ownerId))) throw new HttpError(404, "OWNER_NOT_FOUND", "The owner account does not exist");
    const concurrentOperationRows = await tx.select().from(bonusCodeClaimOperations).where(and(
      eq(bonusCodeClaimOperations.ownerId, ownerId),
      eq(bonusCodeClaimOperations.operationId, operationId)
    )).limit(1);
    const concurrentOperation = concurrentOperationRows[0];
    if (concurrentOperation) {
      if (concurrentOperation.codeId !== code.id || concurrentOperation.payloadHash !== requestHash) {
        throw new HttpError(409, "IDEMPOTENCY_CONFLICT", "operationId was already used with a different request");
      }
      const replay = await loadRedemption(tx, concurrentOperation.redemptionId);
      return { ...replay, operationId, replayed: true };
    }
    const grant = await issueBonusGrantInTransaction(tx, {
      actorOwnerId: code.issuerOwnerId,
      ownerId,
      operationId: grantOperationId,
      amount: formatUnits(code.amountUnits),
      reason: "Bonus code redemption"
    }, { ownerAlreadyLocked: true, idempotencyKeyAlreadyLocked: true });
    if (grant.replayed) {
      // A correctly committed code claim always has its redemption row. A naked prior grant under this deterministic key is a namespace collision, not a valid redemption.
      throw new HttpError(409, "BONUS_CODE_GRANT_OPERATION_COLLISION", "The bonus claim cannot be safely linked to an existing ledger operation");
    }
    const createdAt = await databaseNow(tx);
    const receiptId = randomUUID();
    const redemption: BonusCodeRedemptionView = {
      id: receiptId,
      codeId: code.id,
      label: code.label,
      kind: code.kind,
      amount: formatUnits(code.amountUnits),
      grantId: grant.grant.id,
      createdAt: createdAt.toISOString()
    };

    const updated = await tx.execute(sql`UPDATE oid_bonus_code
      SET used_count = used_count + 1
      WHERE id=${code.id} AND disabled_at IS NULL AND used_count < maximum_uses
      RETURNING id`);
    if (updated.length !== 1) throw new HttpError(409, "BONUS_CODE_UNAVAILABLE", "This bonus code no longer accepts a claim");
    await tx.insert(bonusCodeRedemptions).values({
      id: receiptId,
      codeId: code.id,
      ownerId,
      bonusGrantId: grant.grant.id,
      financialOperationId: grantOperationId,
      createdAt
    });
    await tx.insert(bonusCodeClaimOperations).values({
      ownerId,
      operationId,
      codeId: code.id,
      redemptionId: receiptId,
      payloadHash: requestHash,
      createdAt
    });
    await tx.insert(ledgerAudit).values({
      id: randomUUID(),
      eventType: "bonus_code_redeemed",
      operationId,
      actorOwnerId: ownerId,
      subjectOwnerId: ownerId,
      metadata: { codeId: code.id, receiptId, grantId: grant.grant.id, amount: redemption.amount, kind: code.kind },
      createdAt
    });
    return { redemption, operationId, replayed: false };
  });
}

export async function readOwnerBonusCodeRedemptions(
  db: OwnerDatabase,
  ownerIdValue: string
): Promise<{ redemptions: BonusCodeRedemptionView[] }> {
  const ownerId = parseUuid(ownerIdValue, "INVALID_OWNER_ID", "A verified owner is required");
  const rows = await db.select({
    id: bonusCodeRedemptions.id,
    codeId: bonusCodeRedemptions.codeId,
    label: bonusCodes.label,
    kind: bonusCodes.kind,
    amountUnits: bonusCodes.amountUnits,
    bonusGrantId: bonusCodeRedemptions.bonusGrantId,
    createdAt: bonusCodeRedemptions.createdAt
  }).from(bonusCodeRedemptions)
    .innerJoin(bonusCodes, eq(bonusCodes.id, bonusCodeRedemptions.codeId))
    .where(eq(bonusCodeRedemptions.ownerId, ownerId))
    .orderBy(desc(bonusCodeRedemptions.createdAt), desc(bonusCodeRedemptions.id));
  return { redemptions: rows.map(redemptionView) };
}
