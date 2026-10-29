import { createHash } from "node:crypto";
import { sql, type SQL } from "drizzle-orm";

// AICODE-NOTE: Drizzle raw SQL treats a JavaScript array as one scalar parameter, not a PostgreSQL array; UUID binds produced SQLSTATE 22P02. Expand UUID lists into cast scalar binds, and build typed arrays with ARRAY[...].
export function reportUuidList(values: readonly string[]) {
  return sql.join(values.map((value) => sql`${value}::uuid`), sql`, `);
}

export function reportUuidArray(values: readonly string[]) {
  return values.length ? sql`ARRAY[${reportUuidList(values)}]::uuid[]` : sql`'{}'::uuid[]`;
}

export function reportIntegerArray(values: readonly number[]) {
  return values.length ? sql`ARRAY[${sql.join(values.map((value) => sql`${value}::integer`), sql`, `)}]::integer[]` : sql`'{}'::integer[]`;
}

// AICODE-NOTE: Report retention is exactly 30 UTC days; calendar-day timestamptz arithmetic can lose an hour across DST.
export function reportRetentionDeadline(timestamp: SQL) {
  return sql`${timestamp} + interval '2592000 seconds'`;
}

export function reportDeletionReceiptStatement(input: {
  reportId: string;
  betaEndedAt: string;
  expiresAt: string;
  imageCount: number;
  storageKeys: readonly string[];
  storageBytes: readonly number[];
}) {
  const storageKeys = reportUuidArray(input.storageKeys);
  const storageBytes = reportIntegerArray(input.storageBytes);
  return sql`
    INSERT INTO oid_support_report_deletion_receipt(report_id,beta_ended_at,expires_at,deleted_at,image_count,pending_storage_keys,pending_storage_bytes,purge_status,last_attempt_at,last_error_code)
    VALUES (${input.reportId}::uuid,${input.betaEndedAt}::timestamptz,${input.expiresAt}::timestamptz,
      clock_timestamp(),${input.imageCount},${storageKeys},${storageBytes},CASE WHEN cardinality(${storageKeys})=0 THEN 'complete' ELSE 'pending' END,
      clock_timestamp(),NULL) ON CONFLICT(report_id) DO NOTHING
  `;
}

export function reportRows<T>(result: unknown): T[] {
  return result as unknown as T[];
}

export function reportFirst<T>(result: unknown): T | undefined {
  return reportRows<T>(result)[0];
}

export function reportHash(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

export function reportUuid(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

export function asIso(value: Date | string): string {
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}
