import postgres from "postgres";
import { drizzle } from "drizzle-orm/postgres-js";
import type { OwnerIdentityConfig } from "./config.js";
import * as schema from "./schema.js";
import { ledgerSchema } from "./ledger-schema.js";
import { bonusCodeSchema } from "./bonus-code-schema.js";
import { reportSchema } from "./report-schema.js";

export function createDatabase(config: OwnerIdentityConfig) {
  const client = postgres(config.databaseUrl, { max: 10, idle_timeout: 20, connect_timeout: 10 });
  return { client, db: drizzle(client, { schema: { ...schema, ...ledgerSchema, ...bonusCodeSchema, ...reportSchema } }) };
}

export type OwnerDatabase = ReturnType<typeof createDatabase>["db"];

// AICODE-NOTE: Diagnostic lock waits must never consume the business pool.
export function createDiagnosticDatabase(config: OwnerIdentityConfig) {
  const client=postgres(config.databaseUrl,{max:2,idle_timeout:20,connect_timeout:5,
    connection:{statement_timeout:1000,lock_timeout:500,application_name:'w3bench-diagnostics'}});
  return {client,db:drizzle(client,{schema:{...schema,...ledgerSchema,...bonusCodeSchema,...reportSchema}})};
}
