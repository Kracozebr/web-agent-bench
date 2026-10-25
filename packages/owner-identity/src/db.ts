import postgres from "postgres";
import { drizzle } from "drizzle-orm/postgres-js";
import type { OwnerIdentityConfig } from "./config.js";
import * as schema from "./schema.js";
import { ledgerSchema } from "./ledger-schema.js";

export function createDatabase(config: OwnerIdentityConfig) {
  const client = postgres(config.databaseUrl, { max: 10, idle_timeout: 20, connect_timeout: 10 });
  return { client, db: drizzle(client, { schema: { ...schema, ...ledgerSchema } }) };
}

export type OwnerDatabase = ReturnType<typeof createDatabase>["db"];
