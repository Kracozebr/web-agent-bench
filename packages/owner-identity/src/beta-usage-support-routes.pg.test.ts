import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import Fastify from "fastify";
import { test } from "node:test";
import { sql } from "drizzle-orm";
import type { OwnerIdentityConfig } from "./config.js";
import { createDatabase, type OwnerDatabase } from "./db.js";
import { HttpError } from "./http-error.js";
import { BETA_CLIENT_FAMILIES, parseBetaDeploymentManifest, type BetaDeploymentManifest } from "./beta-profile.js";
import {
  pinnedBetaClientRegistryFromManifest,
  type PinnedBetaClientRegistry
} from "./beta-usage-support-export.js";
import { registerBetaUsageSupportRoutes } from "./beta-usage-support-routes.js";

const optIn = process.env.OID_BETA_USAGE_SUPPORT_ROUTE_PG_REGRESSION === "true";
const EXPECTED_DB = /^oid_acceptance_[a-f0-9]{32}$/;
const testRegistry: PinnedBetaClientRegistry = {
  version: "beta-client-registry/v1",
  sha256: createHash("sha256").update("explicit SC-023 route test registry").digest("hex"),
  clients: [
    { family: "codex", oauthClientId: "route-test-codex-client" },
    { family: "claude-code", oauthClientId: "route-test-claude-code-client" },
    { family: "claude-desktop", oauthClientId: "route-test-claude-desktop-client" },
    { family: "hermes", oauthClientId: "route-test-hermes-client" }
  ],
  provenance: { source: "explicit_test_fixture", hashBasis: "fixed test-only registry projection" }
};

function rows<T>(value: unknown): T[] {
  return value as T[];
}

function first<T>(value: unknown): T {
  const result = rows<T>(value);
  if (!result.length) throw new Error("beta_usage_route_pg_expected_row_missing");
  return result[0]!;
}

function acceptanceUrl(raw: string | undefined, expectedDatabase: string, role: "oid_owner" | "oid_observer"): string {
  if (!raw) throw new Error("beta_usage_route_pg_database_url_missing");
  const url = new URL(raw);
  if (url.hostname !== "postgres" || url.username !== role) throw new Error("beta_usage_route_pg_database_endpoint_rejected");
  url.pathname = `/${expectedDatabase}`;
  return url.href;
}

async function readonlyCounts(db: OwnerDatabase) {
  return db.transaction(async (tx) => {
    const identity = first<{ database: string; role: string; read_only: string }>(await tx.execute(sql`
      SELECT current_database() AS database,current_user AS role,current_setting('transaction_read_only') AS read_only
    `));
    assert.equal(identity.role, "oid_observer");
    assert.equal(identity.read_only, "on");
    return first<Record<string, string>>(await tx.execute(sql`
      SELECT
        (SELECT count(*) FROM oid_owner)::text AS owners,
        (SELECT count(*) FROM oid_agent)::text AS agents,
        (SELECT count(*) FROM oid_agent_access_grant)::text AS grants,
        (SELECT count(*) FROM oid_benchmark_run)::text AS runs,
        (SELECT count(*) FROM oid_run_task_action)::text AS actions,
        (SELECT count(*) FROM oid_support_report)::text AS reports,
        (SELECT count(*) FROM oid_support_report_deletion_receipt)::text AS report_receipts,
        (SELECT count(*) FROM oid_ledger_entry)::text AS ledger
    `));
  }, { isolationLevel: "repeatable read", accessMode: "read only" });
}

function manifestFixture(): BetaDeploymentManifest {
  const hash = "d".repeat(64);
  const publicOrigin = "https://beta.example.test";
  const clients = BETA_CLIENT_FAMILIES.map((family) => ({
    family,
    enabled: true,
    verificationStatus: "verified",
    edition: "test-edition",
    version: "1.0.0",
    platform: "test-platform",
    mcpClientName: `${family} test client`,
    mcpClientVersion: "1.0.0",
    protocolVersions: ["2025-06-18"],
    authMethods: ["oauth_authorization_code"],
    oauthClientId: `test-${family}-oauth-client`,
    redirectUris: [`https://clients.example.test/${family}/callback`],
    verificationEvidenceSha256: [hash]
  }));
  return parseBetaDeploymentManifest({
    schemaVersion: "beta-deployment-manifest/v1",
    state: "qualification",
    executionProfileId: "beta-bef-v1",
    transportProfileId: "beta-remote-v1",
    source: { commit: "c".repeat(40), applicationBuildSha256: hash, evaluatorSourceSha256: hash },
    publicOrigin,
    apiBindHost: "127.0.0.1",
    apiPort: 8784,
    trustedProxyCidrs: ["127.0.0.1/32"],
    qualificationReadCidrs: ["203.0.113.0/24"],
    google: {
      issuer: "https://accounts.google.com",
      clientId: "google-client-id-test",
      callbackUri: `${publicOrigin}/api/auth/callback/google`,
      adminSubject: "admin-subject-test"
    },
    release: {
      releaseIdentity: "sc023-test-release",
      manifestHash: hash,
      benchmarkHash: hash,
      policyHash: hash,
      benchmarkVersion: "sc023-fixture-v1",
      executionIdentityHash: hash,
      environmentManifestSha256: hash,
      applicationSourceSha256: hash,
      sourceBlockHash: hash
    },
    queue: {
      executionCapacity: 1,
      maxAcceptedPerOwner: 2,
      maxAcceptedGlobal: 8,
      maxPendingPerOwner: 2,
      maxPendingGlobal: 30,
      queueWaitSeconds: 86400,
      successorPreparationTimeoutSeconds: 180,
      platformRecoverySeconds: 180
    },
    storage: {
      privateDataDir: "/var/lib/owner-identity/private",
      evidenceDirectory: "evidence",
      reportRetentionDaysAfterClosure: 30
    },
    secretReferences: {
      authSecretEnv: "OID_AUTH_SECRET",
      googleClientSecretEnv: "OID_GOOGLE_CLIENT_SECRET",
      bonusCodeVerifierSecretEnv: "OID_BONUS_CODE_VERIFIER_SECRET"
    },
    clients
  });
}

test("usage/support export is unavailable without the startup-validated Beta registry", async () => {
  const app = Fastify();
  registerBetaUsageSupportRoutes(app, {
    db: {} as OwnerDatabase,
    requireAdmin: async () => ({ context: { owner: { id: "test-admin-owner" } } }),
    rateLimit: async () => undefined,
    rateLimitMax: 10
  });
  try {
    await app.ready();
    const response = await app.inject({ method: "GET", url: "/api/admin/operations/usage-support-export" });
    assert.equal(response.statusCode, 503);
    assert.equal(response.headers["cache-control"], "no-store");
    assert.equal(response.headers["pragma"], "no-cache");
    assert.equal(response.json().error.code, "BETA_USAGE_REGISTRY_UNAVAILABLE");
  } finally {
    await app.close();
  }
});

test("beta client registry fingerprint identifies the validated canonical manifest projection", () => {
  const manifest = manifestFixture();
  const registry = pinnedBetaClientRegistryFromManifest(manifest);
  const clients = manifest.clients.map(({ family, enabled, oauthClientId }) => ({ family, enabled, oauthClientId }))
    .sort((left, right) => left.family < right.family ? -1 : left.family > right.family ? 1 : 0);
  const expectedProjection = JSON.stringify({ schemaVersion: manifest.schemaVersion, clients });
  assert.equal(registry.version, "beta-client-registry/v1");
  assert.equal(registry.sha256, createHash("sha256").update(expectedProjection).digest("hex"));
  assert.deepEqual(registry.provenance, {
    source: "validated_config.betaManifest",
    hashBasis: "SHA-256(JSON.stringify({schemaVersion,clients sorted by family with family/enabled/oauthClientId}))"
  });
  assert.deepEqual(registry.clients.map(({ family }) => family).sort(), [...BETA_CLIENT_FAMILIES].sort());
});

test("admin usage export route denies non-admins and returns no-store aggregate JSON without identifiers", { skip: !optIn }, async () => {
  const expectedDatabase = process.env.OID_BETA_USAGE_SUPPORT_ROUTE_PG_TEST_DATABASE ?? "";
  assert.match(expectedDatabase, EXPECTED_DB, "the opt-in regression requires a unique oid_acceptance database identity");
  const owner = createDatabase({ databaseUrl: acceptanceUrl(process.env.OID_DATABASE_URL, expectedDatabase, "oid_owner") } as OwnerIdentityConfig);
  const observer = createDatabase({ databaseUrl: acceptanceUrl(process.env.OID_OBSERVER_DATABASE_URL, expectedDatabase, "oid_observer") } as OwnerIdentityConfig);
  const app = Fastify();
  let adminAllowed = false;
  let adminChecks = 0;
  try {
    const ownerIdentity = first<{ database: string; role: string }>(await owner.db.execute(sql`
      SELECT current_database() AS database,current_user AS role
    `));
    const observerIdentity = first<{ database: string; role: string; read_only: string }>(await observer.db.execute(sql`
      SELECT current_database() AS database,current_user AS role,current_setting('transaction_read_only') AS read_only
    `));
    assert.deepEqual(ownerIdentity, { database: expectedDatabase, role: "oid_owner" });
    assert.equal(observerIdentity.database, expectedDatabase);
    assert.equal(observerIdentity.role, "oid_observer");
    assert.equal(observerIdentity.read_only, "on");

    registerBetaUsageSupportRoutes(app, {
      db: owner.db,
      clientRegistry: testRegistry,
      requireAdmin: async () => {
        adminChecks += 1;
        if (!adminAllowed) throw new HttpError(403, "FORBIDDEN", "The configured administrator identity is required");
        return { context: { owner: { id: "test-admin-owner" } } };
      },
      rateLimit: async () => undefined,
      rateLimitMax: 10
    });
    await app.ready();

    const before = await readonlyCounts(observer.db);
    const denied = await app.inject({ method: "GET", url: "/api/admin/operations/usage-support-export" });
    assert.equal(denied.statusCode, 403);
    assert.equal(denied.headers["cache-control"], "no-store");
    assert.equal(denied.headers["pragma"], "no-cache");

    adminAllowed = true;
    const response = await app.inject({
      method: "GET",
      url: "/api/admin/operations/usage-support-export?oauthClientId=untrusted-request-value"
    });
    assert.equal(response.statusCode, 200);
    assert.match(String(response.headers["content-type"]), /application\/json/);
    assert.equal(response.headers["cache-control"], "no-store");
    assert.equal(response.headers["pragma"], "no-cache");
    assert.equal(response.headers["x-content-type-options"], "nosniff");
    assert.equal(response.headers["content-disposition"], 'attachment; filename="beta-usage-support.json"');
    assert.equal(adminChecks, 2);
    const exported = response.json() as {
      metadata: { clientRegistry: { provenance: { source: string } } };
      support: { reports: number; reporterFamilyUnknown: number };
      funding: { paidConversion: { status: string; owners: number | null } };
    };
    assert.equal(exported.metadata.clientRegistry.provenance.source, "explicit_test_fixture");
    assert.equal(exported.support.reports, exported.support.reporterFamilyUnknown);
    assert.equal(exported.funding.paidConversion.status, "not_measured");
    assert.equal(exported.funding.paidConversion.owners, null);
    assert.equal(/[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/i.test(response.body), false,
      "aggregate export must not contain owner, agent, run, or report UUIDs");

    const after = await readonlyCounts(observer.db);
    assert.deepEqual(after, before, "denied and successful export requests must leave durable facts unchanged");
  } finally {
    await app.close();
    await Promise.all([owner.client.end({ timeout: 5 }), observer.client.end({ timeout: 5 })]);
  }
});
