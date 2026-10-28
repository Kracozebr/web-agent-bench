import { isIP } from "node:net";

export type RegistrationMode = "closed" | "open";
export type GoogleMode = "google" | "provider-fixture" | "disabled";

export interface OwnerIdentityConfig {
  databaseUrl: string;
  authSecret: string;
  publicOrigin: string;
  apiHost: string;
  apiPort: number;
  googleClientId?: string;
  googleClientSecret?: string;
  googleFixtureOrigin?: string;
  adminProvider?: string;
  adminSubject?: string;
  registrationMode: RegistrationMode;
  sessionTtlSeconds: number;
  invitationTtlSeconds: number;
  manualCredentialTtlSeconds: number;
  mcpClientId: string;
  mcpClientRedirectUri: string;
  mcpTransportProfile?: "strict-2026-07-28" | "codex-local-manual-2025-06-18";
  agentCredentialRateLimitMax: number;
  agentPreflightRateLimitMax: number;
  authRateLimitMax: number;
  siweRateLimitMax: number;
  rateLimitWindowSeconds: number;
  siweChainId: 8453;
  nonceTtlSeconds: 900;
  nodeEnv: string;
  localBefTaskCoordinatorEnabled: boolean;
  localBefTaskCoordinatorConfigPath?: string;
  localBefTaskCoordinatorTickMs: number;
  localBefTaskCoordinatorBatchSize: number;
}

function optional(env: NodeJS.ProcessEnv, key: string): string | undefined {
  const value = env[key]?.trim();
  return value ? value : undefined;
}

function integer(env: NodeJS.ProcessEnv, key: string, fallback: number, min: number, max: number): number {
  const raw = optional(env, key);
  if (raw === undefined) return fallback;
  if (!/^\d+$/.test(raw)) throw new Error(`${key} must be an integer`);
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new Error(`${key} must be between ${min} and ${max}`);
  }
  return value;
}

function booleanFlag(env: NodeJS.ProcessEnv, key: string, fallback: boolean): boolean {
  const raw = optional(env, key);
  if (raw === undefined) return fallback;
  if (raw === "true") return true;
  if (raw === "false") return false;
  throw new Error(`${key} must be true or false`);
}

export function isLoopbackHost(value: string): boolean {
  const host = value.trim().toLowerCase().replace(/^\[|\]$/g, "");
  if (host === "localhost" || host === "::1") return true;
  const version = isIP(host);
  return version === 4 && host.split(".")[0] === "127";
}

function origin(env: NodeJS.ProcessEnv): string {
  const raw = optional(env, "OID_PUBLIC_ORIGIN") ?? "http://127.0.0.1:3000";
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error("OID_PUBLIC_ORIGIN must be an absolute origin URL");
  }
  if (!/^https?:$/.test(parsed.protocol) || parsed.origin !== raw.replace(/\/$/, "") || parsed.username || parsed.password) {
    throw new Error("OID_PUBLIC_ORIGIN must contain only an http(s) origin");
  }
  const host = parsed.hostname.toLowerCase();
  const local = host === "localhost" || isIP(host) > 0;
  if (env.NODE_ENV === "production" && (parsed.protocol !== "https:" || local)) {
    throw new Error("Production OID_PUBLIC_ORIGIN must be a public HTTPS origin");
  }
  return parsed.origin;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): OwnerIdentityConfig {
  const databaseUrl = optional(env, "OID_DATABASE_URL");
  const authSecret = optional(env, "OID_AUTH_SECRET");
  if (!databaseUrl) throw new Error("OID_DATABASE_URL is required");
  if (!authSecret || authSecret.length < 32) throw new Error("OID_AUTH_SECRET must contain at least 32 characters");

  const configuredMcpClientId = optional(env, "OID_MCP_CLIENT_ID");
  const configuredMcpClientRedirectUri = optional(env, "OID_MCP_CLIENT_REDIRECT_URI");
  if (env.NODE_ENV === "production" && (!configuredMcpClientId || !configuredMcpClientRedirectUri)) {
    throw new Error("OID_MCP_CLIENT_ID and OID_MCP_CLIENT_REDIRECT_URI must be explicitly configured in production");
  }
  const mcpClientId = configuredMcpClientId ?? "oid-local-mcp-client";
  if (!/^[A-Za-z0-9._:-]{8,128}$/.test(mcpClientId)) {
    throw new Error("OID_MCP_CLIENT_ID must be an 8-128 character fixed client identifier");
  }
  const mcpClientRedirectUri = configuredMcpClientRedirectUri ?? "http://127.0.0.1:38765/oauth/callback";
  let parsedMcpRedirect: URL;
  try {
    parsedMcpRedirect = new URL(mcpClientRedirectUri);
  } catch {
    throw new Error("OID_MCP_CLIENT_REDIRECT_URI must be an absolute loopback callback URL");
  }
  if (parsedMcpRedirect.protocol !== "http:" || parsedMcpRedirect.hostname !== "127.0.0.1" ||
    parsedMcpRedirect.port.length === 0 || parsedMcpRedirect.username || parsedMcpRedirect.password ||
    parsedMcpRedirect.search || parsedMcpRedirect.hash || parsedMcpRedirect.pathname !== "/oauth/callback" ||
    parsedMcpRedirect.href !== mcpClientRedirectUri) {
    throw new Error("OID_MCP_CLIENT_REDIRECT_URI must be an exact http://127.0.0.1:<port>/oauth/callback URI");
  }

  const googleClientId = optional(env, "OID_GOOGLE_CLIENT_ID");
  const googleClientSecret = optional(env, "OID_GOOGLE_CLIENT_SECRET");
  if (Boolean(googleClientId) !== Boolean(googleClientSecret)) {
    throw new Error("OID_GOOGLE_CLIENT_ID and OID_GOOGLE_CLIENT_SECRET must be configured together");
  }
  const googleFixtureOrigin = optional(env, "OID_GOOGLE_FIXTURE_ORIGIN");
  if (googleFixtureOrigin && env.NODE_ENV === "production") {
    throw new Error("OID_GOOGLE_FIXTURE_ORIGIN is forbidden in production");
  }
  if (googleFixtureOrigin) {
    const fixture = new URL(googleFixtureOrigin);
    if (!/^https?:$/.test(fixture.protocol) || fixture.origin !== googleFixtureOrigin.replace(/\/$/, "")) {
      throw new Error("OID_GOOGLE_FIXTURE_ORIGIN must be an absolute http(s) origin");
    }
  }
  const adminProvider = optional(env, "OID_ADMIN_PROVIDER");
  const adminSubject = optional(env, "OID_ADMIN_SUBJECT");
  if (Boolean(adminProvider) !== Boolean(adminSubject)) {
    throw new Error("OID_ADMIN_PROVIDER and OID_ADMIN_SUBJECT must be configured together");
  }
  const registrationMode = optional(env, "OID_REGISTRATION_MODE") ?? "closed";
  if (registrationMode !== "closed" && registrationMode !== "open") {
    throw new Error("OID_REGISTRATION_MODE must be closed or open");
  }
  const localBefTaskCoordinatorEnabled = booleanFlag(env, "OID_LOCAL_BEF_TASK_COORDINATOR_ENABLED", false);
  const localBefTaskCoordinatorConfigPath = optional(env, "OID_LOCAL_BEF_TASK_COORDINATOR_CONFIG");
  const nodeEnv = env.NODE_ENV?.toLowerCase() ?? "development";
  if (localBefTaskCoordinatorEnabled && nodeEnv === "production") {
    throw new Error("OID_LOCAL_BEF_TASK_COORDINATOR_ENABLED is forbidden in production");
  }
  if (localBefTaskCoordinatorEnabled && nodeEnv !== "development" && nodeEnv !== "test") {
    throw new Error("OID_LOCAL_BEF_TASK_COORDINATOR_ENABLED is allowed only in development or test");
  }
  const apiHost = optional(env, "OID_API_HOST") ?? "127.0.0.1";
  if (localBefTaskCoordinatorEnabled && !isLoopbackHost(apiHost)) {
    throw new Error("The local BEF task coordinator requires a loopback OID_API_HOST");
  }
  if (localBefTaskCoordinatorEnabled && !localBefTaskCoordinatorConfigPath) {
    throw new Error("OID_LOCAL_BEF_TASK_COORDINATOR_CONFIG is required when the local BEF task coordinator is enabled");
  }

  const mcpTransportProfile = optional(env, "OID_MCP_TRANSPORT_PROFILE") ?? "strict-2026-07-28";
  if (mcpTransportProfile !== "strict-2026-07-28" && mcpTransportProfile !== "codex-local-manual-2025-06-18") {
    throw new Error("OID_MCP_TRANSPORT_PROFILE is not a supported pinned profile");
  }
  if (mcpTransportProfile === "codex-local-manual-2025-06-18") {
    const publicUrl = new URL(origin(env));
    if (!localBefTaskCoordinatorEnabled || !localBefTaskCoordinatorConfigPath ||
        !["development", "test"].includes(nodeEnv) || publicUrl.protocol !== "http:" || !isLoopbackHost(publicUrl.hostname)) {
      throw new Error("The Codex MCP compatibility profile requires the local BEF coordinator and loopback HTTP origin");
    }
  }
  return {
    databaseUrl,
    authSecret,
    publicOrigin: origin(env),
    apiHost,
    apiPort: integer(env, "OID_API_PORT", 8784, 1, 65535),
    ...(googleClientId ? { googleClientId } : {}),
    ...(googleClientSecret ? { googleClientSecret } : {}),
    ...(googleFixtureOrigin ? { googleFixtureOrigin } : {}),
    ...(adminProvider ? { adminProvider } : {}),
    ...(adminSubject ? { adminSubject } : {}),
    registrationMode,
    sessionTtlSeconds: integer(env, "OID_SESSION_TTL_SECONDS", 604800, 300, 31536000),
    invitationTtlSeconds: integer(env, "OID_INVITATION_TTL_SECONDS", 604800, 60, 2592000),
    manualCredentialTtlSeconds: integer(env, "OID_MANUAL_CREDENTIAL_TTL_SECONDS", 86400, 300, 2592000),
    mcpClientId,
    mcpClientRedirectUri,
    mcpTransportProfile,
    agentCredentialRateLimitMax: integer(env, "OID_AGENT_CREDENTIAL_RATE_LIMIT_MAX", 30, 1, 1000),
    agentPreflightRateLimitMax: integer(env, "OID_AGENT_PREFLIGHT_RATE_LIMIT_MAX", 60, 1, 1000),
    authRateLimitMax: integer(env, "OID_AUTH_RATE_LIMIT_MAX", 10, 1, 1000),
    siweRateLimitMax: integer(env, "OID_SIWE_RATE_LIMIT_MAX", 6, 1, 1000),
    rateLimitWindowSeconds: integer(env, "OID_RATE_LIMIT_WINDOW_SECONDS", 60, 1, 3600),
    siweChainId: 8453,
    nonceTtlSeconds: 900,
    nodeEnv: env.NODE_ENV ?? "development",
    localBefTaskCoordinatorEnabled,
    ...(localBefTaskCoordinatorConfigPath ? { localBefTaskCoordinatorConfigPath } : {}),
    localBefTaskCoordinatorTickMs: integer(env, "OID_LOCAL_BEF_TASK_COORDINATOR_TICK_MS", 1000, 500, 10000),
    localBefTaskCoordinatorBatchSize: integer(env, "OID_LOCAL_BEF_TASK_COORDINATOR_BATCH_SIZE", 10, 1, 20)
  };
}

export function getGoogleMode(config: OwnerIdentityConfig): GoogleMode {
  if (!config.googleClientId) return "disabled";
  return config.googleFixtureOrigin ? "provider-fixture" : "google";
}
