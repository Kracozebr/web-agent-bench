import { isLoopbackHost, type OwnerIdentityConfig } from './config.js';
import { HttpError } from './http-error.js';

export const REMOTE_MCP_PROTOCOLS = ['2026-07-28', '2025-06-18'] as const;
export const CONNECTION_GRANT_TTL_SECONDS = 30 * 24 * 60 * 60;
export const CONNECTION_ACCESS_TTL_SECONDS = 3600;
export const CONNECTION_REFRESH_RETRY_SECONDS = 30;
export function agentOAuthResource(config: Pick<OwnerIdentityConfig, 'publicOrigin' | 'mcpTransportProfile'>): string {
  return `${config.publicOrigin}/api/agent${config.mcpTransportProfile === 'remote-oauth-v1' ? '/mcp' : ''}`;
}
export function connectionOAuthScopes(config: Pick<OwnerIdentityConfig, 'mcpTransportProfile'>): string[] {
  return config.mcpTransportProfile === 'remote-oauth-v1' ? ['agent:operate', 'offline_access'] : ['agent:operate'];
}
export function validConnectionScopes(config: Pick<OwnerIdentityConfig, 'mcpTransportProfile'>, scope: unknown): boolean {
  if (typeof scope !== 'string') return false;
  const scopes = scope.split(/\s+/).filter(Boolean);
  return scopes.includes('agent:operate') && new Set(scopes).size === scopes.length &&
    scopes.every((item) => connectionOAuthScopes(config).includes(item));
}

const targetClients = [
  ['codex-desktop', 'Codex Desktop'], ['codex-cli', 'Codex CLI'],
  ['claude-desktop', 'Claude Desktop'], ['claude-code', 'Claude Code'],
  ['openclaw', 'OpenClaw'], ['opencode', 'OpenCode'], ['hermes', 'Hermes'],
  ['kilocode', 'KiloCode'], ['cline', 'Cline'], ['goose', 'Goose'],
] as const;

/** AICODE-NOTE: Native qualification is evidence, never inferred from a client name/version or a successful SDK call. */
export function remoteConnectionSetup(config: Pick<OwnerIdentityConfig, 'publicOrigin' | 'nodeEnv' | 'mcpClientRegistry' | 'mcpTransportProfile'>) {
  const origin = new URL(config.publicOrigin);
  const development = ['development', 'test'].includes(config.nodeEnv.toLowerCase()) &&
    origin.protocol === 'http:' && isLoopbackHost(origin.hostname);
  if (origin.origin !== config.publicOrigin || origin.username || origin.password ||
      (origin.protocol !== 'https:' && !development)) {
    throw new HttpError(503, 'REMOTE_MCP_ORIGIN_UNAVAILABLE', 'Remote MCP requires a canonical HTTPS origin or explicit loopback development');
  }
  return {
    serverUrl: `${origin.origin}/api/agent/mcp`, resource: agentOAuthResource(config),
    environment: development ? 'loopback-development' as const : 'configured-https' as const,
    externalVerification: 'unverified' as const,
    transportProfile: config.mcpTransportProfile ?? 'strict-2026-07-28',
    renewableOAuthAvailable: config.mcpTransportProfile === 'remote-oauth-v1',
    registration: config.mcpClientRegistry?.length ? 'pre-registered' as const : 'unavailable' as const,
    clientRegistrations: (config.mcpClientRegistry ?? []).map(({ clientId, clientName, redirectUris }) => ({ clientId, clientName, redirectUris })),
    scopes: connectionOAuthScopes(config),
    protocolVersions: [...REMOTE_MCP_PROTOCOLS],
    setup: { method: 'remote-url' as const, nativeAddUrl: null,
      instructions: 'Add this URL as a remote Streamable HTTP MCP server. This service uses a pre-registered public OAuth client: select the configured client ID and exact callback in your client and request agent:operate offline_access with the displayed resource. Sign in in the browser, select this agent, and review consent. Clients unable to supply this registration remain unverified. Your model-provider account is separate. Local disconnect does not revoke platform access.' },
    clients: targetClients.map(([id, label]) => ({ id, label, qualification: 'unverified' as const, nativeAddUrl: null })),
  };
}

export function connectionHealth(grant: { revokedAt: Date | null; expiresAt: Date },
  lastPreflightAt: Date | null, now = new Date()) {
  if (grant.revokedAt) return 'revoked' as const;
  if (grant.expiresAt <= now) return 'expired' as const;
  if (!lastPreflightAt) return 'authorized' as const;
  return now.getTime() - lastPreflightAt.getTime() > 5 * 60_000 ? 'offline' as const : 'preflight-verified' as const;
}
