import { isLoopbackHost, type OwnerIdentityConfig } from './config.js';
import { HttpError } from './http-error.js';

const CODEX_PROFILE = 'codex-local-manual-2025-06-18';
const LEGACY_METHODS = new Set(['initialize', 'notifications/initialized', 'ping', 'tools/list', 'tools/call']);
function object(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {};
}
/** AICODE-NOTE: This selects a wire parser only; the already authenticated principal and domain checks retain all authority. */
export function selectAgentMcpTransport(config: OwnerIdentityConfig, manualCredential: boolean,
  body: unknown, headers: Record<string, unknown>): 'strict' | 'codex-local' {
  const message = object(body);
  const legacy = message.jsonrpc === '2.0' && typeof message.method === 'string' && !headers['mcp-method'];
  if (!legacy || config.mcpTransportProfile !== CODEX_PROFILE) return 'strict';
  const origin = new URL(config.publicOrigin);
  if (!config.localBefTaskCoordinatorEnabled || !config.localBefTaskCoordinatorConfigPath ||
      !['development', 'test'].includes(config.nodeEnv.toLowerCase()) ||
      !isLoopbackHost(config.apiHost) || origin.protocol !== 'http:' ||
      !isLoopbackHost(origin.hostname)) {
    throw new HttpError(503, 'LOCAL_MCP_PROFILE_UNAVAILABLE', 'The selected compatibility profile requires the verified local BEF runtime');
  }
  if (!manualCredential) throw new HttpError(403, 'LEGACY_MANUAL_CREDENTIAL_REQUIRED', 'This local transport profile requires a manual agent credential');
  const protocol = headers['mcp-protocol-version'];
  if (protocol !== undefined && protocol !== '2025-06-18') throw new HttpError(400, 'UNSUPPORTED_MCP_PROTOCOL', 'Unsupported compatibility protocol');
  if (!LEGACY_METHODS.has(message.method as string)) throw new HttpError(400, 'UNSUPPORTED_MCP_METHOD', 'Unsupported compatibility method');
  if (message.method === 'initialize') {
    const params = object(message.params), client = object(params.clientInfo);
    if (params.protocolVersion !== '2025-06-18' || client.name !== 'codex-mcp-client' || client.version !== '0.165.0') {
      throw new HttpError(400, 'UNSUPPORTED_MCP_CLIENT_PROFILE', 'Unsupported local client profile');
    }
  }
  return 'codex-local';
}