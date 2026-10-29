import { isLoopbackHost, type OwnerIdentityConfig } from './config.js';
import { HttpError } from './http-error.js';

const CODEX_PROFILE = 'codex-local-manual-2025-06-18';
const LEGACY_METHODS = new Set(['initialize', 'notifications/initialized', 'ping', 'tools/list', 'tools/call']);
type SelectedTransport = 'strict' | 'codex-local' | 'beta-remote';
function object(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function acceptsStreamableHttp(value: unknown): boolean {
  if (typeof value !== 'string') return false;
  const mediaTypes = new Set(value.split(',').map((part) => part.split(';', 1)[0]!.trim().toLowerCase()));
  return mediaTypes.has('application/json') && mediaTypes.has('text/event-stream');
}

/** AICODE-NOTE: This selects wire parsing only. Authenticated principals and domain checks retain all authority. */
export function selectAgentMcpTransport(config: OwnerIdentityConfig, manualCredential: boolean,
  body: unknown, headers: Record<string, unknown>, oauthClientId?: string): SelectedTransport {
  const message = object(body);
  const method = typeof message.method === 'string' ? message.method : '';
  const legacy = message.jsonrpc === '2.0' && Boolean(method) && !headers['mcp-method'];

  if (config.mcpTransportProfile === 'beta-remote-v1') {
    const manifest = config.betaManifest;
    if (!manifest || !['production'].includes(config.nodeEnv.toLowerCase())) {
      throw new HttpError(503, 'BETA_MCP_PROFILE_UNAVAILABLE', 'The beta transport requires a production beta manifest');
    }
    if (message.jsonrpc !== '2.0' || !method || !acceptsStreamableHttp(headers.accept)) {
      throw new HttpError(400, 'MCP_STREAMABLE_HTTP_REQUIRED', 'The beta remote profile requires a valid Streamable HTTP JSON-RPC request');
    }
    const initialize = method === 'initialize';
    const params = object(message.params), clientInfo = object(params.clientInfo);
    const modernClientInfo = object(object(message._meta)['io.modelcontextprotocol/clientInfo']);
    const headerProtocol = headers['mcp-protocol-version'];
    const bodyProtocol = initialize && typeof params.protocolVersion === 'string' ? params.protocolVersion : undefined;
    if (headerProtocol !== undefined && typeof headerProtocol !== 'string') {
      throw new HttpError(400, 'UNSUPPORTED_MCP_PROTOCOL', 'Unsupported MCP protocol header');
    }
    if (bodyProtocol && headerProtocol && bodyProtocol !== headerProtocol) {
      throw new HttpError(400, 'UNSUPPORTED_MCP_PROTOCOL', 'MCP initialize and request protocol versions do not match');
    }
    const protocol = bodyProtocol ?? headerProtocol;
    const modern = protocol === '2026-07-28';
    if (modern && (headers['mcp-method'] !== method ||
        (method === 'tools/call' && headers['mcp-name'] !== params.name))) {
      throw new HttpError(400, 'MCP_STREAMABLE_HTTP_REQUIRED', 'The beta modern profile requires matching MCP routing headers');
    }
    if (!modern && headers['mcp-method'] !== undefined) {
      throw new HttpError(400, 'UNSUPPORTED_MCP_PROTOCOL', 'The pinned handshake protocol does not use modern routing headers');
    }
    const clients = manifest.clients.filter((profile) => profile.enabled &&
      (manualCredential ? profile.authMethods.includes('manual_bearer') :
        Boolean(oauthClientId && profile.oauthClientId === oauthClientId)) &&
      (modern
        ? profile.mcpClientName === modernClientInfo.name && profile.mcpClientVersion === modernClientInfo.version
        : (!initialize || (profile.mcpClientName === clientInfo.name && profile.mcpClientVersion === clientInfo.version))) &&
      (!protocol || profile.protocolVersions.includes(protocol as typeof profile.protocolVersions[number])));
    if (!protocol || clients.length === 0 || (legacy && !LEGACY_METHODS.has(method))) {
      throw new HttpError(400, 'UNSUPPORTED_BETA_CLIENT_PROFILE', 'The client, authentication method, or protocol is not in the pinned beta profile');
    }
    if (legacy && protocol !== '2025-06-18') {
      throw new HttpError(400, 'UNSUPPORTED_MCP_PROTOCOL', 'The headerless request is not a pinned handshake protocol request');
    }
    return 'beta-remote';
  }

  if (!legacy || config.mcpTransportProfile !== CODEX_PROFILE) return 'strict';
  const origin = new URL(config.publicOrigin);
  if (!config.localBefTaskCoordinatorEnabled || !config.localBefTaskCoordinatorConfigPath ||
      !['development', 'test'].includes(config.nodeEnv.toLowerCase()) ||
      !isLoopbackHost(config.apiHost) || origin.protocol !== 'http:' || !isLoopbackHost(origin.hostname)) {
    throw new HttpError(503, 'LOCAL_MCP_PROFILE_UNAVAILABLE', 'The selected compatibility profile requires the verified local BEF runtime');
  }
  if (!manualCredential) throw new HttpError(403, 'LEGACY_MANUAL_CREDENTIAL_REQUIRED', 'This local transport profile requires a manual agent credential');
  const protocol = headers['mcp-protocol-version'];
  if (protocol !== undefined && protocol !== '2025-06-18') throw new HttpError(400, 'UNSUPPORTED_MCP_PROTOCOL', 'Unsupported compatibility protocol');
  if (!LEGACY_METHODS.has(method)) throw new HttpError(400, 'UNSUPPORTED_MCP_METHOD', 'Unsupported compatibility method');
  if (method === 'initialize') {
    const params = object(message.params), client = object(params.clientInfo);
    if (params.protocolVersion !== '2025-06-18' || client.name !== 'codex-mcp-client' || client.version !== '0.165.0') {
      throw new HttpError(400, 'UNSUPPORTED_MCP_CLIENT_PROFILE', 'Unsupported local client profile');
    }
  }
  return 'codex-local';
}
