import { isIP } from 'node:net';
import { isAbsolute } from 'node:path';
import { z } from 'zod';

export const BETA_EXECUTION_PROFILE_ID = 'beta-bef-v1' as const;
export const BETA_TRANSPORT_PROFILE_ID = 'beta-remote-v1' as const;
export const BETA_MCP_PROTOCOLS = ['2025-06-18', '2026-07-28'] as const;
export const BETA_CLIENT_FAMILIES = ['codex', 'claude-code', 'claude-desktop', 'hermes'] as const;

const Hash = z.string().regex(/^[0-9a-f]{64}$/i);
const Commit = z.string().regex(/^[0-9a-f]{40,64}$/i);

function exactHttpsOrigin(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && url.origin === value && !url.username && !url.password;
  } catch { return false; }
}

function loopbackHost(host: string): boolean {
  const normalized = host.toLowerCase().replace(/^\[|\]$/g, '');
  return normalized === 'localhost' || normalized === '::1' || (isIP(normalized) === 4 && normalized.startsWith('127.'));
}

/** Exact fixed OAuth callbacks only. Wildcards, query fragments and user-info are never allowed. */
export function isExactBetaRedirectUri(value: string): boolean {
  try {
    const url = new URL(value);
    if (url.href !== value || url.username || url.password || url.search || url.hash || url.pathname === '') return false;
    if (url.protocol === 'https:') return true;
    return url.protocol === 'http:' && loopbackHost(url.hostname) && url.port.length > 0;
  } catch { return false; }
}

function validCidr(value: string): boolean {
  const [address, rawPrefix, extra] = value.split('/');
  if (!address || rawPrefix === undefined || extra !== undefined) return false;
  const version = isIP(address);
  if (!version || !/^\d{1,3}$/.test(rawPrefix)) return false;
  const prefix = Number(rawPrefix);
  // A /0 trusts or exposes every address. It is never a restricted proxy or read allowlist.
  return version === 4 ? prefix > 0 && prefix <= 32 : prefix > 0 && prefix <= 128;
}

const Cidr = z.string().refine(validCidr, 'must be an exact IPv4 or IPv6 CIDR');
const RedirectUri = z.string().refine(isExactBetaRedirectUri, 'must be an exact HTTPS or loopback callback URI');

function ipv4Value(address: string): bigint | null {
  if (isIP(address) !== 4) return null;
  return address.split('.').reduce((value, part) => (value << 8n) | BigInt(Number(part)), 0n);
}

function ipv6Value(address: string): bigint | null {
  if (isIP(address) !== 6) return null;
  let source = address.toLowerCase();
  const ipv4Tail = source.match(/(?:^|:)(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (ipv4Tail) {
    const packed = ipv4Value(ipv4Tail[1]!);
    if (packed === null) return null;
    source = source.slice(0, -ipv4Tail[1]!.length) + `${((packed >> 16n) & 0xffffn).toString(16)}:${(packed & 0xffffn).toString(16)}`;
  }
  const halves = source.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0]!.split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1]!.split(':') : [];
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) return null;
  const parts = [...left, ...Array.from({ length: missing }, () => '0'), ...right];
  if (parts.length !== 8 || parts.some((part) => !/^[0-9a-f]{1,4}$/.test(part))) return null;
  return parts.reduce((value, part) => (value << 16n) | BigInt(Number.parseInt(part, 16)), 0n);
}

function mappedIpv4(address: string): string | null {
  const match = address.toLowerCase().match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/);
  return match && isIP(match[1]!) === 4 ? match[1]! : null;
}

/** Match a concrete peer address against exact CIDRs. Callers must supply the socket peer,
 * never an address copied from Forwarded/X-Forwarded-For request headers. */
export function isAddressInCidrs(address: string | undefined, cidrs: readonly string[]): boolean {
  if (!address) return false;
  const unwrapped = address.startsWith('[') && address.endsWith(']') ? address.slice(1, -1) : address;
  const mapped = mappedIpv4(unwrapped);
  const actualAddress = mapped ?? unwrapped;
  const version = isIP(actualAddress);
  if (!version) return false;
  for (const cidr of cidrs) {
    const [rawNetwork, rawPrefix, extra] = cidr.split('/');
    if (!rawNetwork || rawPrefix === undefined || extra !== undefined) continue;
    const networkVersion = isIP(rawNetwork);
    const prefix = Number(rawPrefix);
    const maxPrefix = networkVersion === 4 ? 32 : networkVersion === 6 ? 128 : 0;
    if (version !== networkVersion || !Number.isInteger(prefix) || prefix <= 0 || prefix > maxPrefix) continue;
    const actual = version === 4 ? ipv4Value(actualAddress) : ipv6Value(actualAddress);
    const network = version === 4 ? ipv4Value(rawNetwork) : ipv6Value(rawNetwork);
    if (actual === null || network === null) continue;
    const bits = BigInt(maxPrefix);
    const mask = ((1n << bits) - 1n) ^ ((1n << (bits - BigInt(prefix))) - 1n);
    if ((actual & mask) === (network & mask)) return true;
  }
  return false;
}

/** Qualification reads must be reached directly from an allowlisted peer. A shared proxy peer
 * cannot distinguish an allowlisted operator from an internet caller, so proxy forwarding is
 * denied here regardless of any client-controlled forwarding headers. */
export function isQualificationReadPeerAllowed(address: string | undefined, manifest: BetaDeploymentManifest): boolean {
  return manifest.state === 'qualification' && !isAddressInCidrs(address, manifest.trustedProxyCidrs) &&
    isAddressInCidrs(address, manifest.qualificationReadCidrs);
}

const ClientProfile = z.object({
  family: z.enum(BETA_CLIENT_FAMILIES),
  enabled: z.boolean(),
  verificationStatus: z.enum(['unverified', 'verified']),
  edition: z.string().min(1).max(120).nullable(),
  version: z.string().min(1).max(120).nullable(),
  platform: z.string().min(1).max(120).nullable(),
  mcpClientName: z.string().min(1).max(120).nullable(),
  mcpClientVersion: z.string().min(1).max(120).nullable(),
  protocolVersions: z.array(z.enum(BETA_MCP_PROTOCOLS)).max(2),
  authMethods: z.array(z.enum(['manual_bearer', 'oauth_authorization_code'])).max(2),
  oauthClientId: z.string().regex(/^[A-Za-z0-9._:-]{8,128}$/).nullable(),
  redirectUris: z.array(RedirectUri).max(8),
  verificationEvidenceSha256: z.array(Hash).max(32)
}).strict().superRefine((profile, ctx) => {
  const add = (path: string, message: string) => ctx.addIssue({ code: 'custom', path: [path], message });
  if (profile.enabled) {
    if (!profile.edition) add('edition', 'an enabled client must pin an edition');
    if (!profile.version) add('version', 'an enabled client must pin a version');
    if (!profile.platform) add('platform', 'an enabled client must pin a platform');
    if (!profile.mcpClientName || !profile.mcpClientVersion) add('mcpClientName', 'an enabled client must pin MCP initialization metadata');
    if (profile.protocolVersions.length === 0) add('protocolVersions', 'an enabled client must allow an implemented protocol version');
    if (profile.authMethods.length === 0) add('authMethods', 'an enabled client must declare an authentication method');
  } else if (profile.edition || profile.version || profile.platform || profile.mcpClientName || profile.mcpClientVersion ||
      profile.protocolVersions.length || profile.authMethods.length || profile.oauthClientId || profile.redirectUris.length) {
    add('enabled', 'disabled profiles must not declare connection values');
  }
  const oauthEnabled = profile.authMethods.includes('oauth_authorization_code');
  if (oauthEnabled !== Boolean(profile.oauthClientId) || oauthEnabled !== (profile.redirectUris.length > 0)) {
    add('oauthClientId', 'OAuth client id and exact callbacks must be declared together with OAuth');
  }
  if (profile.verificationStatus === 'verified' && (!profile.enabled || profile.verificationEvidenceSha256.length === 0)) {
    add('verificationEvidenceSha256', 'verified profiles require enabled status and pinned evidence hashes');
  }
  if (new Set(profile.protocolVersions).size !== profile.protocolVersions.length ||
      new Set(profile.authMethods).size !== profile.authMethods.length ||
      new Set(profile.redirectUris).size !== profile.redirectUris.length) {
    add('protocolVersions', 'protocols, auth methods and redirect URIs must be unique');
  }
});

export const BetaDeploymentManifestSchema = z.object({
  schemaVersion: z.literal('beta-deployment-manifest/v1'),
  state: z.enum(['qualification', 'cohort_release']),
  executionProfileId: z.literal(BETA_EXECUTION_PROFILE_ID),
  transportProfileId: z.literal(BETA_TRANSPORT_PROFILE_ID),
  source: z.object({
    commit: Commit,
    applicationBuildSha256: Hash,
    evaluatorSourceSha256: Hash
  }).strict(),
  publicOrigin: z.string().refine(exactHttpsOrigin, 'must be an HTTPS origin'),
  apiBindHost: z.string().min(1).max(253),
  apiPort: z.number().int().min(1).max(65535),
  trustedProxyCidrs: z.array(Cidr).min(1).max(32),
  qualificationReadCidrs: z.array(Cidr).max(32),
  google: z.object({
    issuer: z.literal('https://accounts.google.com'),
    clientId: z.string().min(8).max(512),
    callbackUri: RedirectUri,
    adminSubject: z.string().regex(/^[A-Za-z0-9._:-]{8,256}$/)
  }).strict(),
  release: z.object({
    releaseIdentity: z.string().min(1).max(120),
    manifestHash: Hash,
    benchmarkHash: Hash,
    policyHash: Hash,
    benchmarkVersion: z.string().min(1).max(120),
    executionIdentityHash: Hash,
    environmentManifestSha256: Hash,
    applicationSourceSha256: Hash,
    sourceBlockHash: Hash
  }).strict(),
  queue: z.object({
    executionCapacity: z.literal(1),
    maxAcceptedPerOwner: z.literal(2),
    maxAcceptedGlobal: z.literal(8),
    maxPendingPerOwner: z.literal(2),
    maxPendingGlobal: z.literal(30),
    queueWaitSeconds: z.literal(86400),
    successorPreparationTimeoutSeconds: z.literal(180),
    platformRecoverySeconds: z.literal(180)
  }).strict(),
  storage: z.object({
    privateDataDir: z.string().min(1).max(1024).refine(isAbsolute, 'must be an absolute persistent path'),
    evidenceDirectory: z.string().regex(/^[A-Za-z0-9._-]{1,80}$/),
    reportRetentionDaysAfterClosure: z.literal(30)
  }).strict(),
  secretReferences: z.object({
    authSecretEnv: z.literal('OID_AUTH_SECRET'),
    googleClientSecretEnv: z.literal('OID_GOOGLE_CLIENT_SECRET'),
    bonusCodeVerifierSecretEnv: z.literal('OID_BONUS_CODE_VERIFIER_SECRET')
  }).strict(),
  clients: z.array(ClientProfile).length(BETA_CLIENT_FAMILIES.length),
  releaseEvidenceSha256: Hash.optional()
}).strict().superRefine((manifest, ctx) => {
  const families = manifest.clients.map((profile) => profile.family);
  if (new Set(families).size !== BETA_CLIENT_FAMILIES.length || BETA_CLIENT_FAMILIES.some((family) => !families.includes(family))) {
    ctx.addIssue({ code: 'custom', path: ['clients'], message: 'must declare each of the four selected client families exactly once' });
  }
  const oauthClients = manifest.clients.flatMap((profile) => profile.oauthClientId ? [profile.oauthClientId] : []);
  if (new Set(oauthClients).size !== oauthClients.length) {
    ctx.addIssue({ code: 'custom', path: ['clients'], message: 'OAuth client identifiers must be unique per client family' });
  }
  if (manifest.google.callbackUri !== `${manifest.publicOrigin}/api/auth/callback/google`) {
    ctx.addIssue({ code: 'custom', path: ['google', 'callbackUri'], message: 'must exactly match the configured Google callback' });
  }
  if (manifest.state === 'qualification' && manifest.qualificationReadCidrs.length === 0) {
    ctx.addIssue({ code: 'custom', path: ['qualificationReadCidrs'], message: 'qualification requires an explicit anonymous-read allowlist' });
  }
  if (manifest.state === 'cohort_release' && (!manifest.releaseEvidenceSha256 || manifest.clients.some((profile) =>
      !profile.enabled || profile.verificationStatus !== 'verified' || profile.verificationEvidenceSha256.length === 0))) {
    ctx.addIssue({ code: 'custom', path: ['clients'], message: 'cohort release requires pinned complete evidence and all four verified client profiles' });
  }
});

export type BetaDeploymentManifest = z.infer<typeof BetaDeploymentManifestSchema>;
export type BetaClientProfile = BetaDeploymentManifest['clients'][number];
export type BetaMcpClientRegistration = { clientId: string; redirectUris: string[]; clientName: string };

export function parseBetaDeploymentManifest(value: unknown): BetaDeploymentManifest {
  const result = BetaDeploymentManifestSchema.safeParse(value);
  if (!result.success) throw new Error('beta_manifest_invalid');
  return result.data;
}

export function betaMcpClientRegistry(manifest: BetaDeploymentManifest): BetaMcpClientRegistration[] {
  return manifest.clients.flatMap((profile) => profile.enabled && profile.oauthClientId
    ? [{ clientId: profile.oauthClientId, redirectUris: [...profile.redirectUris], clientName: `${profile.family} ${profile.edition} ${profile.version}` }]
    : []);
}
