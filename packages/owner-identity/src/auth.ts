import { randomBytes, randomUUID, createHash, createHmac } from "node:crypto";
import { AsyncLocalStorage } from "node:async_hooks";
import { betterAuth } from "better-auth";
import { mcp } from "@better-auth/mcp";
import { google, verifyGoogleIdToken } from "better-auth/social-providers";
import { drizzleAdapter } from "@better-auth/drizzle-adapter";
import { jwt, siwe } from "better-auth/plugins";
import { verifyMessage } from "viem";
import type { OwnerIdentityConfig } from "./config.js";
import type { OwnerDatabase } from "./db.js";
import { agentAccessGrants, agentOauthAuthorizations, agentProfiles, authSchema, owners, siweChallenges } from "./schema.js";
import { and, eq, gt, isNull } from "drizzle-orm";

interface SiweRequestContext {
  purpose: "signin";
  contextHash: string;
}

const siweRequestContext = new AsyncLocalStorage<SiweRequestContext>();
export interface OAuthSelectionContext {
  authUserId: string;
  authSessionId: string;
  ownerId: string;
  agentId: string;
  grantId: string;
}
const oauthSelectionContext = new AsyncLocalStorage<OAuthSelectionContext>();
const hash = (value: string) => createHash("sha256").update(value).digest("hex");

function siweNonce(message: string): string | undefined {
  return /^Nonce:\s*([a-zA-Z0-9]{8,250})\s*$/m.exec(message)?.[1];
}

export function withSiweRequest<T>(context: SiweRequestContext, fn: () => T): T {
  return siweRequestContext.run(context, fn);
}

export function withOAuthSelection<T>(context: OAuthSelectionContext, fn: () => T): T {
  return oauthSelectionContext.run(context, fn);
}

export function createAuth(config: OwnerIdentityConfig, db: OwnerDatabase) {
  const publicUrl = new URL(config.publicOrigin);
  const agentResource = `${config.publicOrigin}/api/agent`;
  const issuer = `${config.publicOrigin}/api/auth`;
  const googleProvider = config.googleClientId && config.googleClientSecret
    ? google({ clientId: config.googleClientId, clientSecret: config.googleClientSecret, prompt: "select_account" }) : undefined;
  return betterAuth({
    appName: "Web3 Agent Bench Owner Identity",
    baseURL: config.publicOrigin,
    basePath: "/api/auth",
    secret: config.authSecret,
    logger: { disabled: true },
    database: drizzleAdapter(db, { provider: "pg", schema: authSchema }),
    trustedOrigins: [config.publicOrigin],
    session: { expiresIn: config.sessionTtlSeconds, updateAge: 3600 },
    account: {
      accountLinking: {
        enabled: true,
        disableImplicitLinking: true,
        allowDifferentEmails: true,
        trustedProviders: []
      }
    },
    emailAndPassword: { enabled: false },
    socialProviders: config.googleClientId && config.googleClientSecret ? {
      google: {
        clientId: config.googleClientId,
        clientSecret: config.googleClientSecret,
        prompt: "select_account",
        // AICODE-NOTE: In this pinned version the authorization-code getUserInfo
        // default decodes the JWT. Explicitly invoke its exported JWT verifier.
        getUserInfo: async (tokens) => {
          if (!tokens.idToken) return null;
          const expectedNonce = (tokens as { expectedIdTokenNonce?: string }).expectedIdTokenNonce;
          const claims = await verifyGoogleIdToken({
            token: tokens.idToken, audience: config.googleClientId!,
            ...(expectedNonce ? { nonce: expectedNonce } : {}),
          });
          if (!claims || typeof claims.sub !== "string" || !claims.sub || typeof claims.email !== "string") return null;
          return googleProvider?.getUserInfo(tokens) ?? null;
        }
      }
    } : {},
    advanced: {
      useSecureCookies: config.nodeEnv === "production",
      defaultCookieAttributes: {
        sameSite: "lax",
        httpOnly: true,
        secure: config.nodeEnv === "production",
        path: "/"
      }
    },
    plugins: [jwt({ jwt: { issuer, audience: agentResource } }), mcp({
      resource: agentResource,
      scopes: ["agent:operate"],
      loginPage: "/owner/agents/oauth-select",
      consentPage: "/owner/agents/oauth-consent",
      allowUnauthenticatedClientRegistration: false,
      allowDynamicClientRegistration: false,
      grantTypes: ["authorization_code"],
      codeExpiresIn: 600,
      accessTokenExpiresIn: 3600,
      refreshTokenReuseInterval: 0,
      postLogin: {
        page: "/owner/agents/oauth-select",
        shouldRedirect: ({ user, session, isContinuation }: { user: { id: string }; session: { id: string }; isContinuation: boolean }) => {
          const selection = oauthSelectionContext.getStore();
          const boundSelection = Boolean(isContinuation && selection && selection.authUserId === user.id && selection.authSessionId === session.id);
          return !boundSelection;
        },
        consentReferenceId: ({ user, session }: { user: { id: string }; session: { id: string } }) => {
          const selection = oauthSelectionContext.getStore();
          if (!selection) return undefined;
          if (selection.authUserId !== user.id || selection.authSessionId !== session.id) throw new Error("OAuth agent selection context is mismatched");
          return selection.grantId;
        }
      },
      customAccessTokenClaims: async ({ user, referenceId }: { user?: { id: string } | null; referenceId?: string }) => {
        if (!user?.id || !referenceId) throw new Error("OAuth token has no authenticated owner or agent grant reference");
        const grant = await db.query.agentAccessGrants.findFirst({ where: and(
          eq(agentAccessGrants.id, referenceId), eq(agentAccessGrants.source, "oauth"),
          isNull(agentAccessGrants.revokedAt), gt(agentAccessGrants.expiresAt, new Date())
        ) });
        if (!grant) throw new Error("OAuth agent grant is not active");
        const authorization = await db.query.agentOauthAuthorizations.findFirst({ where: and(
          eq(agentOauthAuthorizations.grantId, grant.id),
          eq(agentOauthAuthorizations.status, "approved"),
          eq(agentOauthAuthorizations.authUserId, user.id)
        ) });
        if (!authorization || authorization.ownerId !== grant.ownerId || authorization.agentId !== grant.agentId ||
          authorization.clientId !== grant.oauthClientId || authorization.resource !== grant.resource ||
          authorization.accessGeneration !== grant.accessGeneration || !authorization.authorizationCodeHash) {
          throw new Error("OAuth agent consent is missing or no longer bound to this grant");
        }
        const profile = await db.query.agentProfiles.findFirst({ where: eq(agentProfiles.id, grant.agentId) });
        const owner = await db.query.owners.findFirst({ where: eq(owners.id, grant.ownerId) });
        if (!profile || !owner || owner.authUserId !== user.id || owner.admissionStatus !== "admitted" ||
          profile.ownerId !== grant.ownerId || profile.accessGeneration !== grant.accessGeneration || profile.accessRevokedAt) {
          throw new Error("OAuth agent grant owner or generation binding is no longer valid");
        }
        return {
          oid_owner_id: grant.ownerId,
          oid_agent_id: grant.agentId,
          oid_grant_id: grant.id,
          oid_access_generation: grant.accessGeneration,
          oid_role: grant.role
        };
      }
    }), siwe({
      domain: publicUrl.host,
      anonymous: true,
      getNonce: async () => {
        const context = siweRequestContext.getStore();
        if (!context || context.purpose !== "signin") throw new Error("SIWE nonce request context is missing");
        const nonce = randomBytes(24).toString("base64url").replace(/[-_]/g, "A");
        const now = new Date();
        await db.insert(siweChallenges).values({
          nonceHash: hash(nonce),
          purpose: "signin",
          ownerId: null,
          authSessionId: null,
          operationId: randomUUID(),
          attemptHash: context.contextHash,
          createdAt: now,
          expiresAt: new Date(now.getTime() + config.nonceTtlSeconds * 1000)
        });
        return nonce;
      },
      verifyMessage: async ({ message, signature, address, chainId }) => {
        const context = siweRequestContext.getStore();
        const nonce = siweNonce(message);
        if (!context || !nonce) return false;
        const domain = /^([^\s]+) wants you to sign in with your Ethereum account:/m.exec(message)?.[1];
        const uri = /^URI:\s*(\S+)\s*$/m.exec(message)?.[1];
        const statement = /Ethereum account:\n[^\n]+\n\n([^\n]+)/m.exec(message)?.[1];
        if (domain !== publicUrl.host || uri !== config.publicOrigin || chainId !== config.siweChainId || statement !== "Sign in to Web3 Agent Bench") return false;
        // AICODE-NOTE: The pinned plugin validates expiration/nonce, but accepts
        // future Issued At values. Enforce the full signed time window here.
        const readTime = (label: string, required = false): number | undefined => {
          const lines = message.split("\n").filter((line) => line.startsWith(`${label}:`));
          if (lines.length > 1 || (required && lines.length !== 1)) return NaN;
          if (!lines.length) return undefined;
          return Date.parse(lines[0]!.slice(label.length + 1).trim());
        };
        const issuedAt = readTime("Issued At", true);
        const expiration = readTime("Expiration Time");
        const notBefore = readTime("Not Before");
        const now = Date.now();
        if (issuedAt === undefined || !Number.isFinite(issuedAt) || issuedAt > now + 30_000 ||
          (expiration !== undefined && (!Number.isFinite(expiration) || expiration <= now || expiration < issuedAt)) ||
          (notBefore !== undefined && (!Number.isFinite(notBefore) || notBefore > now))) return false;
        const challenge = await db.query.siweChallenges.findFirst({
          where: (table, { and, eq, gt, isNull }) => and(
            eq(table.nonceHash, hash(nonce)),
            eq(table.purpose, "signin"),
            isNull(table.ownerId),
            eq(table.attemptHash, context.contextHash),
            gt(table.expiresAt, new Date()),
            isNull(table.consumedAt)
          )
        });
        if (!challenge) return false;
        const consumed = await db.update(siweChallenges)
          .set({ consumedAt: new Date() })
          .where(and(
            eq(siweChallenges.nonceHash, hash(nonce)),
            eq(siweChallenges.purpose, "signin"),
            eq(siweChallenges.attemptHash, context.contextHash),
            gt(siweChallenges.expiresAt, new Date()),
            isNull(siweChallenges.consumedAt)
          ))
          .returning({ nonceHash: siweChallenges.nonceHash });
        if (consumed.length !== 1) return false;
        try {
          return await verifyMessage({ address: address as `0x${string}`, message, signature: signature as `0x${string}` });
        } catch {
          return false;
        }
      }
    })]
  });
}

export function siweRequestFingerprint(config: OwnerIdentityConfig, ip: string, userAgent: string): string {
  return createHmac("sha256", config.authSecret).update(`${ip}\n${userAgent}`).digest("hex");
}
