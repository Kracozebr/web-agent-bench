import { randomBytes, randomUUID, createHash, createHmac } from "node:crypto";
import { AsyncLocalStorage } from "node:async_hooks";
import { betterAuth } from "better-auth";
import { google, verifyGoogleIdToken } from "better-auth/social-providers";
import { drizzleAdapter } from "@better-auth/drizzle-adapter";
import { siwe } from "better-auth/plugins";
import { verifyMessage } from "viem";
import type { OwnerIdentityConfig } from "./config.js";
import type { OwnerDatabase } from "./db.js";
import { authSchema, siweChallenges } from "./schema.js";
import { and, eq, gt, isNull } from "drizzle-orm";

interface SiweRequestContext {
  purpose: "signin";
  contextHash: string;
}

const siweRequestContext = new AsyncLocalStorage<SiweRequestContext>();
const hash = (value: string) => createHash("sha256").update(value).digest("hex");

function siweNonce(message: string): string | undefined {
  return /^Nonce:\s*([a-zA-Z0-9]{8,250})\s*$/m.exec(message)?.[1];
}

export function withSiweRequest<T>(context: SiweRequestContext, fn: () => T): T {
  return siweRequestContext.run(context, fn);
}

export function createAuth(config: OwnerIdentityConfig, db: OwnerDatabase) {
  const publicUrl = new URL(config.publicOrigin);
  const googleProvider = config.googleClientId && config.googleClientSecret
    ? google({ clientId: config.googleClientId, clientSecret: config.googleClientSecret, prompt: "select_account" }) : undefined;
  return betterAuth({
    appName: "Web3 Agent Bench Owner Identity",
    baseURL: config.publicOrigin,
    basePath: "/api/auth",
    secret: config.authSecret,
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
    plugins: [siwe({
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
