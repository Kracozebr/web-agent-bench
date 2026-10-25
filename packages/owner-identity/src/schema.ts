import {
  boolean,
  index,
  integer,
  jsonb,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
  uuid
} from "drizzle-orm/pg-core";

const time = (name: string) => timestamp(name, { withTimezone: true, mode: "date" });

export const authUser = pgTable("oid_auth_user", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  email: text("email").notNull().unique(),
  emailVerified: boolean("email_verified").notNull().default(false),
  image: text("image"),
  createdAt: time("created_at").notNull().defaultNow(),
  updatedAt: time("updated_at").notNull().defaultNow()
});

export const authSession = pgTable("oid_auth_session", {
  id: text("id").primaryKey(),
  expiresAt: time("expires_at").notNull(),
  token: text("token").notNull().unique(),
  createdAt: time("created_at").notNull().defaultNow(),
  updatedAt: time("updated_at").notNull().defaultNow(),
  ipAddress: text("ip_address"),
  userAgent: text("user_agent"),
  userId: text("user_id").notNull().references(() => authUser.id, { onDelete: "cascade" })
}, (table) => [index("oid_auth_session_user_idx").on(table.userId)]);

export const authAccount = pgTable("oid_auth_account", {
  id: text("id").primaryKey(),
  accountId: text("account_id").notNull(),
  providerId: text("provider_id").notNull(),
  userId: text("user_id").notNull().references(() => authUser.id, { onDelete: "cascade" }),
  accessToken: text("access_token"),
  refreshToken: text("refresh_token"),
  idToken: text("id_token"),
  accessTokenExpiresAt: time("access_token_expires_at"),
  refreshTokenExpiresAt: time("refresh_token_expires_at"),
  scope: text("scope"),
  password: text("password"),
  createdAt: time("created_at").notNull().defaultNow(),
  updatedAt: time("updated_at").notNull().defaultNow()
}, (table) => [
  uniqueIndex("oid_auth_account_provider_subject_uq").on(table.providerId, table.accountId),
  index("oid_auth_account_user_idx").on(table.userId)
]);

export const authVerification = pgTable("oid_auth_verification", {
  id: text("id").primaryKey(),
  identifier: text("identifier").notNull(),
  value: text("value").notNull(),
  expiresAt: time("expires_at").notNull(),
  createdAt: time("created_at").notNull().defaultNow(),
  updatedAt: time("updated_at").notNull().defaultNow()
}, (table) => [index("oid_auth_verification_identifier_idx").on(table.identifier)]);

export const authWalletAddress = pgTable("oid_auth_wallet_address", {
  id: text("id").primaryKey(),
  userId: text("user_id").notNull().references(() => authUser.id, { onDelete: "cascade" }),
  address: text("address").notNull(),
  chainId: integer("chain_id").notNull(),
  isPrimary: boolean("is_primary").notNull().default(false),
  createdAt: time("created_at").notNull().defaultNow()
}, (table) => [
  uniqueIndex("oid_auth_wallet_address_chain_uq").on(table.address, table.chainId),
  index("oid_auth_wallet_user_idx").on(table.userId)
]);

export const authSchema = {
  user: authUser,
  session: authSession,
  account: authAccount,
  verification: authVerification,
  walletAddress: authWalletAddress
};

export const owners = pgTable("oid_owner", {
  id: uuid("id").primaryKey(),
  authUserId: text("auth_user_id").notNull().unique().references(() => authUser.id, { onDelete: "cascade" }),
  admissionStatus: text("admission_status").notNull(),
  createdAt: time("created_at").notNull().defaultNow(),
  admittedAt: time("admitted_at")
}, (table) => [index("oid_owner_admission_status_idx").on(table.admissionStatus)]);

export const authFlows = pgTable("oid_auth_flow", {
  id: uuid("id").primaryKey(),
  operationId: text("operation_id").notNull().unique(),
  provider: text("provider").notNull(),
  purpose: text("purpose").notNull(),
  ownerId: uuid("owner_id").references(() => owners.id, { onDelete: "cascade" }),
  authSessionId: text("auth_session_id").references(() => authSession.id, { onDelete: "cascade" }),
  attemptHash: text("attempt_hash").notNull(),
  startedAt: time("started_at").notNull().defaultNow(),
  expiresAt: time("expires_at").notNull(),
  completedAt: time("completed_at"),
  outcome: text("outcome")
}, (table) => [index("oid_auth_flow_context_idx").on(table.attemptHash, table.startedAt)]);

export const googleLinkStates = pgTable("oid_google_link_state", {
  stateHash: text("state_hash").primaryKey(),
  operationId: text("operation_id").notNull().unique(),
  ownerId: uuid("owner_id").notNull().references(() => owners.id, { onDelete: "cascade" }),
  authSessionId: text("auth_session_id").notNull().references(() => authSession.id, { onDelete: "cascade" }),
  flowHash: text("flow_hash").notNull(),
  createdAt: time("created_at").notNull().defaultNow(),
  expiresAt: time("expires_at").notNull(),
  consumedAt: time("consumed_at")
}, (table) => [index("oid_google_link_owner_idx").on(table.ownerId, table.createdAt)]);

export const identities = pgTable("oid_identity", {
  id: uuid("id").primaryKey(),
  ownerId: uuid("owner_id").notNull().references(() => owners.id, { onDelete: "cascade" }),
  authUserId: text("auth_user_id").notNull().references(() => authUser.id, { onDelete: "cascade" }),
  provider: text("provider").notNull(),
  subject: text("subject").notNull(),
  verifiedAt: time("verified_at").notNull(),
  createdAt: time("created_at").notNull().defaultNow()
}, (table) => [
  uniqueIndex("oid_identity_provider_subject_uq").on(table.provider, table.subject),
  uniqueIndex("oid_identity_owner_provider_uq").on(table.ownerId, table.provider),
  index("oid_identity_auth_user_idx").on(table.authUserId)
]);

export const invitations = pgTable("oid_invitation", {
  id: uuid("id").primaryKey(),
  verifierHash: text("verifier_hash").notNull().unique(),
  issueOperationId: text("issue_operation_id").notNull(),
  issuedByOwnerId: uuid("issued_by_owner_id").notNull().references(() => owners.id),
  createdAt: time("created_at").notNull().defaultNow(),
  expiresAt: time("expires_at").notNull(),
  revokedAt: time("revoked_at"),
  redeemedAt: time("redeemed_at")
}, (table) => [
  uniqueIndex("oid_invitation_issue_operation_uq").on(table.issueOperationId),
  index("oid_invitation_issuer_created_idx").on(table.issuedByOwnerId, table.createdAt)
]);

export const admissions = pgTable("oid_admission", {
  ownerId: uuid("owner_id").primaryKey().references(() => owners.id, { onDelete: "cascade" }),
  operationId: text("operation_id").notNull().unique(),
  invitationId: uuid("invitation_id").unique().references(() => invitations.id),
  policyRevision: integer("policy_revision").notNull(),
  admittedAt: time("admitted_at").notNull().defaultNow()
});

export const invitationRedemptions = pgTable("oid_invitation_redemption", {
  invitationId: uuid("invitation_id").primaryKey().references(() => invitations.id),
  ownerId: uuid("owner_id").notNull().unique().references(() => owners.id),
  operationId: text("operation_id").notNull().unique(),
  policyRevision: integer("policy_revision").notNull(),
  redeemedAt: time("redeemed_at").notNull().defaultNow()
});

export const registrationPolicy = pgTable("oid_registration_policy", {
  id: integer("id").primaryKey(),
  mode: text("mode").notNull(),
  revision: integer("revision").notNull(),
  updatedAt: time("updated_at").notNull().defaultNow(),
  updatedByOwnerId: uuid("updated_by_owner_id").references(() => owners.id)
});

export const siweChallenges = pgTable("oid_siwe_challenge", {
  nonceHash: text("nonce_hash").primaryKey(),
  purpose: text("purpose").notNull(),
  ownerId: uuid("owner_id").references(() => owners.id, { onDelete: "cascade" }),
  authSessionId: text("auth_session_id").references(() => authSession.id, { onDelete: "cascade" }),
  operationId: text("operation_id").notNull().unique(),
  attemptHash: text("attempt_hash").notNull(),
  createdAt: time("created_at").notNull().defaultNow(),
  expiresAt: time("expires_at").notNull(),
  consumedAt: time("consumed_at")
}, (table) => [index("oid_siwe_challenge_owner_idx").on(table.ownerId, table.createdAt)]);

export const rateLimits = pgTable("oid_rate_limit", {
  keyHash: text("key_hash").primaryKey(),
  bucketStart: integer("bucket_start").notNull(),
  requestCount: integer("request_count").notNull(),
  updatedAt: time("updated_at").notNull().defaultNow()
});

export const auditEvents = pgTable("oid_audit", {
  id: uuid("id").primaryKey(),
  eventType: text("event_type").notNull(),
  operationId: text("operation_id").notNull(),
  actorOwnerId: uuid("actor_owner_id").references(() => owners.id),
  subjectOwnerId: uuid("subject_owner_id").references(() => owners.id),
  invitationId: uuid("invitation_id").references(() => invitations.id),
  policyRevision: integer("policy_revision"),
  metadata: jsonb("metadata").notNull().default({}),
  createdAt: time("created_at").notNull().defaultNow()
}, (table) => [
  index("oid_audit_operation_idx").on(table.operationId),
  index("oid_audit_type_created_idx").on(table.eventType, table.createdAt)
]);
