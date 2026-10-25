import {
  boolean,
  foreignKey,
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

export const agentProfiles = pgTable("oid_agent", {
  id: uuid("id").primaryKey(),
  ownerId: uuid("owner_id").notNull().references(() => owners.id, { onDelete: "cascade" }),
  name: text("name").notNull(),
  description: text("description").notNull().default(""),
  clientMetadata: jsonb("client_metadata").$type<{ clientName: string | null; modelName: string | null }>().notNull().default({ clientName: null, modelName: null }),
  declaredVersion: text("declared_version"),
  revision: integer("revision").notNull().default(1),
  accessRevision: integer("access_revision").notNull().default(1),
  accessGeneration: integer("access_generation").notNull().default(1),
  accessRevokedAt: time("access_revoked_at"),
  createdAt: time("created_at").notNull().defaultNow(),
  updatedAt: time("updated_at").notNull().defaultNow()
}, (table) => [
  index("oid_agent_owner_updated_idx").on(table.ownerId, table.updatedAt),
  uniqueIndex("oid_agent_owner_id_uq").on(table.ownerId, table.id)
]);

export const agentPolicies = pgTable("oid_agent_policy", {
  agentId: uuid("agent_id").primaryKey().references(() => agentProfiles.id, { onDelete: "cascade" }),
  training: boolean("training").notNull().default(false),
  ranked: boolean("ranked").notNull().default(false),
  forumMessages: boolean("forum_messages").notNull().default(false),
  customTopics: boolean("custom_topics").notNull().default(false),
  revision: integer("revision").notNull().default(1),
  updatedAt: time("updated_at").notNull().defaultNow()
});

export const agentOperations = pgTable("oid_agent_operation", {
  operationId: text("operation_id").primaryKey(),
  ownerId: uuid("owner_id").notNull().references(() => owners.id, { onDelete: "cascade" }),
  agentId: uuid("agent_id").references(() => agentProfiles.id, { onDelete: "cascade" }),
  action: text("action").notNull(),
  payloadHash: text("payload_hash").notNull(),
  responseJson: jsonb("response_json"),
  createdAt: time("created_at").notNull().defaultNow()
}, (table) => [index("oid_agent_operation_owner_created_idx").on(table.ownerId, table.createdAt)]);

export const agentAccessGrants = pgTable("oid_agent_access_grant", {
  id: uuid("id").primaryKey(),
  ownerId: uuid("owner_id").notNull(),
  agentId: uuid("agent_id").notNull(),
  operationId: text("operation_id").notNull().unique(),
  source: text("source").notNull().default("manual"),
  resource: text("resource").notNull(),
  role: text("role").notNull().default("agent"),
  accessGeneration: integer("access_generation").notNull(),
  createdAt: time("created_at").notNull().defaultNow(),
  expiresAt: time("expires_at").notNull(),
  revokedAt: time("revoked_at"),
  revocationReason: text("revocation_reason")
}, (table) => [
  foreignKey({
    columns: [table.ownerId, table.agentId],
    foreignColumns: [agentProfiles.ownerId, agentProfiles.id],
    name: "oid_agent_access_grant_owner_agent_fk"
  }).onDelete("cascade"),
  index("oid_agent_access_grant_agent_created_idx").on(table.agentId, table.createdAt),
  index("oid_agent_access_grant_agent_generation_idx").on(table.agentId, table.accessGeneration)
]);

export const agentManualCredentials = pgTable("oid_agent_manual_credential", {
  id: uuid("id").primaryKey(),
  grantId: uuid("grant_id").notNull().unique().references(() => agentAccessGrants.id, { onDelete: "cascade" }),
  verifierHash: text("verifier_hash").notNull().unique(),
  createdAt: time("created_at").notNull().defaultNow()
}, (table) => [index("oid_agent_manual_credential_created_idx").on(table.createdAt)]);

export const agentCancellationOutbox = pgTable("oid_agent_cancellation_outbox", {
  eventId: uuid("event_id").primaryKey(),
  ownerId: uuid("owner_id").notNull(),
  agentId: uuid("agent_id").notNull(),
  accessGeneration: integer("access_generation").notNull(),
  operationId: text("operation_id").notNull().unique(),
  eventType: text("event_type").notNull().default("agent.access.revoked"),
  status: text("status").notNull().default("pending"),
  payloadJson: jsonb("payload_json").$type<{ scope: "all"; reason: "owner_global_revoke" }>().notNull(),
  createdAt: time("created_at").notNull().defaultNow()
}, (table) => [
  foreignKey({
    columns: [table.ownerId, table.agentId],
    foreignColumns: [agentProfiles.ownerId, agentProfiles.id],
    name: "oid_agent_cancellation_outbox_owner_agent_fk"
  }).onDelete("cascade"),
  uniqueIndex("oid_agent_cancellation_outbox_generation_uq").on(table.agentId, table.accessGeneration),
  index("oid_agent_cancellation_outbox_status_created_idx").on(table.status, table.createdAt)
]);

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
