export type IdentityProvider = "google" | "wallet";

export interface OwnerIdentity {
  provider: IdentityProvider;
  subject: string;
  verifiedAt: string;
  displayLabel?: string;
}

export interface OwnerProjection {
  id: string;
  admissionStatus: "pending" | "admitted";
  isAdmin: boolean;
  identities: OwnerIdentity[];
}

export interface OwnerResponse {
  owner: OwnerProjection;
  admission: {
    status: "pending" | "admitted";
    policyRevision: number;
  };
}

export interface RegistrationPolicy {
  mode: "closed" | "open";
  revision: number;
  updatedAt?: string;
}

export interface OwnerBillingBalances {
  cash: { available: string; reserved: string };
  bonus: { available: string; reserved: string; expired: string };
}

export interface OwnerBonusGrant {
  id: string;
  amount: string;
  available: string;
  reserved: string;
  expired: string;
  createdAt: string;
  expiresAt: string | null;
  reason: string;
  status: "available" | "partially_reserved" | "reserved" | "expired" | "spent";
}

export interface AdminIssuedBonusGrant {
  id: string;
  ownerId: string;
  amount: string;
  reason: string;
  createdAt: string;
  expiresAt: string | null;
}

export interface OwnerBillingHistoryEntry {
  id: string;
  type: string;
  source: "cash_usdc" | "tester_bonus";
  amount: string;
  createdAt: string;
  expiresAt?: string | null;
  reason?: string;
  status?: string;
}

export interface OwnerBillingResponse {
  cash: OwnerBillingBalances["cash"];
  bonus: OwnerBillingBalances["bonus"];
  grants: OwnerBonusGrant[];
  history: OwnerBillingHistoryEntry[];
  observedAt: string;
  nextUtcResetAt: string;
}

export interface AgentFinancialPolicy {
  revision: number;
  allowCashShortfall: boolean;
  operationLimit: string | null;
  utcDayLimit: string | null;
  categoryLimits: {
    benchmark: string | null;
    forum: string | null;
  };
}

export type AgentFinancialPolicyResponse = AgentFinancialPolicy;

export type RunMode = "training" | "ranked";

export interface RunCatalogRelease {
  releaseIdentity: string;
  manifestHash: string;
  benchmarkVersion: string;
  benchmarkHash: string;
  policyHash: string;
  taskIds: string[];
  openTaskIds: string[];
  completeRankedRelease: boolean;
  rankedPrice: string;
  trainingPrice: string;
  precision: 6;
}

export interface RunCatalogResponse {
  status: "active" | "active_release_unavailable";
  activeRelease: RunCatalogRelease | null;
  intentCreationReady: boolean;
  intentCreationReason: string;
  readyToStart: boolean;
  readinessReason: string;
}

export interface RunLaunchIntent {
  id: string;
  agentId: string;
  mode: RunMode;
  taskIds: string[];
  benchmarkVersion: string;
  manifestHash: string;
  benchmarkHash: string;
  policyHash: string;
  quote: { price: string; precision: 6; token: "USDC" };
  cashCeiling: string;
  status: "pending" | "accepted" | "cancelled" | "expired";
  createdAt: string;
  expiresAt: string;
  acceptedAt: string | null;
  runId: string | null;
  runStatus: string | null;
  queueDeadline: string | null;
  queueExpiryFencePending: boolean;
  terminalReason: string | null;
}

export interface RunLaunchIntentsResponse { intents: RunLaunchIntent[] }
export interface RunLaunchIntentResponse { intent: RunLaunchIntent; replayed?: boolean }

export interface OwnerRunProjection {
  id: string;
  intentId: string;
  agentId: string;
  mode: RunMode;
  taskIds: string[];
  benchmarkVersion: string;
  manifestHash: string;
  benchmarkHash: string;
  policyHash: string;
  quotePrice: string;
  cashCeiling: string;
  status: string;
  queueDeadline: string | null;
  queuedAt: string | null;
  startedAt: string | null;
  overallDeadline: string | null;
  finishedAt: string | null;
  terminalReason: string | null;
  cancellationReason: string | null;
  cancellationRequestedAt: string | null;
  cancellationEvidenceHash: string | null;
  queueExpiryFencePending: boolean;
}

export interface OwnerRunsResponse { runs: OwnerRunProjection[] }
export interface OwnerRunResponse { run: OwnerRunProjection; replayed: boolean }

export interface IdentityConfig {
  googleEnabled: boolean;
  googleMode: "provider-fixture" | "google" | "disabled";
  siwe: {
    enabled: boolean;
    domain: string;
    uri: string;
    chainId: number;
    statement: string;
    nonceTtlSeconds: number;
  };
}

export interface InvitationRecord {
  id: string;
  issuedAt: string;
  expiresAt: string;
  status: "issued" | "revoked" | "redeemed" | "expired";
  revokedAt?: string | null;
  redeemedAt?: string | null;
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string | undefined;

  constructor(status: number, message: string, code?: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

const knownMessages: Record<string, string> = {
  UNAUTHORIZED: "Sign in again to continue.",
  FORBIDDEN: "This account is not authorized for that action.",
  INVITATION_INVALID: "That invitation could not be accepted. Check the code or ask its issuer for a new one.",
  INVITATION_EXPIRED: "That invitation has expired. Ask an administrator for a new invitation.",
  INVITATION_REVOKED: "That invitation has been revoked. Ask an administrator for a new invitation.",
  INVITATION_CONSUMED: "That invitation has already been used.",
  ADMISSION_ALREADY_GRANTED: "This owner is already admitted. Refresh the owner session; no invitation is needed.",
  IDENTITY_ALREADY_LINKED: "This sign-in method is already linked to another owner.",
  POLICY_REVISION_CONFLICT: "Admission settings changed in another session. The latest settings have been loaded.",
  REVISION_CONFLICT: "Settings changed in another session. The latest server revision has been loaded; review it before saving again.",
  ACCESS_REVISION_CONFLICT: "This agent’s access changed in another session. Check its current status before trying again.",
  CREDENTIAL_EXISTS: "A manual credential already exists. Check its safe status and replace it to issue a new one.",
  REAUTHORIZATION_REQUIRED: "All access for this agent was revoked. A new owner authorization is required before issuing another credential.",
  ACCESS_ALREADY_REVOKED: "All access for this agent has already been revoked.",
  OPERATION_ID_CONFLICT: "This operation identifier was already used with different data. Refresh the server state before retrying.",
  IDEMPOTENCY_CONFLICT: "This operation identifier was already used with different data. Use the unchanged request to recover its result, or start a new operation after reviewing server state.",
  OWNER_NOT_FOUND: "The target owner was not found. Check the owner UUID before retrying.",
  AGENT_NOT_FOUND: "This agent is no longer available to this owner. Refresh the agent list before changing its policy.",
  INVALID_OPERATION_ID: "The request identifier is invalid. Submit the form again to start a valid operation.",
  INVALID_REQUEST: "The server rejected unsupported or malformed fields. Review the form and try again.",
  INVALID_OWNER_ID: "Enter a valid owner UUID.",
  INVALID_AGENT_ID: "This agent identifier is invalid. Refresh the agent list and try again.",
  INVALID_AMOUNT: "Enter a positive amount with no more than six decimal places.",
  INVALID_REASON: "Enter a non-empty reason of at most 500 characters.",
  INVALID_EXPIRY: "Enter a valid expiry time, or leave it blank for no expiry.",
  EXPIRY_NOT_FUTURE: "That expiry time is no longer in the future. Choose a later time or leave it blank for no expiry.",
  INVALID_REVISION: "The settings revision is invalid. Refresh the page before saving again.",
  INVALID_CASH_POLICY: "The cash permission value is invalid. Refresh the page and try again.",
  INVALID_CATEGORY_LIMITS: "The category limits are invalid. Refresh the page and review the benchmark and forum caps.",
  IMMUTABLE_GRANT: "Bonus grant terms are immutable after issuance.",
  UNKNOWN_FIELD: "The server rejected an unsupported agent field. Review the current server response before trying again.",
  RATE_LIMITED: "Too many attempts. Wait a moment and try again.",
  RUN_POLICY_UNCONFIGURED: "Run admission is not enabled until bounded intent and queue settings are configured.",
  RELEASE_UNAVAILABLE: "No validated active benchmark release is available. Run intent creation is disabled.",
  RELEASE_INCOMPLETE: "A complete twelve-task active release is required before admission.",
  MODE_NOT_AUTHORIZED: "This agent does not currently have permission for the selected run mode.",
  PENDING_INTENT_LIMIT: "The owner has reached the pending intent limit. Refresh status before trying again.",
  GLOBAL_INTENT_CAPACITY: "Shared intent capacity is full. Refresh status before trying again.",
  RUN_INTENT_EXPIRED: "This launch intent has expired. Create a new intent after reviewing the current quote.",
  RUN_INTENT_CANCELLED: "This launch intent was cancelled and cannot be accepted.",
  RUN_INTENT_TERMINAL: "This launch intent is no longer pending and cannot admit a run.",
  STALE_RUN_INTENT: "The active version or quote changed. Review the current release and create a new intent.",
  STALE_AGENT_POLICY: "Agent permissions changed after this intent was created. Review the current policy and create a new intent.",
  STALE_OWNER_POLICY: "Owner financial limits changed after this intent was created. Review them and create a new intent.",
  AGENT_BUDGET_EXCEEDED: "The current agent budget does not permit this run at the pinned quote.",
  CASH_CEILING_EXCEEDED: "The run would require more cash than the owner approved in this intent.",
  CASH_PERMISSION_REQUIRED: "Cash spending requires separate owner permission. No run was admitted.",
  INSUFFICIENT_FUNDS: "Available cash and bonus funds do not cover this run. No run was admitted.",
  BETA_BONUS_BALANCE_REQUIRED: "Beta runs must be covered fully by bonus credit; cash cannot cover a shortfall. Redeem a bonus code or ask an administrator for a grant.",
  BETA_STARTS_PAUSED: "New run starts are paused by the administrator. Retry after operations resume; no new run was started.",
  OPERATIONS_CONTROL_UNAVAILABLE: "Run starts are temporarily unavailable because the operations control could not be read. Retry after service recovers.",
  RELEASE_INVALID: "The active release failed server validation. Intent creation is disabled.",
};

function readCode(payload: unknown): string | undefined {
  if (typeof payload !== "object" || payload === null) return undefined;
  const root = payload as { error?: unknown; code?: unknown };
  if (typeof root.code === "string") return root.code.toUpperCase();
  if (typeof root.error === "object" && root.error !== null) {
    const error = root.error as { code?: unknown };
    if (typeof error.code === "string") return error.code.toUpperCase();
  }
  return undefined;
}

export async function apiRequest<T>(path: `/api/${string}`, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  const isFormData = typeof FormData !== "undefined" && init.body instanceof FormData;
  if (init.body && !isFormData && !headers.has("content-type")) headers.set("content-type", "application/json");
  const response = await fetch(path, {
    ...init,
    credentials: "same-origin",
    cache: "no-store",
    headers,
  });

  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    payload = undefined;
  }

  if (!response.ok) {
    const code = readCode(payload);
    const fallback = response.status === 401
      ? knownMessages.UNAUTHORIZED
      : response.status === 403
        ? knownMessages.FORBIDDEN
        : "The server did not confirm the request. Refresh the page before retrying.";
    throw new ApiError(response.status, (code && knownMessages[code]) || fallback, code);
  }

  return payload as T;
}

export async function getCurrentOwner(): Promise<OwnerProjection | null> {
  try {
    const response = await apiRequest<OwnerResponse>("/api/owner");
    return response.owner;
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) return null;
    throw error;
  }
}

export function errorText(error: unknown): string {
  if (error instanceof ApiError) return error.message;
  if (error instanceof Error && /user rejected|user denied|request rejected/i.test(error.message)) {
    return "The wallet request was declined. No sign-in or identity change was confirmed.";
  }
  return "The request could not be completed. Refresh the server state before retrying.";
}

export function newOperationId(): string {
  return crypto.randomUUID();
}
