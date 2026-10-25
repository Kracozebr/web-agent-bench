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
  REVISION_CONFLICT: "This agent changed in another session. The latest server revision has been loaded; review it before saving again.",
  ACCESS_REVISION_CONFLICT: "This agent’s access changed in another session. Check its current status before trying again.",
  CREDENTIAL_EXISTS: "A manual credential already exists. Check its safe status and replace it to issue a new one.",
  REAUTHORIZATION_REQUIRED: "All access for this agent was revoked. A new owner authorization is required before issuing another credential.",
  ACCESS_ALREADY_REVOKED: "All access for this agent has already been revoked.",
  OPERATION_ID_CONFLICT: "This operation identifier was already used with different data. Refresh the server state before retrying.",
  UNKNOWN_FIELD: "The server rejected an unsupported agent field. Review the current server response before trying again.",
  RATE_LIMITED: "Too many attempts. Wait a moment and try again.",
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
  if (init.body && !headers.has("content-type")) headers.set("content-type", "application/json");
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
