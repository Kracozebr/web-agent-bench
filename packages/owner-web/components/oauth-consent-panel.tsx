"use client";

import { useEffect, useRef, useState } from "react";
import { apiRequest, errorText, newOperationId } from "@/lib/api";

type PermissionKey = "training" | "ranked" | "forumMessages" | "customTopics";
type PermissionSet = Record<PermissionKey, boolean>;

interface OAuthConsentContext {
  flowId: string;
  client: { clientId: string; name: string };
  resource: string;
  scopes: string[];
  agent: {
    id: string;
    name: string;
    permissions: PermissionSet;
    policyRevision: number;
  };
  expiresAt: string;
}

interface OAuthConsentDecisionResponse {
  redirectUrl: string;
}

interface ConnectionProfileResponse {
  redirectUri: string;
}

type PageState = "loading" | "ready" | "error";

const permissions: Array<{ key: PermissionKey; label: string; testId: string }> = [
  { key: "training", label: "Training runs", testId: "training" },
  { key: "ranked", label: "Ranked runs", testId: "ranked" },
  { key: "forumMessages", label: "Forum messages", testId: "forum-messages" },
  { key: "customTopics", label: "Custom topic creation", testId: "custom-topics" },
];

function takeOAuthQuery(): string | null {
  const rawQuery = window.location.search.startsWith("?")
    ? window.location.search.slice(1)
    : "";
  window.history.replaceState(window.history.state, "", window.location.pathname);
  return rawQuery || null;
}

function safeRedirectError(status: number): string {
  if (status === 400 || status === 410) return "This authorization request is invalid or expired. Start a new connection from your client.";
  if (status === 403 || status === 404) return "This authorization request is not available to the signed-in owner.";
  if (status === 409) return "This authorization request has already been used or changed. Start a new connection from your client.";
  return "The authorization decision could not be confirmed. Refresh the page before trying again.";
}

function formatExpiry(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Unavailable" : date.toLocaleString();
}

function isConfiguredCallback(redirectUrl: string, configuredRedirectUri: string): boolean {
  try {
    const configured = new URL(configuredRedirectUri);
    const destination = new URL(redirectUrl);
    return (configured.protocol === "http:" || configured.protocol === "https:")
      && !configured.username
      && !configured.password
      && !configured.search
      && !configured.hash
      && destination.origin === configured.origin
      && destination.pathname === configured.pathname
      && !destination.username
      && !destination.password
      && destination.hash === "";
  } catch {
    return false;
  }
}

export function OAuthConsentPanel() {
  const [context, setContext] = useState<OAuthConsentContext | null>(null);
  const [configuredRedirectUri, setConfiguredRedirectUri] = useState<string | null>(null);
  const [pageState, setPageState] = useState<PageState>("loading");
  const [busy, setBusy] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");
  const oauthQuery = useRef<string | null>(null);
  const queryInitialized = useRef(false);
  const operationIds = useRef<Partial<Record<"approve" | "deny", string>>>({});

  useEffect(() => {
    if (!queryInitialized.current) {
      oauthQuery.current = takeOAuthQuery();
      queryInitialized.current = true;
    }
    if (!oauthQuery.current) {
      setErrorMessage("The authorization request is missing. Start a new connection from your client.");
      setPageState("error");
      return;
    }

    let active = true;
    void Promise.all([
      apiRequest<OAuthConsentContext>("/api/owner/agents/oauth-consent-context", {
        method: "POST",
        referrerPolicy: "no-referrer",
        body: JSON.stringify({ oauth_query: oauthQuery.current }),
      }),
      apiRequest<ConnectionProfileResponse>("/api/identity/connection-profile", { referrerPolicy: "no-referrer" }),
    ]).then(([response, profile]) => {
      if (!active) return;
      setContext(response);
      setConfiguredRedirectUri(profile.redirectUri);
      setPageState("ready");
    }).catch((reason: unknown) => {
      if (!active) return;
      setErrorMessage(errorText(reason));
      setPageState("error");
    });

    return () => {
      active = false;
    };
  }, []);

  async function submitDecision(accept: boolean) {
    if (!oauthQuery.current || !context || !configuredRedirectUri || busy) return;
    const decision = accept ? "approve" : "deny";
    const operationId = operationIds.current[decision] ?? newOperationId();
    operationIds.current[decision] = operationId;
    setBusy(true);
    setErrorMessage("");

    try {
      const response = await fetch("/api/owner/agents/oauth-consent", {
        method: "POST",
        credentials: "same-origin",
        cache: "no-store",
        referrerPolicy: "no-referrer",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          operationId,
          flowId: context.flowId,
          expectedPolicyRevision: context.agent.policyRevision,
          oauth_query: oauthQuery.current,
          accept,
        }),
      });

      if (!response.ok) {
        setErrorMessage(safeRedirectError(response.status));
        return;
      }

      const result = await response.json() as OAuthConsentDecisionResponse;
      if (typeof result.redirectUrl !== "string") {
        setErrorMessage("The authorization service did not return the expected authorization result.");
        return;
      }
      if (isConfiguredCallback(result.redirectUrl, configuredRedirectUri)) {
        window.location.assign(result.redirectUrl);
        return;
      }
      setErrorMessage("The authorization service returned an unexpected destination. Start a new connection from your client.");
    } catch {
      setErrorMessage("The authorization service could not confirm this decision. Retry or start a new connection from your client.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="oauth-consent-shell" aria-labelledby="oauth-consent-title">
      <div className="page-heading">
        <p className="eyebrow">Private browser authorization</p>
        <h1 id="oauth-consent-title">Review delegated access</h1>
        <p className="lede">Review the application, resource, agent, and current owner-managed permissions before deciding.</p>
      </div>

      <div className="card oauth-consent-card">
        <section
          className="oauth-consent-context"
          data-testid="oauth-consent-context"
          aria-labelledby="oauth-consent-context-title"
          aria-busy={pageState === "loading"}
        >
          <h2 id="oauth-consent-context-title">Connection request</h2>
          {pageState === "loading" ? <p className="loading" role="status">Loading the verified authorization request…</p> : null}
          {pageState === "error" ? <p className="status-box status-error" role="alert">{errorMessage}</p> : null}

          {pageState === "ready" && context ? (
            <div className="stack oauth-consent-details">
              <dl className="kv-list">
                <dt>Application</dt><dd data-testid="oauth-consent-client">{context.client.name}</dd>
                <dt>Client ID</dt><dd data-testid="oauth-consent-client-id">{context.client.clientId}</dd>
                <dt>Resource</dt><dd data-testid="oauth-consent-resource"><code>{context.resource}</code></dd>
                <dt>Agent</dt><dd data-testid="oauth-consent-agent">{context.agent.name} <span className="fine">({context.agent.id})</span></dd>
                <dt>Role</dt><dd data-testid="oauth-consent-role">agent</dd>
                <dt>Permission policy revision</dt><dd data-testid="oauth-consent-policy-revision">{context.agent.policyRevision}</dd>
                <dt>Authorization request expires</dt><dd data-testid="oauth-consent-expires-at">{formatExpiry(context.expiresAt)}</dd>
              </dl>

              <section aria-labelledby="oauth-consent-scopes-title">
                <h3 id="oauth-consent-scopes-title">Requested scopes</h3>
                {context.scopes.length ? (
                  <ul className="oauth-consent-scopes" data-testid="oauth-consent-scopes">
                    {context.scopes.map((scope) => <li key={scope}><code>{scope}</code></li>)}
                  </ul>
                ) : <p className="fine" data-testid="oauth-consent-scopes">No additional scopes requested.</p>}
              </section>

              <section aria-labelledby="oauth-consent-permissions-title">
                <h3 id="oauth-consent-permissions-title">Current action permissions</h3>
                <ul className="oauth-consent-permissions">
                  {permissions.map(({ key, label, testId }) => (
                    <li key={key}>
                      <span>{label}</span>
                      <strong data-testid={`oauth-consent-permission-${testId}`}>
                        {context.agent.permissions[key] ? "Allowed" : "Not allowed"}
                      </strong>
                    </li>
                  ))}
                </ul>
                <p className="notice">
                  The owner manages these permissions. The server checks current policy on each operation, so a later owner change takes effect without another consent.
                </p>
              </section>
            </div>
          ) : null}
        </section>

        {pageState === "ready" && context ? (
          <div className="oauth-consent-actions">
            <button
              className="button button-primary"
              data-testid="oauth-consent-approve"
              type="button"
              onClick={() => void submitDecision(true)}
              disabled={busy}
            >
              {busy ? "Submitting…" : "Approve access"}
            </button>
            <button
              className="button button-danger"
              data-testid="oauth-consent-deny"
              type="button"
              onClick={() => void submitDecision(false)}
              disabled={busy}
            >
              Deny request
            </button>
          </div>
        ) : null}

        {pageState === "ready" ? (
          <p className="status-box" role={errorMessage ? "alert" : "status"} aria-live="polite">{errorMessage}</p>
        ) : null}
      </div>
    </section>
  );
}
