"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { apiRequest, errorText, newOperationId } from "@/lib/api";

interface AgentChoice {
  id: string;
  name: string;
}

interface AgentsResponse {
  agents: AgentChoice[];
}

interface OAuthSelectResponse {
  redirectUrl: string;
}

type PageState = "loading" | "ready" | "error";

// AICODE-NOTE: The signed OAuth query arrives in the provider's standard authorization URL, then stays in memory and POST bodies only; never put it in custom URLs, logs, storage, or rendered text.
function takeOAuthQuery(): string | null {
  const rawQuery = window.location.search.startsWith("?")
    ? window.location.search.slice(1)
    : "";
  window.history.replaceState(window.history.state, "", window.location.pathname);
  return rawQuery || null;
}

function safeRedirectError(status: number): string {
  if (status === 400 || status === 410) return "This authorization request is invalid or expired. Start a new connection from your client.";
  if (status === 403 || status === 404) return "That agent is not available to this owner or authorization request.";
  if (status === 409) return "This authorization request has already been used or changed. Start a new connection from your client.";
  return "The authorization request could not continue. Refresh the page or start a new connection.";
}

export function OAuthAgentSelectPanel() {
  const [agents, setAgents] = useState<AgentChoice[]>([]);
  const [selectedAgentId, setSelectedAgentId] = useState("");
  const [pageState, setPageState] = useState<PageState>("loading");
  const [busy, setBusy] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");
  const oauthQuery = useRef<string | null>(null);
  const queryInitialized = useRef(false);
  const operationId = useRef<string | null>(null);

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
    void apiRequest<AgentsResponse>("/api/owner/agents", { referrerPolicy: "no-referrer" }).then((response) => {
      if (!active) return;
      setAgents(response.agents);
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

  async function continueWithSelectedAgent() {
    if (!oauthQuery.current || !selectedAgentId || busy) return;
    const currentOperationId = operationId.current ?? newOperationId();
    operationId.current = currentOperationId;
    setBusy(true);
    setErrorMessage("");

    try {
      const response = await fetch("/api/owner/agents/oauth-select", {
        method: "POST",
        credentials: "same-origin",
        cache: "no-store",
        referrerPolicy: "no-referrer",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          operationId: currentOperationId,
          oauth_query: oauthQuery.current,
          agentId: selectedAgentId,
        }),
      });

      if (!response.ok) {
        setErrorMessage(safeRedirectError(response.status));
        return;
      }

      const result = await response.json() as OAuthSelectResponse;
      if (typeof result.redirectUrl !== "string") {
        setErrorMessage("The authorization service did not return the expected consent page.");
        return;
      }
      const destination = new URL(result.redirectUrl);
      if (
        destination.origin === window.location.origin
        && destination.pathname === "/owner/agents/oauth-consent"
        && !destination.username
        && !destination.password
        && destination.hash === ""
      ) {
        window.location.assign(destination.href);
        return;
      }
      setErrorMessage("The authorization service returned an unexpected destination. Start a new connection from your client.");
    } catch {
      setErrorMessage("The authorization service could not confirm this step. Retry or start a new connection from your client.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="oauth-consent-shell" aria-labelledby="oauth-agent-select-title">
      <div className="page-heading">
        <p className="eyebrow">Private browser authorization</p>
        <h1 id="oauth-agent-select-title">Choose an agent</h1>
        <p className="lede">Choose which of your existing agents will be bound to this connection. Choosing an agent does not approve access.</p>
      </div>

      <div className="card oauth-consent-card">
        {pageState === "loading" ? <p className="loading" role="status">Loading your private agent list…</p> : null}
        {pageState === "error" ? <p className="status-box status-error" role="alert">{errorMessage}</p> : null}

        {pageState === "ready" ? (
          <div className="form oauth-consent-form">
            <div className="field">
              <label htmlFor="oauth-consent-agent">Agent for this connection</label>
              <select
                id="oauth-consent-agent"
                data-testid="oauth-consent-agent-select"
                value={selectedAgentId}
                onChange={(event) => {
                  setSelectedAgentId(event.target.value);
                  operationId.current = null;
                }}
                disabled={busy || agents.length === 0}
                aria-describedby="oauth-consent-agent-help"
              >
                <option value="">Choose one of your agents</option>
                {agents.map((agent) => (
                  <option key={agent.id} value={agent.id}>{agent.name}</option>
                ))}
              </select>
              <p id="oauth-consent-agent-help" className="fine">The server will verify the selected agent belongs to your admitted owner account.</p>
            </div>

            {agents.length === 0 ? (
              <div className="empty-state">
                <p>Create an agent card, then return to your client and start the connection again.</p>
                <Link className="button button-small" href="/agents">Manage agents</Link>
              </div>
            ) : null}

            <div className="oauth-consent-actions">
              <button
                className="button button-primary"
                data-testid="oauth-agent-continue"
                type="button"
                onClick={() => void continueWithSelectedAgent()}
                disabled={!selectedAgentId || busy || agents.length === 0}
              >
                {busy ? "Continuing…" : "Continue to review"}
              </button>
            </div>
            <p className="status-box" role="status" aria-live="polite">{errorMessage}</p>
          </div>
        ) : null}
      </div>
    </section>
  );
}
