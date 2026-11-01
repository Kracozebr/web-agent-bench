"use client";
import { useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { apiRequest, errorText, newOperationId } from "@/lib/api";

interface Connection { id: string; clientId: string; clientLabel: string; clientLabelProvenance: "registered-oauth-client"; status: "authorized" | "preflight-verified" | "offline" | "expired" | "revoked"; createdAt: string; expiresAt: string; revokedAt: string | null; lastPreflightAt: string | null; protocolVersion: string | null; permissions: Record<string, boolean> }
interface Connections { registration: "pre-registered" | "unavailable"; serverUrl: string; resource: string; clients: { id: string; label: string; qualification: string }[]; clientRegistrations: { clientId: string; clientName: string; redirectUris: string[] }[]; scopes: string[]; connections: Connection[]; access: { status: string; revision: number }; setup: { method: string; nativeAddUrl: string | null; instructions: string } }

export function AgentConnectionsPanel({ agentId }: { agentId: string }) {
  const [data, setData] = useState<Connections | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [selectedClientId, setSelectedClientId] = useState("");
  const operations = useRef<Record<string, string>>({});
  const base = `/api/owner/agents/${encodeURIComponent(agentId)}/connections` as const;
  const refresh = useCallback(async () => {
    setBusy(true); setError("");
    try { setData(await apiRequest<Connections>(base)); }
    catch (failure) { setError(errorText(failure)); }
    finally { setBusy(false); }
  }, [base]);
  useEffect(() => { void refresh(); }, [refresh]);
  async function revoke(connection: Connection) {
    if (!window.confirm("Revoke this client's authorization? Other client connections and spending caps stay unchanged.")) return;
    setBusy(true); setError("");
    const operationId = operations.current[connection.id] ??= newOperationId();
    try {
      await apiRequest(`${base}/${encodeURIComponent(connection.id)}/revoke`, { method: "POST", body: JSON.stringify({ operationId }) });
      delete operations.current[connection.id]; await refresh();
    } catch (failure) { setError(errorText(failure)); }
    finally { setBusy(false); }
  }
  const selectedClient = data?.clients.find((client) => client.id === selectedClientId);
  return <section className="stack-sm" aria-label="Client connections" data-testid={`agent-connections-${agentId}`}>
    <div className="section-heading"><h3>Connect your agent</h3><button className="button button-small" type="button" disabled={busy} onClick={() => void refresh()}>Check connection</button></div>
    <p>Add the Remote MCP URL in your client's connector settings, then sign in and authorize this agent. Reconnect through the same URL. Supported clients renew authorization automatically until revoked or invalidated.</p>
    {error ? <p className="status-box status-error" role="alert">{error}</p> : null}
    {data ? <>
      {data.registration === "unavailable" ? <p className="notice notice-warning">OAuth setup is unavailable: no registered client is configured. Contact support before connecting.</p> : null}
      <p className="fine">Your client must support this service's registered OAuth callback. Review Advanced setup below if it needs a client ID or resource. Your model-provider account is separate from platform authorization.</p>
      <section className="stack-sm" aria-label="Client setup options" data-testid="connection-client-options">
        <h4>Choose your client for setup help</h4>
        <label>Client<select aria-label="Client for setup help" data-testid="connection-client-select" value={selectedClientId} onChange={(event) => setSelectedClientId(event.target.value)}>
          <option value="">Other client / generic setup</option>
          {data.clients.map((client) => <option key={client.id} value={client.id}>{client.label} ({client.qualification || "unverified"})</option>)}
        </select></label>
        <ul data-testid="connection-client-qualifications">{data.clients.map((client) => <li key={client.id} data-testid={`connection-client-${client.id}`}><strong>{client.label}</strong>: {client.qualification || "unverified"}</li>)}</ul>
        <div className="notice" role="status" data-testid="connection-selected-client-help">
          <p>{selectedClient ? `${selectedClient.label}: ${selectedClient.qualification || "unverified"}.` : "Generic setup: compatibility is unverified."} This service does not detect whether the application is installed. An unavailable application remains unverified.</p>
          <p>Your selected client must support remote Streamable HTTP MCP, OAuth, and the registered client ID and callback shown in Advanced setup. A client that supports only local stdio cannot connect through this Remote MCP URL.</p>
          <p data-testid="connection-url-fallback-reason">Use the URL and browser authorization flow: no verified native add link is available for these client options. Selecting a name does not establish installation, compatibility, identity, or a live connection.</p>
          <p data-testid="connection-setup-instructions">{data.setup.instructions}</p>
        </div>
      </section>
      <label>Remote MCP URL<input readOnly value={data.serverUrl} aria-label="Remote MCP URL" /></label>
      <details><summary>Connection help</summary><p>Choose a client that supports remote HTTP MCP and OAuth. A saved URL alone does not prove that a client can use tools. “Preflight verified” records the last successful server check; it does not prove the client is online now.</p><p>Removing the connector locally disconnects the client; revoke authorization here to invalidate its grant.</p><p><Link href="/reports">Report a connection problem</Link></p></details>
      {!data.connections.length ? <p className="notice">No client authorization is recorded for this agent.</p> : data.connections.map((connection) => <article className="card" data-testid={`agent-connection-${connection.id}`} key={connection.id}>
        <h4>{connection.clientLabel || "Authorized client"}</h4>
        <p className="fine">Registered OAuth client label; this is not a verified application identity.</p>
        <p>{({ authorized: "Authorized; tool connection not yet verified", "preflight-verified": "Preflight verified", offline: "Last connection check is old; check your client", expired: "Authorization expired; reconnect", revoked: "Authorization revoked; reconnect" })[connection.status]}</p>
        <p className="fine">Last verified: {connection.lastPreflightAt ? new Date(connection.lastPreflightAt).toLocaleString() : "Not observed"}</p>
        <details><summary>Permissions and technical details</summary><p>{Object.entries(connection.permissions).filter(([, enabled]) => enabled).map(([name]) => name).join(", ") || "No permissions"}</p><p>Authorization expires: {new Date(connection.expiresAt).toLocaleString()}</p><p>Protocol: {connection.protocolVersion ?? "Not observed"}</p></details>
        {connection.status !== "revoked" ? <button type="button" className="button button-danger" disabled={busy} data-testid={`connection-revoke-${connection.id}`} onClick={() => void revoke(connection)}>Revoke this connection</button> : null}
      </article>)}
      <details><summary>Advanced: registered OAuth setup</summary><p>Use the exact registered client ID and callback. A client that cannot supply this registration remains unverified; a saved connector alone does not prove compatibility.</p><p>Resource: <code>{data.resource}</code></p><p>Scopes: {(data.scopes ?? []).join(", ")}</p>{(data.clientRegistrations ?? []).map((client) => <div key={client.clientId}><strong>{client.clientName}</strong><p>Client ID: <code>{client.clientId}</code></p><p>Callbacks: {client.redirectUris.map((uri) => <code key={uri}>{uri} </code>)}</p></div>)}</details>
    </> : !error ? <p role="status">Checking recorded connections…</p> : null}
  </section>;
}
