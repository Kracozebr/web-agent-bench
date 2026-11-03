"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { apiRequest, errorText, newOperationId } from "@/lib/api";
import { isDiagnosticCallback } from "@/lib/diagnostics";

interface ConsentRequest {
  requestId: string; clientName: string; scopes: string[]; expiresAt: string;
  agents: { agentId: string; name: string; connections: { connectionId: string; label: string }[] }[];
}
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;

export function DiagnosticConsentPanel() {
  const [request, setRequest] = useState<ConsentRequest | null>(null);
  const [agentId, setAgentId] = useState("");
  const [connectionId, setConnectionId] = useState("");
  const [approved, setApproved] = useState(false);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const submission = useRef<{ requestId: string; operationId: string; approved: boolean; agentId?: string; connectionId?: string } | null>(null);
  useEffect(() => {
    const requestId = new URLSearchParams(window.location.search).get("requestId");
    if (!requestId || !UUID.test(requestId)) { setError("This diagnostic authorization request is missing or invalid. Restart connection from the helper."); setLoading(false); return; }
    let active = true;
    void apiRequest<ConsentRequest>(`/api/owner/diagnostics/oauth/requests/${requestId}`, { referrerPolicy: "no-referrer" })
      .then(result => { if (active) setRequest(result); })
      .catch(reason => { if (active) setError(errorText(reason)); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, []);
  const connections = request?.agents.find(item => item.agentId === agentId)?.connections ?? [];

  async function consent(allow: boolean) {
    if (!request || busy || (allow && (!agentId || !connectionId || !approved))) return;
    const original = submission.current;
    const selected = { requestId: request.requestId, approved: allow, ...(allow ? { agentId, connectionId } : {}) };
    const pending = original && original.approved === allow && original.agentId === selected.agentId && original.connectionId === selected.connectionId
      ? original : { ...selected, operationId: newOperationId() };
    submission.current = pending;
    setBusy(true); setError("");
    try {
      const result = await apiRequest<{ redirectUrl: string }>("/api/diagnostics/oauth/consent", {
        method: "POST", body: JSON.stringify(pending), referrerPolicy: "no-referrer",
      });
      // AICODE-NOTE: Never render/store callback code/state; only follow the exact registered local helper callback.
      if (!isDiagnosticCallback(result.redirectUrl)) throw new Error("invalid_callback");
      window.location.assign(result.redirectUrl);
    } catch (failure) { setError(errorText(failure)); }
    finally { setBusy(false); }
  }

  return <section className="oauth-consent-shell" aria-labelledby="diagnostic-consent-title">
    <div className="page-heading"><p className="eyebrow">Private diagnostic connection</p><h1 id="diagnostic-consent-title">Authorize automatic diagnostic reports</h1>
      <p className="lede">This helper sends safe error evidence and one aggregated report to the platform administrator. Its diagnostic permission cannot execute benchmark tasks, spend bonuses, read diagnostics or access administration.</p></div>
    {loading ? <p role="status">Loading authorization request…</p> : null}
    {error ? <p role="alert" className="status-box status-error">{error} <Link href="/sign-in">Sign in</Link></p> : null}
    {request ? <div className="card form" data-testid="diagnostic-consent">
      <p>Client: {request.clientName}</p><p>Permission: write diagnostics and receive delivery receipts; renew authorization until revoked.</p>
      <p className="fine">Diagnostic authorization is separate from your Codex login. The helper does not read Codex credentials. Revoking the linked connection also revokes this helper.</p>
      <div className="field"><label htmlFor="diagnostic-agent">Agent</label><select id="diagnostic-agent" data-testid="diagnostic-consent-agent" value={agentId} disabled={busy} onChange={event => { setAgentId(event.target.value); setConnectionId(""); setApproved(false); submission.current = null; }}>
        <option value="">Choose an agent</option>{request.agents.map(agent => <option key={agent.agentId} value={agent.agentId}>{agent.name}</option>)}
      </select></div>
      <div className="field"><label htmlFor="diagnostic-connection">Native client connection</label><select id="diagnostic-connection" data-testid="diagnostic-consent-connection" value={connectionId} disabled={busy || !agentId} onChange={event => { setConnectionId(event.target.value); setApproved(false); submission.current = null; }}>
        <option value="">Choose a connection</option>{connections.map(connection => <option key={connection.connectionId} value={connection.connectionId}>{connection.label}</option>)}
      </select></div>
      <label className="check"><input type="checkbox" data-testid="diagnostic-consent-approved" checked={approved} disabled={busy || !connectionId} onChange={event => setApproved(event.target.checked)}/> Allow automatic safe diagnostics and administrator reports for this connection.</label>
      <p className="fine">Reports distinguish client observations from verified platform causes. Missing evidence stays unknown. Pending local files are delivered when the helper can reconnect; they are not covered by the server backup.</p>
      <div className="button-row"><button className="button" type="button" data-testid="diagnostic-consent-allow" disabled={busy || !approved || !connectionId} onClick={() => void consent(true)}>Authorize diagnostics helper</button>
        <button className="button button-secondary" type="button" disabled={busy} onClick={() => void consent(false)}>Decline</button></div>
    </div> : null}
  </section>;
}
