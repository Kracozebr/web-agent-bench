"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { ApiError, apiRequest, errorText, getCurrentOwner, InvitationRecord, newOperationId, OwnerProjection, RegistrationPolicy } from "@/lib/api";
import { BonusGrantPanel } from "@/components/bonus-grant-panel";

interface InvitationsResponse { invitations: InvitationRecord[] }
interface IssuedInvitation { id: string; secret: string; expiresAt: string }

export function AdminPanel() {
  const router = useRouter();
  const [owner, setOwner] = useState<OwnerProjection | null>(null);
  const [invitations, setInvitations] = useState<InvitationRecord[]>([]);
  const [policy, setPolicy] = useState<RegistrationPolicy | null>(null);
  const [selectedMode, setSelectedMode] = useState<"closed" | "open">("closed");
  const [expiresInSeconds, setExpiresInSeconds] = useState("");
  const [issued, setIssued] = useState<IssuedInvitation | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState(false);

  const loadAdminState = useCallback(async () => {
    const [invitationResponse, registrationPolicy] = await Promise.all([
      apiRequest<InvitationsResponse>("/api/admin/invitations"),
      apiRequest<RegistrationPolicy>("/api/admin/registration-policy"),
    ]);
    setInvitations(invitationResponse.invitations);
    setPolicy(registrationPolicy);
    setSelectedMode(registrationPolicy.mode);
  }, []);

  useEffect(() => {
    let active = true;
    void getCurrentOwner().then(async (current) => {
      if (!active) return;
      if (!current) {
        router.replace("/sign-in");
        return;
      }
      if (current.admissionStatus !== "admitted") {
        router.replace("/activate");
        return;
      }
      setOwner(current);
      if (!current.isAdmin) {
        setLoading(false);
        return;
      }
      await loadAdminState();
      if (active) setLoading(false);
    }).catch((reason: unknown) => {
      if (active) {
        setMessage(errorText(reason));
        setError(true);
        setLoading(false);
      }
    });
    return () => { active = false; };
  }, [loadAdminState, router]);

  async function issueInvitation(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const seconds = expiresInSeconds.trim() ? Number(expiresInSeconds) : undefined;
    if (seconds !== undefined && (!Number.isSafeInteger(seconds) || seconds <= 0)) {
      setMessage("Enter a positive expiry duration in seconds, or leave it blank to use the server default.");
      setError(true);
      return;
    }
    setBusy(true);
    setIssued(null);
    setError(false);
    setMessage("Requesting a single-use invitation from the server…");
    try {
      const expiresAt = seconds === undefined ? undefined : new Date(Date.now() + seconds * 1000);
      if (expiresAt && Number.isNaN(expiresAt.getTime())) {
        throw new Error("That expiry duration is outside the supported date range.");
      }
      const result = await apiRequest<{ invitation: { id: string; expiresAt: string }; secret: string }>("/api/admin/invitations", {
        method: "POST",
        body: JSON.stringify({
          operationId: newOperationId(),
          ...(expiresAt ? { expiresAt: expiresAt.toISOString() } : {}),
        }),
      });
      setIssued({ id: result.invitation.id, secret: result.secret, expiresAt: result.invitation.expiresAt });
      setExpiresInSeconds("");
      setMessage("The server issued an invitation. Its secret is shown once below and is not stored in the browser.");
      try {
        await loadAdminState();
      } catch {
        setError(true);
        setMessage("The server confirmed issuance and returned the one-time secret, but the status list could not refresh. Copy the secret privately before leaving this page.");
      }
    } catch (reason) {
      const uncertain = !(reason instanceof ApiError) || reason.status >= 500;
      setMessage(uncertain
        ? "The issuance outcome is not confirmed. Refresh the status list before retrying. If a new invitation appears without its secret, revoke it; the secret cannot be recovered."
        : errorText(reason));
      setError(true);
      try { await loadAdminState(); } catch { /* Preserve the mutation error; refresh is available below. */ }
    } finally {
      setBusy(false);
    }
  }

  async function revokeInvitation(id: string) {
    setBusy(true);
    setIssued(null);
    setError(false);
    setMessage("Submitting invitation revocation…");
    try {
      await apiRequest(`/api/admin/invitations/${encodeURIComponent(id)}/revoke`, {
        method: "POST",
        body: JSON.stringify({ operationId: newOperationId() }),
      });
      setMessage("The server confirmed invitation revocation.");
      try {
        await loadAdminState();
      } catch {
        setError(true);
        setMessage("The server confirmed revocation, but the invitation status list could not refresh. Reload before retrying.");
      }
    } catch (reason) {
      setMessage(errorText(reason));
      setError(true);
      try { await loadAdminState(); } catch { /* Keep the original error visible. */ }
    } finally {
      setBusy(false);
    }
  }

  async function saveRegistrationMode() {
    if (!policy) return;
    setBusy(true);
    setIssued(null);
    setError(false);
    setMessage("Saving admission mode with the current policy revision…");
    try {
      const saved = await apiRequest<RegistrationPolicy>("/api/admin/registration-policy", {
        method: "PUT",
        body: JSON.stringify({ mode: selectedMode, expectedRevision: policy.revision, operationId: newOperationId() }),
      });
      setPolicy(saved);
      setSelectedMode(saved.mode);
      setMessage(`The server confirmed ${saved.mode} new admission (policy revision ${saved.revision}). Existing admitted owners are unchanged.`);
    } catch (reason) {
      setMessage(errorText(reason));
      setError(true);
      try { await loadAdminState(); } catch { /* Preserve the save error; refresh is available below. */ }
    } finally {
      setBusy(false);
    }
  }

  async function refresh() {
    setBusy(true);
    setIssued(null);
    setError(false);
    try {
      await loadAdminState();
      setMessage("Loaded the latest server state.");
    } catch (reason) {
      setMessage(errorText(reason));
      setError(true);
    } finally {
      setBusy(false);
    }
  }

  if (loading) return <p className="loading" role="status">Checking configured administrator access…</p>;

  if (!owner?.isAdmin) return (
    <section className="card auth-card" aria-labelledby="admin-denied-title">
      <p className="eyebrow">Restricted controls</p>
      <h1 id="admin-denied-title">Administrator access required</h1>
      <p className="lede">The server owner projection does not grant this account administration access. Signup and invitation possession cannot assign this role.</p>
      <p className={`status-box ${error ? "status-error" : ""}`} role={error ? "alert" : "status"}>{message}</p>
      <a className="button" href="/account">Return to owner settings</a>
    </section>
  );

  return (
    <div className="stack">
      <div className="page-heading">
        <p className="eyebrow">Configured administrator</p>
        <h1>Admission controls</h1>
        <p className="lede">Manage owner admission and issue immutable tester bonus grants. The API verifies administrator authority for every action.</p>
      </div>
      <BonusGrantPanel />
      <div className="content-grid">
        <section className="card span-6" aria-labelledby="policy-title">
          <div className="section-heading">
            <div><h2 id="policy-title">New admission</h2><p className="fine">Returning admitted owners keep their access when this setting changes.</p></div>
            {policy && <span className="pill">Revision {policy.revision}</span>}
          </div>
          <div className="form">
            <div className="field">
              <label htmlFor="registration-mode">Registration mode</label>
              <select id="registration-mode" data-testid="registration-mode" value={selectedMode} onChange={(event) => setSelectedMode(event.target.value as "closed" | "open")} disabled={busy || !policy}>
                <option value="closed">Closed · invitation required</option>
                <option value="open">Open · new owners may join</option>
              </select>
            </div>
            <div className="notice notice-warning">Changing admission mode does not migrate existing owners, change prices, grant bonuses, or alter withdrawal rights.</div>
            <button className="button button-primary" data-testid="registration-save" type="button" onClick={() => void saveRegistrationMode()} disabled={busy || !policy || selectedMode === policy.mode}>
              Save admission mode
            </button>
          </div>
        </section>

        <section className="card span-6" aria-labelledby="issue-title">
          <h2 id="issue-title">Issue an invitation</h2>
          <p className="fine">The API stores a verifier. The opaque invitation value is returned once and cannot be recovered from this page later.</p>
          <form className="admin-form-row" onSubmit={(event) => void issueInvitation(event)}>
            <div className="field">
              <label htmlFor="invite-expiry">Expiry duration (seconds, optional)</label>
              <input id="invite-expiry" data-testid="invite-expiry" type="number" min="1" step="1" inputMode="numeric" placeholder="Use server default" value={expiresInSeconds} onChange={(event) => setExpiresInSeconds(event.target.value)} disabled={busy} />
            </div>
            <button className="button button-primary" data-testid="invite-create" type="submit" disabled={busy}>Issue invitation</button>
          </form>
          {issued && (
            <div className="once-secret" data-testid="invite-secret-once" role="status" aria-live="polite">
              <p className="once-secret-title">Invitation secret — shown once</p>
              <code className="code-secret">{issued.secret}</code>
              <p className="fine">Share this value privately with the intended owner. This page will not persist it or retrieve it again.</p>
              <p className="fine">Expires {new Date(issued.expiresAt).toLocaleString()} · reference <code>{issued.id}</code></p>
            </div>
          )}
        </section>

        <section className="card span-12" aria-labelledby="invitations-title">
          <div className="section-heading">
            <div><h2 id="invitations-title">Invitation status</h2><p className="fine">This list contains status and expiry only; invitation secrets are never returned by the listing endpoint.</p></div>
            <button className="button button-small" type="button" onClick={() => void refresh()} disabled={busy}>Refresh</button>
          </div>
          {!invitations.length ? <div className="empty-state">No invitations are currently listed.</div> : (
            <div className="table-wrap">
              <table data-testid="admin-invitations">
                <thead><tr><th scope="col">Reference</th><th scope="col">Status</th><th scope="col">Expires</th><th scope="col">Action</th></tr></thead>
                <tbody>
                  {invitations.map((item) => (
                    <tr key={item.id}>
                      <td><code>{item.id}</code></td>
                      <td><span className={`pill ${item.status === "issued" ? "pill-success" : item.status === "revoked" ? "pill-danger" : ""}`}>{item.status}</span></td>
                      <td>{new Date(item.expiresAt).toLocaleString()}</td>
                      <td>{item.status === "issued" && <button className="button button-small button-danger" data-testid={`invite-revoke-${item.id}`} type="button" onClick={() => void revokeInvitation(item.id)} disabled={busy}>Revoke</button>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
        <div className="span-12">
          <p className={`status-box ${error ? "status-error" : ""}`} role={error ? "alert" : "status"} aria-live="polite">{message}</p>
        </div>
      </div>
    </div>
  );
}
