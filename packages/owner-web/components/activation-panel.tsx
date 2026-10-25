"use client";

import { FormEvent, useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { ApiError, apiRequest, errorText, getCurrentOwner, newOperationId, OwnerProjection } from "@/lib/api";

export function ActivationPanel() {
  const router = useRouter();
  const [owner, setOwner] = useState<OwnerProjection | null>(null);
  const [loading, setLoading] = useState(true);
  const [invitation, setInvitation] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState(false);
  const operationId = useRef<string | undefined>(undefined);

  useEffect(() => {
    let active = true;
    void getCurrentOwner().then((current) => {
      if (!active) return;
      if (!current) router.replace("/sign-in");
      else if (current.admissionStatus === "admitted") router.replace("/account");
      else {
        setOwner(current);
        setLoading(false);
      }
    }).catch((reason: unknown) => {
      if (active) {
        setMessage(errorText(reason));
        setError(true);
        setLoading(false);
      }
    });
    return () => { active = false; };
  }, [router]);

  async function activate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!operationId.current) operationId.current = newOperationId();
    setBusy(true);
    setError(false);
    setMessage("Submitting the invitation for server-side activation…");
    let activationCommitted = false;
    try {
      const response = await apiRequest<{
        owner: { id: string; admissionStatus: "admitted" };
        admission: { status: "admitted"; policyRevision: number };
      }>("/api/admission/activate", {
        method: "POST",
        body: JSON.stringify({ ...(invitation.trim() ? { invitation: invitation.trim() } : {}), operationId: operationId.current }),
      });
      if (response.admission.status !== "admitted" || response.owner.admissionStatus !== "admitted") {
        throw new Error("The server response did not confirm pilot admission.");
      }
      activationCommitted = true;
      const confirmedOwner = await getCurrentOwner();
      if (!confirmedOwner || confirmedOwner.id !== response.owner.id || confirmedOwner.admissionStatus !== "admitted") {
        operationId.current = undefined;
        setMessage("The server confirmed activation, but the current owner session did not confirm that same admitted owner. Refresh server state before retrying; do not reuse the invitation blindly.");
        setError(true);
        return;
      }
      setOwner(confirmedOwner);
      setInvitation("");
      operationId.current = undefined;
      router.replace("/account");
    } catch (reason) {
      const missingInviteInClosedMode = !invitation.trim() && reason instanceof ApiError && reason.code === "INVITATION_INVALID";
      setMessage(activationCommitted
        ? "The server confirmed activation, but the owner session could not be refreshed. Reload this page to check the admitted state before retrying."
        : missingInviteInClosedMode
          ? "No invitation was accepted. Registration may still be closed; enter a valid invitation code or refresh owner status if an administrator opened registration."
          : errorText(reason));
      setError(true);
      if (activationCommitted || (reason instanceof ApiError && reason.status < 500)) operationId.current = undefined;
    } finally {
      setBusy(false);
    }
  }

  if (loading) return <p className="loading" role="status">Checking your verified owner session…</p>;

  return (
    <section className="card auth-card" aria-labelledby="activate-title">
      <div className="page-heading">
        <p className="eyebrow">Pilot admission</p>
        <h1 id="activate-title">Activate your owner account</h1>
        <p className="lede">Your sign-in is verified, but this owner account has not yet been admitted.</p>
      </div>
      {owner && <p className="fine">Owner reference: <code data-testid="owner-id">{owner.id}</code></p>}
      <div className="notice notice-warning">
        Invitation activation grants pilot admission only. It does not issue a bonus, create agent access, or authorize a payment or withdrawal.
      </div>
      <form className="form" onSubmit={(event) => void activate(event)}>
        <div className="field">
          <label htmlFor="invitation-code">Invitation code (leave blank if registration is open)</label>
          <input
            id="invitation-code"
            data-testid="invitation-code"
            type="password"
            autoComplete="off"
            spellCheck={false}
            value={invitation}
            onChange={(event) => setInvitation(event.target.value)}
            disabled={busy}
          />
        </div>
        <button className="button button-primary" data-testid="activate-owner" type="submit" disabled={busy || !owner}>
          {busy ? "Checking invitation…" : "Activate owner account"}
        </button>
        <p className={`status-box ${error ? "status-error" : ""}`} role={error ? "alert" : "status"} aria-live="polite">{message}</p>
      </form>
      <p className="fine">An invitation is required while registration is closed; leave the field blank if an administrator opened registration. Any invitation is sent in the request body, never the page address. If a request outcome is unclear, refresh this page before retrying.</p>
    </section>
  );
}
