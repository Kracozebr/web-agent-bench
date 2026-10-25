"use client";

import { type FormEvent, useRef, useState } from "react";
import { apiRequest, errorText, newOperationId, type AdminIssuedBonusGrant } from "@/lib/api";

interface BonusGrantResponse {
  grant: AdminIssuedBonusGrant;
  replayed: boolean;
  operationId: string;
}

interface PendingGrant {
  payload: string;
  operationId: string;
}

function isPositiveDecimal(value: string): boolean {
  if (!/^(?:0|[1-9]\d*)(?:\.\d{1,6})?$/.test(value)) return false;
  return value.replace(/[.]/g, "").replace(/0/g, "").length > 0;
}

function formatTimestamp(value: string | null): string {
  if (!value) return "No expiry";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return `${new Intl.DateTimeFormat("en", {
    dateStyle: "medium",
    timeStyle: "medium",
    timeZone: "UTC",
  }).format(date)} UTC`;
}

export function BonusGrantPanel() {
  const [ownerId, setOwnerId] = useState("");
  const [amount, setAmount] = useState("");
  const [reason, setReason] = useState("");
  const [expiry, setExpiry] = useState("");
  const [grant, setGrant] = useState<AdminIssuedBonusGrant | null>(null);
  const [replayed, setReplayed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [recovering, setRecovering] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState(false);
  const pending = useRef<PendingGrant | null>(null);

  async function submitGrant(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const normalizedOwnerId = ownerId.trim();
    const normalizedReason = reason.trim();
    const normalizedAmount = amount.trim();
    if (!normalizedOwnerId) {
      setError(true);
      setMessage("Enter the intended owner UUID.");
      return;
    }
    if (!isPositiveDecimal(normalizedAmount)) {
      setError(true);
      setMessage("Enter a positive amount with no more than six decimal places.");
      return;
    }
    if (!normalizedReason || normalizedReason.length > 500) {
      setError(true);
      setMessage("Enter a reason of 1 to 500 characters.");
      return;
    }

    let expiresAt: string | undefined;
    if (expiry) {
      const parsedExpiry = new Date(expiry);
      if (Number.isNaN(parsedExpiry.getTime())) {
        setError(true);
        setMessage("Enter a valid expiry time or leave it blank for no expiry.");
        return;
      }
      expiresAt = parsedExpiry.toISOString();
    }

    const requestBody = {
      ownerId: normalizedOwnerId,
      amount: normalizedAmount,
      reason: normalizedReason,
      ...(expiresAt ? { expiresAt } : {}),
    };
    const payload = JSON.stringify(requestBody);
    const operationId = pending.current?.payload === payload
      ? pending.current.operationId
      : newOperationId();
    pending.current = { payload, operationId };

    setBusy(true);
    setGrant(null);
    setError(false);
    setMessage("Submitting the grant to the server…");
    try {
      const result = await apiRequest<BonusGrantResponse>("/api/admin/bonus-grants", {
        method: "POST",
        body: JSON.stringify({ operationId, ...requestBody }),
      });
      if (!result.grant?.id || result.grant.ownerId !== normalizedOwnerId) {
        throw new Error("The server did not confirm the requested owner grant.");
      }
      setGrant(result.grant);
      setReplayed(result.replayed);
      pending.current = null;
      setRecovering(false);
      setOwnerId("");
      setAmount("");
      setReason("");
      setExpiry("");
      setMessage(result.replayed
        ? "The server recovered the original persisted grant for this operation."
        : "The server confirmed the persisted grant. Its terms are immutable.");
    } catch (cause) {
      const confirmedClientRejection = cause instanceof Error && "status" in cause
        && typeof cause.status === "number" && cause.status < 500;
      if (confirmedClientRejection) {
        pending.current = null;
        setRecovering(false);
      } else {
        setRecovering(true);
      }
      setMessage(confirmedClientRejection
        ? errorText(cause)
        : "The grant outcome is not confirmed. Keep these details and retry to recover the same operation before starting a new grant.");
      setError(true);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card" aria-labelledby="bonus-grant-title">
      <div className="section-heading">
        <div>
          <h2 id="bonus-grant-title">Grant tester bonus</h2>
          <p className="fine">This creates an immutable promotional grant in the owner ledger. Bonuses are service credit, not cash or withdrawable funds.</p>
        </div>
      </div>
      <form className="form" data-testid="bonus-grant-form" onSubmit={(event) => void submitGrant(event)}>
        <div className="agent-fields">
          <div className="field">
            <label htmlFor="bonus-grant-owner-id">Owner UUID</label>
            <input id="bonus-grant-owner-id" data-testid="bonus-grant-owner-id" type="text" autoComplete="off" spellCheck={false} value={ownerId} onChange={(event) => setOwnerId(event.target.value)} disabled={busy || recovering} required />
          </div>
          <div className="field">
            <label htmlFor="bonus-grant-amount">Amount (USDC service value)</label>
            <input id="bonus-grant-amount" data-testid="bonus-grant-amount" type="text" inputMode="decimal" autoComplete="off" placeholder="0.000001" value={amount} onChange={(event) => setAmount(event.target.value)} disabled={busy || recovering} required aria-describedby="bonus-grant-amount-help" />
            <small id="bonus-grant-amount-help" className="fine">Enter an exact decimal string with up to six fractional digits.</small>
          </div>
          <div className="field">
            <label htmlFor="bonus-grant-expiry">Expiry (optional)</label>
            <input id="bonus-grant-expiry" data-testid="bonus-grant-expiry" type="datetime-local" value={expiry} onChange={(event) => setExpiry(event.target.value)} disabled={busy || recovering} aria-describedby="bonus-grant-expiry-help" />
            <small id="bonus-grant-expiry-help" className="fine">Times use your local time and are saved as UTC. Leave blank for no expiry. The server checks that a supplied expiry is still in the future when saved.</small>
          </div>
        </div>
        <div className="field">
          <label htmlFor="bonus-grant-reason">Reason</label>
          <textarea id="bonus-grant-reason" data-testid="bonus-grant-reason" maxLength={500} value={reason} onChange={(event) => setReason(event.target.value)} disabled={busy || recovering} required />
        </div>
        <div className="button-row">
          <button className="button button-primary" data-testid="bonus-grant-submit" type="submit" disabled={busy}>
            {busy ? "Submitting…" : recovering ? "Retry original grant" : "Issue bonus grant"}
          </button>
        </div>
      </form>
      {grant ? (
        <div className="notice notice-success bonus-grant-result" data-testid="bonus-grant-result" role="status" aria-live="polite">
          <strong>{replayed ? "Persisted grant recovered" : "Persisted grant confirmed"}</strong>
          <dl className="kv-list">
            <dt>Grant ID</dt><dd><code>{grant.id}</code></dd>
            <dt>Owner UUID</dt><dd><code>{grant.ownerId}</code></dd>
            <dt>Amount</dt><dd>{grant.amount} USDC service value</dd>
            <dt>Reason</dt><dd>{grant.reason}</dd>
            <dt>Created</dt><dd>{formatTimestamp(grant.createdAt)}</dd>
            <dt>Expiry</dt><dd>{formatTimestamp(grant.expiresAt)}</dd>
          </dl>
        </div>
      ) : null}
      <p className={`status-box ${error ? "status-error" : ""}`} data-testid="bonus-grant-status" role={error ? "alert" : "status"} aria-live="polite">{message}</p>
    </section>
  );
}
