"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";
import { ApiError, apiRequest, errorText, newOperationId } from "@/lib/api";

interface BonusCodeRedemption {
  id: string;
  codeId: string;
  label: string;
  kind: "group" | "single_use";
  amount: string;
  grantId: string;
  createdAt: string;
}

interface RedemptionResponse {
  redemptions: BonusCodeRedemption[];
}

interface ClaimResponse {
  redemption: BonusCodeRedemption;
  operationId: string;
  replayed: boolean;
}

interface PendingClaim {
  operationId: string;
  code: string;
}

export function OwnerBonusCodesPanel({ onRedeemed }: { onRedeemed?: () => Promise<unknown> }) {
  const [code, setCode] = useState("");
  const [redemptions, setRedemptions] = useState<BonusCodeRedemption[]>([]);
  const [receipt, setReceipt] = useState<ClaimResponse | null>(null);
  const [pendingClaim, setPendingClaim] = useState<PendingClaim | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState(false);

  const loadRedemptions = useCallback(async () => {
    const result = await apiRequest<RedemptionResponse>("/api/owner/bonus-codes/redemptions");
    setRedemptions(result.redemptions);
  }, []);

  useEffect(() => {
    let active = true;
    void loadRedemptions().then(() => {
      if (active) setLoading(false);
    }).catch((cause: unknown) => {
      if (!active) return;
      setMessage(errorText(cause));
      setError(true);
      setLoading(false);
    });
    return () => { active = false; };
  }, [loadRedemptions]);

  async function redeem(event?: FormEvent<HTMLFormElement>) {
    event?.preventDefault();
    const operation = pendingClaim ?? (code.trim() ? { operationId: newOperationId(), code: code.trim() } : null);
    if (!operation) {
      setError(true);
      setMessage("Enter the bonus code you received.");
      return;
    }
    setPendingClaim(operation);
    setReceipt(null);
    setBusy(true);
    setError(false);
    setMessage("Submitting the code to the owner ledger…");
    try {
      const result = await apiRequest<ClaimResponse>("/api/owner/bonus-codes/redeem", {
        method: "POST",
        body: JSON.stringify({ operationId: operation.operationId, code: operation.code }),
      });
      setReceipt(result);
      setPendingClaim(null);
      setCode("");
      setMessage(`${result.redemption.amount} bonus credit was added to this owner ledger${result.replayed ? " (receipt recovered)" : ""}.`);
      await loadRedemptions().catch(() => undefined);
      await onRedeemed?.().catch(() => undefined);
    } catch (cause) {
      const uncertain = !(cause instanceof ApiError) || cause.status >= 500;
      if (!uncertain) setPendingClaim(null);
      setMessage(uncertain
        ? "The result is not confirmed. Retry this same claim to recover the original receipt safely."
        : errorText(cause));
      setError(true);
    } finally {
      setBusy(false);
    }
  }

  async function refresh() {
    setBusy(true);
    setError(false);
    try {
      await loadRedemptions();
      setMessage("Loaded the latest bonus-code receipts.");
    } catch (cause) {
      setMessage(errorText(cause));
      setError(true);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card" aria-labelledby="bonus-code-redeem-title" data-testid="owner-bonus-codes">
      <div className="section-heading">
        <div>
          <h2 id="bonus-code-redeem-title">Redeem a bonus code</h2>
          <p className="fine">Use a code to add bonus USDC for training and benchmarks. Bonus funds cannot be withdrawn and do not change your agent permissions.</p>
        </div>
        <button className="button button-small" data-testid="bonus-code-redemptions-refresh" type="button" onClick={() => void refresh()} disabled={busy || loading}>
          {busy ? "Loading…" : "Refresh"}
        </button>
      </div>
      <form className="form" data-testid="bonus-code-redemption-form" onSubmit={(event) => void redeem(event)}>
        <div className="field">
          <label htmlFor="bonus-code-value">Bonus code</label>
          <input id="bonus-code-value" data-testid="bonus-code-input" type="password" autoComplete="off" spellCheck={false}
            value={pendingClaim?.code ?? code} onChange={(event) => setCode(event.target.value)} disabled={busy || Boolean(pendingClaim)}
            placeholder="Enter the code you received" />
        </div>
        <button className="button button-primary" data-testid="bonus-code-redeem-submit" type="submit" disabled={busy || loading || Boolean(pendingClaim)}>
          Redeem code
        </button>
        {pendingClaim && (
          <button className="button" data-testid="bonus-code-redeem-retry" type="button" onClick={() => void redeem()} disabled={busy}>
            {busy ? "Retrying…" : "Retry same claim"}
          </button>
        )}
      </form>
      {receipt && (
        <div className="notice notice-success" data-testid="bonus-code-redemption-receipt" role="status">
          <strong>Bonus added</strong>
          <span>{receipt.redemption.amount} bonus USDC · {receipt.redemption.label} · {new Intl.DateTimeFormat("en", { dateStyle: "medium", timeStyle: "medium", timeZone: "UTC" }).format(new Date(receipt.redemption.createdAt))} UTC</span>
          <details><summary>Receipt reference</summary><code>{receipt.redemption.id}</code></details>
        </div>
      )}
      {loading ? <p className="loading" role="status">Loading your bonus-code receipts…</p> : !redemptions.length ? (
        <div className="empty-state" data-testid="bonus-code-redemptions-empty">No bonus codes have been redeemed by this owner.</div>
      ) : (
        <div className="table-wrap">
          <table data-testid="bonus-code-redemptions">
            <thead><tr><th scope="col">Date (UTC)</th><th scope="col">Bonus</th><th scope="col">Offer</th><th scope="col">Receipt</th></tr></thead>
            <tbody>{redemptions.map((item) => (
              <tr key={item.id} data-testid={`bonus-code-redemption-${item.id}`}>
                <td>{new Intl.DateTimeFormat("en", { dateStyle: "medium", timeStyle: "medium", timeZone: "UTC" }).format(new Date(item.createdAt))}</td>
                <td>{item.amount} USDC</td>
                <td>{item.label}</td>
                <td><details><summary>View reference</summary><code>{item.id}</code></details></td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      )}
      <p className={`status-box ${error ? "status-error" : ""}`} role={error ? "alert" : "status"} aria-live="polite" data-testid="bonus-code-redemption-status">{message}</p>
    </section>
  );
}
