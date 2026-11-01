"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { ApiError, apiRequest, errorText, getCurrentOwner, type OwnerBonusGrant, type OwnerBillingHistoryEntry, type OwnerBillingResponse, type OwnerProjection } from "@/lib/api";
import { Money } from "./money";
import { ledgerDisplayAmount, moneyDisplay } from "@/lib/money";
import { OwnerBonusCodesPanel } from "@/components/owner-bonus-codes-panel";

function formatTimestamp(value: string | null | undefined): string {
  if (!value) return "No expiry";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return `${new Intl.DateTimeFormat("en", {
    dateStyle: "medium",
    timeStyle: "medium",
    timeZone: "UTC",
  }).format(date)} UTC`;
}

function formatHistoryExpiry(value: string | null | undefined): string {
  return value === undefined ? "—" : formatTimestamp(value);
}

function label(value: string): string {
  return value.replace(/[_-]+/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}


function HistoryTable({ entries }: { entries: OwnerBillingHistoryEntry[] }) {
  if (!entries.length) {
    return <div className="empty-state" data-testid="billing-history-empty">No financial activity is recorded for this owner.</div>;
  }
  return (
    <div className="table-wrap">
      <table data-testid="billing-history">
        <thead>
          <tr><th scope="col">Reference</th><th scope="col">Activity</th><th scope="col">Source</th><th scope="col">Amount</th><th scope="col">Recorded</th><th scope="col">Expiry</th><th scope="col">Reason</th><th scope="col">Status</th></tr>
        </thead>
        <tbody>
          {entries.map((entry) => (
            <tr key={entry.id} data-testid={`billing-history-entry-${entry.id}`} data-ledger-type={entry.type} data-ledger-amount={entry.amount}>
              <td><details><summary>Reference</summary><code>{entry.id}</code></details></td>
              <td>{entry.type === "reserve" ? "Hold reserved" : entry.type === "release" ? "Hold released" : entry.type === "refund" ? "Refund credit" : label(entry.type)}</td>
              <td>{label(entry.source)}</td>
              <td><Money amount={ledgerDisplayAmount(entry.type, entry.amount)} /><details className="ledger-detail"><summary>Ledger record and direction</summary>{entry.amount} USDC / {moneyDisplay(entry.amount)?.units ?? "Unavailable"} micro-USDC raw magnitude / {entry.type}. Reserve and release entries move holds; they are not spending.</details></td>
              <td>{formatTimestamp(entry.createdAt)}</td>
              <td>{formatHistoryExpiry(entry.expiresAt)}</td>
              <td>{entry.reason || "—"}</td>
              <td>{entry.status ? label(entry.status) : "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function BillingPanel() {
  const router = useRouter();
  const [owner, setOwner] = useState<OwnerProjection | null>(null);
  const [billing, setBilling] = useState<OwnerBillingResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [grantCursor, setGrantCursor] = useState<string | null>(null);
  const [historyCursor, setHistoryCursor] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState(false);

  const loadBilling = useCallback(async () => {
    const [response, grants, history] = await Promise.all([
      apiRequest<OwnerBillingResponse>("/api/owner/billing"),
      apiRequest<{ grants: OwnerBonusGrant[]; nextCursor: string | null }>("/api/owner/billing/grants?limit=5"),
      apiRequest<{ history: OwnerBillingHistoryEntry[]; nextCursor: string | null }>("/api/owner/billing/history?limit=5"),
    ]);
    setBilling({ ...response, grants: grants.grants, history: history.history });
    setGrantCursor(grants.nextCursor); setHistoryCursor(history.nextCursor);
    return response;
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
      await loadBilling();
      if (active) setLoading(false);
    }).catch((cause: unknown) => {
      if (!active) return;
      if (cause instanceof ApiError && cause.status === 401) {
        router.replace("/sign-in");
        return;
      }
      setMessage(errorText(cause));
      setError(true);
      setLoading(false);
    });
    return () => { active = false; };
  }, [loadBilling, router]);

  async function loadOlder(kind: "grants" | "history") {
    const cursor = kind === "grants" ? grantCursor : historyCursor;
    if (!cursor) return;
    setBusy(true); setError(false);
    try {
      const result = await apiRequest<{ grants?: OwnerBonusGrant[]; history?: OwnerBillingHistoryEntry[]; nextCursor: string | null }>(`/api/owner/billing/${kind}?limit=5&cursor=${encodeURIComponent(cursor)}`);
      setBilling((current) => current ? { ...current, [kind]: [...current[kind], ...(result[kind] ?? []).filter((item) => !current[kind].some((existing) => existing.id === item.id))] } : current);
      if (kind === "grants") setGrantCursor(result.nextCursor); else setHistoryCursor(result.nextCursor);
    } catch (failure) { setMessage(errorText(failure)); setError(true); }
    finally { setBusy(false); }
  }

  async function refresh() {
    setBusy(true);
    setError(false);
    try {
      await loadBilling();
      setMessage("Loaded the latest server billing projection.");
    } catch (cause) {
      if (cause instanceof ApiError && cause.status === 401) {
        router.replace("/sign-in");
        return;
      }
      setMessage(errorText(cause));
      setError(true);
    } finally {
      setBusy(false);
    }
  }

  if (loading) return <p className="loading" role="status">Checking your owner session and private billing projection…</p>;
  if (!owner) return (
    <section className="card auth-card" aria-labelledby="billing-unavailable-title">
      <h1 id="billing-unavailable-title">Billing unavailable</h1>
      <p className={`status-box ${error ? "status-error" : ""}`} role={error ? "alert" : "status"}>{message || "An admitted owner session is required to view private billing."}</p>
      <Link className="button" href="/sign-in">Return to sign-in</Link>
    </section>
  );

  return (
    <div className="stack" data-testid="billing-page">
      <div className="page-heading">
        <p className="eyebrow">Private owner ledger</p>
        <h1>Billing</h1>
        <p className="lede">Review cash and tester bonus separately. These server-reported internal balances do not prove on-chain deposits; bonus credit is not cash and cannot be withdrawn or transferred.</p>
        <p className="fine">Cash permission and spending caps are set per agent in <Link href="/agents">Agents</Link>.</p>
      </div>
      {!billing ? (
        <section className="card" data-testid="billing-unavailable">
          <h2>Billing data is unavailable</h2>
          <p className="status-box status-error" role="alert">{message || "The server did not return a billing projection."}</p>
          <button className="button" type="button" onClick={() => void refresh()} disabled={busy}>{busy ? "Loading…" : "Retry"}</button>
        </section>
      ) : (
        <>
          <section className="card" aria-labelledby="billing-balances-title" data-testid="billing-balances">
            <div className="section-heading">
              <div>
                <h2 id="billing-balances-title">Source balances</h2>
                <p className="fine">Observed {formatTimestamp(billing.observedAt)} · next UTC budget reset {formatTimestamp(billing.nextUtcResetAt)}</p>
              </div>
              <button className="button button-small" data-testid="billing-refresh" type="button" onClick={() => void refresh()} disabled={busy}>{busy ? "Refreshing…" : "Refresh"}</button>
            </div>
            <div className="content-grid billing-balance-grid">
              <article className="card span-4 balance-card">
                <p className="eyebrow">Cash</p>
                <h3>Available</h3>
                <p className="balance-amount" data-testid="billing-cash-available"><Money amount={billing.cash.available} /></p>
                <p className="fine">Internal cash ledger only</p>
              </article>
              <article className="card span-4 balance-card">
                <p className="eyebrow">Cash</p>
                <h3>Reserved</h3>
                <p className="balance-amount" data-testid="billing-cash-reserved"><Money amount={billing.cash.reserved} /></p>
                <p className="fine">Amount currently reserved in this ledger</p>
              </article>
              <article className="card span-4 balance-card">
                <p className="eyebrow">Tester bonus</p>
                <h3>Available</h3>
                <p className="balance-amount" data-testid="billing-bonus-available"><Money amount={billing.bonus.available} /></p>
                <p className="fine">Promotional service credit</p>
              </article>
              <article className="card span-4 balance-card">
                <p className="eyebrow">Tester bonus</p>
                <h3>Reserved</h3>
                <p className="balance-amount" data-testid="billing-bonus-reserved"><Money amount={billing.bonus.reserved} /></p>
                <p className="fine">Amount currently reserved in this ledger</p>
              </article>
              <article className="card span-4 balance-card">
                <p className="eyebrow">Tester bonus</p>
                <h3>Expired</h3>
                <p className="balance-amount" data-testid="billing-bonus-expired"><Money amount={billing.bonus.expired} /></p>
                <p className="fine">Expired promotional value is unavailable</p>
              </article>
            </div>
          </section>

          <OwnerBonusCodesPanel onRedeemed={loadBilling} />

          <section className="card" aria-labelledby="billing-grants-title">
            <div className="section-heading">
              <div><h2 id="billing-grants-title">Bonus grants</h2><p className="fine">Grant amount and expiry are immutable. Existing terms are shown as recorded by the server.</p></div>
            </div>
            {!billing.grants.length ? <div className="empty-state" data-testid="billing-grants-empty">No bonus grants are recorded for this owner.</div> : (
              <div className="table-wrap">
                <table data-testid="billing-grants">
                <thead><tr><th scope="col">Grant reference</th><th scope="col">Created</th><th scope="col">Amount</th><th scope="col">Available</th><th scope="col">Reserved</th><th scope="col">Expired</th><th scope="col">Expiry</th><th scope="col">Status</th><th scope="col">Reason</th></tr></thead>
                  <tbody>
                    {billing.grants.map((grant) => (
                      <tr key={grant.id} data-testid={`billing-grant-${grant.id}`}>
                        <td data-testid={`billing-grant-id-${grant.id}`}><details><summary>Grant reference</summary><code>{grant.id}</code></details></td>
                        <td>{formatTimestamp(grant.createdAt)}</td>
                        <td><Money amount={grant.amount} /></td>
                        <td><Money amount={grant.available} /></td>
                        <td><Money amount={grant.reserved} /></td>
                        <td><Money amount={grant.expired} /></td>
                        <td>{formatTimestamp(grant.expiresAt)}</td>
                        <td>{grant.status ? label(grant.status) : "—"}</td>
                        <td>{grant.reason || "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          {grantCursor ? <button data-testid="billing-grants-older" className="button button-small" disabled={busy} onClick={() => void loadOlder("grants")}>Load older bonus grants</button> : null}
          <section className="card" aria-labelledby="billing-history-title">
            <div className="section-heading">
              <div><h2 id="billing-history-title">Financial history</h2><p className="fine">Newest five entries first. Load older activity to reach the complete owner history. Exact amounts remain available for entries that round to the same displayed value.</p></div>
            </div>
            <HistoryTable entries={billing.history} />
            {historyCursor ? <button data-testid="billing-history-older" className="button button-small" disabled={busy} onClick={() => void loadOlder("history")}>Load older financial activity</button> : null}
          </section>
        </>
      )}
      <p className={`status-box ${error ? "status-error" : ""}`} role={error ? "alert" : "status"} aria-live="polite">{message}</p>
    </div>
  );
}
