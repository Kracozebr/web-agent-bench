"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { ApiError, apiRequest, errorText, getCurrentOwner, newOperationId, type OwnerProjection } from "@/lib/api";

interface BonusCode {
  id: string;
  label: string;
  kind: "group" | "single_use";
  amount: string;
  maximumUses: number;
  usedCount: number;
  issuedAt: string;
  disabledAt: string | null;
}

interface BonusCodeResponse { codes: BonusCode[] }
interface IssuePayload {
  operationId: string;
  label: string;
  kind: "group" | "single_use";
  amount: string;
  maximumUses: number;
}
interface IssueResponse {
  code: BonusCode;
  operationId: string;
  replayed: boolean;
  secret: string | null;
}

function formatTimestamp(value: string | null): string {
  if (!value) return "Active";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : `${new Intl.DateTimeFormat("en", { dateStyle: "medium", timeStyle: "medium", timeZone: "UTC" }).format(date)} UTC`;
}

export function AdminBonusCodesPanel() {
  const router = useRouter();
  const [owner, setOwner] = useState<OwnerProjection | null>(null);
  const [codes, setCodes] = useState<BonusCode[]>([]);
  const [label, setLabel] = useState("");
  const [kind, setKind] = useState<"group" | "single_use">("group");
  const [amount, setAmount] = useState("1.000000");
  const [maximumUses, setMaximumUses] = useState("10");
  const [pendingIssue, setPendingIssue] = useState<IssuePayload | null>(null);
  const [pendingDisables, setPendingDisables] = useState<Record<string, string>>({});
  const [issuedSecret, setIssuedSecret] = useState<{ codeId: string; value: string } | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState(false);

  const loadCodes = useCallback(async () => {
    const result = await apiRequest<BonusCodeResponse>("/api/admin/bonus-codes");
    setCodes(result.codes);
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
      await loadCodes();
      if (active) setLoading(false);
    }).catch((cause: unknown) => {
      if (!active) return;
      setMessage(errorText(cause));
      setError(true);
      setLoading(false);
    });
    return () => { active = false; };
  }, [loadCodes, router]);

  async function issue(payload: IssuePayload) {
    setBusy(true);
    setIssuedSecret(null);
    setError(false);
    setPendingIssue(payload);
    setMessage("Issuing an immutable bonus-code offer…");
    try {
      const result = await apiRequest<IssueResponse>("/api/admin/bonus-codes", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      setPendingIssue(null);
      setCodes((current) => [result.code, ...current.filter((item) => item.id !== result.code.id)]);
      if (result.secret) {
        setIssuedSecret({ codeId: result.code.id, value: result.secret });
        setMessage("The offer is saved. Copy the plaintext now; the server will not return it again.");
      } else {
        setMessage("The offer is saved, but its one-time plaintext was already delivered or lost. Disable it and issue a replacement if nobody received it.");
      }
      setLabel("");
      if (kind === "group") setMaximumUses("10");
      try { await loadCodes(); } catch { /* Keep the mutation receipt visible; refresh is available. */ }
    } catch (cause) {
      const uncertain = !(cause instanceof ApiError) || cause.status >= 500;
      if (!uncertain) setPendingIssue(null);
      setMessage(uncertain
        ? "The issuance result is not confirmed. Retry this same operation to recover its identity; a lost one-time plaintext cannot be recovered."
        : errorText(cause));
      setError(true);
      try { await loadCodes(); } catch { /* Keep the mutation error visible. */ }
    } finally {
      setBusy(false);
    }
  }

  async function submitIssue(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const parsedMaximum = Number(maximumUses);
    if (!Number.isSafeInteger(parsedMaximum) || parsedMaximum < 1) {
      setMessage("Enter a positive whole-number redemption maximum.");
      setError(true);
      return;
    }
    const payload: IssuePayload = {
      operationId: newOperationId(),
      label: label.trim(),
      kind,
      amount: amount.trim(),
      maximumUses: kind === "single_use" ? 1 : parsedMaximum,
    };
    await issue(payload);
  }

  async function disable(code: BonusCode) {
    const operationId = pendingDisables[code.id] ?? newOperationId();
    setPendingDisables((current) => ({ ...current, [code.id]: operationId }));
    setBusy(true);
    setIssuedSecret(null);
    setError(false);
    setMessage(`Disabling future claims for ${code.label}…`);
    try {
      const result = await apiRequest<{ code: BonusCode }>(`/api/admin/bonus-codes/${encodeURIComponent(code.id)}/disable`, {
        method: "POST",
        body: JSON.stringify({ operationId }),
      });
      setPendingDisables((current) => {
        const next = { ...current };
        delete next[code.id];
        return next;
      });
      setCodes((current) => current.map((item) => item.id === result.code.id ? result.code : item));
      setMessage("Future claims are disabled. Credits already issued remain in their owners’ ledgers.");
      await loadCodes().catch(() => undefined);
    } catch (cause) {
      const uncertain = !(cause instanceof ApiError) || cause.status >= 500;
      if (uncertain) {
        setMessage("The disable result is not confirmed. Retry with the same operation to recover the original outcome.");
      } else {
        setPendingDisables((current) => {
          const next = { ...current };
          delete next[code.id];
          return next;
        });
        setMessage(errorText(cause));
      }
      setError(true);
    } finally {
      setBusy(false);
    }
  }

  if (loading) return <p className="loading" role="status">Checking administrator access and bonus-code inventory…</p>;

  if (!owner?.isAdmin) return (
    <section className="card auth-card" aria-labelledby="bonus-code-admin-denied-title">
      <p className="eyebrow">Restricted controls</p>
      <h1 id="bonus-code-admin-denied-title">Administrator access required</h1>
      <p className="lede">Only the configured administrator can issue or disable bonus codes.</p>
      <p className={`status-box ${error ? "status-error" : ""}`} role={error ? "alert" : "status"}>{message}</p>
      <Link className="button" href="/admin">Return to administration</Link>
    </section>
  );

  return (
    <div className="stack" data-testid="admin-bonus-codes-page">
      <div className="page-heading">
        <p className="eyebrow">Configured administrator</p>
        <h1>Bonus codes</h1>
        <p className="lede">Issue internal service credit with fixed six-decimal terms and a total redemption cap. Plaintext is shown once and is never available from the inventory list.</p>
        <p className="fine"><Link href="/admin">Return to admission controls</Link></p>
      </div>

      <section className="card" aria-labelledby="bonus-code-issue-title">
        <h2 id="bonus-code-issue-title">Issue a new offer</h2>
        <form className="admin-form-row" data-testid="bonus-code-issue-form" onSubmit={(event) => void submitIssue(event)}>
          <div className="field">
            <label htmlFor="bonus-code-label">Offer label</label>
            <input id="bonus-code-label" data-testid="bonus-code-label" maxLength={100} value={label} onChange={(event) => setLabel(event.target.value)} disabled={busy || Boolean(pendingIssue)} />
          </div>
          <div className="field">
            <label htmlFor="bonus-code-kind">Code type</label>
            <select id="bonus-code-kind" data-testid="bonus-code-kind" value={kind} onChange={(event) => {
              const next = event.target.value as "group" | "single_use";
              setKind(next);
              if (next === "single_use") setMaximumUses("1");
            }} disabled={busy || Boolean(pendingIssue)}>
              <option value="group">Group · one claim per owner</option>
              <option value="single_use">Single use · first eligible owner</option>
            </select>
          </div>
          <div className="field">
            <label htmlFor="bonus-code-amount">Credit per claim (USDC units)</label>
            <input id="bonus-code-amount" data-testid="bonus-code-amount" type="text" inputMode="decimal" value={amount} onChange={(event) => setAmount(event.target.value)} disabled={busy || Boolean(pendingIssue)} />
          </div>
          <div className="field">
            <label htmlFor="bonus-code-maximum">Total claims</label>
            <input id="bonus-code-maximum" data-testid="bonus-code-maximum" type="number" min="1" step="1" inputMode="numeric" value={kind === "single_use" ? "1" : maximumUses}
              onChange={(event) => setMaximumUses(event.target.value)} disabled={busy || Boolean(pendingIssue) || kind === "single_use"} />
          </div>
          <button className="button button-primary" data-testid="bonus-code-issue-submit" type="submit" disabled={busy || Boolean(pendingIssue)}>
            Issue bonus code
          </button>
          {pendingIssue && (
            <button className="button" data-testid="bonus-code-issue-retry" type="button" onClick={() => void issue(pendingIssue)} disabled={busy}>
              {busy ? "Retrying…" : "Retry same issuance"}
            </button>
          )}
        </form>
        {issuedSecret && (
          <div className="once-secret" data-testid="bonus-code-secret-once" role="status" aria-live="polite">
            <p className="once-secret-title">Bonus code — shown once</p>
            <code className="code-secret">{issuedSecret.value}</code>
            <p className="fine">Share this value privately. It is not stored in the browser or returned by any later list or retry response.</p>
            <p className="fine">Offer reference <code>{issuedSecret.codeId}</code></p>
            <button className="button button-small" data-testid="bonus-code-secret-hide" type="button" onClick={() => setIssuedSecret(null)}>Hide one-time value</button>
          </div>
        )}
      </section>

      <section className="card" aria-labelledby="bonus-code-inventory-title">
        <div className="section-heading">
          <div><h2 id="bonus-code-inventory-title">Offer inventory</h2><p className="fine">Only terms, usage and status are listed. Existing claims remain credited after an offer is disabled.</p></div>
          <button className="button button-small" data-testid="bonus-code-inventory-refresh" type="button" onClick={() => void loadCodes().catch((cause: unknown) => { setMessage(errorText(cause)); setError(true); })} disabled={busy}>Refresh</button>
        </div>
        {!codes.length ? <div className="empty-state" data-testid="bonus-code-inventory-empty">No bonus codes have been issued.</div> : (
          <div className="table-wrap">
            <table data-testid="admin-bonus-code-inventory">
              <thead><tr><th scope="col">Offer reference</th><th scope="col">Label</th><th scope="col">Type</th><th scope="col">Credit</th><th scope="col">Usage</th><th scope="col">Issued (UTC)</th><th scope="col">Status</th><th scope="col">Action</th></tr></thead>
              <tbody>{codes.map((item) => (
                <tr key={item.id} data-testid={`bonus-code-row-${item.id}`}>
                  <td><code>{item.id}</code></td>
                  <td>{item.label}</td>
                  <td>{item.kind === "group" ? "Group" : "Single use"}</td>
                  <td>{item.amount} USDC</td>
                  <td data-testid={`bonus-code-usage-${item.id}`}>{item.usedCount} / {item.maximumUses}</td>
                  <td>{formatTimestamp(item.issuedAt)}</td>
                  <td><span className={`pill ${item.disabledAt ? "pill-danger" : item.usedCount >= item.maximumUses ? "" : "pill-success"}`}>{item.disabledAt ? "Disabled" : item.usedCount >= item.maximumUses ? "Exhausted" : "Active"}</span></td>
                  <td>{(!item.disabledAt && item.usedCount < item.maximumUses) || pendingDisables[item.id] ? <button className="button button-small button-danger" data-testid={`bonus-code-disable-${item.id}`} type="button" onClick={() => void disable(item)} disabled={busy}>{pendingDisables[item.id] ? "Retry disable" : "Disable"}</button> : null}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        )}
      </section>
      <p className={`status-box ${error ? "status-error" : ""}`} role={error ? "alert" : "status"} aria-live="polite" data-testid="bonus-code-admin-status">{message}</p>
    </div>
  );
}
