"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { ApiError, apiRequest, errorText, getCurrentOwner, newOperationId, type OwnerProjection } from "@/lib/api";

type Mode = "active" | "paused";
type ReasonCode = "maintenance" | "incident_response" | "resource_pressure" | "scheduled_pause" | "other";
interface OperationControl {
  mode: Mode;
  revision: number;
  changedAt: string;
  changedByOwnerId: string | null;
  reasonCode: ReasonCode | null;
  operationId: string | null;
}
interface ControlEvent {
  operationId: string;
  actorOwnerId: string;
  revision: number;
  previousMode: Mode;
  mode: Mode;
  reasonCode: ReasonCode;
  createdAt: string | null;
}
interface OperationsSnapshot {
  control: OperationControl;
  recentControlEvents: ControlEvent[];
  api: { database: "ready" };
  starts: {
    ready: boolean;
    workerLease: "held" | "missing" | "not_configured";
    betaRuntimeHealth: "ready" | "unavailable" | "not_configured";
    environmentCapacity: "ready" | "unavailable" | "not_configured";
    storage: "ready" | "low" | "unavailable" | "not_configured";
  };
  queue: {
    pendingIntents: number;
    queuedRuns: number;
    preparingRuns: number;
    runningRuns: number;
    acceptedUnstartedRuns: number;
    oldestUnstartedAt: string | null;
    oldestUnstartedAgeSeconds: number;
  };
  failures: { failedRuns: number; unknownRuns: number; unknownActions: number };
  reports: Array<{ status: string; count: number }>;
  storage: { status: string; capacityBytes: string | null; freeBytes: string | null; requiredFreeBytes: string | null; freePercent: number | null };
}
interface ControlPayload { operationId: string; expectedRevision: number; mode: Mode; reasonCode: ReasonCode }
interface PendingControl { payload: ControlPayload }

const REASONS: Array<{ value: ReasonCode; label: string }> = [
  { value: "maintenance", label: "Maintenance" },
  { value: "incident_response", label: "Incident response" },
  { value: "resource_pressure", label: "Resource pressure" },
  { value: "scheduled_pause", label: "Scheduled pause" },
  { value: "other", label: "Other" },
];

function timestamp(value: string | null | undefined): string {
  if (!value) return "Not recorded";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? "Unavailable" :
    `${new Intl.DateTimeFormat("en", { dateStyle: "medium", timeStyle: "medium", timeZone: "UTC" }).format(parsed)} UTC`;
}

function bytes(value: string | null): string {
  if (!value || !/^\d+$/.test(value)) return "Unavailable";
  const number = Number(value);
  if (!Number.isFinite(number)) return "Unavailable";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let size = number;
  let index = 0;
  while (size >= 1024 && index < units.length - 1) { size /= 1024; index += 1; }
  return `${size.toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
}

export function AdminOperationsPanel() {
  const router = useRouter();
  const [owner, setOwner] = useState<OwnerProjection | null>(null);
  const [snapshot, setSnapshot] = useState<OperationsSnapshot | null>(null);
  const [reasonCode, setReasonCode] = useState<ReasonCode>("maintenance");
  const [pending, setPending] = useState<PendingControl | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [usageExportBusy, setUsageExportBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState(false);

  const refresh = useCallback(async () => {
    const current = await apiRequest<OperationsSnapshot>("/api/admin/operations");
    setSnapshot(current);
  }, []);

  useEffect(() => {
    let active = true;
    void getCurrentOwner().then(async (current) => {
      if (!active) return;
      if (!current) { router.replace("/sign-in"); return; }
      if (current.admissionStatus !== "admitted") { router.replace("/activate"); return; }
      setOwner(current);
      if (!current.isAdmin) { setLoading(false); return; }
      await refresh();
      if (active) { setMessage("Operations state loaded from PostgreSQL."); setLoading(false); }
    }).catch((cause: unknown) => {
      if (!active) return;
      setMessage(errorText(cause)); setError(true); setLoading(false);
    });
    return () => { active = false; };
  }, [refresh, router]);

  async function submitControl(item: PendingControl) {
    setBusy(true);
    setPending(item);
    setError(false);
    setMessage(item.payload.mode === "paused" ? "Pausing new run admissions and queued starts…" : "Resuming new run admissions and queued starts…");
    try {
      const result = await apiRequest<{ control: OperationControl; replayed: boolean }>("/api/admin/operations/control", {
        method: "POST", body: JSON.stringify(item.payload),
      });
      setPending(null);
      setMessage(result.replayed ? "The original operations-control update was recovered." : "The operations-control update is saved and audited.");
      try { await refresh(); } catch { /* Keep the mutation result and allow a manual refresh. */ }
    } catch (cause) {
      const uncertain = !(cause instanceof ApiError) || cause.status >= 500;
      if (!uncertain) setPending(null);
      setMessage(uncertain
        ? "The update result is not confirmed. Retry the same operation to recover its original result."
        : errorText(cause));
      setError(true);
      try { await refresh(); } catch { /* Preserve the mutation failure until refresh succeeds. */ }
    } finally {
      setBusy(false);
    }
  }

  async function downloadUsageSupportExport() {
    setUsageExportBusy(true);
    setError(false);
    setMessage("Preparing the read-only usage/support export…");
    try {
      const exportJson = await apiRequest<unknown>("/api/admin/operations/usage-support-export");
      const blob = new Blob([`${JSON.stringify(exportJson, null, 2)}\n`], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = "beta-usage-support.json";
      document.body.append(anchor);
      anchor.click();
      anchor.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      setMessage("The usage/support JSON export was downloaded.");
    } catch (cause) {
      setMessage(errorText(cause));
      setError(true);
    } finally {
      setUsageExportBusy(false);
    }
  }

  function startControlUpdate(mode: Mode) {
    if (!snapshot) return;
    void submitControl({ payload: { operationId: newOperationId(), expectedRevision: snapshot.control.revision, mode, reasonCode } });
  }

  if (loading) return <p className="loading" role="status">Checking administrator access and operations state…</p>;
  if (!owner?.isAdmin) return (
    <section className="card auth-card" aria-labelledby="operations-admin-denied-title">
      <p className="eyebrow">Restricted controls</p>
      <h1 id="operations-admin-denied-title">Administrator access required</h1>
      <p className="lede">Only the configured administrator can pause or resume run starts.</p>
      <Link className="button" href="/admin">Return to administration</Link>
    </section>
  );

  return (
    <div className="stack" data-testid="admin-operations-page">
      <div className="page-heading">
        <p className="eyebrow">Configured administrator</p>
        <h1>Beta operations</h1>
        <p className="lede">Pause blocks new run admissions and starts of accepted queued runs. Running work, reports, reads, and reconciliation continue.</p>
        <p className="fine"><Link href="/admin">Return to administration</Link></p>
      </div>

      {snapshot ? (
        <>
          <section className="card" aria-labelledby="operations-control-title">
            <div className="section-heading">
              <div>
                <h2 id="operations-control-title">Run-start control</h2>
                <p className="fine">Revision {snapshot.control.revision} · changed {timestamp(snapshot.control.changedAt)}</p>
              </div>
              <span className={`pill ${snapshot.control.mode === "active" ? "pill-success" : "pill-danger"}`} data-testid="operations-mode">
                {snapshot.control.mode === "active" ? "Starts active" : "Starts paused"}
              </span>
            </div>
            {snapshot.control.reasonCode && <p className="fine">Last change reason: {REASONS.find((item) => item.value === snapshot.control.reasonCode)?.label ?? "Other"}</p>}
            <div className="admin-form-row">
              <div className="field">
                <label htmlFor="operations-reason">Change reason</label>
                <select id="operations-reason" value={reasonCode} onChange={(event) => setReasonCode(event.target.value as ReasonCode)} disabled={busy}>
                  {REASONS.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}
                </select>
              </div>
              {snapshot.control.mode === "active" ? (
                <button className="button button-danger" data-testid="operations-pause" type="button" onClick={() => startControlUpdate("paused")} disabled={busy || Boolean(pending)}>
                  Pause new starts
                </button>
              ) : (
                <button className="button button-primary" data-testid="operations-resume" type="button" onClick={() => startControlUpdate("active")} disabled={busy || Boolean(pending)}>
                  Resume run starts
                </button>
              )}
              {pending && (
                <button className="button" data-testid="operations-control-retry" type="button" onClick={() => void submitControl(pending)} disabled={busy}>
                  {busy ? "Retrying…" : "Retry same update"}
                </button>
              )}
              <button className="button button-small" data-testid="operations-refresh" type="button" onClick={() => void refresh().catch((cause: unknown) => { setMessage(errorText(cause)); setError(true); })} disabled={busy}>
                Refresh status
              </button>
            </div>
          </section>

          <section className="card" aria-labelledby="operations-readiness-title">
            <h2 id="operations-readiness-title">Service and start readiness</h2>
            <p className="fine">Readiness below reports safe aggregate state; it does not certify target-host release acceptance.</p>
            <div className="table-wrap">
              <table data-testid="operations-readiness">
                <tbody>
                  <tr><th scope="row">Owner API database</th><td>{snapshot.api.database}</td></tr>
                  <tr><th scope="row">New starts ready</th><td>{snapshot.starts.ready ? "Yes" : "No"}</td></tr>
                  <tr><th scope="row">Worker lease</th><td>{snapshot.starts.workerLease.replaceAll("_", " ")}</td></tr>
                  <tr><th scope="row">BEF runtime</th><td>{snapshot.starts.betaRuntimeHealth.replaceAll("_", " ")}</td></tr>
                  <tr><th scope="row">Environment capacity</th><td>{snapshot.starts.environmentCapacity.replaceAll("_", " ")}</td></tr>
                  <tr><th scope="row">Private storage</th><td>{snapshot.storage.status} · {bytes(snapshot.storage.freeBytes)} free of {bytes(snapshot.storage.capacityBytes)}
                    {snapshot.storage.freePercent !== null ? ` (${snapshot.storage.freePercent}% free)` : ""}</td></tr>
                </tbody>
              </table>
            </div>
          </section>

          <section className="card" aria-labelledby="operations-queue-title">
            <div className="section-heading">
              <div><h2 id="operations-queue-title">Queue and outcomes</h2><p className="fine">Counts contain no owner or agent identifiers.</p></div>
              <button className="button button-small" type="button" onClick={() => void refresh().catch((cause: unknown) => { setMessage(errorText(cause)); setError(true); })} disabled={busy}>Refresh</button>
            </div>
            <div className="table-wrap">
              <table data-testid="operations-queue-metrics">
                <tbody>
                  <tr><th scope="row">Pending intents</th><td>{snapshot.queue.pendingIntents}</td></tr>
                  <tr><th scope="row">Accepted unstarted runs</th><td>{snapshot.queue.acceptedUnstartedRuns}</td></tr>
                  <tr><th scope="row">Queued / preparing</th><td>{snapshot.queue.queuedRuns} / {snapshot.queue.preparingRuns}</td></tr>
                  <tr><th scope="row">Running</th><td>{snapshot.queue.runningRuns}</td></tr>
                  <tr><th scope="row">Oldest unstarted queue age</th><td>{snapshot.queue.oldestUnstartedAgeSeconds}s · {timestamp(snapshot.queue.oldestUnstartedAt)}</td></tr>
                  <tr><th scope="row">Failed / unknown runs</th><td>{snapshot.failures.failedRuns} / {snapshot.failures.unknownRuns}</td></tr>
                  <tr><th scope="row">Unknown action receipts</th><td>{snapshot.failures.unknownActions}</td></tr>
                  <tr><th scope="row">Support reports by status</th><td>{snapshot.reports.length ? snapshot.reports.map((item) => `${item.status}: ${item.count}`).join(" · ") : "0"}</td></tr>
                </tbody>
              </table>
            </div>
          </section>

          <section className="card" aria-labelledby="operations-usage-export-title">
            <h2 id="operations-usage-export-title">Usage and support export</h2>
            <p className="fine">Downloads deduplicated owner and agent usage, report counts, and bonus debits separately from paid conversion. Historical client families without a trusted grant binding remain unknown.</p>
            <button className="button button-primary" data-testid="operations-usage-export" type="button"
              onClick={() => void downloadUsageSupportExport()} disabled={busy || usageExportBusy}>
              {usageExportBusy ? "Preparing export…" : "Download usage/support JSON"}
            </button>
          </section>

          <section className="card" aria-labelledby="operations-history-title">
            <h2 id="operations-history-title">Recent audited changes</h2>
            {!snapshot.recentControlEvents.length ? <p className="empty-state">No administrator changes have been recorded.</p> : (
              <div className="table-wrap">
                <table data-testid="operations-control-history">
                  <thead><tr><th scope="col">Revision</th><th scope="col">Change</th><th scope="col">Reason</th><th scope="col">UTC</th><th scope="col">Operation</th></tr></thead>
                  <tbody>{snapshot.recentControlEvents.map((item) => (
                    <tr key={item.operationId}>
                      <td>{item.revision}</td>
                      <td>{item.previousMode} → {item.mode}</td>
                      <td>{REASONS.find((reason) => reason.value === item.reasonCode)?.label ?? "Other"}</td>
                      <td>{timestamp(item.createdAt)}</td>
                      <td><code>{item.operationId}</code></td>
                    </tr>
                  ))}</tbody>
                </table>
              </div>
            )}
          </section>
        </>
      ) : <section className="card"><p className="empty-state">Operations state is unavailable. Refresh after the API becomes ready.</p></section>}

      <p className={`status-box ${error ? "status-error" : ""}`} role={error ? "alert" : "status"} aria-live="polite" data-testid="operations-admin-status">{message}</p>
    </div>
  );
}
