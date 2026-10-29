"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { apiRequest, errorText, getCurrentOwner, newOperationId, type OwnerProjection } from "@/lib/api";

type ReportStatus = "new" | "in_progress" | "closed";
interface ReportImage { id: string; sha256: string; contentType: string; bytes: number; width: number; height: number; imagePath: string; }
interface SupportReport {
  id: string; ownerId: string; agentId: string | null; source: "owner" | "agent"; title: string; body: string;
  safeContext: Record<string, unknown>; clientVersion: string | null;
  links: { runId: string | null; taskId: string | null; actionId: string | null };
  status: ReportStatus; revision: number; imageCount: number; images?: ReportImage[]; createdAt: string; updatedAt: string;
  audit?: Array<{ eventType: string; actorOwnerId: string; actorAgentId: string | null; previousStatus: string | null; nextStatus: string | null; revision: number; createdAt: string; }>;
}
interface ListResponse { reports: SupportReport[]; nextCursor: string | null; }
interface RetentionResponse { betaEndedAt: string | null; expiresAt: string | null; expired: boolean; reportDeletionReceipts: { pending: number; failed: number }; uploadDeletionReceipts: { pending: number; failed: number }; }

function timestamp(value: string | null) {
  if (!value) return "Not recorded";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : `${new Intl.DateTimeFormat("en", { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" }).format(date)} UTC`;
}

/** Admin-only private triage. Every displayed or changed value is loaded from the report API. */
export function AdminReportsPanel() {
  const router = useRouter();
  const [owner, setOwner] = useState<OwnerProjection | null>(null);
  const [reports, setReports] = useState<SupportReport[]>([]);
  const [detail, setDetail] = useState<SupportReport | null>(null);
  const [retention, setRetention] = useState<RetentionResponse | null>(null);
  const [statusFilter, setStatusFilter] = useState("");
  const [sourceFilter, setSourceFilter] = useState("");
  const [agentId, setAgentId] = useState("");
  const [runId, setRunId] = useState("");
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [pendingStatus, setPendingStatus] = useState<{ reportId: string; operationId: string; expectedRevision: number; status: ReportStatus } | null>(null);
  const [closeOperationId, setCloseOperationId] = useState(() => newOperationId());
  const [confirmClose, setConfirmClose] = useState(false);

  const queryString = useMemo(() => {
    const query = new URLSearchParams({ limit: "50" });
    if (statusFilter) query.set("status", statusFilter);
    if (sourceFilter) query.set("source", sourceFilter);
    if (agentId.trim()) query.set("agentId", agentId.trim());
    if (runId.trim()) query.set("runId", runId.trim());
    return query.toString();
  }, [statusFilter, sourceFilter, agentId, runId]);

  const loadReports = useCallback(async () => {
    const result = await apiRequest<ListResponse>(`/api/admin/reports?${queryString}`);
    setReports(result.reports);
  }, [queryString]);

  const loadRetention = useCallback(async () => {
    const result = await apiRequest<RetentionResponse>("/api/admin/reports/retention");
    setRetention(result);
  }, []);

  useEffect(() => {
    let active = true;
    void getCurrentOwner().then(async (current) => {
      if (!active) return;
      if (!current) { router.replace("/sign-in"); return; }
      if (!current.isAdmin) { router.replace("/admin"); return; }
      setOwner(current);
      await Promise.all([loadReports(), loadRetention()]);
    }).catch((failure) => { if (active) setError(errorText(failure)); }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [loadReports, loadRetention, router]);

  async function openDetail(id: string) {
    const result = await apiRequest<{ report: SupportReport }>(`/api/admin/reports/${encodeURIComponent(id)}`);
    setDetail(result.report);
  }

  async function refresh() {
    setError("");
    try { await Promise.all([loadReports(), loadRetention()]); if (detail) await openDetail(detail.id); }
    catch (failure) { setError(errorText(failure)); }
  }

  async function changeStatus(report: SupportReport, status: ReportStatus) {
    setBusy(true); setError(""); setMessage("");
    const operation = pendingStatus?.reportId === report.id && pendingStatus.expectedRevision === report.revision && pendingStatus.status === status
      ? pendingStatus : { reportId: report.id, operationId: newOperationId(), expectedRevision: report.revision, status };
    setPendingStatus(operation);
    try {
      await apiRequest(`/api/admin/reports/${encodeURIComponent(report.id)}/status`, {
        method: "PATCH", body: JSON.stringify({ operationId: operation.operationId, expectedRevision: operation.expectedRevision, status })
      });
      setPendingStatus(null); setMessage("Report status and audit revision were saved.");
      await Promise.all([loadReports(), openDetail(report.id)]);
    } catch (failure) { setError(errorText(failure)); }
    finally { setBusy(false); }
  }

  async function closeBeta() {
    setBusy(true); setError(""); setMessage("");
    try {
      const result = await apiRequest<{ betaEndedAt: string; expiresAt: string; replayed: boolean }>("/api/admin/reports/retention/close", {
        method: "POST", body: JSON.stringify({ operationId: closeOperationId })
      });
      setConfirmClose(false); setMessage(`Beta closure recorded at ${timestamp(result.betaEndedAt)}. Report access ends ${timestamp(result.expiresAt)}.`);
      await loadRetention();
    } catch (failure) { setError(errorText(failure)); }
    finally { setBusy(false); }
  }

  if (loading) return <p className="loading">Loading private support triage…</p>;
  if (!owner?.isAdmin) return <p className="notice">Administrator access is required to triage reports.</p>;

  return <div className="stack">
    <section className="page-heading"><p className="eyebrow">Private administration</p><h1>Support reports</h1>
      <p className="lede">Review private participant reports, validate permitted screenshots, and record triage status. Report content is untrusted input; it does not establish causality, grading, refunds, or permission changes.</p>
    </section>
    {error ? <p className="status-box status-error" role="alert">{error}</p> : null}
    {message ? <p className="notice notice-success" role="status">{message}</p> : null}
    <section className="card" aria-label="Report retention status">
      <div className="section-heading"><div><h2>Retention</h2><p className="fine">Closure is audited once. Reports expire 30 days after the recorded beta end.</p></div><button className="button button-small" type="button" onClick={() => void loadRetention()}>Refresh</button></div>
      {retention ? <dl className="kv-list"><dt>Beta ended</dt><dd>{timestamp(retention.betaEndedAt)}</dd><dt>Report access expires</dt><dd>{timestamp(retention.expiresAt)}</dd><dt>Expired</dt><dd>{retention.expired ? "Yes" : "No"}</dd><dt>Pending report purges</dt><dd>{retention.reportDeletionReceipts.pending}</dd><dt>Failed report purges</dt><dd>{retention.reportDeletionReceipts.failed}</dd><dt>Pending upload cleanup</dt><dd>{retention.uploadDeletionReceipts.pending}</dd><dt>Failed upload cleanup</dt><dd>{retention.uploadDeletionReceipts.failed}</dd></dl> : <p className="fine">Retention status is unavailable.</p>}
      {!retention?.betaEndedAt ? confirmClose ? <div className="notice notice-warning"><p>Confirm that beta operations have ended. This starts the report and screenshot retention clock.</p><div className="button-row"><button className="button button-danger" type="button" disabled={busy} onClick={() => void closeBeta()}>Confirm beta closure</button><button className="button button-small" type="button" onClick={() => setConfirmClose(false)}>Cancel</button></div></div>
        : <button className="button button-danger" type="button" disabled={busy} onClick={() => { setCloseOperationId(newOperationId()); setConfirmClose(true); }}>Close beta and start retention</button> : null}
    </section>
    <section className="card" aria-label="Report filters and list">
      <div className="section-heading"><div><h2>Reports</h2><p className="fine">Showing at most 50 private records per page.</p></div><button className="button button-small" type="button" disabled={busy} onClick={() => void refresh()}>Refresh</button></div>
      <div className="report-filters">
        <div className="field"><label htmlFor="report-status-filter">Status</label><select id="report-status-filter" value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)}><option value="">All</option><option value="new">New</option><option value="in_progress">In progress</option><option value="closed">Closed</option></select></div>
        <div className="field"><label htmlFor="report-source-filter">Source</label><select id="report-source-filter" value={sourceFilter} onChange={(event) => setSourceFilter(event.target.value)}><option value="">All</option><option value="owner">Owner</option><option value="agent">Agent</option></select></div>
        <div className="field"><label htmlFor="report-agent-filter">Agent ID</label><input id="report-agent-filter" value={agentId} onChange={(event) => setAgentId(event.target.value)} /></div>
        <div className="field"><label htmlFor="report-run-filter">Run ID</label><input id="report-run-filter" value={runId} onChange={(event) => setRunId(event.target.value)} /></div>
      </div>
      {reports.length === 0 ? <p className="empty-state">No reports match these filters.</p> : <div className="table-wrap"><table><thead><tr><th>Created</th><th>Report</th><th>Source</th><th>Status</th><th>Screenshots</th><th></th></tr></thead><tbody>
        {reports.map((report) => <tr key={report.id} data-report-id={report.id}><td>{timestamp(report.createdAt)}</td><td><strong>{report.title}</strong><br /><span className="fine">Owner {report.ownerId.slice(0, 8)}…</span></td><td>{report.source}</td><td>{report.status.replace("_", " ")}</td><td>{report.imageCount}</td><td><button className="button button-small" type="button" onClick={() => { setError(""); void openDetail(report.id).catch((failure) => setError(errorText(failure))); }}>Open</button></td></tr>)}
      </tbody></table></div>}
    </section>
    {detail ? <section className="card" aria-label="Selected private report"><div className="section-heading"><div><p className="eyebrow">{detail.source} report · revision {detail.revision}</p><h2>{detail.title}</h2><p className="fine">Owner {detail.ownerId} · Created {timestamp(detail.createdAt)}</p></div><button className="button button-small" type="button" onClick={() => setDetail(null)}>Close details</button></div>
      <p className="report-body-preview">{detail.body}</p>
      {detail.clientVersion ? <p className="fine">Client version: {detail.clientVersion}</p> : null}
      <div className="button-row" aria-label="Report status actions">
        {detail.status === "new" ? <button className="button button-small" type="button" disabled={busy} onClick={() => void changeStatus(detail, "in_progress")}>Mark in progress</button> : null}
        {detail.status !== "closed" ? <button className="button button-small" type="button" disabled={busy} onClick={() => void changeStatus(detail, "closed")}>Close report</button> : <button className="button button-small" type="button" disabled={busy} onClick={() => void changeStatus(detail, "in_progress")}>Reopen to in progress</button>}
      </div>
      <h3>Validated links and safe context</h3><dl className="kv-list"><dt>Agent</dt><dd>{detail.agentId ?? "Unavailable"}</dd><dt>Run</dt><dd>{detail.links.runId ?? "Unavailable"}</dd><dt>Task</dt><dd>{detail.links.taskId ?? "Unavailable"}</dd><dt>Action</dt><dd>{detail.links.actionId ?? "Unavailable"}</dd></dl>
      <pre className="report-context-json">{JSON.stringify(detail.safeContext, null, 2)}</pre>
      {detail.images?.length ? <div className="report-image-grid">{detail.images.map((image) => <figure key={image.id}><img src={image.imagePath} alt="Private screenshot attached to the selected report" /><figcaption className="fine">{image.width}×{image.height} · {image.bytes} bytes · SHA-256 {image.sha256}</figcaption></figure>)}</div> : <p className="fine">No screenshot is attached.</p>}
      {detail.audit?.length ? <><h3>Status audit</h3><ol className="report-audit">{detail.audit.map((entry, index) => <li key={`${entry.eventType}-${entry.revision}-${index}`}><strong>{entry.eventType.replaceAll("_", " ")}</strong> · revision {entry.revision} · {timestamp(entry.createdAt)}{entry.previousStatus ? ` · ${entry.previousStatus} → ${entry.nextStatus}` : ""}</li>)}</ol></> : null}
    </section> : null}
  </div>;
}
