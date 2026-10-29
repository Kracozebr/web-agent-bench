"use client";

import { type FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { apiRequest, errorText, getCurrentOwner, newOperationId, type OwnerProjection } from "@/lib/api";

type ReportStatus = "new" | "in_progress" | "closed";
interface ReportImage { id: string; sha256: string; contentType: string; bytes: number; width: number; height: number; imagePath: string; }
interface SupportReport {
  id: string; source: "owner" | "agent"; title: string; body: string; safeContext: Record<string, unknown>;
  clientVersion: string | null; links: { runId: string | null; taskId: string | null; actionId: string | null };
  status: ReportStatus; revision: number; imageCount: number; images?: ReportImage[]; createdAt: string; updatedAt: string;
}
interface ListResponse { reports: SupportReport[]; nextCursor: string | null; }
interface PendingAttachment { report: SupportReport; file: File; uploadOperationId: string; attachOperationId: string; uploadId?: string; }

function timestamp(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : new Intl.DateTimeFormat("en", { dateStyle: "medium", timeStyle: "short" }).format(date);
}

async function multipartUploadForm(file: File, operationId: string): Promise<FormData> {
  if (!file.size || file.size > 5 * 1024 * 1024 || !["image/png", "image/jpeg", "image/webp"].includes(file.type)) {
    throw new Error("Choose a PNG, JPEG, or WebP screenshot no larger than 5 MiB.");
  }
  const bytes = new Uint8Array(await file.arrayBuffer());
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  const sha256 = Array.from(digest, (value) => value.toString(16).padStart(2, "0")).join("");
  const form = new FormData();
  form.append("operationId", operationId);
  form.append("expectedBytes", String(file.size));
  form.append("sha256", sha256);
  form.append("contentType", file.type);
  form.append("file", file, file.name);
  return form;
}

/** Owner report form and private receipt list. Upload idempotency keys live only for this mounted form. */
export function OwnerReportsPanel() {
  const router = useRouter();
  const [owner, setOwner] = useState<OwnerProjection | null>(null);
  const [reports, setReports] = useState<SupportReport[]>([]);
  const [title, setTitle] = useState("");
  const [body, setBody] = useState("");
  const [runId, setRunId] = useState("");
  const [taskId, setTaskId] = useState("");
  const [actionId, setActionId] = useState("");
  const [clientVersion, setClientVersion] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [fileOperationId, setFileOperationId] = useState(() => newOperationId());
  const [submission, setSubmission] = useState<{
    operationId: string; title: string; body: string; runId?: string; taskId?: string; actionId?: string;
    clientVersion?: string; file?: File; fileOperationId?: string;
  } | null>(null);
  const [pendingAttachment, setPendingAttachment] = useState<PendingAttachment | null>(null);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [selectedReport, setSelectedReport] = useState<SupportReport | null>(null);

  const previewUrl = useMemo(() => file ? URL.createObjectURL(file) : "", [file]);
  useEffect(() => () => { if (previewUrl) URL.revokeObjectURL(previewUrl); }, [previewUrl]);

  const loadReports = useCallback(async () => {
    const result = await apiRequest<ListResponse>("/api/owner/reports?limit=50");
    setReports(result.reports);
  }, []);

  useEffect(() => {
    let active = true;
    void getCurrentOwner().then(async (current) => {
      if (!active) return;
      if (!current) { router.replace("/sign-in"); return; }
      if (current.admissionStatus !== "admitted") { router.replace("/activate"); return; }
      setOwner(current);
      await loadReports();
    }).catch((failure) => { if (active) setError(errorText(failure)); }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [loadReports, router]);

  async function refresh() {
    setError("");
    try { await loadReports(); }
    catch (failure) { setError(errorText(failure)); }
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true); setError(""); setMessage("");
    const pending = submission ?? {
      operationId: newOperationId(), title, body,
      ...(runId.trim() ? { runId: runId.trim() } : {}), ...(taskId.trim() ? { taskId: taskId.trim() } : {}),
      ...(actionId.trim() ? { actionId: actionId.trim() } : {}), ...(clientVersion.trim() ? { clientVersion: clientVersion.trim() } : {}),
      ...(file ? { file, fileOperationId } : {})
    };
    setSubmission(pending);
    try {
      let imageUploadIds: string[] = [];
      if (pending.file && pending.fileOperationId) {
        const form = await multipartUploadForm(pending.file, pending.fileOperationId);
        const uploaded = await apiRequest<{ upload: { id: string; status: string } }>("/api/owner/report-images/uploads/multipart", { method: "POST", body: form });
        if (uploaded.upload.status !== "ready") throw new Error("The screenshot upload did not become ready.");
        imageUploadIds = [uploaded.upload.id];
      }
      const result = await apiRequest<{ report: SupportReport; replayed: boolean }>("/api/owner/reports", {
        method: "POST", body: JSON.stringify({
          operationId: pending.operationId, title: pending.title, body: pending.body,
          ...(pending.runId ? { runId: pending.runId } : {}), ...(pending.taskId ? { taskId: pending.taskId } : {}),
          ...(pending.actionId ? { actionId: pending.actionId } : {}), ...(pending.clientVersion ? { clientVersion: pending.clientVersion } : {}),
          imageUploadIds
        })
      });
      await loadReports();
      setMessage(result.replayed ? "Your report receipt was recovered." : "Your report was submitted.");
      setSubmission(null); setTitle(""); setBody(""); setRunId(""); setTaskId(""); setActionId(""); setClientVersion(""); setFile(null); setFileOperationId(newOperationId());
    } catch (failure) {
      setError(`${errorText(failure)} Retry keeps the same operation IDs and screenshot bytes while this page stays open.`);
    } finally { setBusy(false); }
  }

  async function openReport(id: string) {
    setError("");
    try {
      const result = await apiRequest<{ report: SupportReport }>(`/api/owner/reports/${encodeURIComponent(id)}`);
      setSelectedReport(result.report);
    } catch (failure) { setError(errorText(failure)); }
  }

  async function runAttachment(pending: PendingAttachment) {
    setBusy(true); setError(""); setMessage(""); setPendingAttachment(pending);
    try {
      let uploadId = pending.uploadId;
      if (!uploadId) {
        const form = await multipartUploadForm(pending.file, pending.uploadOperationId);
        const uploaded = await apiRequest<{ upload: { id: string; status: string } }>("/api/owner/report-images/uploads/multipart", { method: "POST", body: form });
        if (uploaded.upload.status !== "ready") throw new Error("The screenshot upload did not become ready.");
        uploadId = uploaded.upload.id;
        pending = { ...pending, uploadId };
        setPendingAttachment(pending);
      }
      await apiRequest(`/api/owner/reports/${encodeURIComponent(pending.report.id)}/images`, {
        method: "POST", body: JSON.stringify({ operationId: pending.attachOperationId, imageUploadIds: [uploadId] })
      });
      await loadReports(); await openReport(pending.report.id); setMessage("Screenshot attached to your agent report."); setPendingAttachment(null);
    } catch (failure) { setError(`${errorText(failure)} Retry uses the same upload and attachment operation IDs.`); }
    finally { setBusy(false); }
  }

  if (loading) return <p className="loading">Loading your private reports…</p>;
  if (!owner) return <p className="notice">Sign in with an admitted owner account to manage reports.</p>;

  return <div className="stack">
    <section className="page-heading"><p className="eyebrow">Private support</p><h1>Reports</h1>
      <p className="lede">Send a private issue report to the support team. Do not include passwords, tokens, private keys, or hidden task answers. Reports and screenshots are not grading or billing evidence.</p>
    </section>
    {error ? <p className="status-box status-error" role="alert">{error}</p> : null}
    {message ? <p className="notice notice-success" role="status">{message}</p> : null}
    <section className="card" aria-label="Submit a support report">
      <h2>New report</h2>
      <form className="form" onSubmit={(event) => void submit(event)}>
        <div className="field"><label htmlFor="report-title">Title</label><input id="report-title" maxLength={160} required value={title} onChange={(event) => { setTitle(event.target.value); setSubmission(null); }} /></div>
        <div className="field"><label htmlFor="report-body">What happened?</label><textarea id="report-body" maxLength={4000} required value={body} onChange={(event) => { setBody(event.target.value); setSubmission(null); }} /><small className="fine">Up to 4,000 characters. Avoid secret values and personal data.</small></div>
        <details><summary>Optional run context</summary><div className="report-context-fields">
          <div className="field"><label htmlFor="report-run">Run ID</label><input id="report-run" value={runId} onChange={(event) => { setRunId(event.target.value); setSubmission(null); }} /></div>
          <div className="field"><label htmlFor="report-task">Task ID</label><input id="report-task" maxLength={128} value={taskId} onChange={(event) => { setTaskId(event.target.value); setSubmission(null); }} /></div>
          <div className="field"><label htmlFor="report-action">Action ID</label><input id="report-action" value={actionId} onChange={(event) => { setActionId(event.target.value); setSubmission(null); }} /></div>
          <div className="field"><label htmlFor="report-client">Client version</label><input id="report-client" maxLength={64} value={clientVersion} onChange={(event) => { setClientVersion(event.target.value); setSubmission(null); }} /></div>
        </div></details>
        <div className="field"><label htmlFor="report-image">Optional screenshot (PNG, JPEG, or WebP; up to 5 MiB)</label><input id="report-image" type="file" accept="image/png,image/jpeg,image/webp" onChange={(event) => { const next = event.target.files?.[0] ?? null; setFile(next); setFileOperationId(newOperationId()); setSubmission(null); }} /></div>
        {previewUrl ? <figure className="report-preview"><img src={previewUrl} alt="Local screenshot preview before upload" /><figcaption className="fine">Preview is local to this page. The server will validate and strip image metadata.</figcaption></figure> : null}
        <div className="button-row"><button className="button button-primary" type="submit" disabled={busy}>{busy ? "Submitting…" : submission ? "Retry submission" : "Submit report"}</button></div>
      </form>
    </section>
    {pendingAttachment ? <section className="notice notice-warning" aria-label="Pending screenshot attachment"><p>Screenshot attachment needs a retry.</p><button className="button button-small" type="button" disabled={busy} onClick={() => void runAttachment(pendingAttachment)}>Retry attachment</button></section> : null}
    <section className="card" aria-label="Your report history">
      <div className="section-heading"><div><h2>Your reports</h2><p className="fine">Only receipts and details belonging to your owner account appear here.</p></div><button className="button button-small" type="button" onClick={() => void refresh()}>Refresh</button></div>
      {reports.length === 0 ? <p className="empty-state">No reports have been submitted.</p> : <div className="report-list">{reports.map((report) => <article className="report-card" key={report.id}>
        <div><div className="inline-controls"><strong>{report.title}</strong><span className="pill">{report.status.replace("_", " ")}</span><span className="pill">{report.source}</span></div><p className="fine">{timestamp(report.createdAt)} · {report.imageCount} screenshot{report.imageCount === 1 ? "" : "s"}</p></div>
        <p className="report-body-preview">{report.body}</p>
        <div className="button-row"><button className="button button-small" type="button" onClick={() => void openReport(report.id)}>View private details</button>
          {report.source === "agent" && report.imageCount < 3 ? <label className="button button-small">Attach screenshot<input className="visually-hidden" type="file" accept="image/png,image/jpeg,image/webp" disabled={busy} onChange={(event) => { const selected = event.target.files?.[0]; event.target.value = ""; if (selected) void runAttachment({ report, file: selected, uploadOperationId: newOperationId(), attachOperationId: newOperationId() }); }} /></label> : null}</div>
      </article>)}</div>}
    </section>
    {selectedReport ? <section className="card" aria-label="Report details"><div className="section-heading"><div><h2>{selectedReport.title}</h2><p className="fine">{selectedReport.status} · updated {timestamp(selectedReport.updatedAt)}</p></div><button className="button button-small" type="button" onClick={() => setSelectedReport(null)}>Close details</button></div>
      <p className="report-body-preview">{selectedReport.body}</p>
      {selectedReport.links.runId || selectedReport.links.taskId || selectedReport.links.actionId ? <dl className="kv-list">{selectedReport.links.runId ? <><dt>Run</dt><dd>{selectedReport.links.runId}</dd></> : null}{selectedReport.links.taskId ? <><dt>Task</dt><dd>{selectedReport.links.taskId}</dd></> : null}{selectedReport.links.actionId ? <><dt>Action</dt><dd>{selectedReport.links.actionId}</dd></> : null}</dl> : <p className="fine">No run context was attached.</p>}
      {selectedReport.images?.length ? <div className="report-image-grid">{selectedReport.images.map((image) => <figure key={image.id}><img src={image.imagePath} alt="Private screenshot attached to this report" /><figcaption className="fine">{image.width}×{image.height} · {image.bytes} bytes · SHA-256 {image.sha256.slice(0, 12)}…</figcaption></figure>)}</div> : null}
    </section> : null}
  </div>;
}
