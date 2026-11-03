"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { apiRequest, errorText, getCurrentOwner } from "@/lib/api";
import { diagnosticCoverageText, diagnosticResponsibilityText, diagnosticSummary, diagnosticTrustText, parseDiagnosticBundle,
  type DiagnosticCaseView, type DiagnosticDetail, type DiagnosticBundle, type DiagnosticSegmentReceipt } from "@/lib/diagnostics";

function timestamp(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Time unavailable" : date.toLocaleString();
}

export function DiagnosticsPanel({ admin = false }: { admin?: boolean }) {
  const router = useRouter();
  const [cases, setCases] = useState<DiagnosticCaseView[]>([]);
  const [detail, setDetail] = useState<DiagnosticDetail | null>(null);
  const [ready, setReady] = useState(false);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [bundle, setBundle] = useState<DiagnosticBundle | null>(null);
  const [importStatus, setImportStatus] = useState("");
  const base = admin ? "/api/admin/diagnostics/cases" : "/api/owner/diagnostics/cases";
  const refresh = useCallback(async () => {
    const result = await apiRequest<{ cases: DiagnosticCaseView[] }>(base);
    setCases(result.cases);
  }, [base]);

  useEffect(() => {
    let active = true;
    void getCurrentOwner().then(async owner => {
      if (!active) return;
      if (!owner) { router.replace("/sign-in"); return; }
      if (owner.admissionStatus !== "admitted") { router.replace("/activate"); return; }
      if (admin && !owner.isAdmin) return;
      await refresh();
      const caseId = new URLSearchParams(window.location.search).get("caseId");
      if (caseId && /^[a-f0-9-]{36}$/i.test(caseId)) {
        const selected = await apiRequest<DiagnosticDetail>(`${base}/${encodeURIComponent(caseId)}`);
        if (active) setDetail(selected);
      }
      if (active) setReady(true);
    }).catch(failure => { if (active) setError(errorText(failure)); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [admin, base, refresh, router]);

  async function loadDetail(caseId: string) {
    setBusy(true); setError("");
    try { setDetail(await apiRequest<DiagnosticDetail>(`${base}/${encodeURIComponent(caseId)}`)); }
    catch (failure) { setError(errorText(failure)); }
    finally { setBusy(false); }
  }
  async function importBundle() {
    if (!bundle) return;
    setBusy(true); setError(""); setImportStatus("Sending the original diagnostic batches…");
    let received = 0;
    try {
      for (const segment of bundle.segments) for (const batch of segment.batches) {
        const receipt = await apiRequest<DiagnosticSegmentReceipt>("/api/owner/diagnostics/import", {method:"POST",body:JSON.stringify({
          diagnosticSessionId:bundle.diagnosticSessionId,...(bundle.intentId ? {intentId:bundle.intentId}:{}),
          ...(bundle.caseId ? {caseId:bundle.caseId}:{}),...(bundle.binding ? {binding:bundle.binding}:{}),batch,
        })});
        if (receipt.segmentId !== batch.segmentId || receipt.highestContiguousSequence < batch.batchSequence ||
            receipt.highestContiguousSequence === batch.batchSequence && receipt.highestContiguousHash !== batch.payloadHash) {
          throw new Error("The server has not acknowledged this original batch. Retry the same export; do not edit its sequence or hash.");
        }
        received++;
      }
      setImportStatus(`${received} original batch receipt(s) verified. Report creation and complete collection are separate; inspect the case coverage below.`);
      setBundle(null); await refresh();
    } catch (failure) {
      setImportStatus(`${received} batch receipt(s) verified before delivery stopped. Retry the same export; saved identities prevent duplicate reports.`);
      setError(errorText(failure));
    } finally { setBusy(false); }
  }

  if (loading) return <p role="status">Loading private diagnostics…</p>;
  if (!ready) return <p role="alert">{error || "Diagnostics are not available to this account."}</p>;
  return <>
    <section className="page-heading">
      <p className="eyebrow">Private support evidence</p>
      <h1>{admin ? "Client diagnostics" : "Your diagnostics"}</h1>
      <p className="lede">Inspect received call evidence and collection gaps. Diagnostic reports do not change benchmark scores, payments or run status.</p>
      <p><Link href={admin ? "/admin/reports" : "/reports"}>Open reports</Link>{!admin ? <> · <Link href="/agents">Manage connected agents</Link></> : null}</p>
    </section>
    {error ? <p className="status-box status-error" role="alert">{error}</p> : null}
    {!admin ? <section className="card" aria-label="Import helper diagnostics">
      <h2>Import a helper export</h2>
      <p>Use this fallback if automatic delivery could not finish. Select the bounded JSON export produced by the diagnostic helper. Raw client logs may contain secrets and are rejected.</p>
      <input type="file" accept="application/json,.json" disabled={busy} aria-label="Diagnostic helper export" onChange={event => {
        setError(""); setBundle(null); setImportStatus(""); const file = event.target.files?.[0];
        if (!file) return;
        if (file.size > 8 * 1024 * 1024) { setError("Diagnostic export exceeds 8 MiB."); event.target.value = ""; return; }
        void file.text().then(text => { const parsed = parseDiagnosticBundle(text); setBundle(parsed); setImportStatus("Export checked locally. Its original batch identities will be preserved."); }).catch(() => setError("Select a bounded helper export with a saved case or owned connection binding. Raw logs are not supported."));
      }}/>
      <p><button type="button" className="button" disabled={!bundle || busy} onClick={() => void importBundle()}>Import diagnostics</button></p>
      {importStatus ? <p role="status">{importStatus}</p> : null}
    </section> : null}
    <section className="card" aria-label="Diagnostic cases" data-testid="diagnostic-cases">
      <div className="section-heading"><h2>{admin ? "Received cases" : "Your cases"}</h2><button type="button" className="button button-small" disabled={busy} onClick={() => { setError(""); void refresh().catch(e => setError(errorText(e))); }}>Refresh diagnostics</button></div>
      <p className="fine">An empty list does not prove the client had no errors. Client files that have not reached the server are outside the server backup.</p>
      {!cases.length ? <p>No received diagnostic cases.</p> : <div className="record-list">{cases.map(item => <article key={item.caseId} data-testid={`diagnostic-case-${item.caseId}`}>
        <h3>{item.runId ? `Run ${item.runId}` : "Client session without a confirmed run"}</h3>
        <p>{diagnosticSummary(item)}</p><p>{diagnosticCoverageText(item.captureState)}</p>
        <p className="fine">{diagnosticTrustText(item.sourceTrust)}</p>
        <p className="fine">Updated {timestamp(item.updatedAt)} · Case reference {item.caseId}</p>
        <p>{item.reportId ? <>Report recorded: {item.reportId}. Its existence does not establish that every client batch was received.</> : "No report receipt is recorded for this case."}</p>
        <button type="button" className="button button-small" disabled={busy} onClick={() => void loadDetail(item.caseId)}>View diagnostic details</button>
      </article>)}</div>}
    </section>
    {detail ? <section className="card" aria-label="Diagnostic details" data-testid="diagnostic-details">
      <div className="section-heading"><h2>Diagnostic details</h2><button className="button button-small" type="button" onClick={() => setDetail(null)}>Close details</button></div>
      <p>Case {detail.case.caseId}</p><p>{diagnosticCoverageText(detail.case.captureState)}</p>
      <p>{diagnosticTrustText(detail.case.sourceTrust)}</p>
      {detail.segments.length ? <ul>{detail.segments.map(receipt => <li key={receipt.segmentId}>
        Segment {receipt.segmentId}: acknowledged through batch {receipt.highestContiguousSequence}; {receipt.completion}.
        {receipt.diagnosticsSynced ? " Declared segment coverage synchronized." : " Complete synchronization is not confirmed."}
        {receipt.reportCreated ? " Report receipt recorded." : " No report creation receipt."}
      </li>)}</ul> : <p>No segment watermark receipts were received.</p>}
      <p className="fine">Each row shows only the server's safe diagnostic projection. Unknown responsibility stays unknown. A timeout is not proof that an action did not execute.</p>
      <div className="table-scroll"><table><thead><tr><th>Tool / stage</th><th>Outcome / code</th><th>Time</th><th>Responsibility / evidence</th></tr></thead><tbody>{detail.events.map(event => <tr key={event.eventId}>
        <td>{event.tool}<br/><small>{event.source} · {event.stage}</small></td>
        <td>{event.outcome}<br/>{event.errorCode ?? "No recorded error code"}{event.clientRunStatus && event.clientRunObservedAt ? <><br/><small>Unverified client observation: {event.clientRunStatus} at {timestamp(event.clientRunObservedAt)}. This does not confirm the server run status or grade.</small></> : null}</td>
        <td>{timestamp(event.startedAt)}<br/>{event.durationMs === null ? "Duration unavailable" : `${event.durationMs} ms`}</td>
        <td>{diagnosticResponsibilityText(event.responsibility)}<br/><small>{event.attributionReason}</small><br/><small>{event.evidenceIds.length ? event.evidenceIds.join(", ") : "No attribution evidence reference"}</small>{event.traceId ? <><br/><small>Trace {event.traceId}</small></> : null}</td>
      </tr>)}</tbody></table></div>
      {!detail.events.length ? <p>No detailed events were received. Check collection coverage above.</p> : null}
      <p className="fine">Server backup covers received evidence. Pending local files require the diagnostic helper to run again; stopped or uninstalled helpers cannot promise timely deletion or delivery.</p>
    </section> : null}
  </>;
}
