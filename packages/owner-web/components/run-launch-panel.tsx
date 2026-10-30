"use client";

import { type FormEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { RunFeedbackPanel } from "./run-feedback-panel";
import {
  ApiError,
  apiRequest,
  errorText,
  getCurrentOwner,
  newOperationId,
  trainingCatalogWeights,
  selectedRunQuote,
  trainingQuoteDescription,
  type RunCatalogResponse,
  type RunLaunchIntent,
  type RunMode,
  type OwnerRunProjection,
} from "@/lib/api";

interface AgentCard {
  id: string;
  name: string;
  permissions: { training: boolean; ranked: boolean };
}

interface AgentsResponse { agents: AgentCard[] }
interface IntentsResponse { intents: RunLaunchIntent[] }
interface IntentResponse { intent: RunLaunchIntent; replayed: boolean }
interface RunsResponse { runs: OwnerRunProjection[] }
interface RunResponse { run: OwnerRunProjection; replayed: boolean }

interface PendingOperation {
  payload: string;
  operationId: string;
}

const rankedTaskIds = ["S1", "S2", "S3", "S4", "M1", "M2", "M3", "M4", "H1", "H2", "H3", "U1"];
function timestamp(value: string | null): string {
  if (!value) return "Not set";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? "Unavailable" : parsed.toLocaleString();
}

function copyText(value: string): Promise<void> {
  return navigator.clipboard.writeText(value);
}

function agentCanUse(agent: AgentCard, mode: RunMode): boolean {
  return agent.permissions[mode] === true;
}

export function RunLaunchPanel() {
  const router = useRouter();
  const [ownerReady, setOwnerReady] = useState(false);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [agents, setAgents] = useState<AgentCard[]>([]);
  const [catalog, setCatalog] = useState<RunCatalogResponse | null>(null);
  const [intents, setIntents] = useState<RunLaunchIntent[]>([]);
  const [runs, setRuns] = useState<OwnerRunProjection[]>([]);
  const [agentId, setAgentId] = useState("");
  const [mode, setMode] = useState<RunMode>("training");
  const [taskIds, setTaskIds] = useState<string[]>(["S1"]);
  const [cashCeiling, setCashCeiling] = useState("0");
  const [message, setMessage] = useState("");
  const [error, setError] = useState(false);
  const [copiedIntentId, setCopiedIntentId] = useState<string | null>(null);
  const [copiedHandoffId, setCopiedHandoffId] = useState<string | null>(null);
  const pendingCreate = useRef<PendingOperation | null>(null);
  const pendingCancels = useRef<Record<string, PendingOperation>>({});
  const pendingRunCancels = useRef<Record<string, PendingOperation>>({});

  const refresh = useCallback(async () => {
    setBusy(true);
    setError(false);
    try {
      const [nextCatalog, agentResponse, intentResponse, runResponse] = await Promise.all([
        apiRequest<RunCatalogResponse>("/api/owner/runs/catalog"),
        apiRequest<AgentsResponse>("/api/owner/agents"),
        apiRequest<IntentsResponse>("/api/owner/runs/intents"),
        apiRequest<RunsResponse>("/api/owner/runs"),
      ]);
      setCatalog(nextCatalog);
      setAgents(agentResponse.agents);
      setIntents(intentResponse.intents);
      setRuns(runResponse.runs);
      setMessage("Loaded the latest private release, permission and intent status from the server.");
    } catch (reason) {
      if (reason instanceof ApiError && reason.status === 401) router.replace("/sign-in");
      setMessage(errorText(reason));
      setError(true);
    } finally {
      setBusy(false);
      setLoading(false);
    }
  }, [router]);

  useEffect(() => {
    let active = true;
    void getCurrentOwner().then((owner) => {
      if (!active) return;
      if (!owner) {
        router.replace("/sign-in");
        return;
      }
      if (owner.admissionStatus !== "admitted") {
        router.replace("/activate");
        return;
      }
      setOwnerReady(true);
      const params = new URLSearchParams(window.location.search);
      const preferredAgentId = params.get("agentId");
      if (preferredAgentId) setAgentId(preferredAgentId);
      void refresh().then(() => {
        if (active && preferredAgentId) setAgentId(preferredAgentId);
      });
    }).catch((reason: unknown) => {
      if (!active) return;
      if (reason instanceof ApiError && reason.status === 401) router.replace("/sign-in");
      setMessage(errorText(reason));
      setError(true);
      setLoading(false);
    });
    return () => { active = false; };
  }, [refresh, router]);

  const selectedAgent = agents.find((agent) => agent.id === agentId) ?? null;
  const release = catalog?.activeRelease ?? null;
  const trainingWeights = release ? trainingCatalogWeights(release) : null;
  const trainingTaskIds = trainingWeights ? [...trainingWeights.keys()] : [];
  const releaseAvailable = Boolean(
    release?.completeRankedRelease
    && /^[0-9a-f]{64}$/i.test(release.manifestHash)
    && typeof release.releaseIdentity === "string" && release.releaseIdentity.length > 0
    && Array.isArray(release.taskIds)
    && rankedTaskIds.every((id, index) => release.taskIds[index] === id)
    && release.taskIds.length === rankedTaskIds.length
    && trainingWeights,
  );
  const modeAllowed = selectedAgent ? agentCanUse(selectedAgent, mode) : false;
  const selectedTasks = mode === "ranked" ? rankedTaskIds : trainingTaskIds.filter((id) => taskIds.includes(id));
  const cashCeilingValid = /^\d+(?:\.\d{1,6})?$/.test(cashCeiling.trim());
  const quotePrice = useMemo(() => release ? selectedRunQuote(release, mode, selectedTasks) : null, [mode, release, selectedTasks]);
  const canCreate = Boolean(ownerReady && !busy && releaseAvailable && catalog?.intentCreationReady === true && selectedAgent && modeAllowed && selectedTasks.length > 0 && cashCeilingValid && quotePrice !== null);

  function changeMode(nextMode: RunMode) {
    setMode(nextMode);
    if (nextMode === "training") setTaskIds((current) => current.filter((id) => trainingTaskIds.includes(id)));
  }

  function toggleTrainingTask(id: string, checked: boolean) {
    setTaskIds((current) => checked
      ? (current.includes(id) ? current : [...current, id])
      : current.filter((item) => item !== id));
  }

  async function createIntent(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedAgent || !releaseAvailable || catalog?.intentCreationReady !== true || !modeAllowed || selectedTasks.length === 0 || !cashCeilingValid || quotePrice === null || !release) return;

    const payload = {
      agentId: selectedAgent.id,
      mode,
      taskIds: selectedTasks,
      cashCeiling: cashCeiling.trim(),
      expectedReleaseIdentity: release!.releaseIdentity,
      expectedManifestHash: release!.manifestHash,
      expectedQuotePrice: quotePrice!,
    };
    const serialized = JSON.stringify(payload);
    if (pendingCreate.current?.payload !== serialized) {
      pendingCreate.current = { payload: serialized, operationId: newOperationId() };
    }
    setBusy(true);
    setError(false);
    setMessage("Submitting a private launch intent for server review…");
    try {
      const response = await apiRequest<IntentResponse>("/api/owner/runs/intents", {
        method: "POST",
        body: JSON.stringify({ operationId: pendingCreate.current.operationId, ...payload }),
      });
      pendingCreate.current = null;
      setIntents((current) => [response.intent, ...current.filter((item) => item.id !== response.intent.id)]);
      setMessage(response.replayed
        ? "The server recovered the same private intent after a retry. It has not been admitted or reserved."
        : "The server created this private intent. No run, reservation, queue slot or timer exists until the matching agent accepts it.");
    } catch (reason) {
      if (reason instanceof ApiError && reason.status < 500) pendingCreate.current = null;
      setMessage(errorText(reason));
      setError(true);
    } finally {
      setBusy(false);
    }
  }

  async function cancelIntent(intent: RunLaunchIntent) {
    const payload = JSON.stringify({ intentId: intent.id });
    if (pendingCancels.current[intent.id]?.payload !== payload) {
      pendingCancels.current[intent.id] = { payload, operationId: newOperationId() };
    }
    setBusy(true);
    setError(false);
    setMessage(`Cancelling private intent ${intent.id}…`);
    try {
      const response = await apiRequest<IntentResponse>(`/api/owner/runs/intents/${encodeURIComponent(intent.id)}/cancel`, {
        method: "POST",
        body: JSON.stringify({ operationId: pendingCancels.current[intent.id]!.operationId }),
      });
      delete pendingCancels.current[intent.id];
      setIntents((current) => current.map((item) => item.id === response.intent.id ? response.intent : item));
      setMessage(response.intent.status === "cancelled"
        ? "The server confirmed cancellation of the private intent. No reservation or queued run was created."
        : `The server returned intent status: ${response.intent.status}.`);
    } catch (reason) {
      if (reason instanceof ApiError && reason.status < 500) delete pendingCancels.current[intent.id];
      setMessage(errorText(reason));
      setError(true);
    } finally {
      setBusy(false);
    }
  }

  async function cancelRun(runId: string) {
    const payload = JSON.stringify({ runId });
    if (pendingRunCancels.current[runId]?.payload !== payload) {
      pendingRunCancels.current[runId] = { payload, operationId: newOperationId() };
    }
    setBusy(true);
    setError(false);
    setMessage(`Requesting cancellation for admitted run ${runId}…`);
    try {
      const response = await apiRequest<RunResponse>(`/api/owner/runs/${encodeURIComponent(runId)}/cancel`, {
        method: "POST",
        body: JSON.stringify({ operationId: pendingRunCancels.current[runId]!.operationId }),
      });
      delete pendingRunCancels.current[runId];
      setRuns((current) => [response.run, ...current.filter((item) => item.id !== response.run.id)]);
      setIntents((current) => current.map((item) => item.runId === response.run.id
        ? { ...item, runStatus: response.run.status, queueDeadline: response.run.queueDeadline,
          queueExpiryFencePending: response.run.queueExpiryFencePending }
        : item));
      setMessage(response.run.status === "cancelled"
        ? "The server confirmed the pre-start run cancellation and hold release."
        : `The server recorded run status ${response.run.status}; any started-run fee follows the ordinary cancellation policy.`);
    } catch (reason) {
      if (reason instanceof ApiError && reason.status < 500) delete pendingRunCancels.current[runId];
      setMessage(errorText(reason));
      setError(true);
    } finally {
      setBusy(false);
    }
  }

  async function copyIntentId(intentId: string) {
    try {
      await copyText(intentId);
      setCopiedIntentId(intentId);
      setError(false);
      setMessage("Copied the nonauthorizing intent reference. The ID is not an access token or permission.");
    } catch {
      setMessage("Clipboard access is unavailable. Select and copy the intent reference directly.");
      setError(true);
    }
  }

  async function copyHandoffPrompt(intent: RunLaunchIntent) {
    const prompt = `Run the free Web3 Agent Bench preflight for your configured connection. If it confirms that this agent is authorized for ${intent.mode} and the current selection, accept private launch intent ${intent.id} through the run-intent acceptance tool. If the server denies it, report the denial without retrying with another identity. This ID is only a reference; it is not a credential or permission.`;
    try {
      await copyText(prompt);
      setCopiedHandoffId(intent.id);
      setError(false);
      setMessage("Copied a handoff prompt containing only the nonauthorizing intent reference.");
    } catch {
      setMessage("Clipboard access is unavailable. The safe handoff prompt is shown below for manual copying.");
      setError(true);
    }
  }

  if (loading) return <p className="loading" role="status">Checking your admitted owner session and active benchmark release…</p>;

  if (!ownerReady) return (
    <section className="card auth-card" aria-labelledby="runs-unavailable-title">
      <h1 id="runs-unavailable-title">Private runs unavailable</h1>
      <p className={`status-box ${error ? "status-error" : ""}`} role={error ? "alert" : "status"}>{message || "An admitted owner session is required to create or view launch intents."}</p>
      <Link className="button" href="/sign-in">Return to sign-in</Link>
    </section>
  );

  return (
    <div className="stack" data-testid="run-launch-page">
      <div className="page-heading">
        <p className="eyebrow">Private owner workspace</p>
        <h1>Launch a benchmark run</h1>
        <p className="lede">Review the active release, choose an authorized agent and create a private intent for that agent to accept.</p>
      </div>

      <div className="notice" data-testid="run-launch-boundary">
        Creating an intent does not reserve funds, create a run, claim a queue slot or start a timer. Admission happens only after the matching connected agent accepts and the server confirms the current policy, quote and funding limits. A cash ceiling only bounds a possible cash allocation; it does not grant permission to spend cash.
      </div>

      <section className="card stack-sm" aria-labelledby="run-catalog-title">
        <div className="section-heading">
          <div>
            <h2 id="run-catalog-title">Active release</h2>
            <p className="fine">Release identity and completeness come from the server catalog. A partial or missing release cannot be used to create an intent.</p>
          </div>
          <button className="button button-small" data-testid="run-intents-refresh" type="button" onClick={() => void refresh()} disabled={busy}>
            {busy ? "Refreshing…" : "Refresh status"}
          </button>
        </div>
        {releaseAvailable && release ? (
          <div className="stack-sm" data-testid="run-catalog-status" role="status">
            <span className="pill pill-success">Complete 12-task release available</span>
            <dl className="kv-list">
              <dt>Benchmark version</dt><dd>{release.benchmarkVersion}</dd>
              <dt>Release identity</dt><dd data-testid="run-release-identity">{release.releaseIdentity}</dd>
              <dt>Manifest hash</dt><dd>{release.manifestHash}</dd>
              <dt>Benchmark hash</dt><dd>{release.benchmarkHash}</dd>
              <dt>Policy hash</dt><dd>{release.policyHash}</dd>
              <dt>Ranked quote</dt><dd>{release.rankedPrice} USDC</dd>
              <dt>Full open training quote</dt><dd>{trainingQuoteDescription(release)}</dd>
            </dl>
            {!catalog?.readyToStart ? <p className="notice notice-warning" data-testid="run-release-readiness">Execution start is still gated: {catalog?.readinessReason || "executor readiness is not confirmed"}.</p> : null}
            {catalog?.intentCreationReady !== true ? <p className="notice notice-warning" data-testid="run-intent-policy-readiness">Intent creation is disabled until the server confirms a bounded intent lifetime and pending-intent capacity policy. {catalog?.intentCreationReason || "Launch intent policy is not configured."}</p> : null}
          </div>
        ) : (
          <div className="notice notice-warning" data-testid="run-catalog-status" role="status">
            {catalog?.status === "active_release_unavailable"
              ? `No complete active 12-task release is available. Intent creation is disabled. ${catalog.readinessReason || ""}`
              : "The server has not confirmed a complete active 12-task release. Intent creation is disabled."}
          </div>
        )}
      </section>

      <section className="card stack-sm" aria-labelledby="run-intent-create-title">
        <div>
          <h2 id="run-intent-create-title">Create launch intent</h2>
          <p className="fine">The server fixes the catalog and quote in the intent. If that quote, version or funding need later changes, review and create a new intent.</p>
        </div>
        <form className="form" data-testid="run-intent-form" onSubmit={(event) => void createIntent(event)}>
          <div className="field">
            <label htmlFor="run-agent">Agent</label>
            <select id="run-agent" data-testid="run-agent-select" value={agentId} onChange={(event) => setAgentId(event.target.value)} disabled={busy} required>
              <option value="">Choose an agent</option>
              {agents.map((agent) => <option key={agent.id} value={agent.id}>{agent.name} ({agent.id})</option>)}
            </select>
            <span className="fine">The agent must have the corresponding current permission. Its credential and policy are checked again when it accepts.</span>
          </div>

          <div className="field">
            <label htmlFor="run-mode">Run mode</label>
            <select id="run-mode" data-testid="run-mode-select" value={mode} onChange={(event) => changeMode(event.target.value as RunMode)} disabled={busy}>
              <option value="training">Training</option>
              <option value="ranked">Ranked</option>
            </select>
          </div>

          {mode === "training" ? (
            <fieldset className="permission-fieldset" disabled={busy || !releaseAvailable}>
              <legend>Training tasks</legend>
              <p className="fine">Select one or more available training tasks. The current catalog determines eligibility.</p>
              <div className="permission-list" data-testid="run-training-task-list">
                {trainingTaskIds.map((id) => (
                  <label className="permission-switch" key={id} htmlFor={`run-task-${id}`}>
                    <span className="permission-copy"><strong>{id}</strong><small>Training task</small></span>
                    <input
                      id={`run-task-${id}`}
                      data-testid={`run-task-checkbox-${id}`}
                      type="checkbox"
                      checked={taskIds.includes(id)}
                      onChange={(event) => toggleTrainingTask(id, event.target.checked)}
                    />
                  </label>
                ))}
              </div>
            </fieldset>
          ) : (
            <div className="notice" data-testid="run-ranked-task-selection">Ranked mode includes all twelve tasks: {rankedTaskIds.join(", ")}.</div>
          )}

          <div className="field">
            <label htmlFor="run-cash-ceiling">Maximum cash allocation (USDC)</label>
            <input
              id="run-cash-ceiling"
              data-testid="run-cash-ceiling"
              type="number"
              min="0"
              step="0.000001"
              inputMode="decimal"
              value={cashCeiling}
              onChange={(event) => setCashCeiling(event.target.value)}
              disabled={busy}
              required
            />
            <span className="fine" data-testid="run-selected-quote">Server quote for this selection: {quotePrice ?? "unavailable"} USDC. The intent pins this value and rejects a stale release or changed quote.</span>
            <span className="fine">This is a bound on cash the accepted run may need, not permission to spend. Cash spending also requires the separate owner policy.</span>
          </div>

          {!modeAllowed && selectedAgent ? <p className="notice notice-warning" data-testid="run-agent-permission-warning">This agent does not currently have {mode} permission. Save its policy in Agents before creating an intent.</p> : null}
          <button className="button button-primary" data-testid="run-intent-create" type="submit" disabled={!canCreate || !cashCeiling.trim()}>
            {busy ? "Submitting…" : "Create private intent"}
          </button>
        </form>
      </section>

      <section className="card stack-sm" aria-labelledby="run-intent-list-title">
        <div className="section-heading">
          <div>
            <h2 id="run-intent-list-title">Private intents and run status</h2>
            <p className="fine">Intent IDs are safe references, not credentials. Run identity and status appear only after the server confirms agent acceptance.</p>
          </div>
        </div>
        <div className="agent-list" data-testid="run-intents">
          {!intents.length ? <div className="empty-state" data-testid="run-intents-empty">No launch intents are listed for this owner.</div> : intents.map((intent) => (
            <article className="agent-card" data-testid={`run-intent-${intent.id}`} key={intent.id}>
              <div className="section-heading">
                <div>
                  <p className="eyebrow">{intent.mode} · {intent.taskIds.length} task{intent.taskIds.length === 1 ? "" : "s"}</p>
                  <h3>Intent {intent.id}</h3>
                  <span className={`pill ${intent.status === "accepted" ? "pill-success" : intent.status === "pending" ? "pill-warning" : ""}`} data-testid={`run-intent-status-${intent.id}`}>{intent.status}</span>
                </div>
                <button className="button button-small" data-testid={`run-intent-copy-${intent.id}`} type="button" onClick={() => void copyIntentId(intent.id)} disabled={busy}>
                  {copiedIntentId === intent.id ? "Copied reference" : "Copy intent ID"}
                </button>
              </div>
              <dl className="kv-list">
                <dt>Agent</dt><dd>{intent.agentId}</dd>
                <dt>Tasks</dt><dd>{intent.taskIds.join(", ")}</dd>
                <dt>Benchmark version</dt><dd>{intent.benchmarkVersion}</dd>
                <dt>Manifest hash</dt><dd>{intent.manifestHash}</dd>
                <dt>Quote</dt><dd>{intent.quote.price} {intent.quote.token} · {intent.quote.precision} decimals</dd>
                <dt>Cash ceiling</dt><dd>{intent.cashCeiling} USDC</dd>
                <dt>Created</dt><dd>{timestamp(intent.createdAt)}</dd>
                <dt>Intent expires</dt><dd>{timestamp(intent.expiresAt)}</dd>
                {intent.status === "pending" ? <><dt>Admission</dt><dd>No run admitted and no funds or queue slot reserved</dd></> : null}
                {intent.acceptedAt ? <><dt>Accepted</dt><dd>{timestamp(intent.acceptedAt)}</dd></> : null}
                {intent.runId ? <><dt>Run ID</dt><dd>{intent.runId}</dd></> : null}
                {intent.runStatus ? <><dt>Run status</dt><dd>{intent.runStatus}</dd></> : null}
                {intent.queueDeadline ? <><dt>Queue deadline</dt><dd>{timestamp(intent.queueDeadline)}</dd></> : null}
                {intent.queueExpiryFencePending ? <><dt>Queue expiry</dt><dd className="notice notice-warning" data-testid={`intent-queue-expiry-fence-${intent.id}`}>
                  This run expired before starting. Cancellation is finishing; reserved bonus USDC will be released after cleanup is confirmed.
                </dd></> : null}
                {intent.terminalReason ? <><dt>Terminal reason</dt><dd>{intent.terminalReason}</dd></> : null}
              </dl>
              {intent.status === "pending" ? (
                <div className="stack-sm">
                  <div className="notice">Handoff reference: <code>{intent.id}</code>. The matching agent must run its own preflight and accept this intent. This reference alone cannot authorize or admit a run.</div>
                  <div className="stack-sm">
                    <button className="button button-small" data-testid={`run-intent-handoff-${intent.id}`} type="button" onClick={() => void copyHandoffPrompt(intent)} disabled={busy}>
                      {copiedHandoffId === intent.id ? "Copied safe handoff" : "Copy safe handoff prompt"}
                    </button>
                    <p className="fine" data-testid={`run-intent-handoff-text-${intent.id}`}>Run the free preflight for the configured connection, then ask the matching agent to accept intent {intent.id} if its current permission allows. The intent ID is a reference, not a credential.</p>
                  </div>
                  <div className="button-row">
                    <button className="button button-danger" data-testid={`run-intent-cancel-${intent.id}`} type="button" onClick={() => void cancelIntent(intent)} disabled={busy}>Cancel pending intent</button>
                  </div>
                </div>
              ) : null}
            </article>
          ))}
        </div>
        <p className={`status-box ${error ? "status-error" : ""}`} data-testid="run-intents-status" role={error ? "alert" : "status"} aria-live="polite">{message}</p>
      </section>

      <section className="card stack-sm" aria-labelledby="owner-runs-title">
        <div className="section-heading">
          <div>
            <h2 id="owner-runs-title">Admitted runs</h2>
            <p className="fine">Only server-admitted runs appear here. Queued cancellation releases pre-start holds; started-run cancellation follows the retained-fee and executor-fence rules.</p>
          </div>
        </div>
        <div className="agent-list" data-testid="owner-runs">
          {!runs.length ? <div className="empty-state" data-testid="owner-runs-empty">No admitted runs are listed for this owner.</div> : runs.map((run) => {
            const canCancelRun = run.status === "queued" || run.status === "preparing" || run.status === "running";
            return (
              <article className="agent-card" data-testid={`owner-run-${run.id}`} key={run.id}>
                <div className="section-heading">
                  <div>
                    <p className="eyebrow">{run.mode} · {run.taskIds.length} task{run.taskIds.length === 1 ? "" : "s"}</p>
                    <h3>Run {run.id}</h3>
                    <span className={`pill ${run.status === "completed" ? "pill-success" : run.status === "queued" || run.status === "preparing" || run.status === "running" ? "pill-warning" : ""}`} data-testid={`owner-run-status-${run.id}`}>{run.status}</span>
                  </div>
                </div>
                <dl className="kv-list">
                  <dt>Agent</dt><dd>{run.agentId}</dd>
                  {run.intentId ? <><dt>Intent</dt><dd>{run.intentId}</dd></> : null}
                  <dt>Tasks</dt><dd>{run.taskIds.join(", ")}</dd>
                  <dt>Benchmark version</dt><dd>{run.benchmarkVersion}</dd>
                  <dt>Manifest hash</dt><dd>{run.manifestHash}</dd>
                  <dt>Quote</dt><dd>{run.quotePrice} USDC</dd>
                  <dt>Queued</dt><dd>{timestamp(run.queuedAt)}</dd>
                  <dt>Queue deadline</dt><dd>{timestamp(run.queueDeadline)}</dd>
                  {run.startedAt ? <><dt>Started</dt><dd>{timestamp(run.startedAt)}</dd></> : null}
                  {run.overallDeadline ? <><dt>Overall deadline</dt><dd>{timestamp(run.overallDeadline)}</dd></> : null}
                  {run.finishedAt ? <><dt>Finished</dt><dd>{timestamp(run.finishedAt)}</dd></> : null}
                  {run.terminalReason ? <><dt>Terminal reason</dt><dd>{run.terminalReason}</dd></> : null}
                  {run.cancellationReason ? <><dt>Cancellation reason</dt><dd>{run.cancellationReason}</dd></> : null}
                  {run.cancellationRequestedAt ? <><dt>Cancellation requested</dt><dd>{timestamp(run.cancellationRequestedAt)}</dd></> : null}
                  {run.cancellationEvidenceHash ? <><dt>Cancellation evidence</dt><dd>{run.cancellationEvidenceHash}</dd></> : null}
                </dl>
                <RunFeedbackPanel runId={run.id} />
                {run.queueExpiryFencePending ? <div className="notice notice-warning" data-testid={`run-queue-expiry-fence-${run.id}`}>
                  This run expired before starting. Cancellation is finishing; reserved bonus USDC will be released after cleanup is confirmed.
                </div> : run.status === "cancellation_requested" ? <div className="notice notice-warning">The cancellation request is recorded and awaits confirmed executor fence evidence.</div> : null}
                {canCancelRun ? <button className="button button-danger" data-testid={`run-cancel-${run.id}`} type="button" onClick={() => void cancelRun(run.id)} disabled={busy}>Cancel admitted run</button> : null}
              </article>
            );
          })}
        </div>
      </section>
      <p className="fine"><Link href="/agents">Manage agents and permissions</Link> · <Link href="/billing">Review private balance and policy</Link></p>
    </div>
  );
}
