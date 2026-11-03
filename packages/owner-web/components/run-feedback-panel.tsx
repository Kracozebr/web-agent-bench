"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { apiRequest, errorText } from "@/lib/api";

type TaskFeedback = {
  taskId: string;
  status: "known" | "unknown";
  outcome: "passed" | "partial" | "failed" | "unknown";
  credit: { numerator: string; denominator: string } | null;
  reason: "goal_unmet" | "budget_reserve_permission_scope_violation" | "time_exhausted" | "evidence_unknown" | "not_issued" | "not_evaluated" | null;
  submittedAnswer?: Record<string, unknown>;
};

type RunFeedback = { status: "available" | "withheld_until_run_termination"; tasks: TaskFeedback[] };
type Check = { code: string; status: "passed" | "failed" | "unknown"; evidenceRefs: string[] };
type Diagnostics = { runId: string; taskId: string; goalChecks: Check[]; constraintChecks: Check[];
  actions: { actionId: string; sequence: string; kind: string; status: string; createdAt: string; evidenceRefs: string[] }[];
  timing: { issuedAt: string | null; deadlineAt: string | null; closedAt: string | null }; evidenceRefs: string[] };

const checkLabel = (code: string) => code === "task_goal" ? "Task goal" : code === "mandatory_constraints" ? "Mandatory constraints" : /^paid_resource_delivery/.test(code) ? "Recorded delivery evidence after payment" : "Verified task check";
const actionKinds = new Set(["purchase", "pay", "retrieve", "approve", "transfer", "wrap", "unwrap", "swap", "inspect_catalog", "inspect_offer", "unknown"]);
const actionStatuses = new Set(["observed", "pending", "unknown", "rejected_before_execution"]);
function safeRefs(value: unknown, limit: number): value is string[] {
  return Array.isArray(value) && value.length <= limit && value.every((reference) => typeof reference === "string" && /^sha256:[a-f0-9]{64}$/.test(reference));
}
function safeChecks(value: unknown): value is Check[] {
  return Array.isArray(value) && value.length <= 4097 && value.every((check) => check &&
    (check.code === "task_goal" || check.code === "mandatory_constraints" || /^paid_resource_delivery_recorded_[1-9][0-9]*$/.test(check.code)) &&
    ["passed", "failed", "unknown"].includes(check.status) && safeRefs(check.evidenceRefs, 2));
}
function boundedJson(value: unknown, depth = 0): boolean {
  if (depth > 8) return false;
  if (value === null || typeof value === "boolean") return true;
  if (typeof value === "string") return value.length <= 8192;
  if (typeof value === "number") return Number.isFinite(value);
  if (Array.isArray(value)) return value.length <= 128 && value.every((item) => boundedJson(item, depth + 1));
  if (typeof value !== "object") return false;
  const entries = Object.entries(value as Record<string, unknown>);
  return entries.length <= 128 && entries.every(([key, item]) => key.length <= 128 && boundedJson(item, depth + 1));
}
function safeSubmittedAnswer(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value) || !boundedJson(value)) return false;
  const serialized = JSON.stringify(value);
  return typeof serialized === "string" && new TextEncoder().encode(serialized).length <= 8192;
}
function safeDiagnostics(value: Diagnostics, runId: string, taskId: string): boolean {
  return value?.runId === runId && value.taskId === taskId && safeChecks(value.goalChecks) && safeChecks(value.constraintChecks) &&
    safeRefs(value.evidenceRefs, 2) && !!value.timing && [value.timing.issuedAt, value.timing.deadlineAt, value.timing.closedAt].every((time) => time === null || typeof time === "string" && Number.isFinite(Date.parse(time))) &&
    Array.isArray(value.actions) && value.actions.length <= 4096 && value.actions.every((action) =>
      action && /^[a-f0-9-]{36}$/i.test(action.actionId) && /^[1-9][0-9]*$/.test(action.sequence) && actionKinds.has(action.kind) && actionStatuses.has(action.status) && Number.isFinite(Date.parse(action.createdAt)) && safeRefs(action.evidenceRefs, 1));
}

const reasons = {
  goal_unmet: "The task goal was not fully met.",
  budget_reserve_permission_scope_violation: "A mandatory task constraint was violated.",
  time_exhausted: "The task time limit was reached.",
  evidence_unknown: "The available evidence does not establish a result.",
  not_issued: "This task was not issued. It has no evaluation or credit.",
  not_evaluated: "No verified evaluation was recorded. This is not a failed or zero-credit result.",
};

function isFeedback(value: unknown): value is RunFeedback {
  if (!value || typeof value !== "object") return false;
  const feedback = value as RunFeedback;
  if (!["available", "withheld_until_run_termination"].includes(feedback.status) ||
      !Array.isArray(feedback.tasks) || feedback.tasks.length > 12 ||
      new Set(feedback.tasks.map((task) => task?.taskId)).size !== feedback.tasks.length ||
      feedback.status === "withheld_until_run_termination" && feedback.tasks.length !== 0) return false;
  return feedback.tasks.every((task) => task && /^(S[1-4]|M[1-4]|H[1-3]|U1)$/.test(task.taskId) &&
    ["known", "unknown"].includes(task.status) &&
    ["passed", "partial", "failed", "unknown"].includes(task.outcome) &&
    (task.reason === null || Object.hasOwn(reasons, task.reason)) &&
    (task.submittedAnswer === undefined || task.taskId === "S2" && safeSubmittedAnswer(task.submittedAnswer)) &&
    (task.status === "unknown"
      ? task.outcome === "unknown" && task.credit === null
      : task.outcome !== "unknown" && task.credit && /^(0|[1-9][0-9]{0,77})$/.test(task.credit.numerator) &&
        /^[1-9][0-9]{0,77}$/.test(task.credit.denominator) &&
        BigInt(task.credit.numerator) <= BigInt(task.credit.denominator)));
}

/** Only the allowlisted owner feedback projection is rendered; no case or tool evidence is requested. */
export function RunFeedbackPanel({ runId, mode, status, refreshRevision = 0 }: { runId: string; mode?: string; status?: string; refreshRevision?: number }) {
  const [feedback, setFeedback] = useState<RunFeedback | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [diagnostics, setDiagnostics] = useState<Record<string, Diagnostics>>({});
  async function loadDiagnostics(taskId: string) {
    setBusy(true); setError("");
    try {
      const result = await apiRequest<{ diagnostics: Diagnostics }>(`/api/owner/runs/${encodeURIComponent(runId)}/tasks/${encodeURIComponent(taskId)}/diagnostics`);
      if (!safeDiagnostics(result.diagnostics, runId, taskId)) throw new Error("Invalid diagnostic scope or projection");
      setDiagnostics((current) => ({ ...current, [taskId]: result.diagnostics }));
    } catch (failure) { setError(errorText(failure)); }
    finally { setBusy(false); }
  }

  const loadFeedback = useCallback(async () => {
    setBusy(true);
    setError("");
    try {
      const result = await apiRequest<unknown>(`/api/owner/runs/${encodeURIComponent(runId)}/results`);
      if (!isFeedback(result)) throw new Error("Invalid run feedback projection");
      setFeedback(result);
    } catch (failure) {
      setFeedback(null);
      setError(errorText(failure));
    } finally {
      setBusy(false);
    }
  }, [runId]);

  useEffect(() => {
    if (refreshRevision > 0) void loadFeedback();
  }, [loadFeedback, refreshRevision]);

  return (
    <section className="stack-sm" aria-label="Private task results" data-testid={`run-feedback-${runId}`}>
      <div>
        <button className="button button-small" type="button" data-testid={`run-feedback-load-${runId}`}
          onClick={() => void loadFeedback()} disabled={busy}>
          {busy ? "Loading results…" : feedback ? "Refresh results" : "View results"}
        </button>
      </div>
      {error ? <p className="status-box status-error" role="alert">{error}</p> : null}
      {feedback?.status === "withheld_until_run_termination"
        ? <p className="notice" role="status">Ranked results are available after the run ends.</p>
        : feedback ? feedback.tasks.length === 0
          ? <p className="fine" role="status">No task result is available yet.</p>
          : <ul className="stack-sm" data-testid={`run-feedback-tasks-${runId}`}>
            {feedback.tasks.map((task) => <li key={task.taskId} data-testid={`run-feedback-task-${runId}-${task.taskId}`}>
              <strong>{task.taskId}</strong>: {task.reason === "not_issued" ? "Not issued" : task.reason === "not_evaluated" ? "Not evaluated" : task.status === "unknown" ? "Evidence unknown" : task.outcome}
              {task.status === "known" && task.credit ? <span> · Credit {task.credit.numerator}/{task.credit.denominator}</span> : null}
              {task.reason ? <p className="fine">{reasons[task.reason]}</p> : null}
              {task.submittedAnswer !== undefined ? <details data-testid={`submitted-answer-${runId}-${task.taskId}`}>
                <summary>Submitted S2 answer</summary>
                <pre>{JSON.stringify(task.submittedAnswer, null, 2)}</pre>
              </details> : null}
              <Link href={`/reports?runId=${encodeURIComponent(runId)}&taskId=${encodeURIComponent(task.taskId)}`}>Report this task</Link>
              {mode === "training" && task.reason !== "not_issued" && task.reason !== "not_evaluated" && (task.status === "known" || status === "completed" || status === "failed" || status === "cancelled") ? <div className="stack-sm">
                <button data-testid={`run-diagnostics-load-${runId}-${task.taskId}`} className="button button-small" disabled={busy} onClick={() => void loadDiagnostics(task.taskId)}>Explain Training result</button>
                {diagnostics[task.taskId] ? <details open><summary>Private Training checks and accepted actions</summary>
                  <p className="fine">Unknown evidence does not establish agent failure. A recorded action is not proof of its external effect.</p>
                  {[...diagnostics[task.taskId]!.goalChecks, ...diagnostics[task.taskId]!.constraintChecks].map((check, index) => <div key={index}><strong>{checkLabel(check.code)}</strong>: {check.status}<details><summary>Evidence references</summary>{check.evidenceRefs.length ? check.evidenceRefs.map((reference) => <code key={reference}>{reference} </code>) : "Evidence unavailable"}</details></div>)}
                  <dl className="kv-list">{Object.entries(diagnostics[task.taskId]!.timing).map(([name, value]) => <div key={name}><dt>{name === "issuedAt" ? "Issued" : name === "deadlineAt" ? "Deadline" : "Closed"}</dt><dd>{value ? new Date(value).toLocaleString() : "Not observed"}</dd></div>)}</dl>
                  <ol>{diagnostics[task.taskId]!.actions.map((action) => <li key={action.actionId}>{action.kind.replaceAll("_", " ")} / {action.status.replaceAll("_", " ")} / {new Date(action.createdAt).toLocaleString()}<details><summary>Action evidence</summary><code>{action.actionId}</code>{action.evidenceRefs.map((reference) => <p key={reference}><code>{reference}</code></p>)}</details><Link href={`/reports?runId=${encodeURIComponent(runId)}&taskId=${encodeURIComponent(task.taskId)}&actionId=${encodeURIComponent(action.actionId)}`}>Report this action</Link></li>)}</ol>
                </details> : null}
              </div> : null}
            </li>)}
          </ul>
          : null}
    </section>
  );
}
