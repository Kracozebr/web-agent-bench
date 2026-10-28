"use client";

import { useState } from "react";
import { apiRequest, errorText } from "@/lib/api";

type TaskFeedback = {
  taskId: string;
  status: "known" | "unknown";
  outcome: "passed" | "partial" | "failed" | "unknown";
  credit: { numerator: string; denominator: string } | null;
  reason: "goal_unmet" | "budget_reserve_permission_scope_violation" | "time_exhausted" | "evidence_unknown" | null;
};

type RunFeedback = { status: "available" | "withheld_until_run_termination"; tasks: TaskFeedback[] };

const reasons = {
  goal_unmet: "The task goal was not fully met.",
  budget_reserve_permission_scope_violation: "A budget, reserve or permission rule was violated.",
  time_exhausted: "The task time limit was reached.",
  evidence_unknown: "The available evidence does not establish a result.",
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
    (task.status === "unknown"
      ? task.outcome === "unknown" && task.credit === null
      : task.outcome !== "unknown" && task.credit && /^(0|[1-9][0-9]{0,77})$/.test(task.credit.numerator) &&
        /^[1-9][0-9]{0,77}$/.test(task.credit.denominator) &&
        BigInt(task.credit.numerator) <= BigInt(task.credit.denominator)));
}

/** Only the allowlisted owner feedback projection is rendered; no case or tool evidence is requested. */
export function RunFeedbackPanel({ runId }: { runId: string }) {
  const [feedback, setFeedback] = useState<RunFeedback | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function loadFeedback() {
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
  }

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
              <strong>{task.taskId}</strong>: {task.status === "unknown" ? "Evidence unknown" : task.outcome}
              {task.status === "known" && task.credit ? <span> · Credit {task.credit.numerator}/{task.credit.denominator}</span> : null}
              {task.reason ? <p className="fine">{reasons[task.reason]}</p> : null}
            </li>)}
          </ul>
          : null}
    </section>
  );
}
