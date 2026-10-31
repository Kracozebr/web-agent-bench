import { sql } from "drizzle-orm";
import type { OwnerDatabase } from "./db.js";
import { HttpError } from "./http-error.js";
import { isClosedTrainingTask, type TaskId } from "./task-catalog.js";
import type { TaskEvaluationResult } from "./task-evaluator.js";
import { sha256CanonicalTaskJson } from "./task-release.js";

export type TaskFeedback = {
  taskId: TaskId;
  status: TaskEvaluationResult["status"];
  outcome: TaskEvaluationResult["outcome"];
  credit: TaskEvaluationResult["credit"];
  reason: "goal_unmet" | "budget_reserve_permission_scope_violation" | "time_exhausted" | "evidence_unknown" | "not_issued" | "not_evaluated" | null;
  diagnostic?: {
    evaluationState: 'evaluated' | 'not_evaluated'; taskState: string;
    closureReason: 'agent_finish' | 'task_deadline' | 'run_deadline' | null;
    acceptedActionCount: string; reconciledActionCount: string;
    attribution: 'verified_outcome' | 'evidence_unknown' | 'unknown';
  };
};

/** Shared safe projection; no raw case, expected answers, observation IDs or payloads. */
export function projectTaskFeedback(result: TaskEvaluationResult): TaskFeedback {
  const reason = result.status === "unknown" ? "evidence_unknown"
    : result.mandatoryViolation ? "budget_reserve_permission_scope_violation"
    : result.outcome !== "passed" ? "goal_unmet" : null;
  return { taskId: result.taskId, status: result.status, outcome: result.outcome,
    credit: result.credit ? { ...result.credit } : null, reason };
}

export interface TaskFeedbackRow {
  task_id: TaskId; task_status: string; closure_reason: string | null;
  accepted_action_sequence: string; reconciled_action_sequence: string;
  result_json: unknown; result_hash: string | null;
}

/** A missing evaluation is absence of a grade, never evidence of zero credit. */
export function projectStoredTaskFeedback(row: TaskFeedbackRow): TaskFeedback {
  const evaluated = row.result_json !== null && row.result_json !== undefined;
  let feedback: TaskFeedback;
  if (evaluated) {
    const result = (typeof row.result_json === 'string' ? JSON.parse(row.result_json) : row.result_json) as TaskEvaluationResult;
    if (result.taskId !== row.task_id || sha256CanonicalTaskJson(result) !== row.result_hash) throw new Error('Task feedback identity or hash mismatch');
    feedback = projectTaskFeedback(result);
    if (feedback.reason === 'goal_unmet' && row.closure_reason === 'task_deadline') feedback.reason = 'time_exhausted';
  } else feedback = { taskId: row.task_id, status: 'unknown', outcome: 'unknown', credit: null,
    reason: row.task_status === 'queued' ? 'not_issued' : 'not_evaluated' };
  const closureReason = ['agent_finish','task_deadline','run_deadline'].includes(row.closure_reason ?? '')
    ? row.closure_reason as 'agent_finish'|'task_deadline'|'run_deadline' : null;
  feedback.diagnostic = {
    evaluationState: evaluated ? 'evaluated' : 'not_evaluated',
    taskState: ['queued','active','completed','failed','unknown'].includes(row.task_status) ? row.task_status : 'unknown',
    closureReason, acceptedActionCount: String(row.accepted_action_sequence), reconciledActionCount: String(row.reconciled_action_sequence),
    // Goal failure / deadline alone does not establish who caused it.
    attribution: feedback.status === 'unknown' ? evaluated ? 'evidence_unknown' : 'unknown'
      : feedback.outcome === 'passed' ? 'verified_outcome' : 'unknown',
  };
  return feedback;
}

/** Owner feedback remains a private read surface; it cannot accept grades. */
export async function getOwnerRunFeedback(db: OwnerDatabase, ownerId: string, runId: string): Promise<{
  status: "available" | "withheld_until_run_termination";
  tasks: TaskFeedback[];
}> {
  const runs = await db.execute(sql`SELECT mode,status FROM oid_benchmark_run WHERE id=${runId} AND owner_id=${ownerId}`) as unknown as Array<{ mode: string; status: string }>;
  const run = runs[0];
  if (!run) throw new HttpError(404, "RUN_NOT_FOUND", "The run does not exist for this owner");
  const terminal = ["completed", "failed", "unknown", "disqualified", "cancelled", "expired"].includes(run.status);
  if (run.mode === "ranked" && !terminal) return { status: "withheld_until_run_termination", tasks: [] };
  const rows = await db.execute(sql`SELECT t.task_id,t.status AS task_status,t.closure_reason,
      t.accepted_action_sequence::text,t.reconciled_action_sequence::text,e.result_json,e.result_hash
    FROM oid_run_task t LEFT JOIN oid_run_task_evaluation e ON e.run_id=t.run_id AND e.task_index=t.task_index
    WHERE t.run_id=${runId} ORDER BY t.task_index`) as unknown as TaskFeedbackRow[];
  const tasks: TaskFeedback[] = [];
  for (const row of rows) {
    if (run.mode === "training" && isClosedTrainingTask(row.task_id)) continue;
    if (!terminal && !row.result_json) continue;
    tasks.push(projectStoredTaskFeedback(row));
  }
  return { status: "available", tasks };
}
