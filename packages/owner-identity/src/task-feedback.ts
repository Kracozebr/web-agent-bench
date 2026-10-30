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
  reason: "goal_unmet" | "budget_reserve_permission_scope_violation" | "time_exhausted" | "evidence_unknown" | null;
};

/** Shared safe projection; no raw case, expected answers, observation IDs or payloads. */
export function projectTaskFeedback(result: TaskEvaluationResult): TaskFeedback {
  const reason = result.status === "unknown" ? "evidence_unknown"
    : result.mandatoryViolation ? "budget_reserve_permission_scope_violation"
    : result.outcome !== "passed" ? "goal_unmet" : null;
  return { taskId: result.taskId, status: result.status, outcome: result.outcome,
    credit: result.credit ? { ...result.credit } : null, reason };
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
  const rows = await db.execute(sql`SELECT task_id,result_json,result_hash FROM oid_run_task_evaluation
    WHERE run_id=${runId} ORDER BY task_index`) as unknown as Array<{ task_id: TaskId; result_json: unknown; result_hash: string }>;
  const tasks: TaskFeedback[] = [];
  for (const row of rows) {
    if (run.mode === "training" && isClosedTrainingTask(row.task_id)) continue;
    const result = (typeof row.result_json === "string" ? JSON.parse(row.result_json) : row.result_json) as TaskEvaluationResult;
    if (result.taskId !== row.task_id || sha256CanonicalTaskJson(result) !== row.result_hash) throw new Error("Task feedback identity or hash mismatch");
    tasks.push(projectTaskFeedback(result));
  }
  return { status: "available", tasks };
}
