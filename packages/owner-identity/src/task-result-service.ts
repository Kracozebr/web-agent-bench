import { sql } from "drizzle-orm";
import { createHash, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import type { OwnerDatabase } from "./db.js";
import { HttpError } from "./http-error.js";
import { evaluateTaskRubric, type EvaluateTaskInput, type TaskEvaluationResult } from "./task-evaluator.js";
import { canonicalTaskJson, sha256CanonicalTaskJson, type TaskReleaseQuerySource } from "./task-release.js";

type Transaction = Parameters<Parameters<OwnerDatabase["transaction"]>[0]>[0];

/** Internal authenticated observer port. Never populated from an agent HTTP body. */
export interface TaskEvaluationEvidenceSource {
  load(input: { runId: string; taskIndex: number; closureId: string }, tx: Transaction): Promise<EvaluateTaskInput | null>;
}

export interface TaskResultDependencies {
  db: OwnerDatabase;
  taskReleaseSource: TaskReleaseQuerySource;
  evidenceSource: TaskEvaluationEvidenceSource;
  evaluatorSourceHash: string;
}

/** Hash actual evaluator modules loaded by this runtime, including contract helpers. */
export async function getTaskEvaluatorBuildHash(): Promise<string> {
  const extension = import.meta.url.endsWith(".ts") ? "ts" : "js";
  const files = ["task-evaluator", "task-release", "task-catalog"];
  const digest = createHash("sha256");
  for (const file of files) {
    digest.update(`${file}.${extension}\n`);
    digest.update(await readFile(new URL(`./${file}.${extension}`, import.meta.url)));
  }
  return digest.digest("hex");
}

function evidenceManifest(input: EvaluateTaskInput) {
  const references = [input.run.cutoffEvidence, input.observations.captureEvidence];
  for (const value of Object.values(input.observations)) {
    if (Array.isArray(value)) for (const item of value) {
      if (item && typeof item === "object" && "evidence" in item) references.push(item.evidence);
    }
  }
  return { schemaVersion: "bts-evaluation-evidence-manifest/v1", references: [...new Map(references.map((ref) =>
    [canonicalTaskJson(ref), structuredClone(ref)])).values()] };
}

interface ClosureRow {
  owner_id: string; agent_id: string; task_id: string; release_identity: string;
  manifest_hash: string; benchmark_hash: string; benchmark_version: string; policy_hash: string;
  task_preparation_environment_id: string | null; execution_binding_environment_id: string | null;
  task_ids: string[]; mode: "training" | "ranked"; closure_id: string | null; closure_status: string;
  action_cutoff_sequence: string | number | null; reconciled_action_sequence: string | number;
  journal_cutoff_sequence: string | number | null;
}

export interface StoredTaskEvaluation {
  runId: string; taskIndex: number; closureId: string; inputHash: string; resultHash: string;
  evaluatorSourceHash: string; result: TaskEvaluationResult;
}

function validateTarget(runId: string, taskIndex: number): void {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(runId) ||
    !Number.isSafeInteger(taskIndex) || taskIndex < 0 || taskIndex > 11) {
    throw new HttpError(400, "INVALID_TASK_TARGET", "A run UUID and bounded task index are required");
  }
}

async function loadValidatedInput(deps: TaskResultDependencies, tx: Transaction, runId: string, taskIndex: number, lock = true) {
  const rows = await tx.execute(sql`SELECT r.owner_id,r.agent_id,r.release_identity,r.manifest_hash,
      r.benchmark_hash,r.benchmark_version,r.policy_hash,r.task_ids,r.mode,t.task_id,t.closure_id,t.closure_status,
      t.action_cutoff_sequence,t.reconciled_action_sequence,c.action_cutoff_sequence AS journal_cutoff_sequence,
      i.environment_id AS task_preparation_environment_id,eb.env_id AS execution_binding_environment_id
    FROM oid_benchmark_run r JOIN oid_run_task t ON t.run_id=r.id
    LEFT JOIN oid_task_preparation_intent i ON i.run_id=r.id AND i.task_index=t.task_index
    LEFT JOIN oid_task_execution_binding eb ON eb.run_id=r.id AND eb.task_index=t.task_index
    LEFT JOIN oid_run_task_closure c ON c.id=t.closure_id AND c.run_id=r.id AND c.task_index=t.task_index
    WHERE r.id=${runId} AND t.task_index=${taskIndex} ${lock ? sql`FOR UPDATE OF r,t` : sql``}`) as unknown as ClosureRow[];
  const row = rows[0];
  if (!row) throw new HttpError(404, "TASK_NOT_FOUND", "The task does not exist");
  if (row.closure_status !== "closed" || !row.closure_id || row.action_cutoff_sequence === null ||
    row.journal_cutoff_sequence === null || BigInt(row.journal_cutoff_sequence) !== BigInt(row.action_cutoff_sequence) ||
    BigInt(row.reconciled_action_sequence) < BigInt(row.action_cutoff_sequence)) {
    throw new HttpError(409, "TASK_RECONCILIATION_PENDING", "Task actions must be fenced and reconciled before evaluation");
  }
  const record = await deps.taskReleaseSource.getValidatedReleaseRecord(row.release_identity, row.manifest_hash, tx);
  if (!record || record.releaseIdentity !== row.release_identity || record.manifestHash !== row.manifest_hash ||
    record.benchmarkHash !== row.benchmark_hash || record.benchmarkVersion !== row.benchmark_version || record.policyHash !== row.policy_hash) {
    throw new HttpError(503, "PINNED_RELEASE_UNAVAILABLE", "The admitted release cannot be verified");
  }
  const taskCase = record.manifest.cases[row.mode].find((entry) => entry.taskId === row.task_id);
  if (!taskCase || row.task_ids[taskIndex] !== row.task_id) throw new HttpError(503, "PINNED_CASE_UNAVAILABLE", "The admitted task cannot be verified");
  const input = await deps.evidenceSource.load({ runId, taskIndex, closureId: row.closure_id }, tx);
  if (!input) throw new HttpError(503, "TASK_EVIDENCE_UNAVAILABLE", "Authoritative task observations are unavailable");
  const binding = input.run;
  if (binding.ownerId !== row.owner_id || binding.agentId !== row.agent_id || binding.runId !== runId ||
    !row.task_preparation_environment_id || !row.execution_binding_environment_id ||
    binding.environmentId !== row.task_preparation_environment_id || binding.environmentId !== row.execution_binding_environment_id ||
    binding.releaseIdentity !== record.releaseIdentity || binding.manifestHash !== record.manifestHash ||
    binding.caseId !== taskCase.caseId || binding.caseHash !== taskCase.caseHash || binding.rubricHash !== taskCase.rubricHash || binding.taskId !== row.task_id ||
    !Number.isSafeInteger(binding.acceptedActionCutoffSequence) || !Number.isSafeInteger(binding.reconciledThroughActionSequence) ||
    BigInt(binding.acceptedActionCutoffSequence) !== BigInt(row.action_cutoff_sequence) ||
    BigInt(binding.reconciledThroughActionSequence) !== BigInt(row.reconciled_action_sequence)) {
    throw new HttpError(409, "TASK_EVIDENCE_BINDING_MISMATCH", "Observed effects do not match the persisted task closure");
  }
  // AICODE-NOTE: The observer supplies evidence, not the rubric or thresholds; always reload these from the immutable admitted release.
  const trusted: EvaluateTaskInput = { taskCase, release: record.manifest, run: binding, observations: input.observations };
  return { input: trusted, closureId: row.closure_id, taskCase, inputHash: sha256CanonicalTaskJson(trusted) };
}

function stored(row: { closure_id: string; input_hash: string; result_hash: string; evaluator_source_hash: string; result_json: unknown }, runId: string, taskIndex: number): StoredTaskEvaluation {
  const result = (typeof row.result_json === "string" ? JSON.parse(row.result_json) : row.result_json) as TaskEvaluationResult;
  if (sha256CanonicalTaskJson(result) !== row.result_hash) throw new Error("Persisted task result hash mismatch");
  return { runId, taskIndex, closureId: row.closure_id, inputHash: row.input_hash, resultHash: row.result_hash,
    evaluatorSourceHash: row.evaluator_source_hash, result };
}

/** Records one immutable evaluation; it neither completes a run nor publishes a score. */
export async function recordTaskEvaluation(deps: TaskResultDependencies, target: { runId: string; taskIndex: number }): Promise<{ evaluation: StoredTaskEvaluation; replayed: boolean }> {
  validateTarget(target.runId, target.taskIndex);
  if (!/^[0-9a-f]{64}$/.test(deps.evaluatorSourceHash)) throw new Error("The evaluator source digest is required");
  if (await getTaskEvaluatorBuildHash() !== deps.evaluatorSourceHash) throw new HttpError(409, "EVALUATOR_BUILD_MISMATCH", "The pinned evaluator digest does not match this runtime");
  return deps.db.transaction(async (tx) => {
    const loaded = await loadValidatedInput(deps, tx, target.runId, target.taskIndex);
    const result = evaluateTaskRubric(loaded.input);
    const resultHash = sha256CanonicalTaskJson(result);
    const prior = await tx.execute(sql`SELECT closure_id,input_hash,result_hash,evaluator_source_hash,result_json
      FROM oid_run_task_evaluation WHERE run_id=${target.runId} AND task_index=${target.taskIndex}`) as unknown as Array<{
        closure_id: string; input_hash: string; result_hash: string; evaluator_source_hash: string; result_json: unknown;
      }>;
    if (prior[0]) {
      if (prior[0].closure_id !== loaded.closureId || prior[0].input_hash !== loaded.inputHash || prior[0].result_hash !== resultHash ||
        prior[0].evaluator_source_hash !== deps.evaluatorSourceHash) {
        throw new HttpError(409, "TASK_EVALUATION_CONFLICT", "An immutable task evaluation exists; use read-only reconstruction");
      }
      return { evaluation: stored(prior[0], target.runId, target.taskIndex), replayed: true };
    }
    await tx.execute(sql`INSERT INTO oid_run_task_evaluation(run_id,task_index,closure_id,task_id,release_identity,manifest_hash,
      case_hash,rubric_hash,input_hash,result_hash,evaluator_source_hash,observation_evidence,result_json,input_json)
      VALUES (${target.runId},${target.taskIndex},${loaded.closureId},${loaded.taskCase.taskId},${loaded.input.release.releaseIdentity},
      ${loaded.input.release.manifestHash},${loaded.taskCase.caseHash},${loaded.taskCase.rubricHash},${loaded.inputHash},${resultHash},
      ${deps.evaluatorSourceHash},${canonicalTaskJson(evidenceManifest(loaded.input))}::jsonb,
      ${canonicalTaskJson(result)}::jsonb,${canonicalTaskJson(loaded.input)}::jsonb)`);
    // AICODE-NOTE: The run lock above serializes this event with action/closure events.
    // Only the first immutable result emits it; audit replay never republishes a result.
    const payload = { taskIndex: target.taskIndex, taskId: loaded.taskCase.taskId,
      closureId: loaded.closureId, releaseIdentity: loaded.input.release.releaseIdentity,
      manifestHash: loaded.input.release.manifestHash, inputHash: loaded.inputHash,
      resultHash, evaluatorSourceHash: deps.evaluatorSourceHash };
    await tx.execute(sql`INSERT INTO oid_run_event(id,run_id,sequence,source,event_type,payload_hash,payload_json)
      SELECT ${randomUUID()},${target.runId},COALESCE(MAX(sequence),0)+1,'coordinator','task.evaluated',
        ${sha256CanonicalTaskJson(payload)},${canonicalTaskJson(payload)}::jsonb
      FROM oid_run_event WHERE run_id=${target.runId}`);
    return { evaluation: { ...target, closureId: loaded.closureId, inputHash: loaded.inputHash, resultHash,
      evaluatorSourceHash: deps.evaluatorSourceHash, result }, replayed: false };
  });
}

/** Internal audit port. Retained observations are never part of owner/agent feedback. */
export async function readRetainedTaskEvaluationInput(
  db: OwnerDatabase, target: { runId: string; taskIndex: number },
): Promise<{ input: EvaluateTaskInput; inputHash: string; closureId: string }> {
  validateTarget(target.runId, target.taskIndex);
  const rows = await db.execute(sql`SELECT closure_id,input_hash,input_json FROM oid_run_task_evaluation
    WHERE run_id=${target.runId} AND task_index=${target.taskIndex}`) as unknown as Array<{
      closure_id: string; input_hash: string; input_json: EvaluateTaskInput | string | null;
    }>;
  const row = rows[0];
  if (!row) throw new HttpError(404, "TASK_EVALUATION_NOT_FOUND", "No retained evaluation exists");
  if (row.input_json === null) throw new HttpError(503, "TASK_EVALUATION_INPUT_UNAVAILABLE", "The original evaluation input was not retained");
  const input = typeof row.input_json === "string" ? JSON.parse(row.input_json) as EvaluateTaskInput : row.input_json;
  if (sha256CanonicalTaskJson(input) !== row.input_hash) {
    throw new HttpError(409, "TASK_EVALUATION_INPUT_HASH_MISMATCH", "Retained observations do not match the original evaluation input hash");
  }
  return { input, inputHash: row.input_hash, closureId: row.closure_id };
}

/** Replay the original retained input even when the live observer is unavailable. */
export async function reconstructRetainedTaskEvaluation(db: OwnerDatabase, target: { runId: string; taskIndex: number }) {
  const retained = await readRetainedTaskEvaluationInput(db, target);
  const rows = await db.execute(sql`SELECT closure_id,input_hash,result_hash,evaluator_source_hash,result_json
    FROM oid_run_task_evaluation WHERE run_id=${target.runId} AND task_index=${target.taskIndex}`) as unknown as Array<{
      closure_id: string; input_hash: string; result_hash: string; evaluator_source_hash: string; result_json: unknown;
    }>;
  const original = stored(rows[0]!, target.runId, target.taskIndex);
  const reconstruction = evaluateTaskRubric(retained.input);
  const actualEvaluatorHash = await getTaskEvaluatorBuildHash();
  return { original, reconstruction, diverged: original.closureId !== retained.closureId ||
    original.inputHash !== retained.inputHash || original.resultHash !== sha256CanonicalTaskJson(reconstruction) ||
    original.evaluatorSourceHash !== actualEvaluatorHash, inputSource: "immutable_retained_input" as const };
}

/** Re-evaluates current observer evidence and reports drift from the original immutable result. */
export async function reconstructTaskEvaluation(deps: TaskResultDependencies, target: { runId: string; taskIndex: number }) {
  validateTarget(target.runId, target.taskIndex);
  const actualEvaluatorHash = await getTaskEvaluatorBuildHash();
  return deps.db.transaction(async (tx) => {
    await tx.execute(sql`SET TRANSACTION READ ONLY`);
    // Read-only reconstruction uses plain snapshots; no FOR UPDATE or action replay.
    const prior = await tx.execute(sql`SELECT closure_id,input_hash,result_hash,evaluator_source_hash,result_json
      FROM oid_run_task_evaluation WHERE run_id=${target.runId} AND task_index=${target.taskIndex}`) as unknown as Array<{
        closure_id: string; input_hash: string; result_hash: string; evaluator_source_hash: string; result_json: unknown;
      }>;
    if (!prior[0]) throw new HttpError(404, "TASK_EVALUATION_NOT_FOUND", "No retained evaluation exists");
    const original = stored(prior[0], target.runId, target.taskIndex);
    const loaded = await loadValidatedInput(deps, tx, target.runId, target.taskIndex, false);
    const reconstruction = evaluateTaskRubric(loaded.input);
    return { original, reconstruction, diverged: original.closureId !== loaded.closureId || original.inputHash !== loaded.inputHash ||
      original.resultHash !== sha256CanonicalTaskJson(reconstruction) || original.evaluatorSourceHash !== actualEvaluatorHash,
      reason: null };
  });
}
