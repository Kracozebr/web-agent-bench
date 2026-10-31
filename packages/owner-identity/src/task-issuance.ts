import { sql } from "drizzle-orm";
import type { AgentPrincipal } from "./agents.js";
import type { OwnerDatabase } from "./db.js";
import { HttpError } from "./http-error.js";
import type { DataComponentValidator, TaskCase, TaskReleaseManifest, TaskReleaseQuerySource } from "./task-release.js";
import { getTaskExecutionContext } from "./task-execution-binding.js";
import { z } from "zod";
import { TaskFinishAnswerSchemas } from "./task-action-service.js";

export function issuedTaskAnswerContract(taskId: string): Record<string, unknown> {
  const schema = taskId === 'S2' ? TaskFinishAnswerSchemas.S2 : taskId === 'S3' ? TaskFinishAnswerSchemas.S3 : null;
  return schema ? { acceptsStructuredAnswer: true, answerOptional: true, schema: z.toJSONSchema(schema) }
    : { acceptsStructuredAnswer: false, answerOptional: true, instruction: 'Omit answer; grading observes admitted task effects.' };
}

const componentInstruction = (component: { componentId: string; resourceId: string; sourceIds: string[]; validator: DataComponentValidator }) => ({
  componentId: component.componentId, resourceId: component.resourceId, sourceIds: [...component.sourceIds],
  validator: structuredClone(component.validator),
});

/** Only the active scoped agent receives a case. Reference paths stay internal. */
export function issuedTaskConditions(task: TaskCase,
  protocol: TaskReleaseManifest['participantToolProtocol'] = 'combined_purchase_v1'): Record<string, unknown> {
  switch (task.taskId) {
    case "S1": return { tokenAssetId: task.objective.tokenAssetId, sender: "participant",
      recipient: task.objective.recipient, exactPrincipalUnits: task.objective.exactPrincipalUnits,
      nativeReserveWei: task.objective.nativeReserveWei };
    case "S2": return { resourceId: task.objective.resourceId, offerId: task.objective.offerId,
      requiredAnswerFields: [...task.objective.requiredAnswerFields] };
    case "S3": return { required: structuredClone(task.objective.required) };
    case "S4": return { tokenAssetId: task.objective.tokenAssetId, owner: "participant", spender: task.objective.spender };
    case "M1": return protocol === 'separate_payment_delivery_v2' ? {
      component: componentInstruction(task.objective.component),
      paymentScope: { scheme: task.objective.paymentRequirements.scheme, network: task.objective.paymentRequirements.network,
        assetId: task.objective.paymentRequirements.assetId, recipient: task.objective.paymentRequirements.recipient,
        offerId: task.objective.paymentRequirements.offerId, termsSource: 'inspect_offer_or_catalog' },
      expenseBudgetUsdcUnits: task.objective.expenseBudgetUsdcUnits,
    } : { component: componentInstruction(task.objective.component),
      paymentRequirements: structuredClone(task.objective.paymentRequirements),
      expenseBudgetUsdcUnits: task.objective.expenseBudgetUsdcUnits };
    case "M2": return { required: structuredClone(task.objective.required), expenseBudgetUsdcUnits: task.objective.expenseBudgetUsdcUnits,
      tiePolicy: task.objective.tiePolicy };
    case "M3": return { ...structuredClone(task.objective) };
    case "M4": return { ...structuredClone(task.objective) };
    case "H1": return { requiredComponents: task.objective.requiredComponents.map(componentInstruction),
      permittedSources: [...task.objective.permittedSources], expenseBudgetUsdcUnits: task.objective.expenseBudgetUsdcUnits };
    case "H2": return { ...structuredClone(task.objective) };
    case "H3": return { referenceComponent: componentInstruction(task.objective.referenceComponent),
      routeObjective: { referenceField: task.objective.routeObjective.referenceField,
        allowedRouteIds: [...task.objective.routeObjective.allowedRouteIds],
        expectedRouteByValue: structuredClone(task.objective.routeObjective.expectedRouteByValue) },
      inputAssetId: task.objective.inputAssetId, exactInputUnits: task.objective.exactInputUnits,
      permittedRoutes: structuredClone(task.objective.permittedRoutes), minimumOutputUnits: task.objective.minimumOutputUnits,
      nativeReserveWei: task.objective.nativeReserveWei, combinedExpenseBudgetUsdcUnits: task.objective.combinedExpenseBudgetUsdcUnits };
    case "U1": return { requiredComponents: task.objective.requiredComponents.map(componentInstruction),
      permittedSources: [...task.objective.permittedSources], permittedRoutes: structuredClone(task.objective.permittedRoutes),
      allocationAssets: structuredClone(task.objective.allocationAssets), payoutObligations: structuredClone(task.objective.payoutObligations),
      temporarySpenderScope: structuredClone(task.objective.temporarySpenderScope),
      nativeReserveWei: task.objective.nativeReserveWei, expenseBudgetUsdcUnits: task.objective.expenseBudgetUsdcUnits };
  }
}

export interface CurrentTaskDependencies {
  db: OwnerDatabase;
  taskReleaseSource: TaskReleaseQuerySource;
}

export interface IssuedTask {
  runId: string;
  taskIndex: number;
  taskId: string;
  caseHash: string;
  releaseIdentity: string;
  manifestHash: string;
  mode: "training" | "ranked";
  participantToolProtocol: NonNullable<TaskReleaseManifest['participantToolProtocol']>;
  mandatoryRules: string[];
  conditions: Record<string, unknown>;
  answerContract: Record<string, unknown>;
  costPolicy: TaskReleaseManifest["costPolicy"];
  execution: Pick<TaskReleaseManifest["executionIdentity"], "localChainId" | "localNetwork" | "assets" | "contracts">;
  startedAt: string;
  deadlineAt: string;
  overallDeadline: string;
  environmentId: string;
  environmentEvidenceHash: string;
}

/**
 * A fresh database permission check is necessary for long-lived MCP sessions.
 * Owner row locking serializes disclosure with revocation/policy changes.
 */
export async function getCurrentAgentTask(
  deps: CurrentTaskDependencies, principal: AgentPrincipal, runId: string,
): Promise<{ task: IssuedTask | null }> {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(runId)) {
    throw new HttpError(400, "INVALID_RUNID", "runId must be a UUID");
  }
  return deps.db.transaction(async (tx) => {
    await tx.execute(sql`SELECT id FROM oid_owner WHERE id=${principal.ownerId} FOR NO KEY UPDATE`);
    const agents = await tx.execute(sql`SELECT id FROM oid_agent WHERE id=${principal.agentId}
      AND owner_id=${principal.ownerId} FOR NO KEY UPDATE`) as unknown as Array<{ id: string }>;
    if (!agents.length) throw new HttpError(403, "AGENT_ACCESS_REVOKED", "Current agent access is required");
    const grants = await tx.execute(sql`SELECT a.access_generation,a.access_revoked_at,o.admission_status,p.training,p.ranked
      FROM oid_agent a JOIN oid_owner o ON o.id=a.owner_id JOIN oid_agent_policy p ON p.agent_id=a.id
      JOIN oid_agent_access_grant g ON g.agent_id=a.id AND g.owner_id=a.owner_id
      WHERE a.id=${principal.agentId} AND a.owner_id=${principal.ownerId}
        AND g.id=${principal.grantId} AND g.revoked_at IS NULL AND g.expires_at>clock_timestamp()
        AND g.role='agent' AND g.resource=${principal.resource} AND g.access_generation=a.access_generation`) as unknown as Array<{
        access_generation: number; access_revoked_at: unknown; admission_status: string; training: boolean; ranked: boolean;
      }>;
    const grant = grants[0];
    if (!grant || grant.access_revoked_at || grant.access_generation !== principal.accessGeneration || grant.admission_status !== "admitted") {
      throw new HttpError(403, "AGENT_ACCESS_REVOKED", "Current agent access is required");
    }
    const runs = await tx.execute(sql`SELECT release_identity,manifest_hash,benchmark_version,benchmark_hash,policy_hash,task_ids,
      mode,status,overall_deadline,
      EXISTS(SELECT 1 FROM oid_run_mode_cancellation_outbox c WHERE c.owner_id=oid_benchmark_run.owner_id
        AND c.agent_id=oid_benchmark_run.agent_id AND c.mode=oid_benchmark_run.mode
        AND c.policy_revision>oid_benchmark_run.agent_policy_revision) AS mode_fenced,
      overall_deadline>clock_timestamp() AS within_deadline
      FROM oid_benchmark_run WHERE id=${runId} AND owner_id=${principal.ownerId} AND agent_id=${principal.agentId}
        AND access_generation=${principal.accessGeneration} FOR UPDATE`) as unknown as Array<{
          release_identity: string; manifest_hash: string; mode: "training" | "ranked"; status: string;
          overall_deadline: Date | string | null; within_deadline: boolean;
          benchmark_version: string; benchmark_hash: string; policy_hash: string; task_ids: string[];
          mode_fenced: boolean;
        }>;
    const run = runs[0];
    if (!run) throw new HttpError(404, "RUN_NOT_FOUND", "The run does not exist for this agent");
    if (!(run.mode === "training" ? grant.training : grant.ranked)) throw new HttpError(403, "MODE_NOT_ALLOWED", "Current mode permission is required");
    if (run.status !== "running" || !run.within_deadline || run.mode_fenced) return { task: null };
    const tasks = await tx.execute(sql`SELECT task_index,task_id,started_at,deadline_at FROM oid_run_task
      WHERE run_id=${runId} AND status='active' AND closure_status='open' AND deadline_at>clock_timestamp() ORDER BY task_index FOR UPDATE`) as unknown as Array<{
        task_index: number; task_id: string; started_at: Date | string; deadline_at: Date | string;
      }>;
    if (tasks.length !== 1) return { task: null };
    const active = tasks[0]!;
    const release = await deps.taskReleaseSource.getValidatedReleaseRecord(run.release_identity, run.manifest_hash, tx);
    if (!release || release.releaseIdentity !== run.release_identity || release.manifestHash !== run.manifest_hash ||
      release.benchmarkVersion !== run.benchmark_version || release.benchmarkHash !== run.benchmark_hash || release.policyHash !== run.policy_hash) {
      throw new HttpError(503, "PINNED_RELEASE_UNAVAILABLE", "The admitted release cannot be verified");
    }
    const task = release.manifest.cases[run.mode].find((candidate) => candidate.taskId === active.task_id);
    const execution = await getTaskExecutionContext(tx, { runId, taskIndex: active.task_index }, { requireActive: true });
    if (!task || run.task_ids[active.task_index] !== active.task_id || !execution ||
      execution.taskId !== active.task_id || execution.releaseIdentity !== run.release_identity ||
      execution.releaseManifestHash !== run.manifest_hash || execution.caseId !== task.caseId ||
      execution.caseHash !== task.caseHash || execution.executionIdentityHash !== task.executionIdentityHash ||
      execution.initialStateSha256 !== task.initialState.stateSha256 ||
      execution.environmentManifestSha256.toLowerCase() !== release.manifest.executionIdentity.environmentManifestSha256.toLowerCase() ||
      execution.applicationSourceHash.toLowerCase() !== release.manifest.executionIdentity.x402ServiceSha256.toLowerCase()) {
      throw new HttpError(503, "PINNED_CASE_UNAVAILABLE", "The active task case cannot be verified");
    }
    const fresh = await tx.execute(sql`SELECT clock_timestamp()<LEAST(${new Date(active.deadline_at).toISOString()}::timestamptz,
      ${new Date(run.overall_deadline!).toISOString()}::timestamptz) AND EXISTS(
        SELECT 1 FROM oid_agent_access_grant WHERE id=${principal.grantId} AND revoked_at IS NULL AND expires_at>clock_timestamp()
      ) AS valid`) as unknown as Array<{ valid: boolean }>;
    if (!fresh[0]?.valid) return { task: null };
    // AICODE-NOTE: Never spread a sealed case into an agent response: it includes reference-path and initial-state evidence.
    return { task: {
      runId, taskIndex: active.task_index, taskId: task.taskId, caseHash: task.caseHash,
      releaseIdentity: run.release_identity, manifestHash: run.manifest_hash, mode: run.mode,
      participantToolProtocol: release.manifest.participantToolProtocol ?? 'combined_purchase_v1',
      mandatoryRules: [...task.mandatoryRules], conditions: issuedTaskConditions(task, release.manifest.participantToolProtocol),
      answerContract: issuedTaskAnswerContract(task.taskId),
      costPolicy: structuredClone(release.manifest.costPolicy),
      execution: { localChainId: release.manifest.executionIdentity.localChainId,
        localNetwork: release.manifest.executionIdentity.localNetwork,
        assets: structuredClone(release.manifest.executionIdentity.assets), contracts: structuredClone(release.manifest.executionIdentity.contracts) },
      startedAt: new Date(active.started_at).toISOString(), deadlineAt: new Date(active.deadline_at).toISOString(),
      overallDeadline: new Date(run.overall_deadline!).toISOString(),
      environmentId: execution.envId, environmentEvidenceHash: execution.environmentEvidenceHash,
    } };
  });
}
