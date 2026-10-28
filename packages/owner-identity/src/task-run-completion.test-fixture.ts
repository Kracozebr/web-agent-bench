import { createHash, randomUUID } from 'node:crypto';
import postgres from 'postgres';
import { evaluateTaskRubric, type EvaluateTaskInput } from './task-evaluator.js';
import { sha256CanonicalTaskJson, type TaskReleaseQuerySource } from './task-release.js';
import { TASK_IDS } from './task-catalog.js';
export const hash = (label: string) => createHash('sha256').update(label).digest('hex');
export const evidence = (label: string) => ({ path: `synthetic-completion/${label}.json`, sha256: hash(label),
  boundary: 'actual_tool_http_x402_local_evm_application_store' as const });
const OPEN_TRAINING_IDS = ['S1', 'S2', 'S4', 'M1', 'M3', 'M4', 'H1', 'H2'] as const;

function hashRunServicePayload(value: unknown): string {
  const canonical = (item: unknown): unknown => {
    if (Array.isArray(item)) return item.map(canonical);
    if (typeof item !== 'object' || item === null) return item;
    return Object.fromEntries(Object.entries(item as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, child]) => [key, canonical(child)]));
  };
  return createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex');
}

export type FixtureOptions = {
  includeEvaluation?: boolean;
  known?: boolean;
  fence?: boolean;
  openCutoff?: boolean;
  cancellationHistory?: boolean;
  failedOutcome?: boolean;
  overallDeadlinePast?: boolean;
  overallDeadlineSecondsFromNow?: number;
  multiTask?: boolean;
  unterminalPredecessor?: boolean;
  successorPreparationPolicyVersion?: string | null;
  successorPreparationTimeoutSeconds?: number | null;
  verifiedNativeReserveViolation?: boolean;
  contradictoryMandatoryViolationResult?: 'partial' | 'passed';
};

export async function addFixture(client: ReturnType<typeof postgres>, options: FixtureOptions = {}) {
  const userId = randomUUID(), ownerId = randomUUID(), agentId = randomUUID(), intentId = randomUUID();
  const runId = randomUUID(), claimId = randomUUID(), closureId = randomUUID(), grantId = randomUUID();
  const preparationId = randomUUID(), leaseId = randomUUID(), generationId = randomUUID();
  const releaseIdentity = `completion-${randomUUID()}`;
  const environmentId = `completion-env-${randomUUID().slice(0, 8)}`;
  const manifestHash = hash(`${runId}:manifest`), benchmarkHash = hash(`${runId}:benchmark`), policyHash = hash(`${runId}:policy`);
  const caseHash = hash(`${runId}:case`), rubricHash = hash(`${runId}:rubric`), executionIdentityHash = hash(`${runId}:execution`);
  const initialStateHash = hash(`${runId}:initial-state`), environmentManifestHash = hash(`${runId}:environment-manifest`);
  const applicationSourceHash = hash(`${runId}:application-source`), closurePayloadHash = hash(`${runId}:closure`);
  const recipient = '0x2222222222222222222222222222222222222222';
  const taskCase = {
    mode: 'training', taskId: 'S1', caseId: `${releaseIdentity}-S1`, caseHash, rubricHash, executionIdentityHash,
    initialState: { stateSha256: initialStateHash,
      balances: [{ account: recipient, assetId: 'USDC', amountUnits: '0' }, { account: 'participant', assetId: 'ETH', amountUnits: '1' }],
      allowances: [], deliveredComponentIds: [], fulfilledObligationIds: [] },
    objective: { tokenAssetId: 'USDC', sender: 'participant', recipient, exactPrincipalUnits: '1', nativeReserveWei: '1',
      unrelatedEffectBaselineSha256: hash(`${runId}:unrelated-baseline`) }, taskDeadlineSeconds: 120,
  };
  const taskIds = options.unterminalPredecessor ? ['S1', 'S2', 'S4'] : options.multiTask ? ['S1', 'S2'] : ['S1'];
  const additionalCases = taskIds.slice(1).map((taskId) => ({
    mode: 'training' as const, taskId, caseId: `${releaseIdentity}-${taskId}`, caseHash: hash(`${runId}:${taskId}:case`),
    rubricHash: hash(`${runId}:${taskId}:rubric`), executionIdentityHash,
    initialState: { stateSha256: hash(`${runId}:${taskId}:initial-state`) }, taskDeadlineSeconds: 120,
  }));
  const syntheticCase = (taskId: string, mode: 'training' | 'ranked') => {
    const selected = [taskCase, ...additionalCases].find((entry) => entry.taskId === taskId);
    if (selected && mode === 'training') return selected;
    return {
      mode, taskId, caseId: `${releaseIdentity}-${taskId}`, caseHash: hash(`${runId}:${taskId}:case`),
      rubricHash: hash(`${runId}:${taskId}:rubric`), executionIdentityHash,
      initialState: { stateSha256: hash(`${runId}:${taskId}:initial-state`) }, taskDeadlineSeconds: 120,
    };
  };
  const record = {
    releaseIdentity, manifestHash, benchmarkVersion: 'synthetic-completion-v1', benchmarkHash, policyHash,
    manifest: { releaseIdentity, manifestHash, executionIdentityHash,
      executionIdentity: { environmentManifestSha256: environmentManifestHash,
      x402ServiceSha256: applicationSourceHash }, costPolicy: {}, deadlines: { taskTimeoutSeconds: 180 },
      cases: { training: OPEN_TRAINING_IDS.map((taskId) => syntheticCase(taskId, 'training')),
        ranked: TASK_IDS.map((taskId) => syntheticCase(taskId, 'ranked')) } },
  };
  const binding = { ownerId, agentId, runId, environmentId, releaseIdentity, manifestHash,
    caseId: taskCase.caseId, caseHash, rubricHash, taskId: 'S1' };
  const captureEvidence = evidence(`${runId}-capture`);
  const fixtureEvidence = evidence(`${runId}-fixture`), baselineEvidence = evidence(`${runId}-baseline`);
  const fenceEvidence = evidence(`${runId}-fence`);
  const cutoff = options.openCutoff ? 'closing' : 'closed';
  const actionCutoff = 0;
  const startedAt = new Date(Date.now() - 60_000).toISOString();
  const deadlineOffsetSeconds = options.overallDeadlineSecondsFromNow ?? 60;
  if (!Number.isSafeInteger(deadlineOffsetSeconds) || deadlineOffsetSeconds < 1 || deadlineOffsetSeconds > 3600) {
    throw new Error('Synthetic fixture overall deadline offset must be an integer from 1 to 3600 seconds');
  }
  const overallDeadline = options.overallDeadlinePast
    ? new Date(Date.now() - 1_000).toISOString()
    : new Date(Date.now() + deadlineOffsetSeconds * 1000).toISOString();

  await client`INSERT INTO oid_auth_user(id,name,email,email_verified)
    VALUES(${userId},'Synthetic completion owner',${`${userId}@example.invalid`},true)`;
  await client`INSERT INTO oid_owner(id,auth_user_id,admission_status) VALUES(${ownerId},${userId},'admitted')`;
  await client`INSERT INTO oid_agent(id,owner_id,name) VALUES(${agentId},${ownerId},'Synthetic completion agent')`;
  await client`INSERT INTO oid_agent_policy(agent_id,training,ranked,revision) VALUES(${agentId},true,false,1)`;
  await client`INSERT INTO oid_run_launch_intent(id,owner_id,agent_id,operation_id,payload_hash,mode,task_ids,release_identity,
      benchmark_version,manifest_hash,benchmark_hash,policy_hash,quote_price_units,cash_ceiling_units,owner_policy_revision,agent_policy_revision,
      status,created_at,expires_at,accepted_at,successor_preparation_policy_version,successor_preparation_timeout_seconds)
    VALUES(${intentId},${ownerId},${agentId},${randomUUID()},${hash(`${runId}:intent`)},'training',${taskIds},${releaseIdentity},
      'synthetic-completion-v1',${manifestHash},${benchmarkHash},${policyHash},500000,500000,1,1,'accepted',clock_timestamp()-interval '3 hours',
      clock_timestamp()+interval '1 hour',clock_timestamp()-interval '2 hours',
      ${options.successorPreparationPolicyVersion ?? null},${options.successorPreparationTimeoutSeconds ?? null})`;
  await client`INSERT INTO oid_benchmark_run(id,intent_id,owner_id,agent_id,mode,task_ids,release_identity,benchmark_version,manifest_hash,
      benchmark_hash,policy_hash,quote_price_units,cash_ceiling_units,access_generation,agent_policy_revision,status,queued_at,queue_deadline,
      started_at,overall_deadline,environment_id,successor_preparation_policy_version,successor_preparation_timeout_seconds)
    VALUES(${runId},${intentId},${ownerId},${agentId},'training',${taskIds},${releaseIdentity},'synthetic-completion-v1',${manifestHash},
      ${benchmarkHash},${policyHash},500000,500000,1,1,'running',clock_timestamp()-interval '3 hours',clock_timestamp()-interval '2 hours',
      ${startedAt},${overallDeadline},${environmentId},${options.successorPreparationPolicyVersion ?? null},
      ${options.successorPreparationTimeoutSeconds ?? null})`;
  await client`INSERT INTO oid_run_reservation(id,run_id,owner_id,source_kind,cash_provenance,amount_units,state,created_at,changed_at)
    VALUES(${randomUUID()},${runId},${ownerId},'cash_usdc','synthetic-completion-fixture',500000,'debited',clock_timestamp(),clock_timestamp())`;
  await client`INSERT INTO oid_run_budget_hold(run_id,owner_id,agent_id,mode,utc_day,amount_units,state,created_at,changed_at)
    VALUES(${runId},${ownerId},${agentId},'training',to_char(clock_timestamp(),'YYYY-MM-DD'),500000,'charged',clock_timestamp(),clock_timestamp())`;
  await client`INSERT INTO oid_run_dispatch_claim(run_id,owner_id,agent_id,claim_id,turn_number,status,claimed_at)
    VALUES(${runId},${ownerId},${agentId},${claimId},1,'claimed',clock_timestamp()-interval '2 hours')`;
  await client`INSERT INTO oid_run_execution_slot(agent_id,owner_id,run_id,claim_id,state,acquired_at)
    VALUES(${agentId},${ownerId},${runId},${claimId},'running',clock_timestamp()-interval '2 hours')`;
  await client`INSERT INTO oid_run_task(run_id,task_index,task_id,status,started_at,deadline_at)
    VALUES(${runId},0,'S1','active',${startedAt},${overallDeadline})`;
  for (let index = 1; index < taskIds.length; index += 1) {
    const taskStatus = options.unterminalPredecessor && index === 1 ? 'active' : 'queued';
    await client`INSERT INTO oid_run_task(run_id,task_index,task_id,status)
      VALUES(${runId},${index},${taskIds[index]!},${taskStatus})`;
  }
  await client`INSERT INTO oid_run_task_closure(id,run_id,task_index,operation_id,payload_hash,reason,action_cutoff_sequence,
      actor_kind,owner_id,agent_id)
    VALUES(${closureId},${runId},0,NULL,${closurePayloadHash},'agent_finish',${actionCutoff},'coordinator',${ownerId},${agentId})`;
  await client`UPDATE oid_run_task SET closure_id=${closureId},closure_status=${cutoff},action_cutoff_sequence=${actionCutoff},
      closure_reason='agent_finish',closure_payload_hash=${closurePayloadHash},closed_at=${options.openCutoff ? null : new Date().toISOString()}
    WHERE run_id=${runId} AND task_index=0`;

  if (!options.openCutoff) {
    await client`INSERT INTO oid_task_preparation_intent(preparation_id,run_id,task_index,claim_id,lease_id,environment_id,
        release_identity,manifest_hash,task_id,case_id,case_hash,initial_state_sha256,execution_identity_hash,
        environment_manifest_sha256,application_source_hash)
      VALUES(${preparationId},${runId},0,${claimId},${leaseId},${environmentId},${releaseIdentity},${manifestHash},'S1',
        ${taskCase.caseId},${caseHash},${initialStateHash},${executionIdentityHash},${environmentManifestHash},${applicationSourceHash})`;
    await client`INSERT INTO oid_task_environment_lease(lease_id,preparation_id,environment_id,state)
      VALUES(${leaseId},${preparationId},${environmentId},'leased')`;
    await client`INSERT INTO oid_task_preparation_observation(preparation_id,revision,status)
      VALUES(${preparationId},1,'preparing')`;
    await client`INSERT INTO oid_task_preparation_observation(preparation_id,revision,status,generation_id,participant_id,payer_address,
        baseline_state_sha256,fixture_evidence,baseline_evidence)
      VALUES(${preparationId},2,'ready',${generationId},'synthetic-participant','0x1111111111111111111111111111111111111111',
        ${initialStateHash},${JSON.stringify(fixtureEvidence)}::jsonb,${JSON.stringify(baselineEvidence)}::jsonb)`;
    await client`INSERT INTO oid_task_execution_binding(run_id,task_index,env_id,generation_id,manifest_hash,application_source_hash,
        participant_id,payer_address)
      VALUES(${runId},0,${environmentId},${generationId},${environmentManifestHash},${applicationSourceHash},
        'synthetic-participant','0x1111111111111111111111111111111111111111')`;

    const readinessEvidenceHash = sha256CanonicalTaskJson({
      preparationId, leaseId, runId, taskIndex: 0, claimId, releaseIdentity, manifestHash,
      taskId: 'S1', caseId: taskCase.caseId, caseHash, initialStateSha256: initialStateHash,
      executionIdentityHash, environmentManifestSha256: environmentManifestHash,
      applicationSourceHash, generationId, baselineStateSha256: initialStateHash,
      fixtureEvidence, baselineEvidence,
    });
    const startEvent = {
      startedAt: new Date(startedAt).toISOString(), taskId: 'S1', taskDeadline: overallDeadline,
      overallDeadline, environmentId, readinessEvidenceHash,
    };
    await client`INSERT INTO oid_run_event(id,run_id,sequence,source,event_type,payload_hash,payload_json)
      VALUES(${randomUUID()},${runId},1,'coordinator','run.started',${hashRunServicePayload(startEvent)},${JSON.stringify(startEvent)}::jsonb)`;

    const hasVerifiedViolation = options.verifiedNativeReserveViolation === true;
    const isUnknown = options.known === false;
    const finalStateEvidence = evidence(`${runId}-final-state`);
    const observations = { schemaVersion: 'bts-task-observations/v1', binding, coveredThroughSequence: 1,
      captureEvidence, coverage: { transfers: 'complete', balances: isUnknown ? 'incomplete' as const : 'complete' as const },
      transfers: !options.failedOutcome && !hasVerifiedViolation && !isUnknown ? [{
        observationId: `${runId}-principal-transfer`, sequence: 1, actionSequence: 0, source: 'persisted_observer' as const,
        binding, evidence: evidence(`${runId}-principal-transfer`), kind: 'transfer' as const,
        from: 'participant', to: recipient, assetId: 'USDC', amountUnits: '1', receiptStatus: 'success' as const,
        transactionHash: `0x${hash(`${runId}:principal-tx`)}`, operation: 'principal' as const,
      }] : [], payments: [], stateMutations: [],
      finalStates: isUnknown ? [] : [{ observationId: `${runId}-final-state`, sequence: 1, actionSequence: 0,
        source: 'persisted_observer' as const, binding, evidence: finalStateEvidence, kind: 'final_state' as const,
        balances: [
          { account: recipient, assetId: 'USDC', amountUnits: options.failedOutcome || hasVerifiedViolation ? '0' : '1' },
          { account: 'participant', assetId: 'ETH', amountUnits: hasVerifiedViolation ? '0' : '1' },
        ], allowances: [],
      }], allowanceChanges: [], allowanceUses: [], answers: [], selections: [], deliveries: [], trades: [], conversions: [], expenses: [] };
    const bundle = { schemaVersion: 'bts-task-observation-bundle/v1', binding,
      closure: { closureId, operationId: null, payloadHash: closurePayloadHash, reason: 'agent_finish',
        actionCutoffSequence: actionCutoff, reconciledActionSequence: actionCutoff },
      execution: { preparationId, leaseId, generationId, environmentManifestHash, applicationSourceHash,
        executionIdentityHash, initialStateSha256: initialStateHash },
      cutoff: { observationSequence: 1, status: 'authoritative', evidence: captureEvidence }, observations };
    const bundleHash = sha256CanonicalTaskJson(bundle);
    await client`INSERT INTO oid_run_task_observation_bundle(run_id,task_index,owner_id,agent_id,closure_id,closure_operation_id,
        closure_payload_hash,closure_reason,task_id,release_identity,release_manifest_hash,case_id,case_hash,rubric_hash,environment_id,
        preparation_id,lease_id,generation_id,environment_manifest_hash,application_source_hash,execution_identity_hash,initial_state_sha256,
        action_cutoff_sequence,reconciled_action_sequence,observation_cutoff_sequence,cutoff_evidence,bundle_hash,bundle_json)
      VALUES(${runId},0,${ownerId},${agentId},${closureId},NULL,${closurePayloadHash},'agent_finish','S1',${releaseIdentity},${manifestHash},
        ${taskCase.caseId},${caseHash},${rubricHash},${environmentId},${preparationId},${leaseId},${generationId},
        ${environmentManifestHash},${applicationSourceHash},${executionIdentityHash},${initialStateHash},0,0,1,
        ${JSON.stringify(captureEvidence)}::jsonb,${bundleHash},${JSON.stringify(bundle)}::jsonb)`;
    if (options.fence !== false) {
      const fence = { confirmed: true, preparationId, leaseId, environmentId, generationId, evidence: fenceEvidence };
      await client`UPDATE oid_task_environment_lease SET state='fenced',fence_evidence=${JSON.stringify(fence)}::jsonb,
        fenced_at=clock_timestamp() WHERE lease_id=${leaseId}`;
      await client`INSERT INTO oid_task_preparation_observation(preparation_id,revision,status,generation_id,participant_id,payer_address,
          baseline_state_sha256,fixture_evidence,baseline_evidence)
        VALUES(${preparationId},3,'fenced',${generationId},'synthetic-participant','0x1111111111111111111111111111111111111111',
          ${initialStateHash},${JSON.stringify(fixtureEvidence)}::jsonb,${JSON.stringify(baselineEvidence)}::jsonb)`;
    }
    const runInput = { ...binding, acceptedActionCutoffSequence: 0, reconciledThroughActionSequence: 0,
      observationCutoffSequence: 1, cutoffStatus: 'authoritative', cutoffEvidence: captureEvidence };
    const evaluationInput = { taskCase, release: record.manifest, run: runInput, observations } as unknown as EvaluateTaskInput;
    let result: unknown = evaluateTaskRubric(evaluationInput);
    if (options.contradictoryMandatoryViolationResult) {
      if (!hasVerifiedViolation || !result || typeof result !== 'object' || Array.isArray(result) ||
          (result as { mandatoryViolation?: unknown }).mandatoryViolation === null) {
        throw new Error('Contradictory violation fixtures require a canonical native-reserve violation');
      }
      result = options.contradictoryMandatoryViolationResult === 'partial'
        ? { ...(result as Record<string, unknown>), outcome: 'partial', credit: { numerator: '1', denominator: '2' } }
        : { ...(result as Record<string, unknown>), outcome: 'passed', credit: { numerator: '1', denominator: '1' } };
    }
    if (options.includeEvaluation !== false) {
      const inputHash = sha256CanonicalTaskJson(evaluationInput), resultHash = sha256CanonicalTaskJson(result), evaluatorSourceHash = hash('synthetic-evaluator');
      const evalPayload = { taskIndex: 0, taskId: 'S1', closureId, releaseIdentity, manifestHash, inputHash, resultHash, evaluatorSourceHash };
      const evidenceReferences = [captureEvidence, evaluationInput.run.cutoffEvidence,
        ...observations.transfers.map((item) => item.evidence), ...observations.finalStates.map((item) => item.evidence)];
      const uniqueEvidenceReferences = [...new Map(evidenceReferences.map((reference) => [JSON.stringify(reference), reference])).values()];
      await client`INSERT INTO oid_run_task_evaluation(run_id,task_index,closure_id,task_id,release_identity,manifest_hash,case_hash,rubric_hash,
          input_hash,result_hash,evaluator_source_hash,observation_evidence,result_json,input_json)
        VALUES(${runId},0,${closureId},'S1',${releaseIdentity},${manifestHash},${caseHash},${rubricHash},${inputHash},${resultHash},
          ${evaluatorSourceHash},${JSON.stringify({ schemaVersion: 'bts-evaluation-evidence-manifest/v1', references: uniqueEvidenceReferences })}::jsonb,
          ${JSON.stringify(result)}::jsonb,${JSON.stringify(evaluationInput)}::jsonb)`;
      await client`INSERT INTO oid_run_event(id,run_id,sequence,source,event_type,payload_hash,payload_json)
        VALUES(${randomUUID()},${runId},2,'coordinator','task.evaluated',${sha256CanonicalTaskJson(evalPayload)},${JSON.stringify(evalPayload)}::jsonb)`;
    }
    if (options.cancellationHistory) {
      await client`INSERT INTO oid_run_mode_cancellation_outbox(event_id,owner_id,agent_id,mode,policy_revision)
        VALUES(${randomUUID()},${ownerId},${agentId},'training',2)`;
    }
    return { ownerId, agentId, runId, claimId, environmentId, closureId, preparationId, leaseId, generationId,
      overallDeadline, result, record, evaluationInput };
  }

  return { ownerId, agentId, runId, claimId, environmentId, closureId, preparationId, leaseId, generationId,
    overallDeadline, result: null, record, evaluationInput: null };
}

