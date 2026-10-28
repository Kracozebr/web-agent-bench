import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import pg from "pg";

const hash = (value) => createHash("sha256").update(value).digest("hex");
const evidence = (name) => ({ path: `synthetic-result/${name}.json`, sha256: hash(name), boundary: "actual_tool_http_x402_local_evm_application_store" });

// Synthetic immutable-release/observation ports, actual service/PostgreSQL.
// No product API, executor or activated release points at these fixtures.
export async function runTaskResultCases({ databaseUrl, observerDatabaseUrl }) {
  assert.match(new URL(databaseUrl).pathname, /^\/oid_acceptance_[a-f0-9]{32}$/);
  const [{ createDatabase }, { loadConfig }, service, feedback] = await Promise.all([
    import("../../owner-identity/dist/db.js"), import("../../owner-identity/dist/config.js"), import("../../owner-identity/dist/task-result-service.js"),
    import("../../owner-identity/dist/task-feedback.js"),
  ]);
  const setup = new pg.Pool({ connectionString: databaseUrl, max: 2 });
  const observer = new pg.Pool({ connectionString: observerDatabaseUrl, max: 1 });
  const { db, client } = createDatabase(loadConfig({ ...process.env, OID_DATABASE_URL: databaseUrl }));
  const ownerId = randomUUID(), agentId = randomUUID(), userId = randomUUID(), runId = randomUUID(), intentId = randomUUID(), closureId = randomUUID();
  const preparationId = randomUUID(), leaseId = randomUUID(), generationId = randomUUID(), claimId = randomUUID();
  const releaseIdentity = "synthetic-result-release", manifestHash = hash("synthetic-result-manifest");
  const requirements = { scheme: "exact", resourceId: "synthetic-resource", offerId: "synthetic-offer", version: "v2", amountUnits: "100",
    network: "eip155:8453", assetId: "USDC", recipient: "0x1111111111111111111111111111111111111111", authFields: [] };
  const taskCase = { taskId: "S2", caseId: "synthetic-result-S2", caseHash: hash("synthetic-case"), rubricHash: hash("synthetic-rubric"),
    mandatoryRules: ["no_payment", "no_paid_delivery", "no_state_mutation", "authoritative_no_effect_interval"],
    objective: { resourceId: requirements.resourceId, offerId: requirements.offerId, completePaymentRequirements: requirements,
      requiredAnswerFields: ["amountUnits", "network", "assetId", "recipient", "scheme", "resourceId", "offerId", "version"] } };
  const binding = { ownerId, agentId, runId, environmentId: "synthetic-result-env", releaseIdentity, manifestHash,
    caseId: taskCase.caseId, caseHash: taskCase.caseHash, rubricHash: taskCase.rubricHash, taskId: "S2" };
  const input = {
    taskCase, release: { releaseIdentity, manifestHash, executionIdentity: { contracts: [] }, costPolicy: {} },
    run: { ...binding, acceptedActionCutoffSequence: 0, reconciledThroughActionSequence: 0, observationCutoffSequence: 1,
      cutoffStatus: "authoritative", cutoffEvidence: evidence("cutoff") },
    observations: { schemaVersion: "bts-task-observations/v1", binding, coveredThroughSequence: 1, captureEvidence: evidence("capture"),
      coverage: Object.fromEntries(["transfers", "payments", "stateMutations", "balances", "allowances", "answers", "selections", "deliveries", "trades", "conversions", "expenses"].map((name) => [name, "complete"])),
      transfers: [], payments: [], stateMutations: [], finalStates: [], allowanceChanges: [], allowanceUses: [], selections: [], deliveries: [], trades: [], conversions: [], expenses: [],
      answers: [{ kind: "final_answer", observationId: "synthetic-answer", sequence: 1, actionSequence: 0, source: "persisted_observer", binding,
        evidence: evidence("answer"), answer: structuredClone(requirements) }] },
  };
  const manifest = { ...input.release, cases: { training: [], ranked: [taskCase] } };
  const record = { releaseIdentity, manifestHash, benchmarkVersion: "synthetic-result-v1", benchmarkHash: hash("benchmark"), policyHash: hash("policy"), manifest };
  const deps = { db, evaluatorSourceHash: await service.getTaskEvaluatorBuildHash(),
    taskReleaseSource: { async getValidatedReleaseRecord() { return record; } },
    evidenceSource: { async load() { return structuredClone(input); } } };
  const target = { runId, taskIndex: 0 };
  try {
    const role = (await observer.query("SELECT current_user AS role,current_setting('transaction_read_only') AS readonly")).rows[0];
    assert.deepEqual(role, { role: "oid_observer", readonly: "on" });
    await setup.query("INSERT INTO oid_auth_user(id,name,email,email_verified) VALUES($1,'Synthetic evaluation owner',$2,true)", [userId, `${userId}@example.invalid`]);
    await setup.query("INSERT INTO oid_owner(id,auth_user_id,admission_status) VALUES($1,$2,'admitted')", [ownerId, userId]);
    await setup.query("INSERT INTO oid_agent(id,owner_id,name) VALUES($1,$2,'Synthetic evaluation agent')", [agentId, ownerId]);
    await setup.query(`INSERT INTO oid_run_launch_intent(id,owner_id,agent_id,operation_id,payload_hash,mode,task_ids,release_identity,
      benchmark_version,manifest_hash,benchmark_hash,policy_hash,quote_price_units,cash_ceiling_units,owner_policy_revision,agent_policy_revision,expires_at)
      VALUES($1,$2,$3,$4,$5,'ranked',ARRAY['S2'],$6,$7,$8,$9,$10,0,0,1,1,clock_timestamp()+interval '1 hour')`,
    [intentId, ownerId, agentId, randomUUID(), hash("intent"), releaseIdentity, record.benchmarkVersion, manifestHash, record.benchmarkHash, record.policyHash]);
    await setup.query(`INSERT INTO oid_benchmark_run(id,intent_id,owner_id,agent_id,mode,task_ids,release_identity,benchmark_version,
      manifest_hash,benchmark_hash,policy_hash,quote_price_units,cash_ceiling_units,access_generation,agent_policy_revision,status,queue_deadline,environment_id)
      VALUES($1,$2,$3,$4,'ranked',ARRAY['S2'],$5,$6,$7,$8,$9,0,0,1,1,'running',clock_timestamp()+interval '1 hour',$10)`,
    [runId, intentId, ownerId, agentId, releaseIdentity, record.benchmarkVersion, manifestHash, record.benchmarkHash, record.policyHash, binding.environmentId]);
    await setup.query("INSERT INTO oid_run_task(run_id,task_index,task_id,status) VALUES($1,0,'S2','active')", [runId]);
    await setup.query(`INSERT INTO oid_task_preparation_intent(preparation_id,run_id,task_index,claim_id,lease_id,environment_id,
      release_identity,manifest_hash,task_id,case_id,case_hash,initial_state_sha256,execution_identity_hash,
      environment_manifest_sha256,application_source_hash)
      VALUES($1,$2,0,$3,$4,$5,$6,$7,'S2',$8,$9,$10,$11,$12,$13)`, [
      preparationId, runId, claimId, leaseId, binding.environmentId, releaseIdentity, manifestHash, taskCase.caseId,
      taskCase.caseHash, hash("synthetic-initial-state"), hash("synthetic-execution-identity"), hash("synthetic-environment-manifest"),
      hash("synthetic-application-source"),
    ]);
    await setup.query(`INSERT INTO oid_task_execution_binding(run_id,task_index,env_id,generation_id,manifest_hash,application_source_hash)
      VALUES($1,0,$2,$3,$4,$5)`, [runId, binding.environmentId, generationId, hash("synthetic-environment-manifest"),
      hash("synthetic-application-source")]);
    await assert.rejects(service.recordTaskEvaluation(deps, target), (error) => error.code === "TASK_RECONCILIATION_PENDING");
    await assert.rejects(service.recordTaskEvaluation({ ...deps, evaluatorSourceHash: hash("wrong-build") }, target),
      (error) => error.code === "EVALUATOR_BUILD_MISMATCH");
    await setup.query(`INSERT INTO oid_run_task_closure(id,run_id,task_index,operation_id,payload_hash,reason,
      action_cutoff_sequence,actor_kind,owner_id,agent_id) VALUES($1,$2,0,$3,$4,'task_deadline',0,'coordinator',$5,$6)`,
    [closureId, runId, randomUUID(), hash("closure"), ownerId, agentId]);
    await setup.query(`UPDATE oid_run_task SET closure_id=$2,closure_status='closed',action_cutoff_sequence=0,
      closure_reason='task_deadline',closure_operation_id=$3,closed_at=clock_timestamp() WHERE run_id=$1`, [runId, closureId, randomUUID()]);
    const results = await Promise.all(Array.from({ length: 4 }, () => service.recordTaskEvaluation(deps, target)));
    assert.equal(results.filter((entry) => !entry.replayed).length, 1);
    assert.deepEqual(results[0].evaluation.result.credit, { numerator: "1", denominator: "1" });
    const before = (await observer.query("SELECT * FROM oid_run_task_evaluation WHERE run_id=$1", [runId])).rows;
    assert.equal(before.length, 1);
    const resultEvents = (await observer.query("SELECT sequence,payload_hash,payload_json FROM oid_run_event WHERE run_id=$1 AND event_type='task.evaluated'", [runId])).rows;
    assert.equal(resultEvents.length, 1, "Concurrent evaluation must emit exactly one result event");
    assert.equal(resultEvents[0].payload_json.inputHash, before[0].input_hash);
    assert.equal(resultEvents[0].payload_json.resultHash, before[0].result_hash);
    assert.equal(resultEvents[0].payload_json.closureId, closureId);
    const retainedInput = await service.readRetainedTaskEvaluationInput(db, target);
    assert.deepEqual(retainedInput.input, { ...input, release: manifest });
    assert.equal(retainedInput.inputHash, results[0].evaluation.inputHash);
    assert.equal(retainedInput.closureId, closureId);
    assert.ok(before[0].observation_evidence.references.some((entry) => entry.path === "synthetic-result/answer.json"),
      "The immutable audit row must retain individual observation evidence references");
    const reconstructed = await service.reconstructTaskEvaluation(deps, target);
    assert.equal(reconstructed.diverged, false);
    input.observations.answers[0].answer.amountUnits = "101";
    assert.deepEqual((await service.readRetainedTaskEvaluationInput(db, target)).input, retainedInput.input,
      "Retained input must not change with a later observer response");
    const originalReplay = await service.reconstructRetainedTaskEvaluation(db, target);
    assert.equal(originalReplay.diverged, false);
    assert.equal(originalReplay.inputSource, "immutable_retained_input");
    assert.deepEqual(originalReplay.reconstruction.credit, { numerator: "1", denominator: "1" });
    await assert.rejects(service.recordTaskEvaluation(deps, target), (error) => error.code === "TASK_EVALUATION_CONFLICT");
    const divergence = await service.reconstructTaskEvaluation(deps, target);
    assert.equal(divergence.diverged, true);
    assert.deepEqual(divergence.reconstruction.credit, { numerator: "3", denominator: "5" });
    const after = (await observer.query("SELECT * FROM oid_run_task_evaluation WHERE run_id=$1", [runId])).rows;
    assert.deepEqual(after, before);
    assert.deepEqual((await observer.query("SELECT sequence,payload_hash,payload_json FROM oid_run_event WHERE run_id=$1 AND event_type='task.evaluated'", [runId])).rows,
      resultEvents, "Reconstruction and rejected conflicting evidence must not republish a result");
    await assert.rejects(service.recordTaskEvaluation({ ...deps, evidenceSource: { async load() { return { ...input, run: { ...input.run, agentId: randomUUID() } }; } } }, target),
      (error) => error.code === "TASK_EVIDENCE_BINDING_MISMATCH");
    await assert.rejects(setup.query("UPDATE oid_run_task_evaluation SET result_json='{}' WHERE run_id=$1", [runId]), (error) => error.code === "55000");
    await assert.rejects(setup.query("DELETE FROM oid_run_task_evaluation WHERE run_id=$1", [runId]), (error) => error.code === "55000");
    assert.equal((await observer.query("SELECT count(*)::int AS count FROM oid_ledger_entry WHERE owner_id=$1", [ownerId])).rows[0].count, 0);
    await assert.rejects(feedback.getOwnerRunFeedback(db, randomUUID(), runId), (error) => error.code === "RUN_NOT_FOUND");
    assert.deepEqual(await feedback.getOwnerRunFeedback(db, ownerId, runId), { status: "withheld_until_run_termination", tasks: [] });
    // Private fixture-only terminal status: this tests disclosure policy, not a completed benchmark.
    await setup.query("UPDATE oid_benchmark_run SET status='completed',finished_at=clock_timestamp() WHERE id=$1", [runId]);
    assert.deepEqual(await feedback.getOwnerRunFeedback(db, ownerId, runId), { status: "available", tasks: [{
      taskId: "S2", status: "known", outcome: "passed", credit: { numerator: "1", denominator: "1" }, reason: null,
    }] });
    return { status: "passed", fullScenarioAcceptance: false, boundary: "Actual PostgreSQL evaluation store; synthetic release and observation ports",
      observations: ["unreconciled_task_cannot_record_grade", "concurrent_evaluation_once", "exact_credit_and_canonical_hashes",
        "evaluator_digest_matches_actual_runtime_modules", "individual_evidence_references_retained",
        "readonly_reconstruction_no_changes", "changed_evidence_conflicts_without_overwrite", "reconstruction_reports_divergence",
        "foreign_observation_denied", "evaluation_rows_append_only", "evaluation_no_ledger_effects",
        "foreign_owner_feedback_denied", "ranked_feedback_withheld_until_terminal", "terminal_feedback_contains_only_safe_projection",
        "full_evaluation_input_retained_with_original_hash", "later_observer_changes_do_not_rewrite_retained_input",
        "original_input_reconstruction_does_not_require_live_observer", "concurrent_evaluation_emits_one_bound_result_event",
        "reconstruction_and_conflict_do_not_republish_result"],
      runId, evaluation: results[0].evaluation };
  } finally { await client.end(); await setup.end(); await observer.end(); }
}
