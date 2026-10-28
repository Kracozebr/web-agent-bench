import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import pg from "pg";

const key = () => randomUUID();
const inventory = ["S1", "S2", "S3", "S4", "M1", "M2", "M3", "M4", "H1", "H2", "H3", "U1"];
const openIds = ["S1", "S2", "S4", "M1", "M3", "M4", "H1", "H2"];
const weights = (ids) => ids.map((id) => ({ S: 1, M: 2, H: 3, U: 5 })[id[0]]);

// This injected provider is exclusively a coordinator transaction test double.
// It is never registered with HTTP/MCP or claimed as an activated product release.
function syntheticProvider() {
  const release = (mode) => ({ releaseIdentity: "synthetic-transaction-contract-v1", manifestHash: "a".repeat(64),
    benchmarkVersion: "synthetic-transaction-v1", benchmarkHash: "b".repeat(64), policyHash: "c".repeat(64),
    mode, taskIds: mode === "ranked" ? inventory : openIds,
    weights: weights(mode === "ranked" ? inventory : openIds), priceUnits: mode === "ranked" ? "1000000" : "500000", precision: 6 });
  return { getActiveAdmissionRelease: async (mode) => release(mode),
    getValidatedRelease: async () => null,
    getPublicCatalog: () => [] };
}

async function fixtureOwner(pool, count = 1) {
  const ownerId = key();
  const userId = key();
  await pool.query("INSERT INTO oid_auth_user(id,name,email,email_verified) VALUES($1,'Synthetic transaction owner',$2,true)", [userId, `${userId}@example.invalid`]);
  await pool.query("INSERT INTO oid_owner(id,auth_user_id,admission_status,admitted_at) VALUES($1,$2,'admitted',clock_timestamp())", [ownerId, userId]);
  const agentIds = [];
  for (let index = 0; index < count; index++) {
    const agentId = key();
    await pool.query("INSERT INTO oid_agent(id,owner_id,name) VALUES($1,$2,'Synthetic transaction agent')", [agentId, ownerId]);
    await pool.query("INSERT INTO oid_agent_policy(agent_id,training,ranked) VALUES($1,true,true)", [agentId]);
    await pool.query(`INSERT INTO oid_agent_financial_policy(owner_id,agent_id,revision,operation_limit_units,utc_day_limit_units,category_limits)
      VALUES($1,$2,1,10000000,20000000,'{"benchmark":"20.000000","forum":"0.000000"}'::jsonb)`, [ownerId, agentId]);
    agentIds.push(agentId);
  }
  return { ownerId, agentIds };
}

export async function runTransactionCases({ databaseUrl, observerDatabaseUrl }) {
  const [{ createDatabase }, { loadConfig }, { issueBonusGrant, readOwnerBilling }, runs] = await Promise.all([
    import("../../owner-identity/dist/db.js"), import("../../owner-identity/dist/config.js"),
    import("../../owner-identity/dist/ledger.js"), import("../../owner-identity/dist/run-service.js"),
  ]);
  assert.match(new URL(databaseUrl).pathname, /^\/oid_acceptance_[a-f0-9]{32}$/, "Transaction fixtures require an isolated acceptance database");
  const setup = new pg.Pool({ connectionString: databaseUrl, max: 2 });
  const observer = new pg.Pool({ connectionString: observerDatabaseUrl, max: 1 });
  const { db, client } = createDatabase(loadConfig({ ...process.env, OID_DATABASE_URL: databaseUrl }));
  const deps = { db, admissionReleaseProvider: syntheticProvider(), intentTtlSeconds: 900, maxIntentTtlSeconds: 3600,
    queueWaitSeconds: 900, maxQueueWaitSeconds: 3600, executionCapacity: 2,
    maxPendingIntentsPerOwner: 100, maxPendingIntentsGlobal: 1000,
    trainingOverallTimeoutSeconds: 3600, maxTrainingOverallTimeoutSeconds: 7200,
    successorPreparationPolicyVersion: runs.SUCCESSOR_PREPARATION_POLICY_VERSION,
    successorPreparationTimeoutSeconds: 180,
    executionReadinessProvider: { isPreparedForRelease: async () => ({ ready: false, reason: "synthetic_provider_has_no_executor" }) } };
  try {
    const owner = await fixtureOwner(setup, 2);
    const foreign = await fixtureOwner(setup);
    const [agentId, secondAgentId] = owner.agentIds;
    await issueBonusGrant(db, { actorOwnerId: owner.ownerId, ownerId: owner.ownerId,
      operationId: key(), amount: "1.000000", reason: "Synthetic coordinator transaction fixture only" });
    const command = { ownerId: owner.ownerId, agentId, mode: "ranked", taskIds: inventory, cashCeiling: "0.000000", operationId: key(),
      expectedReleaseIdentity: "synthetic-transaction-contract-v1", expectedManifestHash: "a".repeat(64), expectedQuotePrice: "1.000000" };
    const created = await runs.createLaunchIntent(deps, command);
    assert.equal(created.intent.successorPreparationPolicyVersion, runs.SUCCESSOR_PREPARATION_POLICY_VERSION);
    assert.equal(created.intent.successorPreparationTimeoutSeconds, 180);
    assert.equal(created.intent.policyHash, "c".repeat(64), "The private timeout snapshot remains separate from the release policy hash");
    assert.equal(created.intent.quote.price, "1.000000", "The private timeout snapshot does not change the release quote");
    const repeated = await runs.createLaunchIntent(deps, command);
    assert.equal(repeated.intent.id, created.intent.id);
    assert.equal(repeated.intent.expiresAt, created.intent.expiresAt);
    assert.equal(repeated.replayed, true);
    const changedRuntimePolicy = { ...deps, successorPreparationTimeoutSeconds: 300 };
    const changedRuntimeReplay = await runs.createLaunchIntent(changedRuntimePolicy, command);
    assert.equal(changedRuntimeReplay.replayed, true);
    assert.equal(changedRuntimeReplay.intent.successorPreparationPolicyVersion, runs.SUCCESSOR_PREPARATION_POLICY_VERSION);
    assert.equal(changedRuntimeReplay.intent.successorPreparationTimeoutSeconds, 180,
      "The same intent operation returns its persisted policy snapshot after the runtime default changes");
    let billing = await readOwnerBilling(db, owner.ownerId);
    assert.equal(billing.bonus.reserved, "0.000000");
    assert.equal(billing.bonus.available, "1.000000");
    await assert.rejects(runs.getLaunchIntent(db, foreign.ownerId, created.intent.id));
    await assert.rejects(runs.acceptLaunchIntent(deps, { ownerId: foreign.ownerId, agentId: foreign.agentIds[0],
      accessGeneration: 1, intentId: created.intent.id, operationId: key() }));
    const acceptance = { ownerId: owner.ownerId, agentId, accessGeneration: 1, intentId: created.intent.id };
    const accepted = await Promise.all(Array.from({ length: 4 }, () => runs.acceptLaunchIntent(changedRuntimePolicy, { ...acceptance, operationId: key() })));
    assert.equal(new Set(accepted.map((result) => result.run.id)).size, 1, "Concurrent distinct caller keys produced duplicate runs");
    assert.equal(accepted[0].run.startedAt, null);
    assert.equal(accepted[0].run.successorPreparationPolicyVersion, runs.SUCCESSOR_PREPARATION_POLICY_VERSION);
    assert.equal(accepted[0].run.successorPreparationTimeoutSeconds, 180,
      "Acceptance copies the intent snapshot and does not replace it with the current runtime default");
    const policyRows = await observer.query(`SELECT i.successor_preparation_policy_version AS intent_version,
        i.successor_preparation_timeout_seconds AS intent_seconds,
        r.successor_preparation_policy_version AS run_version,r.successor_preparation_timeout_seconds AS run_seconds,
        r.policy_hash,r.quote_price_units::text AS quote_units
      FROM oid_run_launch_intent i JOIN oid_benchmark_run r ON r.intent_id=i.id WHERE i.id=$1`, [created.intent.id]);
    assert.deepEqual(policyRows.rows[0], {
      intent_version: runs.SUCCESSOR_PREPARATION_POLICY_VERSION, intent_seconds: 180,
      run_version: runs.SUCCESSOR_PREPARATION_POLICY_VERSION, run_seconds: 180,
      policy_hash: "c".repeat(64), quote_units: "1000000"
    });
    await assert.rejects(setup.query(`UPDATE oid_run_launch_intent SET successor_preparation_timeout_seconds=300 WHERE id=$1`,
      [created.intent.id]), (error) => error.code === "55000",
    "the admitted launch-intent policy snapshot is immutable");
    await assert.rejects(setup.query(`UPDATE oid_benchmark_run SET successor_preparation_timeout_seconds=300 WHERE intent_id=$1`,
      [created.intent.id]), (error) => error.code === "55000",
    "the accepted run retains the copied policy snapshot immutably");
    await assert.rejects(setup.query(`INSERT INTO oid_run_launch_intent(
        id,owner_id,agent_id,operation_id,payload_hash,mode,task_ids,release_identity,benchmark_version,manifest_hash,
        benchmark_hash,policy_hash,successor_preparation_policy_version,successor_preparation_timeout_seconds,
        quote_price_units,precision,cash_ceiling_units,owner_policy_revision,agent_policy_revision,status,created_at,expires_at
      ) SELECT $1,owner_id,agent_id,$2,$3,mode,task_ids,release_identity,benchmark_version,manifest_hash,benchmark_hash,policy_hash,
        NULL,180,quote_price_units,precision,cash_ceiling_units,owner_policy_revision,agent_policy_revision,'pending',
        clock_timestamp(),clock_timestamp()+interval '5 minutes' FROM oid_run_launch_intent WHERE id=$4`,
    [key(), key(), "e".repeat(64), created.intent.id]), (error) => error.code === "23514",
    "the database rejects a partial policy snapshot pair");
    billing = await readOwnerBilling(db, owner.ownerId);
    assert.equal(billing.bonus.reserved, "1.000000");
    assert.equal(billing.bonus.available, "0.000000");

    const legacyOwner = await fixtureOwner(setup);
    await issueBonusGrant(db, { actorOwnerId: legacyOwner.ownerId, ownerId: legacyOwner.ownerId,
      operationId: key(), amount: "2.000000", reason: "Synthetic legacy policy snapshot fixture only" });
    const legacySource = await runs.createLaunchIntent(deps, { ...command, ownerId: legacyOwner.ownerId,
      agentId: legacyOwner.agentIds[0], operationId: key() });
    const insertHistoricalIntent = async ({ version, seconds }) => {
      const intentId = key();
      await setup.query(`INSERT INTO oid_run_launch_intent(
          id,owner_id,agent_id,operation_id,payload_hash,mode,task_ids,release_identity,benchmark_version,
          manifest_hash,benchmark_hash,policy_hash,successor_preparation_policy_version,successor_preparation_timeout_seconds,
          quote_price_units,precision,cash_ceiling_units,owner_policy_revision,agent_policy_revision,status,created_at,expires_at
        ) SELECT $1,owner_id,agent_id,$2,$3,mode,task_ids,release_identity,benchmark_version,
          manifest_hash,benchmark_hash,policy_hash,$4,$5,quote_price_units,precision,cash_ceiling_units,
          owner_policy_revision,agent_policy_revision,'pending',clock_timestamp(),clock_timestamp()+interval '5 minutes'
        FROM oid_run_launch_intent WHERE id=$6`, [intentId, key(), "d".repeat(64), version, seconds, legacySource.intent.id]);
      return intentId;
    };
    const missingPolicyIntent = await insertHistoricalIntent({ version: null, seconds: null });
    const unsupportedPolicyIntent = await insertHistoricalIntent({ version: "local-bef-successor-preparation/v2", seconds: 300 });
    for (const intentId of [missingPolicyIntent, unsupportedPolicyIntent]) {
      await assert.rejects(runs.acceptLaunchIntent(deps, { ownerId: legacyOwner.ownerId, agentId: legacyOwner.agentIds[0],
        accessGeneration: 1, intentId, operationId: key() }),
      (error) => error.code === "SUCCESSOR_PREPARATION_POLICY_UNAVAILABLE",
      "A legacy multi-task intent without a supported snapshot must reject before creating reservations");
    }
    const legacyBilling = await readOwnerBilling(db, legacyOwner.ownerId);
    assert.equal(legacyBilling.bonus.available, "2.000000");
    assert.equal(legacyBilling.bonus.reserved, "0.000000");
    const legacyEffects = await observer.query(`SELECT
        (SELECT count(*)::int FROM oid_benchmark_run WHERE owner_id=$1) AS runs,
        (SELECT count(*)::int FROM oid_run_reservation WHERE owner_id=$1) AS reservations,
        (SELECT count(*)::int FROM oid_run_budget_hold WHERE owner_id=$1) AS budget_holds`, [legacyOwner.ownerId]);
    assert.deepEqual(legacyEffects.rows[0], { runs: 0, reservations: 0, budget_holds: 0 });

    // This synthetic historical row models a pre-snapshot queued multi-task run.
    // It intentionally has no reservation/claim and must fail during preflight,
    // before readiness or a debit can be attempted.
    let validatedReleaseCalls = 0;
    const guardedStartDeps = { ...deps, admissionReleaseProvider: { ...deps.admissionReleaseProvider,
      async getValidatedRelease(...args) { validatedReleaseCalls += 1; return deps.admissionReleaseProvider.getValidatedRelease(...args); } } };
    const legacyQueuedRunIds = [];
    for (const intentId of [missingPolicyIntent, unsupportedPolicyIntent]) {
      const legacyQueuedRunId = key();
      legacyQueuedRunIds.push(legacyQueuedRunId);
      await setup.query(`INSERT INTO oid_benchmark_run(
          id,intent_id,owner_id,agent_id,mode,task_ids,release_identity,benchmark_version,manifest_hash,benchmark_hash,policy_hash,
          successor_preparation_policy_version,successor_preparation_timeout_seconds,quote_price_units,cash_ceiling_units,
          access_generation,agent_policy_revision,status,queued_at,queue_deadline
        ) SELECT $1,i.id,i.owner_id,i.agent_id,i.mode,i.task_ids,i.release_identity,i.benchmark_version,i.manifest_hash,
          i.benchmark_hash,i.policy_hash,i.successor_preparation_policy_version,i.successor_preparation_timeout_seconds,
          i.quote_price_units,i.cash_ceiling_units,a.access_generation,p.revision,'queued',clock_timestamp(),clock_timestamp()+interval '5 minutes'
        FROM oid_run_launch_intent i JOIN oid_agent a ON a.id=i.agent_id
        JOIN oid_agent_policy p ON p.agent_id=i.agent_id WHERE i.id=$2`, [legacyQueuedRunId, intentId]);
      await setup.query("UPDATE oid_run_launch_intent SET status='accepted',accepted_at=clock_timestamp(),run_id=$2 WHERE id=$1",
        [intentId, legacyQueuedRunId]);
      await assert.rejects(runs.startQueuedRun(guardedStartDeps, { runId: legacyQueuedRunId, claimId: key(), operationId: key() }),
        (error) => error.code === "SUCCESSOR_PREPARATION_POLICY_UNAVAILABLE",
        "A queued legacy multi-task run without a supported snapshot must fail before validated executor work");
      assert.equal((await observer.query("SELECT count(*)::int AS count FROM oid_ledger_entry WHERE operation_id=$1",
        [`rundeb_${legacyQueuedRunId.replaceAll("-", "")}`])).rows[0].count, 0);
      assert.equal((await observer.query("SELECT status FROM oid_benchmark_run WHERE id=$1", [legacyQueuedRunId])).rows[0].status, "queued");
    }
    assert.equal(validatedReleaseCalls, 0, "The saved policy guard runs before release readiness work for missing and unsupported snapshots");
    const missingConfigOwner = await fixtureOwner(setup);
    await issueBonusGrant(db, { actorOwnerId: missingConfigOwner.ownerId, ownerId: missingConfigOwner.ownerId,
      operationId: key(), amount: "2.000000", reason: "Synthetic missing policy configuration fixture only" });
    const missingConfigDeps = { ...deps, successorPreparationPolicyVersion: undefined, successorPreparationTimeoutSeconds: undefined };
    await assert.rejects(runs.createLaunchIntent(missingConfigDeps, { ...command, ownerId: missingConfigOwner.ownerId,
      agentId: missingConfigOwner.agentIds[0], operationId: key() }),
    (error) => error.code === "RUN_POLICY_UNCONFIGURED",
    "A new multi-task intent must not be created without an explicit versioned policy snapshot");
    const missingConfigBilling = await readOwnerBilling(db, missingConfigOwner.ownerId);
    assert.equal(missingConfigBilling.bonus.available, "2.000000");
    assert.equal(missingConfigBilling.bonus.reserved, "0.000000");
    assert.equal((await observer.query("SELECT count(*)::int AS count FROM oid_run_launch_intent WHERE owner_id=$1", [missingConfigOwner.ownerId])).rows[0].count, 0);
    const second = await runs.createLaunchIntent(deps, { ...command, agentId: secondAgentId, operationId: key() });
    await assert.rejects(runs.acceptLaunchIntent(deps, { ownerId: owner.ownerId, agentId: secondAgentId,
      accessGeneration: 1, intentId: second.intent.id, operationId: key() }), "Concurrent owner funding cannot be allocated twice");
    const runId = accepted[0].run.id;
    await Promise.all(Array.from({ length: 3 }, () => runs.requestRunCancellation(db, {
      ownerId: owner.ownerId, runId, operationId: key(), reason: "owner_voluntary" })));
    billing = await readOwnerBilling(db, owner.ownerId);
    assert.equal(billing.bonus.available, "1.000000");
    assert.equal(billing.bonus.reserved, "0.000000");
    const terminalRetry = await runs.acceptLaunchIntent(deps, { ...acceptance, operationId: key() });
    assert.equal(terminalRetry.run.id, runId);
    assert.equal(terminalRetry.run.status, "cancelled");
    const cancelledPending = await runs.createLaunchIntent(deps, { ...command, operationId: key() });
    await runs.cancelLaunchIntent(deps, { ownerId: owner.ownerId, intentId: cancelledPending.intent.id, operationId: key() });
    await assert.rejects(runs.acceptLaunchIntent(deps, { ...acceptance, intentId: cancelledPending.intent.id, operationId: key() }));
    const sourceRows = (await observer.query("SELECT entry_type,amount_units::text,available_delta_units::text,reserved_delta_units::text FROM oid_ledger_entry WHERE owner_id=$1 ORDER BY created_at,id", [owner.ownerId])).rows;
    assert.equal(sourceRows.filter((row) => row.entry_type === "reserve").length, 1);
    assert.equal(sourceRows.filter((row) => row.entry_type === "release").length, 1);
    assert.equal(sourceRows.filter((row) => row.entry_type === "debit").length, 0);
    const runRows = (await observer.query("SELECT id::text,status,started_at FROM oid_benchmark_run WHERE owner_id=$1", [owner.ownerId])).rows;
    assert.equal(runRows.length, 1);
    assert.equal(runRows[0].status, "cancelled");
    const eligibleLegacyOwnerIntent = await runs.createLaunchIntent(deps, { ...command, ownerId: legacyOwner.ownerId,
      agentId: legacyOwner.agentIds[0], operationId: key() });
    const eligibleLegacyOwnerRun = await runs.acceptLaunchIntent(deps, { ownerId: legacyOwner.ownerId,
      agentId: legacyOwner.agentIds[0], accessGeneration: 1, intentId: eligibleLegacyOwnerIntent.intent.id, operationId: key() });
    const eligibleRunBeforeClaim = (await observer.query(`SELECT id::text,status,cardinality(task_ids)::int AS task_count,
        successor_preparation_policy_version,successor_preparation_timeout_seconds,
        queue_deadline>clock_timestamp() AS queue_live FROM oid_benchmark_run WHERE id=$1`,
    [eligibleLegacyOwnerRun.run.id])).rows[0];
    const activeSlotsBeforeClaim = (await observer.query(`SELECT count(*)::int AS count FROM oid_run_execution_slot
      WHERE released_at IS NULL`)).rows[0].count;
    const eligibleClaim = await runs.claimNextQueuedRun({ ...deps, executionCapacity: 2 }, { claimId: key() });
    if (eligibleClaim?.run.id !== eligibleLegacyOwnerRun.run.id) {
      const error = new Error("The policy-aware scheduler did not claim the expected eligible run");
      error.safeDiagnostic = { boundary: "synthetic_run_policy_claim_eligibility_fixture", expectedRunId: eligibleLegacyOwnerRun.run.id,
        actualRunId: eligibleClaim?.run.id ?? null, eligibleRunBeforeClaim, activeSlotsBeforeClaim };
      throw error;
    }
    const invalidQueuedRows = (await observer.query(`SELECT r.id::text,r.status,
        (SELECT count(*)::int FROM oid_run_dispatch_claim c WHERE c.run_id=r.id) AS claim_count,
        (SELECT count(*)::int FROM oid_run_execution_slot s WHERE s.run_id=r.id AND s.released_at IS NULL) AS active_slot_count,
        (SELECT count(*)::int FROM oid_run_reservation rr WHERE rr.run_id=r.id) AS reservation_count,
        (SELECT count(*)::int FROM oid_run_budget_hold b WHERE b.run_id=r.id) AS budget_hold_count,
        (SELECT count(*)::int FROM oid_ledger_entry e WHERE e.owner_id=r.owner_id AND e.entry_type='debit' AND
          e.operation_id='rundeb_'||replace(r.id::text,'-','')) AS debit_count
      FROM oid_benchmark_run r WHERE r.id=ANY($1::uuid[]) ORDER BY r.id`, [legacyQueuedRunIds])).rows;
    assert.equal(invalidQueuedRows.length, 2);
    for (const row of invalidQueuedRows) {
      assert.deepEqual(row, { id: row.id, status: "queued", claim_count: 0, active_slot_count: 0,
        reservation_count: 0, budget_hold_count: 0, debit_count: 0 },
      "an unsupported queued multi-task run remains wholly unallocated while the scheduler skips it");
    }
    await runs.requestRunCancellation(db, { ownerId: legacyOwner.ownerId, runId: eligibleLegacyOwnerRun.run.id,
      operationId: key(), reason: "owner_voluntary" });
    // These synthetic historical rows are no longer needed after proving the
    // no-debit and scheduler eligibility checks. Retire them before fairness
    // so its claim set contains only its explicitly mapped runs.
    for (const legacyQueuedRunId of legacyQueuedRunIds) {
      await runs.requestRunCancellation(db, { ownerId: legacyOwner.ownerId, runId: legacyQueuedRunId,
        operationId: key(), reason: "owner_voluntary" });
    }
    const legacyQueuedStatuses = (await observer.query(`SELECT status FROM oid_benchmark_run
      WHERE id=ANY($1::uuid[]) ORDER BY id`, [legacyQueuedRunIds])).rows.map((row) => row.status);
    assert.deepEqual(legacyQueuedStatuses, ["cancelled", "cancelled"],
      "fixture-only legacy queued rows are retired after the no-debit and scheduler checks");
    const scheduledOwners = [];
    const ownerForRun = new Map();
    for (let index = 0; index < 3; index++) {
      const candidate = await fixtureOwner(setup, 2);
      scheduledOwners.push(candidate.ownerId);
      await issueBonusGrant(db, { actorOwnerId: candidate.ownerId, ownerId: candidate.ownerId,
        operationId: key(), amount: "2.000000", reason: "Synthetic scheduling transaction fixture only" });
      for (const schedulerAgent of candidate.agentIds) {
        const intent = await runs.createLaunchIntent(deps, { ...command, ownerId: candidate.ownerId,
          agentId: schedulerAgent, operationId: key() });
        const admitted = await runs.acceptLaunchIntent(deps, { ownerId: candidate.ownerId, agentId: schedulerAgent,
          accessGeneration: 1, intentId: intent.intent.id, operationId: key() });
        ownerForRun.set(admitted.run.id, candidate.ownerId);
      }
    }
    const claims = [];
    const schedulerDeps = { ...deps, executionCapacity: 6 };
    for (let index = 0; index < 6; index++) {
      const claimId = key();
      const claim = await runs.claimNextQueuedRun(schedulerDeps, { claimId });
      assert.ok(claim);
      const replay = await runs.claimNextQueuedRun(schedulerDeps, { claimId });
      assert.equal(replay.run.id, claim.run.id);
      assert.equal(replay.turnNumber, claim.turnNumber);
      claims.push({ ...claim, ownerId: ownerForRun.get(claim.run.id) });
    }
    assert.equal(new Set(claims.slice(0, 3).map((claim) => claim.ownerId)).size, 3, "Rotation starved a third eligible owner");
    assert.equal(new Set(claims.slice(3).map((claim) => claim.ownerId)).size, 3);
    assert.equal(await runs.claimNextQueuedRun(schedulerDeps), null);
    await assert.rejects(runs.startQueuedRun(schedulerDeps, { runId: claims[0].run.id,
      claimId: claims[0].claimId, operationId: key() }), "Unvalidated release cannot start or debit");
    for (const claim of claims) {
      await runs.requestRunCancellation(db, { ownerId: claim.ownerId, runId: claim.run.id,
        operationId: key(), reason: "owner_voluntary" });
    }
    const schedulerEffects = (await observer.query("SELECT entry_type,count(*)::int AS count FROM oid_ledger_entry WHERE owner_id=ANY($1::uuid[]) GROUP BY entry_type ORDER BY entry_type", [scheduledOwners])).rows;
    assert.equal(schedulerEffects.find((row) => row.entry_type === "debit"), undefined);
    assert.equal(schedulerEffects.find((row) => row.entry_type === "reserve").count, 6);
    assert.equal(schedulerEffects.find((row) => row.entry_type === "release").count, 6);
    const fencedOwner = await fixtureOwner(setup);
    const fencedAgent = fencedOwner.agentIds[0];
    await issueBonusGrant(db, { actorOwnerId: fencedOwner.ownerId, ownerId: fencedOwner.ownerId,
      operationId: key(), amount: "3.000000", reason: "Synthetic delayed cancellation transaction fixture only" });
    const admitTraining = async (generation) => {
      const intent = await runs.createLaunchIntent(deps, { ...command, ownerId: fencedOwner.ownerId,
        agentId: fencedAgent, mode: "training", taskIds: openIds, expectedQuotePrice: "0.500000", operationId: key() });
      return (await runs.acceptLaunchIntent(deps, { ownerId: fencedOwner.ownerId, agentId: fencedAgent,
        accessGeneration: generation, intentId: intent.intent.id, operationId: key() })).run;
    };
    const beforeModeRemoval = await admitTraining(1);
    await setup.query("UPDATE oid_agent_policy SET training=false,revision=2 WHERE agent_id=$1", [fencedAgent]);
    await setup.query("UPDATE oid_agent_policy SET training=true,revision=3 WHERE agent_id=$1", [fencedAgent]);
    const afterModeRestore = await admitTraining(1);
    await runs.consumeRunCancellationOutbox(db);
    await runs.consumeRunCancellationOutbox(db);
    let fencedRuns = (await observer.query("SELECT id::text,status FROM oid_benchmark_run WHERE agent_id=$1 ORDER BY queued_at,id", [fencedAgent])).rows;
    assert.equal(fencedRuns.find((row) => row.id === beforeModeRemoval.id).status, "cancelled");
    assert.equal(fencedRuns.find((row) => row.id === afterModeRestore.id).status, "queued", "Delayed mode event cancelled a new policy successor");
    const modeReceipt = (await observer.query(`SELECT r.cancelled_run_ids FROM oid_run_cancellation_receipt r
      JOIN oid_run_mode_cancellation_outbox o ON o.event_id=r.source_event_id WHERE o.agent_id=$1`, [fencedAgent])).rows;
    assert.equal(modeReceipt.length, 1);
    assert.deepEqual(modeReceipt[0].cancelled_run_ids, [beforeModeRemoval.id]);
    const globalEventId = key();
    await setup.query("UPDATE oid_agent SET access_generation=2,access_revoked_at=clock_timestamp() WHERE id=$1", [fencedAgent]);
    await setup.query(`INSERT INTO oid_agent_cancellation_outbox(event_id,owner_id,agent_id,access_generation,operation_id,payload_json)
      VALUES($1,$2,$3,2,$4,'{"scope":"all","reason":"owner_global_revoke"}'::jsonb)`, [globalEventId, fencedOwner.ownerId, fencedAgent, key()]);
    await setup.query("UPDATE oid_agent SET access_generation=3,access_revoked_at=NULL WHERE id=$1", [fencedAgent]);
    const afterReauthorization = await admitTraining(3);
    await runs.consumeRunCancellationOutbox(db);
    await runs.consumeRunCancellationOutbox(db);
    fencedRuns = (await observer.query("SELECT id::text,status FROM oid_benchmark_run WHERE agent_id=$1 ORDER BY queued_at,id", [fencedAgent])).rows;
    assert.equal(fencedRuns.find((row) => row.id === afterModeRestore.id).status, "cancelled");
    assert.equal(fencedRuns.find((row) => row.id === afterReauthorization.id).status, "queued", "Delayed global event cancelled a reauthorized successor");
    // A private fixture seam moves both timestamps together; this does not claim a live timeout/load measurement.
    await setup.query("UPDATE oid_benchmark_run SET queued_at=clock_timestamp()-interval '2 seconds',queue_deadline=clock_timestamp()-interval '1 second' WHERE id=$1", [afterReauthorization.id]);
    await runs.expireQueuedRuns(db);
    await runs.expireQueuedRuns(db);
    const expiry = (await observer.query("SELECT status,started_at,terminal_reason FROM oid_benchmark_run WHERE id=$1", [afterReauthorization.id])).rows[0];
    assert.equal(expiry.status, "expired");
    assert.equal(expiry.started_at, null);
    const fencedBilling = await readOwnerBilling(db, fencedOwner.ownerId);
    assert.equal(fencedBilling.bonus.available, "3.000000");
    assert.equal(fencedBilling.bonus.reserved, "0.000000");
    return { schemaVersion: "run-transaction-integration/v1", status: "passed", fullScenarioAcceptance: false,
      boundary: "Actual coordinator service and PostgreSQL; synthetic injected release; no HTTP/client/execution release acceptance",
      observations: ["intent_retry_no_reservation", "foreign_identity_denied", "concurrent_acceptance_once", "shared_owner_funds_conserved",
        "prestart_cancellation_once", "terminal_retry_no_reopen", "pending_cancellation_no_admission",
        "three_owner_rotation", "durable_claim_replay", "capacity_bound", "unvalidated_start_no_debit",
        "delayed_mode_event_preserves_successor", "delayed_global_event_preserves_successor",
        "prestart_cancellation_receipt_lists_affected_run", "queue_expiry_release_once"],
      ownerId: owner.ownerId, agentIds: owner.agentIds, runRows, sourceRows,
      scheduler: { claims, effects: schedulerEffects }, cancellationCutoffs: { fencedRuns, modeReceipt, expiry } };
  } catch (error) {
    const cause = error.cause ?? error;
    const fixtureDiagnostic = error.safeDiagnostic && typeof error.safeDiagnostic === "object" ? error.safeDiagnostic : null;
    error.safeDiagnostic = { boundary: "synthetic_coordinator_transaction_fixture",
      databaseCode: typeof cause.code === "string" ? cause.code : "unavailable",
      databaseColumn: typeof cause.column === "string" ? cause.column : null,
      databaseConstraint: typeof cause.constraint === "string" ? cause.constraint : null,
      ...(fixtureDiagnostic ? { fixtureDiagnostic } : {}),
      serviceFrames: String(error.stack ?? "").split("\n").filter((line) => line.includes("run-service")).slice(0, 4) };
    throw error;
  } finally { await client.end(); await setup.end(); await observer.end(); }
}
