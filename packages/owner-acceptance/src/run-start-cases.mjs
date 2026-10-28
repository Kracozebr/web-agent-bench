import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { createRequire } from "node:module";
import { request as httpRequest } from "node:http";
import pg from "pg";
import { createSyntheticTaskPreparationReleaseFixture } from "./task-store-cases.mjs";

const key = () => randomUUID();
const digest = (value) => createHash("sha256").update(value).digest("hex");
const openTaskIds = ["S1", "S2", "S4", "M1", "M3", "M4", "H1", "H2"];
const weightFor = (taskId) => ({ S: 1, M: 2, H: 3, U: 5 })[taskId[0]];
const quoteUnits = "1000000";
const quotePrice = "1.000000";

// This provider and readiness adapter exist only inside direct-service PostgreSQL
// acceptance tests. They are not registered with HTTP/MCP and do not activate a
// product release or prove the availability of a genuine executor.
function syntheticAdmissionPorts() {
  const releases = new Map();
  const activeByMode = new Map();
  const releaseKey = (release) => `${release.releaseIdentity}:${release.manifestHash}:${release.mode}`;
  const makeRelease = (version) => {
    const release = {
      releaseIdentity: `synthetic-run-start-${version}`,
      manifestHash: digest(`${version}:manifest`),
      benchmarkVersion: `synthetic-benchmark-${version}`,
      benchmarkHash: digest(`${version}:benchmark`),
      policyHash: digest(`${version}:policy`),
      mode: "training",
      taskIds: openTaskIds,
      weights: openTaskIds.map(weightFor),
      priceUnits: quoteUnits,
      precision: 6
    };
    releases.set(releaseKey(release), {
      releaseIdentity: release.releaseIdentity,
      manifestHash: release.manifestHash,
      benchmarkVersion: release.benchmarkVersion,
      benchmarkHash: release.benchmarkHash,
      policyHash: release.policyHash,
      mode: release.mode,
      taskIds: release.taskIds,
      weights: release.weights,
      taskDeadlines: openTaskIds.map((taskId) => ({ taskId, timeoutSeconds: 60 })),
      overallTimeoutSeconds: 900,
      pricing: { priceUnits: quoteUnits, precision: 6 }
    });
    return release;
  };
  const first = makeRelease("v1");
  activeByMode.set("training", first);
  return {
    provider: {
      async getActiveAdmissionRelease(mode) { return activeByMode.get(mode) ?? null; },
      async getValidatedRelease(releaseIdentity, manifestHash, mode) {
        return releases.get(`${releaseIdentity}:${manifestHash}:${mode}`) ?? null;
      },
      getPublicCatalog() { return []; }
    },
    readinessProvider: {
      async isPreparedForRelease(releaseIdentity, manifestHash) {
        return {
          ready: true,
          executorId: "synthetic-acceptance-adapter",
          environmentId: `synthetic-env-${releaseIdentity}`,
          evidenceHash: digest(`synthetic-readiness:${releaseIdentity}:${manifestHash}`)
        };
      }
    },
    activate(version) {
      const release = makeRelease(version);
      activeByMode.set("training", release);
      return release;
    }
  };
}

function syntheticAdmissionPortsForCandidate(candidate) {
  const taskIds = candidate.inventory.openTrainingTaskIds;
  const weights = taskIds.map(weightFor);
  const release = {
    releaseIdentity: candidate.releaseIdentity,
    manifestHash: candidate.manifestHash,
    benchmarkVersion: candidate.benchmarkVersion,
    benchmarkHash: candidate.benchmarkHash,
    policyHash: candidate.policyHash,
    mode: "training",
    taskIds,
    weights,
    priceUnits: candidate.pricing.openTrainingPriceUnits,
    precision: 6
  };
  const validated = {
    releaseIdentity: release.releaseIdentity,
    manifestHash: release.manifestHash,
    benchmarkVersion: release.benchmarkVersion,
    benchmarkHash: release.benchmarkHash,
    policyHash: release.policyHash,
    mode: "training",
    taskIds,
    weights,
    taskDeadlines: taskIds.map((taskId) => ({ taskId, timeoutSeconds: candidate.deadlines.taskTimeoutSeconds })),
    overallTimeoutSeconds: candidate.deadlines.trainingRunTimeoutSeconds,
    pricing: { priceUnits: release.priceUnits, precision: 6 }
  };
  return {
    release,
    provider: {
      async getActiveAdmissionRelease(mode) { return mode === "training" ? release : null; },
      async getValidatedRelease(identity, manifestHash, mode) {
        return mode === "training" && identity === release.releaseIdentity && manifestHash === release.manifestHash ? validated : null;
      },
      getPublicCatalog() { return []; }
    }
  };
}

async function fixtureOwner(pool, { allowCashShortfall = false } = {}) {
  const ownerId = key();
  const userId = key();
  const agentId = key();
  await pool.query("INSERT INTO oid_auth_user(id,name,email,email_verified) VALUES($1,'Synthetic run-start owner',$2,true)",
    [userId, `${userId}@example.invalid`]);
  await pool.query("INSERT INTO oid_owner(id,auth_user_id,admission_status,admitted_at) VALUES($1,$2,'admitted',clock_timestamp())", [ownerId, userId]);
  await pool.query("INSERT INTO oid_agent(id,owner_id,name) VALUES($1,$2,'Synthetic run-start agent')", [agentId, ownerId]);
  await pool.query("INSERT INTO oid_agent_policy(agent_id,training,ranked) VALUES($1,true,true)", [agentId]);
  await pool.query(`INSERT INTO oid_agent_financial_policy(owner_id,agent_id,allow_cash_shortfall,revision,
      operation_limit_units,utc_day_limit_units,category_limits)
    VALUES($1,$2,$3,1,10000000,20000000,'{"benchmark":"20.000000","forum":"20.000000"}'::jsonb)`,
  [ownerId, agentId, allowCashShortfall]);
  const grantId = key();
  const resource = "http://task-issuance.example.invalid/api/agent";
  await pool.query(`INSERT INTO oid_agent_access_grant(id,owner_id,agent_id,operation_id,resource,role,access_generation,expires_at)
    VALUES($1,$2,$3,$4,$5,'agent',1,clock_timestamp()+interval '1 day')`, [grantId, ownerId, agentId, key(), resource]);
  return { ownerId, agentId, grantId, resource };
}

async function seedCashCredit(pool, ownerId, amount = "2.000000") {
  const amountUnits = BigInt(amount.replace(".", ""));
  await pool.query(`INSERT INTO oid_ledger_entry(
      id,owner_id,actor_owner_id,bonus_grant_id,operation_id,entry_type,source_kind,amount_units,
      available_delta_units,reserved_delta_units,expired_delta_units,cash_provenance,reason)
    VALUES($1,$2,$2,NULL,$3,'cash_credit','cash_usdc',$4,$4,0,0,$5,'Synthetic transaction fixture cash only')`,
  [key(), ownerId, `cashseed_${key().replaceAll("-", "")}`, amountUnits.toString(), `synthetic-cash-${key()}`]);
}

async function setFinancialPolicy(pool, ownerId, agentId, {
  allowCashShortfall = false,
  operationLimit = "10.000000",
  utcDayLimit = "20.000000",
  benchmarkLimit = "20.000000"
} = {}) {
  const asUnits = (value) => value === null ? null : BigInt(value.replace(".", "")).toString();
  await pool.query(`UPDATE oid_agent_financial_policy SET allow_cash_shortfall=$3,operation_limit_units=$4,
      utc_day_limit_units=$5,category_limits=$6::jsonb,revision=revision+1,updated_at=clock_timestamp()
    WHERE owner_id=$1 AND agent_id=$2`, [ownerId, agentId, allowCashShortfall, asUnits(operationLimit), asUnits(utcDayLimit),
    JSON.stringify({ benchmark: benchmarkLimit, forum: "20.000000" })]);
}

async function createQueuedRun(runs, deps, ports, owner, { cashCeiling = "0.000000" } = {}) {
  const release = await ports.provider.getActiveAdmissionRelease("training");
  const intentResult = await runs.createLaunchIntent(deps, {
    ownerId: owner.ownerId,
    agentId: owner.agentId,
    mode: "training",
    taskIds: openTaskIds,
    cashCeiling,
    expectedReleaseIdentity: release.releaseIdentity,
    expectedManifestHash: release.manifestHash,
    expectedQuotePrice: quotePrice,
    operationId: key()
  });
  const accepted = await runs.acceptLaunchIntent(deps, {
    ownerId: owner.ownerId,
    agentId: owner.agentId,
    accessGeneration: 1,
    intentId: intentResult.intent.id,
    operationId: key()
  });
  const claim = await runs.claimNextQueuedRun(deps, { claimId: key() });
  assert.ok(claim, "A queued fixture run should receive a bounded preparation claim");
  assert.equal(claim.run.id, accepted.run.id, "The claimed run must match the newly admitted fixture run");
  return { intent: intentResult.intent, release, run: accepted.run, claim };
}

async function runSnapshot(observer, runId) {
  const [runResult, taskResult, entryResult, reservationResult, budgetResult, slotResult, eventResult, outboxResult] = await Promise.all([
    observer.query(`SELECT id::text,status,release_identity,benchmark_version,manifest_hash,
        successor_preparation_policy_version,successor_preparation_timeout_seconds,started_at,overall_deadline,
        environment_id,environment_evidence_hash,cancellation_requested_at,cancellation_evidence_hash
      FROM oid_benchmark_run WHERE id=$1`, [runId]),
    observer.query(`SELECT task_index,task_id,status,started_at,deadline_at FROM oid_run_task WHERE run_id=$1 ORDER BY task_index`, [runId]),
    observer.query(`SELECT entry_type,source_kind,amount_units::text,available_delta_units::text,reserved_delta_units::text
      FROM oid_ledger_entry WHERE operation_id=$1 ORDER BY created_at,id`, [`rundeb_${runId.replaceAll("-", "")}`]),
    observer.query(`SELECT source_kind,amount_units::text,state FROM oid_run_reservation WHERE run_id=$1 ORDER BY source_kind`, [runId]),
    observer.query("SELECT state,amount_units::text,utc_day FROM oid_run_budget_hold WHERE run_id=$1", [runId]),
    observer.query("SELECT agent_id::text,state,released_at FROM oid_run_execution_slot WHERE run_id=$1", [runId]),
    observer.query("SELECT event_type,count(*)::int AS count FROM oid_run_event WHERE run_id=$1 GROUP BY event_type ORDER BY event_type", [runId]),
    observer.query("SELECT event_type,status,count(*)::int AS count FROM oid_run_outbox WHERE run_id=$1 GROUP BY event_type,status ORDER BY event_type,status", [runId])
  ]);
  return {
    run: runResult.rows[0] ?? null,
    tasks: taskResult.rows,
    debitEntries: entryResult.rows,
    reservations: reservationResult.rows,
    budgetHolds: budgetResult.rows,
    slots: slotResult.rows,
    events: eventResult.rows,
    outbox: outboxResult.rows
  };
}

export async function runStartCases({ databaseUrl, observerDatabaseUrl }) {
  const [{ createDatabase }, { loadConfig }, { issueBonusGrant, readOwnerBilling }, runs, preparationApi, releaseApi, taskActionApi, executorApi] = await Promise.all([
    import("../../owner-identity/dist/db.js"),
    import("../../owner-identity/dist/config.js"),
    import("../../owner-identity/dist/ledger.js"),
    import("../../owner-identity/dist/run-service.js"),
    import("../../owner-identity/dist/task-preparation.js"),
    import("../../owner-identity/dist/task-release.js"),
    import("../../owner-identity/dist/task-action-service.js"),
    import("../../owner-identity/dist/bef-task-executor.js")
  ]);
  assert.match(new URL(databaseUrl).pathname, /^\/oid_acceptance_[a-f0-9]{32}$/, "Run-start fixtures require an isolated acceptance database");
  const setup = new pg.Pool({ connectionString: databaseUrl, max: 2, application_name: "synthetic-run-start-fixture" });
  const observer = new pg.Pool({ connectionString: observerDatabaseUrl, max: 1, application_name: "synthetic-run-start-readonly-observer" });
  const { db, client } = createDatabase(loadConfig({ ...process.env, OID_DATABASE_URL: databaseUrl }));
  const ports = syntheticAdmissionPorts();
  const deps = {
    db,
    admissionReleaseProvider: ports.provider,
    executionReadinessProvider: ports.readinessProvider,
    intentTtlSeconds: 900,
    maxIntentTtlSeconds: 3600,
    queueWaitSeconds: 900,
    maxQueueWaitSeconds: 3600,
    executionCapacity: 16,
    maxPendingIntentsPerOwner: 20,
    maxPendingIntentsGlobal: 100,
    trainingOverallTimeoutSeconds: 1800,
    maxTrainingOverallTimeoutSeconds: 3600,
    successorPreparationPolicyVersion: runs.SUCCESSOR_PREPARATION_POLICY_VERSION,
    successorPreparationTimeoutSeconds: 180
  };

  try {
    const primaryOwner = await fixtureOwner(setup);
    await issueBonusGrant(db, {
      actorOwnerId: primaryOwner.ownerId,
      ownerId: primaryOwner.ownerId,
      operationId: key(),
      amount: "3.000000",
      reason: "Synthetic run-start transaction fixture only"
    });
    const primary = await createQueuedRun(runs, deps, ports, primaryOwner);
    assert.equal(primary.intent.successorPreparationPolicyVersion, runs.SUCCESSOR_PREPARATION_POLICY_VERSION);
    assert.equal(primary.intent.successorPreparationTimeoutSeconds, 180);
    const pinnedIdentity = primary.run.benchmarkVersion;
    const newerRelease = ports.activate("v2-after-admission");
    assert.notEqual(newerRelease.benchmarkVersion, pinnedIdentity);

    const startOperationId = key();
    const startInput = { runId: primary.run.id, claimId: primary.claim.claimId, operationId: startOperationId };
    const concurrentStarts = await Promise.all(Array.from({ length: 4 }, () => runs.startQueuedRun(deps, startInput)));
    assert.equal(new Set(concurrentStarts.map((result) => result.run.id)).size, 1);
    assert.equal(concurrentStarts.filter((result) => !result.replayed).length, 1,
      "Concurrent identical start operations must commit exactly one start");
    const retryStart = await runs.startQueuedRun(deps, startInput);
    assert.equal(retryStart.replayed, true, "A duplicate start retry must use the durable operation receipt");
    const primarySnapshot = await runSnapshot(observer, primary.run.id);
    assert.equal(primarySnapshot.run.status, "running");
    assert.equal(primarySnapshot.run.benchmark_version, primary.run.benchmarkVersion,
      "An admitted old release must start after the active pointer has changed");
    assert.equal(primarySnapshot.run.release_identity, primary.release.releaseIdentity);
    assert.equal(primarySnapshot.run.successor_preparation_policy_version, runs.SUCCESSOR_PREPARATION_POLICY_VERSION);
    assert.equal(primarySnapshot.run.successor_preparation_timeout_seconds, 180);
    assert.equal(primarySnapshot.tasks.length, openTaskIds.length);
    assert.equal(primarySnapshot.tasks[0].status, "active");
    assert.ok(primarySnapshot.tasks[0].deadline_at);
    assert.ok(new Date(primarySnapshot.run.overall_deadline) > new Date(primarySnapshot.run.started_at));
    assert.equal(primarySnapshot.debitEntries.length, 1, "The concurrent start race must debit the held bonus once");
    assert.equal(primarySnapshot.debitEntries[0].amount_units, quoteUnits);
    assert.equal(primarySnapshot.budgetHolds.length, 1);
    assert.equal(primarySnapshot.budgetHolds[0].state, "charged");
    assert.equal(primarySnapshot.slots.length, 1);
    assert.equal(primarySnapshot.slots[0].state, "running");
    assert.equal(primarySnapshot.events.find((event) => event.event_type === "run.started")?.count, 1);
    const primaryBilling = await readOwnerBilling(db, primaryOwner.ownerId);
    assert.equal(primaryBilling.bonus.available, "2.000000");
    assert.equal(primaryBilling.bonus.reserved, "0.000000");

    // A pre-start cancellation with a durable task-preparation intent must wait
    // for that exact preparation identity to be fenced before releasing holds
    // or the exclusive execution slot. All external ports below are synthetic.
    const preparingCancelOwner = await fixtureOwner(setup);
    await issueBonusGrant(db, { actorOwnerId: preparingCancelOwner.ownerId, ownerId: preparingCancelOwner.ownerId,
      operationId: key(), amount: "3.000000", reason: "Synthetic preparing-cancellation fixture only" });
    const preparingCancel = await createQueuedRun(runs, deps, ports, preparingCancelOwner);
    const preparationId = key(), leaseId = key(), dispatchId = key();
    const prepEnvironmentId = `synthetic-cancel-${preparationId.replaceAll("-", "")}`;
    const prepCaseHash = digest(`cancel-case:${preparationId}`);
    const prepStateHash = digest(`cancel-state:${preparationId}`);
    const prepIdentityHash = digest(`cancel-identity:${preparationId}`);
    const prepApplicationHash = digest(`cancel-app:${preparationId}`);
    await setup.query(`INSERT INTO oid_task_preparation_intent(
        preparation_id,run_id,task_index,claim_id,lease_id,environment_id,release_identity,manifest_hash,task_id,case_id,
        case_hash,initial_state_sha256,execution_identity_hash,environment_manifest_sha256,application_source_hash)
      VALUES($1,$2,0,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$7,$13)`, [
      preparationId, preparingCancel.run.id, preparingCancel.claim.claimId, leaseId, prepEnvironmentId,
      preparingCancel.release.releaseIdentity, preparingCancel.release.manifestHash, preparingCancel.run.taskIds[0],
      `synthetic-cancel-case-${preparationId}`, prepCaseHash, prepStateHash, prepIdentityHash, prepApplicationHash,
    ]);
    await setup.query("INSERT INTO oid_task_environment_lease(lease_id,preparation_id,environment_id) VALUES($1,$2,$3)",
      [leaseId, preparationId, prepEnvironmentId]);
    await setup.query(`INSERT INTO oid_task_preparation_observation(preparation_id,revision,status)
      VALUES($1,1,'preparing')`, [preparationId]);
    await setup.query("INSERT INTO oid_task_preparation_dispatch(preparation_id,dispatch_id) VALUES($1,$2)", [preparationId, dispatchId]);
    const preparingCancellation = await runs.requestRunCancellation(db, {
      ownerId: preparingCancelOwner.ownerId, runId: preparingCancel.run.id, operationId: key(), reason: "owner_voluntary"
    });
    assert.equal(preparingCancellation.run.status, "cancellation_requested");
    let preparationState = (await observer.query(`SELECT r.status,r.started_at,rr.state AS reservation_state,b.state AS budget_state,
        s.state AS slot_state,l.state AS lease_state,d.state AS dispatch_state,o.payload_json
      FROM oid_benchmark_run r JOIN oid_run_reservation rr ON rr.run_id=r.id
      JOIN oid_run_budget_hold b ON b.run_id=r.id JOIN oid_run_execution_slot s ON s.run_id=r.id
      JOIN oid_task_environment_lease l ON l.preparation_id=$2
      JOIN oid_task_preparation_dispatch d ON d.preparation_id=$2
      JOIN oid_run_outbox o ON o.run_id=r.id AND o.event_type='run.cancel.requested'
      WHERE r.id=$1`, [preparingCancel.run.id, preparationId])).rows[0];
    assert.equal(preparationState.status, "cancellation_requested");
    assert.equal(preparationState.started_at, null);
    assert.equal(preparationState.reservation_state, "held");
    assert.equal(preparationState.budget_state, "held");
    assert.equal(preparationState.slot_state, "preparing");
    assert.equal(preparationState.lease_state, "leased");
    assert.equal(preparationState.dispatch_state, "dispatching");
    assert.deepEqual(preparationState.payload_json.taskPreparation, { taskIndex: 0, preparationId, generationId: null },
      "the durable cancellation command pins the original preparation ID and unknown generation");
    const unconfirmedFenceCalls = [];
    const unconfirmedFencer = { async fenceAndStop(input) {
      unconfirmedFenceCalls.push(input);
      // A generic run fence cannot stand in for the exact preparation ID.
      return { fenced: true, evidenceHash: digest(`unbound-fence:${preparationId}`) };
    } };
    const waitingCancel = await runs.consumeRunCancellationOutbox(db, unconfirmedFencer, 50);
    assert.equal(waitingCancel.awaitingExecutor, 1);
    assert.deepEqual(unconfirmedFenceCalls.map((item) => item.taskPreparation), [{ taskIndex: 0, preparationId, generationId: null }]);
    preparationState = (await observer.query(`SELECT r.status,rr.state AS reservation_state,b.state AS budget_state,
        s.state AS slot_state,l.state AS lease_state,d.state AS dispatch_state,
        (SELECT count(*)::int FROM oid_run_event e WHERE e.run_id=r.id AND e.event_type='run.cancelled.before_start') AS cancel_event_count
      FROM oid_benchmark_run r JOIN oid_run_reservation rr ON rr.run_id=r.id
      JOIN oid_run_budget_hold b ON b.run_id=r.id JOIN oid_run_execution_slot s ON s.run_id=r.id
      JOIN oid_task_environment_lease l ON l.preparation_id=$2
      JOIN oid_task_preparation_dispatch d ON d.preparation_id=$2
      WHERE r.id=$1`, [preparingCancel.run.id, preparationId])).rows[0];
    assert.deepEqual(preparationState, { status: "cancellation_requested", reservation_state: "held", budget_state: "held",
      slot_state: "preparing", lease_state: "leased", dispatch_state: "dispatching", cancel_event_count: 0 },
    "a failed exact fence retains financial holds, slot, lease and in-flight dispatch without terminal cancellation");
    const holdsRetainedUntilFence = preparationState.reservation_state === "held" && preparationState.budget_state === "held" &&
      preparationState.slot_state === "preparing" && preparationState.lease_state === "leased";

    const confirmedFenceHash = digest(`synthetic-preparation-fence:${preparationId}`);
    const preparationFenceCalls = [];
    const adapterCredentialClears = [];
    const unboundSessions = [];
    const bridgedFencer = preparationApi.createTaskPreparationCancellationExecutor({
      db,
      releaseSource: { async getValidatedReleaseRecord() { return null; } },
      environmentSelector: { async selectEnvironment() { throw new Error("unused cancellation selector"); } },
      preparationAdapter: {
        async prepare() { throw new Error("cancellation must not retry preparation"); },
        async reconcile() { throw new Error("cancellation must not reconcile by creating a generation"); },
        async fence({ intent, generationId }) {
          preparationFenceCalls.push({ preparationId: intent.preparationId, generationId });
          return { confirmed: true, preparationId: intent.preparationId, leaseId: intent.leaseId,
            environmentId: intent.environmentId, generationId,
            evidence: { path: `artifacts/runs/synthetic-task-preparation-cancellation/${preparationId}.json`,
              sha256: confirmedFenceHash, boundary: "actual_tool_http_x402_local_evm_application_store" } };
        },
        clearCredentials(id) { adapterCredentialClears.push(id); },
      }
    }, { unbindSession(runId, taskIndex) { unboundSessions.push({ runId, taskIndex }); } });
    const firstPreparationFence = await bridgedFencer.fenceAndStop({ runId: preparingCancel.run.id,
      agentId: preparingCancelOwner.agentId, reason: "owner_voluntary", taskPreparation: { taskIndex: 0, preparationId, generationId: null } });
    assert.equal(firstPreparationFence.fenced, true);
    assert.deepEqual(firstPreparationFence.taskPreparation, { taskIndex: 0, preparationId, generationId: null });
    assert.equal(firstPreparationFence.evidenceHash, confirmedFenceHash);
    const fencedBeforeFinalize = (await observer.query(`SELECT r.status,rr.state AS reservation_state,b.state AS budget_state,
        s.state AS slot_state,l.state AS lease_state,d.state AS dispatch_state,
        (SELECT count(*)::int FROM oid_run_event e WHERE e.run_id=r.id AND e.event_type='run.cancelled.before_start') AS cancel_event_count
      FROM oid_benchmark_run r JOIN oid_run_reservation rr ON rr.run_id=r.id
      JOIN oid_run_budget_hold b ON b.run_id=r.id JOIN oid_run_execution_slot s ON s.run_id=r.id
      JOIN oid_task_environment_lease l ON l.preparation_id=$2
      JOIN oid_task_preparation_dispatch d ON d.preparation_id=$2 WHERE r.id=$1`,
      [preparingCancel.run.id, preparationId])).rows[0];
    assert.deepEqual(fencedBeforeFinalize, { status: "cancellation_requested", reservation_state: "held", budget_state: "held",
      slot_state: "preparing", lease_state: "fenced", dispatch_state: "unknown", cancel_event_count: 0 },
    "a process loss after environment fencing keeps cancellation pending until the run transaction finalizes");
    await setup.query(`UPDATE oid_run_outbox SET payload_json=jsonb_set(payload_json,'{taskPreparation}',
      (payload_json->'taskPreparation')-'taskIndex') WHERE run_id=$1 AND event_type='run.cancel.requested'`, [preparingCancel.run.id]);
    const legacyPreparationPin = (await observer.query(`SELECT payload_json->'taskPreparation' AS pin FROM oid_run_outbox
      WHERE run_id=$1 AND event_type='run.cancel.requested'`, [preparingCancel.run.id])).rows[0].pin;
    assert.deepEqual(legacyPreparationPin, { preparationId, generationId: null },
      "legacy durable cancellation pins without taskIndex are retained for exact task-0 compatibility");
    const finalizedPreparingCancellation = await runs.consumeRunCancellationOutbox(db, bridgedFencer, 50);
    assert.equal(finalizedPreparingCancellation.awaitingExecutor, 0);
    assert.deepEqual(preparationFenceCalls, [{ preparationId, generationId: null }]);
    assert.deepEqual(adapterCredentialClears, [preparationId, preparationId], "adapter credential clearing is safe to repeat after a fence retry");
    assert.deepEqual(unboundSessions, [{ runId: preparingCancel.run.id, taskIndex: 0 }, { runId: preparingCancel.run.id, taskIndex: 0 }],
      "session unbinding is idempotently repeated after a lost run-finalization response");
    await runs.consumeRunCancellationOutbox(db, bridgedFencer, 50);
    assert.equal(preparationFenceCalls.length, 1, "a delivered cancellation fence is not replayed");
    const preparedCancelFinal = (await observer.query(`SELECT r.status,r.cancellation_evidence_hash,rr.state AS reservation_state,
        b.state AS budget_state,s.run_id AS slot_run_id,c.status AS claim_status,l.state AS lease_state,
        l.fence_evidence->>'generationId' AS owner_fenced_generation,d.state AS dispatch_state,
        (SELECT count(*)::int FROM oid_run_event e WHERE e.run_id=r.id AND e.event_type='run.cancelled.before_start') AS cancel_event_count,
        (SELECT count(*)::int FROM oid_run_outbox o WHERE o.run_id=r.id AND o.event_type='run.cancel.requested' AND o.status='delivered') AS cancel_outbox_delivered
      FROM oid_benchmark_run r JOIN oid_run_reservation rr ON rr.run_id=r.id
      JOIN oid_run_budget_hold b ON b.run_id=r.id LEFT JOIN oid_run_execution_slot s ON s.run_id=r.id
      JOIN oid_run_dispatch_claim c ON c.run_id=r.id JOIN oid_task_environment_lease l ON l.preparation_id=$2
      JOIN oid_task_preparation_dispatch d ON d.preparation_id=$2 WHERE r.id=$1`,
      [preparingCancel.run.id, preparationId])).rows[0];
    assert.equal(preparedCancelFinal.status, "cancelled");
    assert.equal(preparedCancelFinal.cancellation_evidence_hash, confirmedFenceHash);
    assert.equal(preparedCancelFinal.reservation_state, "released");
    assert.equal(preparedCancelFinal.budget_state, "released");
    assert.equal(preparedCancelFinal.slot_run_id, null);
    assert.equal(preparedCancelFinal.claim_status, "released");
    assert.equal(preparedCancelFinal.lease_state, "fenced");
    assert.equal(preparedCancelFinal.owner_fenced_generation, null, "a null owner generation is not inferred from the fence GET");
    assert.equal(preparedCancelFinal.dispatch_state, "unknown", "fencing settles the original in-flight PUT without retry");
    assert.equal(preparedCancelFinal.cancel_event_count, 1);
    assert.equal(preparedCancelFinal.cancel_outbox_delivered, 1);

    // Queue expiry must use the same exact preparation fence as explicit
    // cancellation. Until it succeeds, the preparing run keeps every hold,
    // its exclusive slot, and the environment lease.
    const preparingExpiryOwner = await fixtureOwner(setup);
    await issueBonusGrant(db, { actorOwnerId: preparingExpiryOwner.ownerId, ownerId: preparingExpiryOwner.ownerId,
      operationId: key(), amount: "3.000000", reason: "Synthetic preparing-expiry fixture only" });
    const preparingExpiry = await createQueuedRun(runs, deps, ports, preparingExpiryOwner);
    const expiryPreparationId = key(), expiryLeaseId = key(), expiryDispatchId = key();
    const expiryEnvironmentId = `synthetic-expiry-${expiryPreparationId.replaceAll("-", "")}`;
    await setup.query(`INSERT INTO oid_task_preparation_intent(
        preparation_id,run_id,task_index,claim_id,lease_id,environment_id,release_identity,manifest_hash,task_id,case_id,
        case_hash,initial_state_sha256,execution_identity_hash,environment_manifest_sha256,application_source_hash)
      VALUES($1,$2,0,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$7,$13)`, [
      expiryPreparationId, preparingExpiry.run.id, preparingExpiry.claim.claimId, expiryLeaseId, expiryEnvironmentId,
      preparingExpiry.release.releaseIdentity, preparingExpiry.release.manifestHash, preparingExpiry.run.taskIds[0],
      `synthetic-expiry-case-${expiryPreparationId}`, digest(`expiry-case:${expiryPreparationId}`),
      digest(`expiry-state:${expiryPreparationId}`), digest(`expiry-identity:${expiryPreparationId}`), digest(`expiry-app:${expiryPreparationId}`),
    ]);
    await setup.query("INSERT INTO oid_task_environment_lease(lease_id,preparation_id,environment_id) VALUES($1,$2,$3)",
      [expiryLeaseId, expiryPreparationId, expiryEnvironmentId]);
    await setup.query("INSERT INTO oid_task_preparation_observation(preparation_id,revision,status) VALUES($1,1,'preparing')",
      [expiryPreparationId]);
    await setup.query("INSERT INTO oid_task_preparation_dispatch(preparation_id,dispatch_id) VALUES($1,$2)",
      [expiryPreparationId, expiryDispatchId]);
    await setup.query("UPDATE oid_benchmark_run SET queued_at=clock_timestamp()-interval '2 seconds',queue_deadline=clock_timestamp()-interval '1 second' WHERE id=$1",
      [preparingExpiry.run.id]);
    await runs.expireQueuedRuns(db);
    let expiryPending = (await observer.query(`SELECT r.status,r.terminal_reason,rr.state AS reservation_state,b.state AS budget_state,
        s.state AS slot_state,l.state AS lease_state,d.state AS dispatch_state,o.payload_json
      FROM oid_benchmark_run r JOIN oid_run_reservation rr ON rr.run_id=r.id
      JOIN oid_run_budget_hold b ON b.run_id=r.id JOIN oid_run_execution_slot s ON s.run_id=r.id
      JOIN oid_task_environment_lease l ON l.preparation_id=$2
      JOIN oid_task_preparation_dispatch d ON d.preparation_id=$2
      JOIN oid_run_outbox o ON o.run_id=r.id AND o.event_type='run.cancel.requested'
      WHERE r.id=$1`, [preparingExpiry.run.id, expiryPreparationId])).rows[0];
    assert.equal(expiryPending.status, "cancellation_requested");
    assert.equal(expiryPending.terminal_reason, null, "expiry is not terminal before the environment fence");
    assert.equal(expiryPending.reservation_state, "held");
    assert.equal(expiryPending.budget_state, "held");
    assert.equal(expiryPending.slot_state, "preparing");
    assert.equal(expiryPending.lease_state, "leased");
    assert.equal(expiryPending.dispatch_state, "dispatching");
    assert.deepEqual(expiryPending.payload_json.taskPreparation, { taskIndex: 0, preparationId: expiryPreparationId, generationId: null },
      "queue expiry must fence the exact preparation identity even when generation is unknown");
    const expiryWithoutExecutor = await runs.consumeRunCancellationOutbox(db, undefined, 50);
    assert.equal(expiryWithoutExecutor.awaitingExecutor, 1);
    const expiryUnconfirmed = await runs.consumeRunCancellationOutbox(db, { async fenceAndStop() { return { fenced: false }; } }, 50);
    assert.equal(expiryUnconfirmed.awaitingExecutor, 1);
    expiryPending = (await observer.query(`SELECT r.status,rr.state AS reservation_state,b.state AS budget_state,
        s.state AS slot_state,l.state AS lease_state FROM oid_benchmark_run r
      JOIN oid_run_reservation rr ON rr.run_id=r.id JOIN oid_run_budget_hold b ON b.run_id=r.id
      JOIN oid_run_execution_slot s ON s.run_id=r.id JOIN oid_task_environment_lease l ON l.preparation_id=$2
      WHERE r.id=$1`, [preparingExpiry.run.id, expiryPreparationId])).rows[0];
    assert.deepEqual(expiryPending, { status: "cancellation_requested", reservation_state: "held", budget_state: "held",
      slot_state: "preparing", lease_state: "leased" }, "an unconfirmed expiry fence must retain the run's resources");
    const expiryFenceHash = digest(`synthetic-expiry-fence:${expiryPreparationId}`);
    const expiryFencer = preparationApi.createTaskPreparationCancellationExecutor({
      db,
      releaseSource: { async getValidatedReleaseRecord() { return null; } },
      environmentSelector: { async selectEnvironment() { throw new Error("unused expiry cancellation selector"); } },
      preparationAdapter: {
        async fence({ intent, generationId }) {
          return { confirmed: true, preparationId: intent.preparationId, leaseId: intent.leaseId,
            environmentId: intent.environmentId, generationId,
            evidence: { path: `artifacts/runs/synthetic-task-preparation-expiry/${expiryPreparationId}.json`,
              sha256: expiryFenceHash, boundary: "actual_tool_http_x402_local_evm_application_store" } };
        },
        clearCredentials() {},
      }
    }, { unbindSession() {} });
    const expiryFenced = await runs.consumeRunCancellationOutbox(db, expiryFencer, 50);
    assert.equal(expiryFenced.awaitingExecutor, 0);
    const preparedExpiryFinal = (await observer.query(`SELECT r.status,r.terminal_reason,r.cancellation_evidence_hash,
        rr.state AS reservation_state,b.state AS budget_state,s.run_id AS slot_run_id,c.status AS claim_status,
        l.state AS lease_state,l.fence_evidence->>'generationId' AS owner_fenced_generation,d.state AS dispatch_state,
        (SELECT count(*)::int FROM oid_run_event e WHERE e.run_id=r.id AND e.event_type='run.queue_expired') AS expiry_event_count,
        (SELECT count(*)::int FROM oid_run_outbox o WHERE o.run_id=r.id AND o.event_type='run.cancel.requested' AND o.status='delivered') AS cancel_outbox_delivered,
        (SELECT count(*)::int FROM oid_run_outbox o WHERE o.run_id=r.id AND o.event_type='run.expired' AND o.status='pending') AS expiry_outbox_pending
      FROM oid_benchmark_run r JOIN oid_run_reservation rr ON rr.run_id=r.id
      JOIN oid_run_budget_hold b ON b.run_id=r.id LEFT JOIN oid_run_execution_slot s ON s.run_id=r.id
      JOIN oid_run_dispatch_claim c ON c.run_id=r.id JOIN oid_task_environment_lease l ON l.preparation_id=$2
      JOIN oid_task_preparation_dispatch d ON d.preparation_id=$2 WHERE r.id=$1`,
      [preparingExpiry.run.id, expiryPreparationId])).rows[0];
    assert.equal(preparedExpiryFinal.status, "expired");
    assert.equal(preparedExpiryFinal.terminal_reason, "queue_deadline_expired");
    assert.equal(preparedExpiryFinal.cancellation_evidence_hash, expiryFenceHash);
    assert.equal(preparedExpiryFinal.reservation_state, "released");
    assert.equal(preparedExpiryFinal.budget_state, "released");
    assert.equal(preparedExpiryFinal.slot_run_id, null);
    assert.equal(preparedExpiryFinal.claim_status, "released");
    assert.equal(preparedExpiryFinal.lease_state, "fenced");
    assert.equal(preparedExpiryFinal.owner_fenced_generation, null);
    assert.equal(preparedExpiryFinal.dispatch_state, "unknown");
    assert.equal(preparedExpiryFinal.expiry_event_count, 1);
    assert.equal(preparedExpiryFinal.cancel_outbox_delivered, 1);
    assert.equal(preparedExpiryFinal.expiry_outbox_pending, 1);

    // Real database scope enforcement with a deliberately synthetic sealed case.
    // This does not activate a release or claim actual task/executor readiness.
    const { getCurrentAgentTask } = await import("../../owner-identity/dist/task-issuance.js");
    const taskPrincipal = { ...primaryOwner, accessGeneration: 1, credentialId: key() };
    const taskCase = {
      taskId: "S1", caseId: `synthetic-issuance-${primary.run.id}`, caseHash: digest(`synthetic:S1:${primary.run.id}`),
      rubricHash: digest("synthetic:S1-rubric"), executionIdentityHash: digest("synthetic:execution-identity"),
      initialState: { stateSha256: digest("synthetic:S1-initial-state") }, mandatoryRules: ["no_wrong_or_extra_principal", "native_reserve"],
      objective: { tokenAssetId: "USDC", sender: "participant", recipient: "0x1111111111111111111111111111111111111111",
        exactPrincipalUnits: "100000", nativeReserveWei: "100000000000000", unrelatedEffectBaselineSha256: "sealed-baseline-sentinel" },
      referencePath: { evidence: "sealed-reference-sentinel" }, initialStateEvidence: "sealed-state-sentinel"
    };
    const executionIdentity = { localChainId: 8453, localNetwork: "synthetic-local-fork", assets: [], contracts: [],
      environmentManifestSha256: digest("synthetic:environment-manifest"), x402ServiceSha256: digest("synthetic:application-source") };
    const taskSource = {
      async getValidatedReleaseRecord(identity, manifestHash) {
        assert.equal(identity, primary.release.releaseIdentity, "Task issuance must retain the admitted old release");
        assert.equal(manifestHash, primary.release.manifestHash);
        return { ...primary.release, releaseIdentity: identity, manifestHash, manifest: {
          costPolicy: { policyVersion: "synthetic-issuance-costs", missingFeeEvidence: "unknown" },
          executionIdentity, cases: { training: [taskCase] }
        } };
      }
    };
    const taskDeps = { db, taskReleaseSource: taskSource };
    // Synthetic identity fixture for the issuer contract only. It is not a real BEF preparation or executor proof.
    const taskEnvId = `synthetic-task-env-${primary.run.id}`;
    const prepId = key(), prepLeaseId = key(), prepGenerationId = key();
    const prepClaimId = (await setup.query('SELECT claim_id FROM oid_run_dispatch_claim WHERE run_id=$1', [primary.run.id])).rows[0].claim_id;
    const syntheticFixtureEvidence = { path: `synthetic-run-start/${primary.run.id}-fixture.json`,
      sha256: digest(`fixture:${primary.run.id}`), boundary: "actual_tool_http_x402_local_evm_application_store" };
    const syntheticBaselineEvidence = { path: `synthetic-run-start/${primary.run.id}-baseline.json`,
      sha256: digest(`baseline:${primary.run.id}`), boundary: "actual_tool_http_x402_local_evm_application_store" };
    await setup.query(`INSERT INTO oid_task_preparation_intent(preparation_id,run_id,task_index,claim_id,lease_id,environment_id,
        release_identity,manifest_hash,task_id,case_id,case_hash,initial_state_sha256,execution_identity_hash,
        environment_manifest_sha256,application_source_hash)
      VALUES($1,$2,0,$3,$4,$5,$6,$7,'S1',$8,$9,$10,$11,$12,$13)`,
    [prepId, primary.run.id, prepClaimId, prepLeaseId, taskEnvId, primary.release.releaseIdentity, primary.release.manifestHash,
      taskCase.caseId, taskCase.caseHash, taskCase.initialState.stateSha256, taskCase.executionIdentityHash,
      executionIdentity.environmentManifestSha256, executionIdentity.x402ServiceSha256]);
    await setup.query(`INSERT INTO oid_task_environment_lease(lease_id,preparation_id,environment_id,state)
      VALUES($1,$2,$3,'leased')`, [prepLeaseId, prepId, taskEnvId]);
    await setup.query(`INSERT INTO oid_task_preparation_observation(preparation_id,revision,status)
      VALUES($1,1,'preparing')`, [prepId]);
    await setup.query(`INSERT INTO oid_task_preparation_observation(preparation_id,revision,status,generation_id,participant_id,payer_address,
        baseline_state_sha256,fixture_evidence,baseline_evidence)
      VALUES($1,2,'ready',$2,'synthetic-participant',$3,$4,$5::jsonb,$6::jsonb)`,
    [prepId, prepGenerationId, `0x${'1'.repeat(40)}`, taskCase.initialState.stateSha256,
      JSON.stringify(syntheticFixtureEvidence), JSON.stringify(syntheticBaselineEvidence)]);
    await setup.query(`INSERT INTO oid_task_execution_binding(run_id,task_index,env_id,generation_id,manifest_hash,
        application_source_hash,participant_id,payer_address)
      VALUES($1,0,$2,$3,$4,$5,'synthetic-participant',$6)`,
    [primary.run.id, taskEnvId, prepGenerationId, executionIdentity.environmentManifestSha256,
      executionIdentity.x402ServiceSha256, `0x${'1'.repeat(40)}`]);
    const compatibilityPointer = `legacy-run-environment-${primary.run.id}`;
    await setup.query('UPDATE oid_benchmark_run SET environment_id=$2 WHERE id=$1', [primary.run.id, compatibilityPointer]);
    const issuance = await getCurrentAgentTask(taskDeps, taskPrincipal, primary.run.id);
    assert.equal(issuance.task.taskId, "S1");
    assert.equal(issuance.task.taskIndex, 0);
    assert.equal(issuance.task.conditions.exactPrincipalUnits, "100000");
    assert.equal(issuance.task.environmentId, taskEnvId, "issuance uses the active task preparation instead of the run compatibility pointer");
    assert.notEqual(issuance.task.environmentId, compatibilityPointer);
    assert.equal(JSON.stringify(issuance).includes("sentinel"), false);
    await assert.rejects(getCurrentAgentTask(taskDeps, { ...taskPrincipal, agentId: key() }, primary.run.id),
      (error) => error.code === "AGENT_ACCESS_REVOKED");
    await assert.rejects(getCurrentAgentTask(taskDeps, { ...taskPrincipal, accessGeneration: 2 }, primary.run.id),
      (error) => error.code === "AGENT_ACCESS_REVOKED");
    for (const state of ["expired", "revoked"]) {
      const grantId = key();
      await setup.query(`INSERT INTO oid_agent_access_grant(id,owner_id,agent_id,operation_id,resource,role,access_generation,expires_at,revoked_at)
        VALUES($1,$2,$3,$4,$5,'agent',1,CASE WHEN $6='expired' THEN clock_timestamp()-interval '1 second'
          ELSE clock_timestamp()+interval '1 day' END,CASE WHEN $6='revoked' THEN clock_timestamp() ELSE NULL END)`,
      [grantId, primaryOwner.ownerId, primaryOwner.agentId, key(), primaryOwner.resource, state]);
      await assert.rejects(getCurrentAgentTask(taskDeps, { ...taskPrincipal, grantId }, primary.run.id),
        (error) => error.code === "AGENT_ACCESS_REVOKED", `The exact ${state} grant must be rechecked inside issuance`);
      await assert.rejects(runs.acceptLaunchIntent(deps, { ownerId: primaryOwner.ownerId, agentId: primaryOwner.agentId,
        accessGeneration: 1, intentId: primary.intent.id, operationId: key(), verifiedGrant: { id: grantId, resource: primaryOwner.resource } }),
      (error) => error.code === "AGENT_ACCESS_REVOKED", "Acceptance retries must recheck the resolved credential grant");
    }
    const foreignTaskOwner = await fixtureOwner(setup);
    await assert.rejects(getCurrentAgentTask(taskDeps, { ...foreignTaskOwner, accessGeneration: 1 }, primary.run.id),
      (error) => error.code === "RUN_NOT_FOUND", "An authorized foreign owner must not see another run's case");
    await assert.rejects(getCurrentAgentTask({ db, taskReleaseSource: { async getValidatedReleaseRecord() { return null; } } },
      taskPrincipal, primary.run.id), (error) => error.code === "PINNED_RELEASE_UNAVAILABLE");
    const Fastify = createRequire(new URL("../../owner-identity/package.json", import.meta.url))("fastify");
    const { registerRunRoutes, registerRunIntentMcpTools } = await import("../../owner-identity/dist/run-routes.js");
    const taskHttp = Fastify({ logger: false });
    const syntheticBearer = `synthetic-task-${key()}`;
    const taskHost = "task-issuance.example.invalid";
    registerRunRoutes(taskHttp, { ...deps, taskReleaseSource: taskSource, publicOrigin: `http://${taskHost}`,
      rateLimitMax: 100, async rateLimit() {}, async requireOrigin() {}, async resolveOwner() { throw new Error("Owner route unused"); },
      async resolveAgentPrincipal(bearer) { return bearer === syntheticBearer ? taskPrincipal : undefined; } });
    try {
      const url = await taskHttp.listen({ host: "127.0.0.1", port: 0 });
      const taskUrl = `${url}/api/agent/runs/${primary.run.id}/current-task`;
      // Native HTTP deliberately preserves Host so the host-policy negatives
      // exercise the actual route instead of fetch's forbidden-header handling.
      const taskFetch = (target, { headers } = {}) => new Promise((resolve, reject) => {
        const req = httpRequest(target, { headers }, (response) => {
          const chunks = [];
          response.on("data", (chunk) => chunks.push(chunk));
          response.on("end", () => resolve(new Response(Buffer.concat(chunks), { status: response.statusCode, headers: response.headers })));
          response.on("error", reject);
        });
        req.on("error", reject); req.end();
      });
      const taskResponse = await taskFetch(taskUrl, { headers: { host: taskHost, authorization: `Bearer ${syntheticBearer}` } });
      assert.equal(taskResponse.status, 200);
      assert.equal(taskResponse.headers.get("cache-control"), "no-store");
      assert.equal(taskResponse.headers.get("vary"), "Authorization");
      assert.deepEqual(await taskResponse.json(), issuance);
      assert.equal((await taskFetch(taskUrl, { headers: { host: taskHost } })).status, 401);
      assert.equal((await taskFetch(taskUrl, { headers: { host: taskHost, authorization: "Bearer invalid" } })).status, 401);
      assert.equal((await taskFetch(taskUrl, { headers: { host: taskHost, authorization: `Bearer ${syntheticBearer}`, origin: "https://foreign.example.invalid" } })).status, 403);
      assert.equal((await taskFetch(taskUrl, { headers: { host: "foreign.example.invalid", authorization: `Bearer ${syntheticBearer}` } })).status, 421);
      const tools = new Map();
      registerRunIntentMcpTools({ registerTool(name, _schema, handler) { tools.set(name, handler); } }, taskPrincipal, { ...deps, taskReleaseSource: taskSource });
      const mcpIssued = await tools.get("runs.current_task")({ runId: primary.run.id });
      assert.deepEqual(mcpIssued.structuredContent, issuance);
    } finally { await taskHttp.close(); }
    const revoker = await setup.connect();
    let staleIssuance;
    try {
      await revoker.query("BEGIN");
      const revokerPid = (await revoker.query("SELECT pg_backend_pid() AS pid")).rows[0].pid;
      await revoker.query("SELECT id FROM oid_agent WHERE id=$1 FOR NO KEY UPDATE", [primaryOwner.agentId]);
      staleIssuance = getCurrentAgentTask(taskDeps, taskPrincipal, primary.run.id).then(
        () => ({ denied: false }), (error) => ({ denied: error.code === "AGENT_ACCESS_REVOKED" }));
      let observedBlocked = false;
      for (let attempt = 0; attempt < 100; attempt += 1) {
        const blocked = (await setup.query(`SELECT EXISTS(SELECT 1 FROM pg_stat_activity
          WHERE $1::int=ANY(pg_blocking_pids(pid))) AS blocked`, [revokerPid])).rows[0].blocked;
        if (blocked) { observedBlocked = true; break; }
        await new Promise((resolve) => setTimeout(resolve, 20));
      }
      assert.equal(observedBlocked, true, "Task issuance must block on the mutation's agent-row lock");
      await revoker.query("UPDATE oid_agent_access_grant SET revoked_at=clock_timestamp(),revocation_reason='replaced' WHERE id=$1", [taskPrincipal.grantId]);
      await revoker.query("UPDATE oid_agent SET access_revision=access_revision+1 WHERE id=$1", [primaryOwner.agentId]);
      await revoker.query("COMMIT");
      assert.deepEqual(await staleIssuance, { denied: true }, "A principal resolved before replacement must not disclose its case afterward");
    } catch (error) {
      await revoker.query("ROLLBACK").catch(() => undefined);
      if (staleIssuance) await staleIssuance;
      throw error;
    } finally { revoker.release(); }
    const successorGrantId = key();
    await setup.query(`INSERT INTO oid_agent_access_grant(id,owner_id,agent_id,operation_id,resource,role,access_generation,expires_at)
      VALUES($1,$2,$3,$4,$5,'agent',1,clock_timestamp()+interval '1 day')`,
    [successorGrantId, primaryOwner.ownerId, primaryOwner.agentId, key(), primaryOwner.resource]);
    taskPrincipal.grantId = successorGrantId;

    const restoredModeOwner = await fixtureOwner(setup);
    await issueBonusGrant(db, { actorOwnerId: restoredModeOwner.ownerId, ownerId: restoredModeOwner.ownerId,
      operationId: key(), amount: "2.000000", reason: "Synthetic removed-and-restored mode start fixture" });
    const restoredModeRun = await createQueuedRun(runs, deps, ports, restoredModeOwner);
    await setup.query("UPDATE oid_agent_policy SET training=false,revision=revision+1 WHERE agent_id=$1", [restoredModeOwner.agentId]);
    await setup.query("UPDATE oid_agent_policy SET training=true,revision=revision+1 WHERE agent_id=$1", [restoredModeOwner.agentId]);
    const removedModeStart = await runs.startQueuedRun(deps, {
      runId: restoredModeRun.run.id, claimId: restoredModeRun.claim.claimId, operationId: key(),
    });
    assert.equal(removedModeStart.run.status, "cancelled", "Restoring mode permission must not revive a run affected by its earlier removal");
    const removedModeSnapshot = await runSnapshot(observer, restoredModeRun.run.id);
    assert.equal(removedModeSnapshot.debitEntries.length, 0);
    assert.equal(removedModeSnapshot.reservations[0].state, "released");

    const operationLimitOwner = await fixtureOwner(setup);
    await issueBonusGrant(db, { actorOwnerId: operationLimitOwner.ownerId, ownerId: operationLimitOwner.ownerId,
      operationId: key(), amount: "2.000000", reason: "Synthetic current-operation-limit fixture only" });
    const operationLimitRun = await createQueuedRun(runs, deps, ports, operationLimitOwner);
    assert.deepEqual(await getCurrentAgentTask(taskDeps, { ...operationLimitOwner, accessGeneration: 1 }, operationLimitRun.run.id), { task: null },
      "Preparing runs must not disclose their case before atomic start");
    await setFinancialPolicy(setup, operationLimitOwner.ownerId, operationLimitOwner.agentId, { operationLimit: "0.500000" });
    const operationDenied = await runs.startQueuedRun(deps, {
      runId: operationLimitRun.run.id, claimId: operationLimitRun.claim.claimId, operationId: key()
    });
    assert.equal(operationDenied.run.status, "cancelled");
    const operationDeniedSnapshot = await runSnapshot(observer, operationLimitRun.run.id);
    assert.equal(operationDeniedSnapshot.debitEntries.length, 0);
    assert.deepEqual(operationDeniedSnapshot.reservations.map(({ source_kind, state }) => [source_kind, state]), [["tester_bonus", "released"]]);
    assert.equal(operationDeniedSnapshot.budgetHolds[0].state, "released");
    const operationDeniedBilling = await readOwnerBilling(db, operationLimitOwner.ownerId);
    assert.equal(operationDeniedBilling.bonus.available, "2.000000");
    assert.equal(operationDeniedBilling.bonus.reserved, "0.000000");

    const dayLimitOwner = await fixtureOwner(setup);
    await issueBonusGrant(db, { actorOwnerId: dayLimitOwner.ownerId, ownerId: dayLimitOwner.ownerId,
      operationId: key(), amount: "2.000000", reason: "Synthetic current-UTC-day-limit fixture only" });
    const dayLimitRun = await createQueuedRun(runs, deps, ports, dayLimitOwner);
    await setFinancialPolicy(setup, dayLimitOwner.ownerId, dayLimitOwner.agentId, { utcDayLimit: "0.500000" });
    const dayDenied = await runs.startQueuedRun(deps, {
      runId: dayLimitRun.run.id, claimId: dayLimitRun.claim.claimId, operationId: key()
    });
    assert.equal(dayDenied.run.status, "cancelled");
    const dayDeniedSnapshot = await runSnapshot(observer, dayLimitRun.run.id);
    assert.equal(dayDeniedSnapshot.debitEntries.length, 0);
    assert.deepEqual(dayDeniedSnapshot.reservations.map(({ source_kind, state }) => [source_kind, state]), [["tester_bonus", "released"]]);
    assert.equal(dayDeniedSnapshot.budgetHolds[0].state, "released");

    const cashOwner = await fixtureOwner(setup, { allowCashShortfall: true });
    await seedCashCredit(setup, cashOwner.ownerId);
    const cashRun = await createQueuedRun(runs, deps, ports, cashOwner, { cashCeiling: quotePrice });
    await setFinancialPolicy(setup, cashOwner.ownerId, cashOwner.agentId, { allowCashShortfall: false });
    const cashDenied = await runs.startQueuedRun(deps, {
      runId: cashRun.run.id, claimId: cashRun.claim.claimId, operationId: key()
    });
    assert.equal(cashDenied.run.status, "cancelled");
    const cashDeniedSnapshot = await runSnapshot(observer, cashRun.run.id);
    assert.equal(cashDeniedSnapshot.debitEntries.length, 0);
    assert.deepEqual(cashDeniedSnapshot.reservations.map(({ source_kind, state }) => [source_kind, state]), [["cash_usdc", "released"]]);
    assert.equal(cashDeniedSnapshot.budgetHolds[0].state, "released");
    const cashEntries = (await observer.query(`SELECT entry_type,count(*)::int AS count FROM oid_ledger_entry
      WHERE owner_id=$1 AND source_kind='cash_usdc' GROUP BY entry_type ORDER BY entry_type`, [cashOwner.ownerId])).rows;
    assert.equal(cashEntries.find((row) => row.entry_type === "debit"), undefined);
    assert.equal(cashEntries.find((row) => row.entry_type === "release")?.count, 1);

    const expiredOwner = await fixtureOwner(setup, { allowCashShortfall: true });
    await seedCashCredit(setup, expiredOwner.ownerId);
    const expiresAt = new Date(Date.now() + 7000).toISOString();
    const expiringGrant = await issueBonusGrant(db, { actorOwnerId: expiredOwner.ownerId, ownerId: expiredOwner.ownerId,
      operationId: key(), amount: "2.000000", reason: "Synthetic allocated-bonus expiry fixture only", expiresAt });
    const expiredRun = await createQueuedRun(runs, deps, ports, expiredOwner, { cashCeiling: quotePrice });
    const expiredReservation = (await observer.query("SELECT source_kind,amount_units::text FROM oid_run_reservation WHERE run_id=$1", [expiredRun.run.id])).rows;
    assert.deepEqual(expiredReservation.map(({ source_kind, amount_units }) => [source_kind, amount_units]), [["tester_bonus", quoteUnits]],
      "The run must reserve bonus first while the grant is still valid");
    await setup.query(`SELECT pg_sleep(GREATEST(0,EXTRACT(EPOCH FROM
      ((SELECT expires_at FROM oid_bonus_grant WHERE id=$1)-clock_timestamp()))+0.05)::double precision)`, [expiringGrant.grant.id]);
    const expiredDenied = await runs.startQueuedRun(deps, {
      runId: expiredRun.run.id, claimId: expiredRun.claim.claimId, operationId: key()
    });
    assert.equal(expiredDenied.run.status, "cancelled");
    const expiredSnapshot = await runSnapshot(observer, expiredRun.run.id);
    assert.equal(expiredSnapshot.debitEntries.length, 0);
    assert.deepEqual(expiredSnapshot.reservations.map(({ source_kind, state }) => [source_kind, state]), [["tester_bonus", "released"]]);
    const expiredSources = (await observer.query(`SELECT entry_type,source_kind,count(*)::int AS count FROM oid_ledger_entry
      WHERE owner_id=$1 GROUP BY entry_type,source_kind ORDER BY entry_type,source_kind`, [expiredOwner.ownerId])).rows;
    assert.equal(expiredSources.find((row) => row.source_kind === "cash_usdc" && row.entry_type === "reserve"), undefined,
      "An expired allocated bonus must not be substituted with cash at start");
    assert.equal(expiredSources.find((row) => row.source_kind === "cash_usdc" && row.entry_type === "debit"), undefined);

    const cancelOperationId = key();
    const requested = await runs.requestRunCancellation(db, { ownerId: primaryOwner.ownerId, runId: primary.run.id,
      operationId: cancelOperationId, reason: "owner_voluntary" });
    const cancelRetry = await runs.requestRunCancellation(db, { ownerId: primaryOwner.ownerId, runId: primary.run.id,
      operationId: cancelOperationId, reason: "owner_voluntary" });
    assert.equal(requested.run.status, "cancellation_requested");
    assert.deepEqual(await getCurrentAgentTask(taskDeps, taskPrincipal, primary.run.id), { task: null },
      "Cancellation must immediately stop task disclosure while executor fencing is pending");
    assert.equal(cancelRetry.replayed, true);
    const waiting = await runs.consumeRunCancellationOutbox(db, undefined, 50);
    assert.ok(waiting.awaitingExecutor >= 1);
    let cancellationSnapshot = await runSnapshot(observer, primary.run.id);
    assert.equal(cancellationSnapshot.run.status, "cancellation_requested");
    assert.equal(cancellationSnapshot.slots.length, 1, "The started run slot must remain held while stop evidence is absent");
    assert.equal(cancellationSnapshot.budgetHolds[0].state, "charged", "Post-start cancellation must not refund the charge");
    assert.equal(cancellationSnapshot.debitEntries.length, 1);
    const fenceEvidenceHash = digest(`synthetic-fence:${primary.run.id}`);
    let fenceCalls = 0;
    const syntheticFencer = {
      async fenceAndStop(input) {
        fenceCalls += 1;
        assert.equal(input.runId, primary.run.id);
        assert.equal(input.agentId, primaryOwner.agentId);
        assert.deepEqual(input.taskPreparation, { taskIndex: 0, preparationId: prepId, generationId: prepGenerationId },
          "A started cancellation must fence the exact bound preparation generation");
        return { fenced: true, evidenceHash: fenceEvidenceHash,
          taskPreparation: { taskIndex: 0, preparationId: prepId, generationId: prepGenerationId } };
      }
    };
    await runs.consumeRunCancellationOutbox(db, syntheticFencer, 50);
    await runs.consumeRunCancellationOutbox(db, syntheticFencer, 50);
    cancellationSnapshot = await runSnapshot(observer, primary.run.id);
    assert.equal(cancellationSnapshot.run.status, "cancelled");
    assert.equal(cancellationSnapshot.run.cancellation_evidence_hash, fenceEvidenceHash);
    assert.equal(cancellationSnapshot.slots.length, 0, "The exact started slot must be released after fence evidence is recorded");
    assert.equal(cancellationSnapshot.budgetHolds[0].state, "charged");
    assert.equal(cancellationSnapshot.debitEntries.length, 1);
    assert.equal(fenceCalls, 1, "Durable cancellation delivery must not invoke the fencer twice");
    assert.equal(cancellationSnapshot.events.find((event) => event.event_type === "run.cancelled.after_start")?.count, 1);

    const successor = await createQueuedRun(runs, deps, ports, primaryOwner);
    assert.equal(successor.run.agentId, primaryOwner.agentId);
    await runs.requestRunCancellation(db, { ownerId: primaryOwner.ownerId, runId: successor.run.id,
      operationId: key(), reason: "owner_voluntary" });
    const successorSlot = (await observer.query("SELECT count(*)::int AS count FROM oid_run_execution_slot WHERE run_id=$1", [successor.run.id])).rows[0];
    assert.equal(successorSlot.count, 0);

    const mixedOwner = await fixtureOwner(setup);
    await issueBonusGrant(db, { actorOwnerId: mixedOwner.ownerId, ownerId: mixedOwner.ownerId,
      operationId: key(), amount: "4.000000", reason: "Synthetic mixed-cancellation recovery fixture only" });
    const mixedStarted = await createQueuedRun(runs, deps, ports, mixedOwner);
    const mixedStart = await runs.startQueuedRun(deps, {
      runId: mixedStarted.run.id, claimId: mixedStarted.claim.claimId, operationId: key()
    });
    assert.equal(mixedStart.run.status, "running");
    // This legacy mixed-cancellation fixture uses the synthetic global-readiness
    // start path, so seed an explicit task-zero preparation identity for the
    // exact-fence cancellation contract instead of relying on run.environment_id.
    const mixedPreparationId = key(), mixedLeaseId = key(), mixedGenerationId = key();
    const mixedEnvironmentId = `synthetic-mixed-${mixedPreparationId.replaceAll("-", "")}`;
    const mixedInitialStateHash = digest(`mixed-initial-state:${mixedStarted.run.id}`);
    const mixedFixtureEvidence = { path: `synthetic-mixed/${mixedPreparationId}-fixture.json`,
      sha256: digest(`mixed-fixture:${mixedPreparationId}`), boundary: "actual_tool_http_x402_local_evm_application_store" };
    const mixedBaselineEvidence = { path: `synthetic-mixed/${mixedPreparationId}-baseline.json`,
      sha256: digest(`mixed-baseline:${mixedPreparationId}`), boundary: "actual_tool_http_x402_local_evm_application_store" };
    await setup.query(`INSERT INTO oid_task_preparation_intent(preparation_id,run_id,task_index,claim_id,lease_id,environment_id,
        release_identity,manifest_hash,task_id,case_id,case_hash,initial_state_sha256,execution_identity_hash,
        environment_manifest_sha256,application_source_hash)
      VALUES($1,$2,0,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, [
      mixedPreparationId, mixedStarted.run.id, mixedStarted.claim.claimId, mixedLeaseId, mixedEnvironmentId,
      mixedStarted.release.releaseIdentity, mixedStarted.release.manifestHash, mixedStarted.run.taskIds[0],
      `synthetic-mixed-case-${mixedPreparationId}`, digest(`mixed-case:${mixedPreparationId}`), mixedInitialStateHash,
      digest(`mixed-identity:${mixedPreparationId}`), digest(`mixed-environment-manifest:${mixedPreparationId}`),
      digest(`mixed-application:${mixedPreparationId}`)
    ]);
    await setup.query("INSERT INTO oid_task_environment_lease(lease_id,preparation_id,environment_id) VALUES($1,$2,$3)",
      [mixedLeaseId, mixedPreparationId, mixedEnvironmentId]);
    await setup.query(`INSERT INTO oid_task_preparation_observation(preparation_id,revision,status)
      VALUES($1,1,'preparing')`, [mixedPreparationId]);
    await setup.query(`INSERT INTO oid_task_preparation_observation(preparation_id,revision,status,generation_id,participant_id,payer_address,
        baseline_state_sha256,fixture_evidence,baseline_evidence)
      VALUES($1,2,'ready',$2,'synthetic-mixed-participant',$3,$4,$5::jsonb,$6::jsonb)`, [
      mixedPreparationId, mixedGenerationId, `0x${"2".repeat(40)}`, mixedInitialStateHash,
      JSON.stringify(mixedFixtureEvidence), JSON.stringify(mixedBaselineEvidence)
    ]);
    const mixedRelease = await ports.provider.getActiveAdmissionRelease("training");
    const mixedPendingIntent = await runs.createLaunchIntent(deps, {
      ownerId: mixedOwner.ownerId,
      agentId: mixedOwner.agentId,
      mode: "training",
      taskIds: openTaskIds,
      cashCeiling: "0.000000",
      expectedReleaseIdentity: mixedRelease.releaseIdentity,
      expectedManifestHash: mixedRelease.manifestHash,
      expectedQuotePrice: quotePrice,
      operationId: key()
    });
    const mixedPending = await runs.acceptLaunchIntent(deps, {
      ownerId: mixedOwner.ownerId,
      agentId: mixedOwner.agentId,
      accessGeneration: 1,
      intentId: mixedPendingIntent.intent.id,
      operationId: key()
    });
    await setup.query("UPDATE oid_agent_policy SET training=false,revision=2 WHERE agent_id=$1", [mixedOwner.agentId]);
    const firstMixedDrain = await runs.consumeRunCancellationOutbox(db, undefined, 50);
    assert.ok(firstMixedDrain.awaitingExecutor >= 1);
    let mixedReceipt = (await observer.query(`SELECT cancelled_run_ids,pending_run_ids,completed_at FROM oid_run_cancellation_receipt r
      JOIN oid_run_mode_cancellation_outbox o ON o.event_id=r.source_event_id WHERE o.agent_id=$1`, [mixedOwner.agentId])).rows[0];
    assert.deepEqual(mixedReceipt.cancelled_run_ids, [mixedPending.run.id],
      "The first mixed-event pass must durably retain the immediate pre-start cancellation");
    assert.deepEqual(mixedReceipt.pending_run_ids, [mixedStarted.run.id]);
    assert.equal(mixedReceipt.completed_at, null);
    await runs.consumeRunCancellationOutbox(db, undefined, 50);
    mixedReceipt = (await observer.query(`SELECT cancelled_run_ids,pending_run_ids,completed_at FROM oid_run_cancellation_receipt r
      JOIN oid_run_mode_cancellation_outbox o ON o.event_id=r.source_event_id WHERE o.agent_id=$1`, [mixedOwner.agentId])).rows[0];
    assert.deepEqual(mixedReceipt.cancelled_run_ids, [mixedPending.run.id],
      "A retry must preserve the pre-start cancellation while the started run awaits a fence");
    assert.deepEqual(mixedReceipt.pending_run_ids, [mixedStarted.run.id]);
    let mixedFenceCalls = 0;
    const mixedFencer = {
      async fenceAndStop(input) {
        mixedFenceCalls += 1;
        assert.equal(input.runId, mixedStarted.run.id);
        assert.deepEqual(input.taskPreparation, { taskIndex: 0, preparationId: mixedPreparationId, generationId: mixedGenerationId },
          "The mixed-event post-start cancellation must retain its exact task-zero fence target");
        return { fenced: true, evidenceHash: digest(`synthetic-mixed-fence:${input.runId}`), taskPreparation: input.taskPreparation };
      }
    };
    await runs.consumeRunCancellationOutbox(db, mixedFencer, 50);
    await runs.consumeRunCancellationOutbox(db, mixedFencer, 50);
    mixedReceipt = (await observer.query(`SELECT cancelled_run_ids,pending_run_ids,completed_at FROM oid_run_cancellation_receipt r
      JOIN oid_run_mode_cancellation_outbox o ON o.event_id=r.source_event_id WHERE o.agent_id=$1`, [mixedOwner.agentId])).rows[0];
    assert.deepEqual([...mixedReceipt.cancelled_run_ids].sort(), [mixedPending.run.id, mixedStarted.run.id].sort());
    assert.deepEqual(mixedReceipt.pending_run_ids, []);
    assert.ok(mixedReceipt.completed_at);
    assert.equal(mixedFenceCalls, 1);
    const mixedOutbox = (await observer.query("SELECT status FROM oid_run_mode_cancellation_outbox WHERE agent_id=$1", [mixedOwner.agentId])).rows[0];
    assert.equal(mixedOutbox.status, "delivered");
    const mixedStatuses = (await observer.query("SELECT id::text,status FROM oid_benchmark_run WHERE id=ANY($1::uuid[]) ORDER BY id",
      [[mixedStarted.run.id, mixedPending.run.id]])).rows;
    assert.deepEqual(mixedStatuses.map((row) => row.status), ["cancelled", "cancelled"]);

    // The strict prepared-start path is a separate synthetic release fixture:
    // preparation identity, debit, task activation, and the public generation
    // binding must commit together without consulting global readiness.
    const { candidate: preparedCandidate, verifier: preparedVerifier } = createSyntheticTaskPreparationReleaseFixture(releaseApi);
    const preparedValidation = await releaseApi.validateTaskReleaseCandidate(preparedCandidate, preparedVerifier);
    assert.equal(preparedValidation.status, "validated");
    const strictAdmission = syntheticAdmissionPortsForCandidate(preparedCandidate);
    const strictQuote = `${BigInt(strictAdmission.release.priceUnits) / 1_000_000n}.${(BigInt(strictAdmission.release.priceUnits) % 1_000_000n).toString().padStart(6, "0")}`;
    let globalReadinessCalls = 0;
    const strictDeps = {
      ...deps,
      admissionReleaseProvider: strictAdmission.provider,
      executionReadinessProvider: { async isPreparedForRelease() { globalReadinessCalls += 1; throw new Error("global readiness must be bypassed"); } }
    };
    const strictReleaseSource = {
      async getValidatedReleaseRecord(identity, manifestHash) {
        return identity === preparedValidation.release.releaseIdentity && manifestHash === preparedValidation.release.manifestHash
          ? preparedValidation.release : null;
      }
    };
    const strictSessions = new Map();
    const strictPreparationDeps = {
      db,
      releaseSource: strictReleaseSource,
      environmentSelector: { async selectEnvironment({ runId }) { return `strict-prepared-${runId.replaceAll("-", "")}`; } },
      preparationAdapter: {
        async prepare({ intent }) {
          const generationId = key();
          const result = {
            environmentId: intent.environmentId, generationId,
            manifestHash: intent.manifestHash, applicationSourceHash: intent.applicationSourceHash,
            environmentManifestSha256: intent.environmentManifestSha256, initialStateSha256: intent.initialStateSha256,
            participantId: `synthetic-participant-${generationId}`, payerAddress: `0x${"1".repeat(40)}`,
            fixtureEvidence: { path: `artifacts/runs/strict-prepared/${intent.preparationId}-fixture.json`, sha256: digest(`fixture:${intent.preparationId}`),
              boundary: "actual_tool_http_x402_local_evm_application_store" },
            baselineEvidence: { path: `artifacts/runs/strict-prepared/${intent.preparationId}-baseline.json`, sha256: digest(`baseline:${intent.preparationId}`),
              boundary: "actual_tool_http_x402_local_evm_application_store" }
          };
          strictSessions.set(intent.preparationId, { generationId, result, expiresAt: Date.now() + 3_600_000, fenced: false });
          return { status: "prepared", result };
        },
        async reconcile({ intent, generationId }) {
          const cached = strictSessions.get(intent.preparationId);
          return cached?.generationId === generationId ? { status: "prepared", result: cached.result } :
            { status: "unknown", generationId, reasonCode: "restart_reconciliation_required" };
        },
        async fence({ intent, generationId }) {
          const cached = strictSessions.get(intent.preparationId);
          if (cached) cached.fenced = true;
          return { confirmed: true, preparationId: intent.preparationId, leaseId: intent.leaseId,
            environmentId: intent.environmentId, generationId,
            evidence: { path: `artifacts/runs/strict-prepared/${intent.preparationId}-fence.json`, sha256: digest(`fence:${intent.preparationId}`),
              boundary: "actual_tool_http_x402_local_evm_application_store" } };
        },
        hasUsableStartSession(intent, minimumValidUntil) {
          const cached = strictSessions.get(intent.preparationId);
          return Boolean(cached && !cached.fenced && cached.generationId === cached.result.generationId &&
            cached.result.environmentId === intent.environmentId && cached.expiresAt > Date.now() &&
            cached.expiresAt > Date.parse(minimumValidUntil));
        }
      }
    };
    async function queueStrictRun(owner) {
      const intentResult = await runs.createLaunchIntent(strictDeps, {
        ownerId: owner.ownerId, agentId: owner.agentId, mode: "training",
        taskIds: preparedCandidate.inventory.openTrainingTaskIds, cashCeiling: "0.000000",
        expectedReleaseIdentity: strictAdmission.release.releaseIdentity,
        expectedManifestHash: strictAdmission.release.manifestHash, expectedQuotePrice: strictQuote, operationId: key()
      });
      const accepted = await runs.acceptLaunchIntent(strictDeps, {
        ownerId: owner.ownerId, agentId: owner.agentId, accessGeneration: 1,
        intentId: intentResult.intent.id, operationId: key()
      });
      const claim = await runs.claimNextQueuedRun(strictDeps, { claimId: key() });
      assert.ok(claim);
      assert.equal(claim.run.id, accepted.run.id);
      return { run: accepted.run, claim };
    }
    async function prepareStrictRun(queued) {
      const target = { runId: queued.run.id, taskIndex: 0, claimId: queued.claim.claimId };
      const begun = await preparationApi.beginTaskPreparation(strictPreparationDeps, target);
      const prepared = await preparationApi.prepareTaskExecution(strictPreparationDeps, target);
      assert.equal(prepared.observation.status, "ready");
      assert.equal(prepared.dispatchStatus, "completed");
      return { target, preparation: prepared };
    }
    const strictOwner = await fixtureOwner(setup);
    await issueBonusGrant(db, { actorOwnerId: strictOwner.ownerId, ownerId: strictOwner.ownerId,
      operationId: key(), amount: "2.000000", reason: "Synthetic strict prepared-start fixture only" });
    const strictQueued = await queueStrictRun(strictOwner);
    const strictPrepared = await prepareStrictRun(strictQueued);
    let strictAttachCalls = 0;
    let attachedMinimumValidUntil = null;
    const strictStartDeps = {
      ...strictDeps,
      preparedTaskStart: preparationApi.createPreparedTaskStartPort(strictPreparationDeps, async (record, minimumValidUntil) => {
        strictAttachCalls += 1;
        attachedMinimumValidUntil = minimumValidUntil;
        assert.equal(record.intent.preparationId, strictPrepared.preparation.intent.preparationId);
      })
    };
    const strictStartInput = { runId: strictQueued.run.id, claimId: strictQueued.claim.claimId, operationId: key() };
    const strictStarts = await Promise.all(Array.from({ length: 4 }, () => runs.startQueuedRun(strictStartDeps, strictStartInput)));
    assert.equal(strictStarts.filter((row) => !row.replayed).length, 1, "strict concurrent start commits once");
    assert.equal(strictAttachCalls, 1, "only the winning start performs the post-commit RAM handoff");
    assert.ok(Date.parse(attachedMinimumValidUntil) > Date.now());
    assert.equal((await runs.startQueuedRun(strictStartDeps, strictStartInput)).replayed, true,
      "strict start retries use the durable operation receipt and do not reattach the session");
    const strictSnapshot = await runSnapshot(observer, strictQueued.run.id);
    const strictBinding = (await observer.query(`SELECT run_id::text,task_index,env_id,generation_id::text,manifest_hash,application_source_hash,
        participant_id,payer_address FROM oid_task_execution_binding WHERE run_id=$1`, [strictQueued.run.id])).rows;
    assert.equal(strictSnapshot.run.status, "running");
    assert.equal(strictSnapshot.run.environment_id, strictPrepared.preparation.intent.environmentId);
    assert.equal(strictSnapshot.tasks[0].status, "active");
    assert.equal(strictSnapshot.debitEntries.length, 1);
    assert.equal(strictBinding.length, 1);
    assert.equal(strictBinding[0].generation_id, strictPrepared.preparation.observation.generationId);
    assert.equal(strictBinding[0].manifest_hash, preparedCandidate.executionIdentity.environmentManifestSha256);
    assert.equal(strictSnapshot.events.find((event) => event.event_type === "run.started")?.count, 1);
    assert.equal(globalReadinessCalls, 0, "the strict prepared port is authoritative over global readiness");

    const syntheticActor = {
      ownerId: strictOwner.ownerId, agentId: strictOwner.agentId, grantId: strictOwner.grantId,
      credentialId: key(), resource: strictOwner.resource, role: "agent", accessGeneration: 1,
      accessRevision: 1, policyRevision: 1,
      permissions: { training: true, ranked: true, forumMessages: false, customTopics: false }
    };
    const pendingAfterRestart = await taskActionApi.admitTaskAction({ db }, syntheticActor, {
      runId: strictQueued.run.id, taskIndex: 0, operationId: key(), command: { kind: "inspect_catalog" }
    });
    let restartedExecutorRequests = 0;
    const restartedExecutor = new executorApi.BefTaskExecutor({
      db, taskReleaseSource: strictReleaseSource, participantApiByEnvironment: {},
      evidenceSink: { async write() { throw new Error("no action evidence should be written before RAM rebind"); } },
      fetch: async () => { restartedExecutorRequests += 1; throw new Error("no request may be sent without the RAM session"); }
    });
    assert.deepEqual(await restartedExecutor.executeNext(strictQueued.run.id, 0), { status: "idle" },
      "a restart with the durable binding but no RAM credentials leaves pending work for cancellation/fencing");
    const pendingRestartRows = await observer.query(`SELECT o.status AS outbox_status,r.receipt_status
      FROM oid_run_task_action a JOIN oid_run_task_action_outbox o ON o.action_id=a.id
      JOIN oid_run_task_action_receipt r ON r.action_id=a.id WHERE a.id=$1`, [pendingAfterRestart.actionId]);
    assert.deepEqual(pendingRestartRows.rows, [{ outbox_status: "pending", receipt_status: "pending" }]);
    assert.equal(restartedExecutorRequests, 0);

    // A conflicting pre-existing generation binding makes the whole start
    // transaction roll back, including the debit and task/run activation.
    const atomicOwner = await fixtureOwner(setup);
    await issueBonusGrant(db, { actorOwnerId: atomicOwner.ownerId, ownerId: atomicOwner.ownerId,
      operationId: key(), amount: "2.000000", reason: "Synthetic strict-start rollback fixture only" });
    const atomicQueued = await queueStrictRun(atomicOwner);
    const atomicPrepared = await prepareStrictRun(atomicQueued);
    await setup.query(`INSERT INTO oid_task_execution_binding(run_id,task_index,env_id,generation_id,manifest_hash,
        application_source_hash,participant_id,payer_address) VALUES($1,0,$2,$3,$4,$5,$6,$7)`, [
      atomicQueued.run.id, atomicPrepared.preparation.intent.environmentId, atomicPrepared.preparation.observation.generationId,
      atomicPrepared.preparation.intent.environmentManifestSha256, atomicPrepared.preparation.intent.applicationSourceHash,
      atomicPrepared.preparation.observation.participantId, atomicPrepared.preparation.observation.payerAddress
    ]);
    const atomicPort = preparationApi.createPreparedTaskStartPort(strictPreparationDeps, async () => {
      throw new Error("handoff must not run when atomic start rolls back");
    });
    await assert.rejects(runs.startQueuedRun({ ...strictDeps, preparedTaskStart: atomicPort }, {
      runId: atomicQueued.run.id, claimId: atomicQueued.claim.claimId, operationId: key()
    }), (error) => error.code === "TASK_EXECUTION_BINDING_ALREADY_EXISTS");
    const atomicSnapshot = await runSnapshot(observer, atomicQueued.run.id);
    assert.equal(atomicSnapshot.run.status, "preparing");
    assert.equal(atomicSnapshot.tasks[0].status, "queued");
    assert.equal(atomicSnapshot.debitEntries.length, 0, "binding insertion failure rolls back the tentative debit");
    assert.equal(atomicSnapshot.reservations[0].state, "held");
    assert.equal((await observer.query("SELECT count(*)::int AS count FROM oid_task_execution_binding WHERE run_id=$1", [atomicQueued.run.id])).rows[0].count, 1,
      "the only persisted row is the conflicting fixture pin, not a partial start effect");

    // A fenced lease and a cancellation that wins before start both remain
    // uncharged and cannot create the public execution binding.
    const staleOwner = await fixtureOwner(setup);
    await issueBonusGrant(db, { actorOwnerId: staleOwner.ownerId, ownerId: staleOwner.ownerId,
      operationId: key(), amount: "2.000000", reason: "Synthetic strict stale-lease fixture only" });
    const staleQueued = await queueStrictRun(staleOwner);
    const stalePrepared = await prepareStrictRun(staleQueued);
    await preparationApi.fenceTaskPreparation(strictPreparationDeps, stalePrepared.preparation.intent.preparationId);
    await assert.rejects(runs.startQueuedRun({ ...strictDeps,
      preparedTaskStart: preparationApi.createPreparedTaskStartPort(strictPreparationDeps, async () => {}) }, {
      runId: staleQueued.run.id, claimId: staleQueued.claim.claimId, operationId: key()
    }), (error) => error.code === "TASK_PREPARATION_FENCED");
    const staleSnapshot = await runSnapshot(observer, staleQueued.run.id);
    assert.equal(staleSnapshot.debitEntries.length, 0);
    assert.equal(staleSnapshot.run.status, "cancelled", "a terminally fenced first preparation cannot leave a run stuck preparing");
    assert.equal(staleSnapshot.reservations[0].state, "released");
    assert.equal((await observer.query("SELECT count(*)::int AS count FROM oid_task_execution_binding WHERE run_id=$1", [staleQueued.run.id])).rows[0].count, 0);

    const lostSessionOwner = await fixtureOwner(setup);
    await issueBonusGrant(db, { actorOwnerId: lostSessionOwner.ownerId, ownerId: lostSessionOwner.ownerId,
      operationId: key(), amount: "2.000000", reason: "Synthetic strict RAM-session-loss fixture only" });
    const lostSessionQueued = await queueStrictRun(lostSessionOwner);
    const lostSessionPrepared = await prepareStrictRun(lostSessionQueued);
    strictSessions.get(lostSessionPrepared.preparation.intent.preparationId).expiresAt = Date.now() - 1;
    await assert.rejects(runs.startQueuedRun({ ...strictDeps,
      preparedTaskStart: preparationApi.createPreparedTaskStartPort(strictPreparationDeps, async () => {}) }, {
      runId: lostSessionQueued.run.id, claimId: lostSessionQueued.claim.claimId, operationId: key()
    }), (error) => error.code === "TASK_PREPARATION_SESSION_UNAVAILABLE");
    const lostSessionSnapshot = await runSnapshot(observer, lostSessionQueued.run.id);
    assert.equal(lostSessionSnapshot.run.status, "cancellation_requested",
      "a durable ready row without the original RAM credentials requests cancellation before debit");
    assert.equal(lostSessionSnapshot.debitEntries.length, 0);
    assert.equal(lostSessionSnapshot.reservations[0].state, "held", "holds remain until the exact preparation fence is confirmed");
    const lostSessionOutbox = (await observer.query(`SELECT payload_json FROM oid_run_outbox
      WHERE run_id=$1 AND event_type='run.cancel.requested'`, [lostSessionQueued.run.id])).rows[0]?.payload_json;
    assert.equal(lostSessionOutbox.taskPreparation.preparationId, lostSessionPrepared.preparation.intent.preparationId);
    assert.equal(lostSessionOutbox.taskPreparation.taskIndex, 0);
    assert.equal(lostSessionOutbox.taskPreparation.generationId, lostSessionPrepared.preparation.observation.generationId);
    assert.equal((await observer.query("SELECT count(*)::int AS count FROM oid_task_execution_binding WHERE run_id=$1", [lostSessionQueued.run.id])).rows[0].count, 0);

    const cancelWinnerOwner = await fixtureOwner(setup);
    await issueBonusGrant(db, { actorOwnerId: cancelWinnerOwner.ownerId, ownerId: cancelWinnerOwner.ownerId,
      operationId: key(), amount: "2.000000", reason: "Synthetic strict cancellation-race fixture only" });
    const cancelWinnerQueued = await queueStrictRun(cancelWinnerOwner);
    const cancelWinnerPrepared = await prepareStrictRun(cancelWinnerQueued);
    await runs.requestRunCancellation(db, { ownerId: cancelWinnerOwner.ownerId, runId: cancelWinnerQueued.run.id,
      operationId: key(), reason: "owner_voluntary" });
    await assert.rejects(runs.startQueuedRun({ ...strictDeps,
      preparedTaskStart: preparationApi.createPreparedTaskStartPort(strictPreparationDeps, async () => {}) }, {
      runId: cancelWinnerQueued.run.id, claimId: cancelWinnerQueued.claim.claimId, operationId: key()
    }), (error) => error.code === "RUN_NOT_PREPARING");
    const cancelWinnerSnapshot = await runSnapshot(observer, cancelWinnerQueued.run.id);
    assert.equal(cancelWinnerSnapshot.run.status, "cancellation_requested");
    assert.equal(cancelWinnerSnapshot.debitEntries.length, 0);
    assert.equal(cancelWinnerSnapshot.reservations[0].state, "held");
    assert.equal((await observer.query("SELECT count(*)::int AS count FROM oid_task_execution_binding WHERE run_id=$1", [cancelWinnerQueued.run.id])).rows[0].count, 0);

    // Hold the start transaction at the exact readiness gate while a
    // cancellation contends on the owner lock. If start wins, all start
    // effects and the binding exist before cancellation is requested.
    const startWinnerOwner = await fixtureOwner(setup);
    await issueBonusGrant(db, { actorOwnerId: startWinnerOwner.ownerId, ownerId: startWinnerOwner.ownerId,
      operationId: key(), amount: "2.000000", reason: "Synthetic strict start-race fixture only" });
    const startWinnerQueued = await queueStrictRun(startWinnerOwner);
    const startWinnerPrepared = await prepareStrictRun(startWinnerQueued);
    let reachStartGate;
    const atStartGate = new Promise((resolve) => { reachStartGate = resolve; });
    let openStartGate;
    const startGate = new Promise((resolve) => { openStartGate = resolve; });
    const baseStrictPort = preparationApi.createPreparedTaskStartPort(strictPreparationDeps, async () => {});
    const racingStrictPort = {
      ...baseStrictPort,
      async assertReadyInTransaction(tx, target, preparationId, minimumValidUntil) {
        const record = await baseStrictPort.assertReadyInTransaction(tx, target, preparationId, minimumValidUntil);
        reachStartGate();
        await startGate;
        return record;
      }
    };
    const startWinnerStart = runs.startQueuedRun({ ...strictDeps, preparedTaskStart: racingStrictPort }, {
      runId: startWinnerQueued.run.id, claimId: startWinnerQueued.claim.claimId, operationId: key()
    });
    await atStartGate;
    const contendingCancel = runs.requestRunCancellation(db, { ownerId: startWinnerOwner.ownerId, runId: startWinnerQueued.run.id,
      operationId: key(), reason: "owner_voluntary" });
    await new Promise((resolve) => setTimeout(resolve, 25));
    openStartGate();
    const [startWinnerResult, cancelAfterStart] = await Promise.all([startWinnerStart, contendingCancel]);
    assert.equal(startWinnerResult.run.status, "running");
    assert.equal(cancelAfterStart.run.status, "cancellation_requested");
    const startWinnerSnapshot = await runSnapshot(observer, startWinnerQueued.run.id);
    assert.equal(startWinnerSnapshot.run.status, "cancellation_requested");
    assert.equal(startWinnerSnapshot.debitEntries.length, 1);
    assert.equal(startWinnerSnapshot.budgetHolds[0].state, "charged");
    assert.equal((await observer.query("SELECT count(*)::int AS count FROM oid_task_execution_binding WHERE run_id=$1", [startWinnerQueued.run.id])).rows[0].count, 1,
      "start-wins ordering commits the generation binding with its debit before cancellation can acquire the owner lock");
    const exactPreparationFencer = preparationApi.createTaskPreparationCancellationExecutor(strictPreparationDeps, {
      unbindSession() {}
    });
    await runs.consumeRunCancellationOutbox(db, exactPreparationFencer, 100);
    const lostSessionFenced = await runSnapshot(observer, lostSessionQueued.run.id);
    assert.equal(lostSessionFenced.run.status, "cancelled");
    assert.equal(lostSessionFenced.reservations[0].state, "released");
    assert.equal((await observer.query("SELECT state FROM oid_task_environment_lease WHERE preparation_id=$1",
      [lostSessionPrepared.preparation.intent.preparationId])).rows[0].state, "fenced");
    const startWinnerFenced = await runSnapshot(observer, startWinnerQueued.run.id);
    assert.equal(startWinnerFenced.run.status, "cancelled");
    assert.equal(startWinnerFenced.debitEntries.length, 1, "post-start cancellation still retains the committed charge");

    async function seedLeasedPreparationAt(run, taskIndex, preparationId, leaseId) {
      const selected = (await setup.query(`SELECT r.release_identity,r.manifest_hash,c.claim_id,t.task_id
        FROM oid_benchmark_run r JOIN oid_run_dispatch_claim c ON c.run_id=r.id
        JOIN oid_run_task t ON t.run_id=r.id AND t.task_index=$2
        WHERE r.id=$1 AND c.status='claimed'`, [run.run.id, taskIndex])).rows[0];
      assert.ok(selected, `selected task ${taskIndex} and its live claim must exist`);
      const environmentId = `synthetic-cancel-index-${taskIndex}-${preparationId}`;
      const evidenceHash = digest(`indexed-cancellation:${run.run.id}:${taskIndex}`);
      await setup.query(`INSERT INTO oid_task_preparation_intent(preparation_id,run_id,task_index,claim_id,lease_id,environment_id,
          release_identity,manifest_hash,task_id,case_id,case_hash,initial_state_sha256,execution_identity_hash,
          environment_manifest_sha256,application_source_hash)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
      [preparationId, run.run.id, taskIndex, selected.claim_id, leaseId, environmentId, selected.release_identity,
        selected.manifest_hash, selected.task_id, `synthetic-case-${selected.task_id}`, evidenceHash, evidenceHash,
        evidenceHash, evidenceHash, evidenceHash]);
      await setup.query(`INSERT INTO oid_task_environment_lease(lease_id,preparation_id,environment_id,state)
        VALUES($1,$2,$3,'leased')`, [leaseId, preparationId, environmentId]);
      await setup.query(`INSERT INTO oid_task_preparation_observation(preparation_id,revision,status)
        VALUES($1,1,'preparing')`, [preparationId]);
      return { taskIndex, preparationId, generationId: null };
    }

    const successorCancelOwner = await fixtureOwner(setup);
    await issueBonusGrant(db, { actorOwnerId: successorCancelOwner.ownerId, ownerId: successorCancelOwner.ownerId,
      operationId: key(), amount: "2.000000", reason: "Synthetic successor-index cancellation fixture only" });
    const successorCancelRun = await createQueuedRun(runs, deps, ports, successorCancelOwner);
    const successorTarget = await seedLeasedPreparationAt(successorCancelRun, 2, key(), key());
    await runs.requestRunCancellation(db, { ownerId: successorCancelOwner.ownerId, runId: successorCancelRun.run.id,
      operationId: key(), reason: "owner_voluntary" });
    const successorCancelPayload = (await observer.query(`SELECT payload_json FROM oid_run_outbox
      WHERE run_id=$1 AND event_type='run.cancel.requested'`, [successorCancelRun.run.id])).rows[0].payload_json;
    assert.deepEqual(successorCancelPayload.taskPreparation, successorTarget,
      "cancellation pins the currently leased successor task index instead of assuming task 0");
    const successorFenceHash = digest(`successor-cancellation-fence:${successorCancelRun.run.id}`);
    const successorFenceCalls = [];
    const successorUnboundSessions = [];
    const successorFencer = preparationApi.createTaskPreparationCancellationExecutor({ db,
      preparationAdapter: {
        async fence({ intent, generationId }) {
          successorFenceCalls.push({ taskIndex: intent.taskIndex, preparationId: intent.preparationId, generationId });
          return { confirmed: true, preparationId: intent.preparationId, leaseId: intent.leaseId,
            environmentId: intent.environmentId, generationId,
            evidence: { path: `synthetic-successor-cancellation/${intent.preparationId}.json`, sha256: successorFenceHash,
              boundary: "actual_tool_http_x402_local_evm_application_store" } };
        },
        clearCredentials() {}
      }
    }, { unbindSession(runId, taskIndex) { successorUnboundSessions.push({ runId, taskIndex }); } });
    await runs.consumeRunCancellationOutbox(db, successorFencer, 100);
    assert.deepEqual(successorFenceCalls, [{ taskIndex: 2, preparationId: successorTarget.preparationId, generationId: null }]);
    assert.deepEqual(successorUnboundSessions, [{ runId: successorCancelRun.run.id, taskIndex: 2 }]);
    assert.equal((await runSnapshot(observer, successorCancelRun.run.id)).run.status, "cancelled",
      "an exact successor-index fence permits normal pre-start cancellation finalization");
    assert.equal((await observer.query("SELECT state FROM oid_task_environment_lease WHERE preparation_id=$1",
      [successorTarget.preparationId])).rows[0].state, "fenced");

    const omittedSuccessorIndexOwner = await fixtureOwner(setup);
    await issueBonusGrant(db, { actorOwnerId: omittedSuccessorIndexOwner.ownerId, ownerId: omittedSuccessorIndexOwner.ownerId,
      operationId: key(), amount: "2.000000", reason: "Synthetic legacy cancellation pin fixture only" });
    const omittedSuccessorIndexRun = await createQueuedRun(runs, deps, ports, omittedSuccessorIndexOwner);
    const omittedSuccessorTarget = await seedLeasedPreparationAt(omittedSuccessorIndexRun, 2, key(), key());
    await runs.requestRunCancellation(db, { ownerId: omittedSuccessorIndexOwner.ownerId, runId: omittedSuccessorIndexRun.run.id,
      operationId: key(), reason: "owner_voluntary" });
    await setup.query(`UPDATE oid_run_outbox SET payload_json=jsonb_set(payload_json,'{taskPreparation}',
      (payload_json->'taskPreparation')-'taskIndex') WHERE run_id=$1 AND event_type='run.cancel.requested'`, [omittedSuccessorIndexRun.run.id]);
    let omittedSuccessorAdapterFenceCalls = 0;
    const omittedSuccessorFencer = preparationApi.createTaskPreparationCancellationExecutor({ db,
      preparationAdapter: { async fence() { omittedSuccessorAdapterFenceCalls += 1; throw new Error("unexpected fence"); } }
    }, { unbindSession() {} });
    await runs.consumeRunCancellationOutbox(db, omittedSuccessorFencer, 100);
    assert.equal(omittedSuccessorAdapterFenceCalls, 0,
      "a historical missing index is compatible only when the immutable preparation is task 0");
    const omittedSuccessorState = await runSnapshot(observer, omittedSuccessorIndexRun.run.id);
    assert.equal(omittedSuccessorState.run.status, "cancellation_requested");
    assert.equal(omittedSuccessorState.reservations[0].state, "held");
    assert.equal((await observer.query("SELECT state FROM oid_task_environment_lease WHERE preparation_id=$1",
      [omittedSuccessorTarget.preparationId])).rows[0].state, "leased");

    const ambiguousCancelOwner = await fixtureOwner(setup);
    await issueBonusGrant(db, { actorOwnerId: ambiguousCancelOwner.ownerId, ownerId: ambiguousCancelOwner.ownerId,
      operationId: key(), amount: "2.000000", reason: "Synthetic ambiguous lease cancellation fixture only" });
    const ambiguousCancelRun = await createQueuedRun(runs, deps, ports, ambiguousCancelOwner);
    await seedLeasedPreparationAt(ambiguousCancelRun, 1, key(), key());
    await seedLeasedPreparationAt(ambiguousCancelRun, 2, key(), key());
    await assert.rejects(runs.requestRunCancellation(db, { ownerId: ambiguousCancelOwner.ownerId,
      runId: ambiguousCancelRun.run.id, operationId: key(), reason: "owner_voluntary" }),
    (error) => error.code === "TASK_PREPARATION_AMBIGUOUS");
    const ambiguousState = (await observer.query(`SELECT r.status,
        (SELECT count(*)::int FROM oid_run_outbox o WHERE o.run_id=r.id AND o.event_type='run.cancel.requested') AS cancel_outbox_count,
        rr.state AS reservation_state,b.state AS budget_state,s.state AS slot_state,c.status AS claim_status,
        (SELECT count(*)::int FROM oid_task_environment_lease l JOIN oid_task_preparation_intent i USING(preparation_id)
          WHERE i.run_id=r.id AND l.state='leased') AS active_lease_count
      FROM oid_benchmark_run r JOIN oid_run_reservation rr ON rr.run_id=r.id
      JOIN oid_run_budget_hold b ON b.run_id=r.id JOIN oid_run_execution_slot s ON s.run_id=r.id
      JOIN oid_run_dispatch_claim c ON c.run_id=r.id WHERE r.id=$1`, [ambiguousCancelRun.run.id])).rows[0];
    assert.deepEqual(ambiguousState, { status: "preparing", cancel_outbox_count: 0, reservation_state: "held",
      budget_state: "held", slot_state: "preparing", claim_status: "claimed", active_lease_count: 2 },
    "ambiguous active preparation leases fail closed without choosing one or releasing run resources");

    return {
      schemaVersion: "run-start-integration/v1",
      status: "passed",
      fullScenarioAcceptance: false,
      boundary: "Actual coordinator service and PostgreSQL with direct-service synthetic release/readiness/fencing ports; no HTTP activation or real executor proof",
      observations: [
        "concurrent_start_same_key_once",
        "duplicate_start_durable_retry",
        "pinned_old_release_starts_after_active_version_change",
        "active_task_issuance_uses_pinned_release_and_redacts_internal_material",
        "foreign_or_rotated_agent_cannot_read_active_task",
        "expired_or_revoked_exact_grant_cannot_read_active_task",
        "expired_or_revoked_resolved_grant_cannot_accept_or_replay_intent",
        "cancellation_immediately_stops_task_disclosure",
        "task_issuance_http_and_mcp_with_explicitly_synthetic_auth_resolver",
        "task_issuance_waits_for_agent_lock_and_denies_replaced_grant",
        "restored_mode_does_not_revive_older_preparing_run_or_charge_it",
        "current_operation_limit_denial_releases_holds",
        "current_utc_day_limit_denial_releases_holds",
        "current_cash_permission_denial_releases_holds",
        "expired_allocated_bonus_no_cash_substitution",
        "poststart_cancel_retains_charge_and_slot_until_fence_evidence",
        "fence_receipt_releases_exact_slot_once",
        "same_agent_successor_claims_after_slot_release",
        "start_and_cancel_have_no_duplicate_effects",
        "mixed_mode_cancellation_staging_survives_pending_executor_retry",
        "preparing_cancellation_waits_for_exact_preparation_fence",
        "queue_expiry_with_preparation_waits_for_exact_fence",
        "strict_prepared_start_binds_exact_ready_generation_atomically_without_global_readiness",
        "strict_started_binding_without_ram_session_leaves_action_pending_for_cancel_fence",
        "strict_start_binding_conflict_rolls_back_debit_and_task_activation",
        "strict_start_rejects_fenced_lease_and_cancel_winner_without_debit",
        "strict_start_ram_loss_requests_exact_prep_fence_without_debit",
        "strict_start_wins_owner_lock_race_before_cancellation",
        "successor_task_cancellation_fences_exact_index",
        "legacy_missing_cancellation_index_is_task0_only",
        "ambiguous_active_preparation_leases_retain_run_resources"
      ],
      evidence: {
        syntheticProvider: true,
        syntheticReadinessAdapter: true,
        syntheticFenceAdapter: true,
        taskIssuance: issuance,
        pinnedReleaseVersion: primarySnapshot.run.benchmark_version,
        activeReleaseVersionAfterAdmission: newerRelease.benchmarkVersion,
        startRun: primarySnapshot.run,
        startDebitEntries: primarySnapshot.debitEntries,
        deniedRuns: [operationDeniedSnapshot.run, dayDeniedSnapshot.run, cashDeniedSnapshot.run, expiredSnapshot.run],
        cancellationRun: cancellationSnapshot.run,
        retainedCancellationCharge: cancellationSnapshot.budgetHolds,
        releasedCancellationSlot: cancellationSnapshot.slots.length === 0,
        fencerInvocations: fenceCalls,
        mixedCancellation: { cancelledRunIds: mixedReceipt.cancelled_run_ids, pendingRunIds: mixedReceipt.pending_run_ids,
          completedAt: mixedReceipt.completed_at, fencerInvocations: mixedFenceCalls },
        preparingCancellation: { preparationId, confirmedFenceHash, initialUnknownGenerationPreserved: preparedCancelFinal.owner_fenced_generation === null,
          holdsRetainedUntilFence,
          finalStatus: preparedCancelFinal.status, leaseState: preparedCancelFinal.lease_state, dispatchState: preparedCancelFinal.dispatch_state },
        indexedCancellation: { runId: successorCancelRun.run.id, taskPreparation: successorTarget,
          fenceEvidenceHash: successorFenceHash },
        legacyMissingIndexCancellation: { runId: omittedSuccessorIndexRun.run.id, taskPreparation: omittedSuccessorTarget,
          adapterFenceCalls: omittedSuccessorAdapterFenceCalls, status: omittedSuccessorState.run.status },
        ambiguousCancellation: { runId: ambiguousCancelRun.run.id, activeLeases: ambiguousState.active_lease_count,
          status: ambiguousState.status, cancelOutboxCount: ambiguousState.cancel_outbox_count },
        strictPreparedStart: { runId: strictQueued.run.id, preparationId: strictPrepared.preparation.intent.preparationId,
          generationId: strictPrepared.preparation.observation.generationId, attachedMinimumValidUntil,
          binding: strictBinding[0], atomicConflictRunId: atomicQueued.run.id, staleLeaseRunId: staleQueued.run.id,
          lostSessionRunId: lostSessionQueued.run.id, cancelWinnerRunId: cancelWinnerQueued.run.id, startWinnerRunId: startWinnerQueued.run.id,
          globalReadinessCalls }
      }
    };
  } catch (error) {
    const cause = error.cause ?? error;
    error.safeDiagnostic = {
      boundary: "synthetic_run_start_transaction_fixture",
      databaseCode: typeof cause.code === "string" ? cause.code : "unavailable",
      databaseColumn: typeof cause.column === "string" ? cause.column : null,
      databaseConstraint: typeof cause.constraint === "string" ? cause.constraint : null,
      serviceFrames: String(error.stack ?? "").split("\n").filter((line) => line.includes("run-service")).slice(0, 5)
    };
    throw error;
  } finally {
    await client.end();
    await setup.end();
    await observer.end();
  }
}
