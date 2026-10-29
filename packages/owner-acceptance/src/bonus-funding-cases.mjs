import assert from "node:assert/strict";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import pg from "pg";

const { Pool } = pg;
const key = () => randomUUID();
const sha256 = (value) => createHash("sha256").update(value, "utf8").digest("hex");
const OPEN_TASK_IDS = ["S1", "S2", "S4", "M1", "M3", "M4", "H1", "H2"];
const taskWeight = (taskId) => ({ S: 1, M: 2, H: 3, U: 5 })[taskId[0]];
const SELECTED_QUOTE_UNITS = "1000000";

// AICODE-NOTE: This isolated direct-service case supplements the positive local
// browser/worker path with a code-derived lot and the beta bonus-only source guard.
// It proves neither target-host execution nor external-model behavior.
async function createFixtureOwner(pool, name, { allowCashShortfall = false } = {}) {
  const ownerId = key();
  const userId = key();
  const agentId = key();
  const grantId = key();
  await pool.query("INSERT INTO oid_auth_user(id,name,email,email_verified) VALUES($1,$2,$3,true)",
    [userId, name, `${userId}@example.invalid`]);
  await pool.query("INSERT INTO oid_owner(id,auth_user_id,admission_status,admitted_at) VALUES($1,$2,'admitted',clock_timestamp())",
    [ownerId, userId]);
  await pool.query("INSERT INTO oid_agent(id,owner_id,name) VALUES($1,$2,$3)", [agentId, ownerId, `${name} agent`]);
  await pool.query("INSERT INTO oid_agent_policy(agent_id,training,ranked) VALUES($1,true,true)", [agentId]);
  await pool.query(`INSERT INTO oid_agent_financial_policy(owner_id,agent_id,allow_cash_shortfall,revision,
      operation_limit_units,utc_day_limit_units,category_limits)
    VALUES($1,$2,$3,1,10000000,20000000,'{"benchmark":"20.000000","forum":"20.000000"}'::jsonb)`,
  [ownerId, agentId, allowCashShortfall]);
  await pool.query(`INSERT INTO oid_agent_access_grant(id,owner_id,agent_id,operation_id,resource,role,access_generation,expires_at)
    VALUES($1,$2,$3,$4,$5,'agent',1,clock_timestamp()+interval '1 day')`,
  [grantId, ownerId, agentId, key(), "http://task-issuance.example.invalid/api/agent"]);
  return { ownerId, agentId, grantId };
}

async function seedCashCredit(pool, ownerId) {
  const amountUnits = "2000000";
  const provenance = `synthetic-cash-${key()}`;
  await pool.query(`INSERT INTO oid_ledger_entry(
      id,owner_id,actor_owner_id,bonus_grant_id,operation_id,entry_type,source_kind,amount_units,
      available_delta_units,reserved_delta_units,expired_delta_units,cash_provenance,reason)
    VALUES($1,$2,$2,NULL,$3,'cash_credit','cash_usdc',$4,$4,0,0,$5,'Synthetic cash for isolated bonus-only denial probe')`,
  [key(), ownerId, `cashseed_${key().replaceAll("-", "")}`, amountUnits, provenance]);
}

function syntheticTrainingPorts() {
  const release = {
    releaseIdentity: "synthetic-bpc-bonus-only-cash-guard-v1",
    manifestHash: sha256("synthetic-bpc-bonus-only-cash-guard-manifest"),
    benchmarkVersion: "synthetic-bpc-bonus-only-cash-guard-v1",
    benchmarkHash: sha256("synthetic-bpc-bonus-only-cash-guard-benchmark"),
    policyHash: sha256("synthetic-bpc-bonus-only-cash-guard-policy"),
    mode: "training",
    taskIds: OPEN_TASK_IDS,
    weights: OPEN_TASK_IDS.map(taskWeight),
    priceUnits: "15000000",
    precision: 6,
  };
  const validated = {
    ...release,
    taskDeadlines: OPEN_TASK_IDS.map((taskId) => ({ taskId, timeoutSeconds: 60 })),
    overallTimeoutSeconds: 900,
    pricing: { priceUnits: release.priceUnits, precision: release.precision },
  };
  return {
    release,
    admissionReleaseProvider: {
      async getActiveAdmissionRelease(mode) { return mode === "training" ? release : null; },
      async getValidatedRelease(identity, manifestHash, mode) {
        return identity === release.releaseIdentity && manifestHash === release.manifestHash && mode === "training"
          ? validated : null;
      },
      getPublicCatalog() { return []; },
    },
    executionReadinessProvider: {
      async isPreparedForRelease(releaseIdentity, manifestHash) {
        return { ready: true, executorId: "synthetic-acceptance-adapter",
          environmentId: `synthetic-env-${releaseIdentity}`, evidenceHash: sha256(`synthetic-ready:${manifestHash}`) };
      },
    },
  };
}

async function readOnlySnapshot(observer, ids) {
  const client = await observer.connect();
  try {
    await client.query("BEGIN READ ONLY");
    const identity = (await client.query(`SELECT current_user AS role,current_database() AS database_name,
      current_setting('transaction_read_only') AS transaction_read_only`)).rows[0];
    const code = (await client.query(`SELECT id::text,issuer_owner_id::text,kind,amount_units::text,maximum_uses,
      used_count,issue_operation_id,disabled_at FROM oid_bonus_code WHERE id=$1`, [ids.codeId])).rows[0] ?? null;
    const redemption = (await client.query(`SELECT id::text,code_id::text,owner_id::text,bonus_grant_id::text,
      financial_operation_id,created_at::text FROM oid_bonus_code_redemption WHERE id=$1`, [ids.redemptionId])).rows[0] ?? null;
    const grant = (await client.query(`SELECT id::text,owner_id::text,issued_by_owner_id::text,amount_units::text,
      reason,operation_id,expires_at::text FROM oid_bonus_grant WHERE id=$1`, [ids.grantId])).rows[0] ?? null;
    const claimOperations = (await client.query(`SELECT owner_id::text,operation_id,code_id::text,redemption_id::text,created_at::text
      FROM oid_bonus_code_claim_operation WHERE code_id=$1 AND owner_id=$2 ORDER BY operation_id`, [ids.codeId, ids.ownerId])).rows;
    const entries = (await client.query(`SELECT id::text,owner_id::text,actor_owner_id::text,entry_type,source_kind,bonus_grant_id::text,operation_id,
      amount_units::text,available_delta_units::text,reserved_delta_units::text,expired_delta_units::text,cash_provenance
      FROM oid_ledger_entry WHERE owner_id=$1 ORDER BY created_at,id`, [ids.ownerId])).rows;
    const ledgerOperations = (await client.query(`SELECT id::text,operation_id,action,actor_owner_id::text,subject_owner_id::text
      FROM oid_ledger_operation WHERE operation_id=$1 ORDER BY id`, [ids.grantOperationId])).rows;
    const audits = (await client.query(`SELECT id::text,event_type,operation_id,actor_owner_id::text,subject_owner_id::text,metadata
      FROM oid_ledger_audit WHERE operation_id=ANY($1::text[]) ORDER BY operation_id,id`,
    [[ids.claimOperationId, ids.grantOperationId]])).rows;
    const totals = (await client.query(`SELECT source_kind,COALESCE(SUM(available_delta_units),0)::text AS available_units,
      COALESCE(SUM(reserved_delta_units),0)::text AS reserved_units,
      COUNT(*) FILTER (WHERE entry_type IN ('reserve','debit'))::int AS reserve_or_debit_count
      FROM oid_ledger_entry WHERE owner_id=$1 GROUP BY source_kind ORDER BY source_kind`, [ids.ownerId])).rows;
    const policy = (await client.query(`SELECT allow_cash_shortfall,operation_limit_units::text,utc_day_limit_units::text
      FROM oid_agent_financial_policy WHERE owner_id=$1 AND agent_id=$2`, [ids.ownerId, ids.agentId])).rows[0] ?? null;
    const intent = (await client.query(`SELECT id::text,owner_id::text,agent_id::text,mode,task_ids,status,run_id::text,
      quote_price_units::text,cash_ceiling_units::text FROM oid_run_launch_intent WHERE id=$1`, [ids.intentId])).rows[0] ?? null;
    const runs = (await client.query(`SELECT id::text,status,quote_price_units::text,cash_ceiling_units::text
      FROM oid_benchmark_run WHERE intent_id=$1`, [ids.intentId])).rows;
    const runOperations = (await client.query(`SELECT id::text,operation_id,actor_kind,actor_agent_id::text,action,response_json
      FROM oid_run_operation WHERE owner_id=$1 AND operation_id=ANY($2::text[]) ORDER BY operation_id,id`,
    [ids.ownerId, [ids.acceptOperationId]])).rows;
    const reservations = (await client.query(`SELECT run_id::text,source_kind,bonus_grant_id::text,cash_provenance,
      amount_units::text,state FROM oid_run_reservation WHERE owner_id=$1`, [ids.ownerId])).rows;
    const budgetHolds = (await client.query(`SELECT h.run_id::text,h.state,h.amount_units::text
      FROM oid_run_budget_hold h JOIN oid_benchmark_run r ON r.id=h.run_id WHERE r.owner_id=$1`, [ids.ownerId])).rows;
    await client.query("COMMIT");
    return { identity, code, redemption, grant, claimOperations, entries, ledgerOperations, audits,
      totals, policy, intent, runs, runOperations, reservations, budgetHolds };
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

async function verifyDatabaseIdentities(setup, observer, expectedDatabaseName) {
  const appIdentity = (await setup.query(`SELECT current_user AS role,current_database() AS database_name`)).rows[0];
  const client = await observer.connect();
  let observerIdentity;
  try {
    await client.query("BEGIN READ ONLY");
    observerIdentity = (await client.query(`SELECT current_user AS role,current_database() AS database_name,
      current_setting('transaction_read_only') AS transaction_read_only`)).rows[0];
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
  assert.equal(appIdentity.role, "oid_owner", "The isolated application connection must use oid_owner");
  assert.equal(appIdentity.database_name, expectedDatabaseName, "The application URL must resolve to the isolated acceptance database");
  assert.equal(observerIdentity.role, "oid_observer", "The independent observer must use oid_observer");
  assert.equal(observerIdentity.database_name, expectedDatabaseName, "The observer URL must resolve to the same isolated acceptance database");
  assert.equal(observerIdentity.transaction_read_only, "on", "The observer transaction must be read-only");
  return { app: appIdentity, observer: observerIdentity };
}

export async function runBonusOnlyCashSubstitutionCase({ databaseUrl, observerDatabaseUrl, captureId }) {
  assert.match(new URL(databaseUrl).pathname, /^\/oid_acceptance_[a-f0-9]{32}$/, "Bonus source probe requires an isolated acceptance database");
  assert.match(new URL(observerDatabaseUrl).pathname, /^\/oid_acceptance_[a-f0-9]{32}$/, "Bonus source probe requires the isolated read-only observer");
  assert.equal(new URL(databaseUrl).pathname, new URL(observerDatabaseUrl).pathname, "App and observer databases must match");
  assert.match(captureId, /^[0-9a-f-]{36}$/i, "A capture identity is required");

  const [{ createDatabase }, { loadConfig }, { issueBonusCode, redeemBonusCode }, runs] = await Promise.all([
    import("../../owner-identity/dist/db.js"),
    import("../../owner-identity/dist/config.js"),
    import("../../owner-identity/dist/bonus-code-service.js"),
    import("../../owner-identity/dist/run-service.js"),
  ]);
  const setup = new Pool({ connectionString: databaseUrl, max: 2, application_name: "bpc-bonus-only-cash-guard-fixture" });
  const observer = new Pool({ connectionString: observerDatabaseUrl, max: 1, application_name: "bpc-bonus-only-cash-guard-observer" });
  const { db, client } = createDatabase(loadConfig({ ...process.env, OID_DATABASE_URL: databaseUrl }));
  let plaintextCode = null;
  let issuedCode = null;
  try {
    const expectedDatabaseName = new URL(databaseUrl).pathname.slice(1);
    const connectionIdentity = await verifyDatabaseIdentities(setup, observer, expectedDatabaseName);
    const issuer = await createFixtureOwner(setup, "Synthetic BPC code issuer");
    const owner = await createFixtureOwner(setup, "Synthetic BPC bonus-only owner", { allowCashShortfall: true });
    await seedCashCredit(setup, owner.ownerId);

    const codeVerifierSecret = randomBytes(32).toString("base64url");
    const issue = await issueBonusCode(db, {
      issuerOwnerId: issuer.ownerId,
      codeVerifierSecret,
      operationId: key(),
      label: `SC005 shortfall ${captureId.slice(0, 8)}`,
      kind: "single_use",
      amount: "0.250000",
      maximumUses: 1,
    });
    issuedCode = issue;
    plaintextCode = issue.secret;
    assert.equal(typeof plaintextCode, "string");
    const redemption = await redeemBonusCode(db, {
      ownerId: owner.ownerId,
      codeVerifierSecret,
      plaintextCode,
      operationId: key(),
    });
    plaintextCode = "";

    const ports = syntheticTrainingPorts();
    const deps = {
      db,
      admissionReleaseProvider: ports.admissionReleaseProvider,
      executionReadinessProvider: ports.executionReadinessProvider,
      bonusOnly: true,
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
      successorPreparationTimeoutSeconds: 180,
    };
    const intentResult = await runs.createLaunchIntent(deps, {
      ownerId: owner.ownerId,
      agentId: owner.agentId,
      mode: "training",
      taskIds: ["S1"],
      cashCeiling: "1.000000",
      expectedReleaseIdentity: ports.release.releaseIdentity,
      expectedManifestHash: ports.release.manifestHash,
      expectedQuotePrice: "1.000000",
      operationId: key(),
    });
    const grantOperationId = `bcg_${sha256(`${issue.code.id}\0${owner.ownerId}`)}`;
    const acceptOperationId = key();
    const ids = { codeId: issue.code.id, redemptionId: redemption.redemption.id, grantId: redemption.redemption.grantId,
      ownerId: owner.ownerId, agentId: owner.agentId, intentId: intentResult.intent.id,
      claimOperationId: redemption.operationId, grantOperationId, acceptOperationId };
    const before = await readOnlySnapshot(observer, ids);
    assert.equal(before.identity.role, "oid_observer", "The before snapshot must use the independent observer role");
    assert.equal(before.identity.database_name, expectedDatabaseName, "The before snapshot must use the isolated acceptance database");
    assert.equal(before.identity.transaction_read_only, "on", "The before snapshot must be read-only");

    let rejection;
    try {
      await runs.acceptLaunchIntent(deps, {
        ownerId: owner.ownerId,
        agentId: owner.agentId,
        accessGeneration: 1,
        intentId: intentResult.intent.id,
        operationId: acceptOperationId,
      });
    } catch (error) {
      rejection = { status: Number.isInteger(error?.status) ? error.status : null,
        code: typeof error?.code === "string" ? error.code : null };
    }
    const after = await readOnlySnapshot(observer, ids);
    assert.equal(after.identity.role, "oid_observer", "The after snapshot must use the independent observer role");
    assert.equal(after.identity.database_name, expectedDatabaseName, "The after snapshot must use the isolated acceptance database");
    assert.equal(after.identity.transaction_read_only, "on", "The after snapshot must be read-only");
    const bonusAvailable = BigInt(after.totals.find((row) => row.source_kind === "tester_bonus")?.available_units ?? "0");
    const cashAvailable = BigInt(after.totals.find((row) => row.source_kind === "cash_usdc")?.available_units ?? "0");
    const shortfall = BigInt(SELECTED_QUOTE_UNITS) - bonusAvailable;
    const codeGrantBound = after.code?.id === ids.codeId && after.code.issuer_owner_id === issuer.ownerId &&
      after.code.issue_operation_id === issue.operationId && after.code.used_count === 1 && after.code.maximum_uses === 1 &&
      after.code.amount_units === "250000" && after.redemption?.id === ids.redemptionId &&
      after.redemption.code_id === ids.codeId && after.redemption.owner_id === owner.ownerId &&
      after.redemption.bonus_grant_id === ids.grantId && after.redemption.financial_operation_id === grantOperationId &&
      after.grant?.id === ids.grantId && after.grant.owner_id === owner.ownerId &&
      after.grant.issued_by_owner_id === issuer.ownerId && after.grant.reason === "Bonus code redemption" &&
      after.grant.operation_id === grantOperationId && after.grant.amount_units === "250000" &&
      after.entries.some((row) => row.entry_type === "bonus_grant" && row.source_kind === "tester_bonus" &&
        row.bonus_grant_id === ids.grantId && row.operation_id === grantOperationId && row.available_delta_units === "250000");
    const noCashFallbackEffects = after.intent?.status === "pending" && after.intent.run_id === null &&
      after.intent.quote_price_units === SELECTED_QUOTE_UNITS &&
      after.intent.cash_ceiling_units === "1000000" && after.runs.length === 0 && after.reservations.length === 0 &&
      after.budgetHolds.length === 0 && after.entries.every((row) => !["reserve", "debit"].includes(row.entry_type)) &&
      JSON.stringify(before.intent) === JSON.stringify(after.intent) &&
      JSON.stringify(before.entries) === JSON.stringify(after.entries) && JSON.stringify(before.totals) === JSON.stringify(after.totals);
    const verified = before.policy?.allow_cash_shortfall === true && after.policy?.allow_cash_shortfall === true &&
      bonusAvailable === 250000n && shortfall === 750000n && cashAvailable >= shortfall &&
      rejection?.status === 409 && rejection.code === "BETA_BONUS_BALANCE_REQUIRED" && codeGrantBound && noCashFallbackEffects;
    assert.equal(verified, true, "Bonus-only acceptance must reject a code-lot shortfall despite sufficient cash and owner cash permission");

    return {
      schemaVersion: "bpc-sc005-bonus-only-cash-substitution/v1",
      boundary: "local_isolated_direct_service_with_independent_read_only_postgres",
      status: "verified",
      captureId,
      policy: { bonusOnly: true, ownerAllowCashShortfall: true },
      syntheticRelease: { mode: "training", selectedTaskIds: ["S1"], fullTaskIds: ports.release.taskIds,
        fullPriceUnits: ports.release.priceUnits, selectedQuoteUnits: SELECTED_QUOTE_UNITS },
      funding: { codeId: ids.codeId, issueOperationId: issue.operationId, issuerOwnerId: issuer.ownerId,
        redemptionId: ids.redemptionId, redemptionOperationId: redemption.operationId, ownerId: owner.ownerId,
        grantId: ids.grantId, grantOperationId, acceptOperationId, codeGrantUnits: "250000", bonusAvailableUnits: bonusAvailable.toString(),
        cashAvailableUnits: cashAvailable.toString(), shortfallUnits: shortfall.toString(), cashCeilingUnits: SELECTED_QUOTE_UNITS },
      rejection,
      codeGrantLineageVerified: codeGrantBound,
      noCashFallbackEffects,
      connectionIdentity,
      intent: after.intent,
      before: { observer: before.identity, code: before.code, redemption: before.redemption, grant: before.grant,
        claimOperations: before.claimOperations, ledgerOperations: before.ledgerOperations, audits: before.audits,
        totals: before.totals, ledgerEntries: before.entries, policy: before.policy, intent: before.intent,
        runs: before.runs, runOperations: before.runOperations, reservations: before.reservations, budgetHolds: before.budgetHolds },
      after: { observer: after.identity, code: after.code, redemption: after.redemption, grant: after.grant,
        claimOperations: after.claimOperations, ledgerOperations: after.ledgerOperations, audits: after.audits,
        totals: after.totals, ledgerEntries: after.entries, policy: after.policy, intent: after.intent,
        runs: after.runs, runOperations: after.runOperations, reservations: after.reservations, budgetHolds: after.budgetHolds },
      productBoundaryClaims: { browser: false, targetHost: false, externalModel: false, fullScenarioAcceptance: false },
    };
  } finally {
    plaintextCode = "";
    if (issuedCode) issuedCode.secret = "";
    await client.end();
    await setup.end();
    await observer.end();
  }
}
