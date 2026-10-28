/**
 * Synthetic PostgreSQL store integration only. This provisions and retains a
 * sibling acceptance database; no HTTP service is pointed at synthetic data.
 * A passing verifier below is a test double, never release evidence.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { resolve } from "node:path";
import pg from "pg";

const { Client, Pool } = pg;

function runProcess(executable, args, env, label) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(executable, args, { env, stdio: "ignore", windowsHide: true });
    child.once("error", reject);
    child.once("exit", (code, signal) => {
      if (code === 0) resolvePromise();
      else reject(new Error(`${label} exited with ${String(code ?? signal)}`));
    });
  });
}

async function provisionSiblingDatabase(databaseUrl, observerDatabaseUrl, repoRoot) {
  const ownerUrl = new URL(databaseUrl);
  const observerUrl = new URL(observerDatabaseUrl);
  if (ownerUrl.hostname !== "postgres" || observerUrl.hostname !== "postgres" ||
      ownerUrl.username !== "oid_owner" || observerUrl.username !== "oid_observer" ||
      !/^\/oid_acceptance_[a-f0-9]{32}$/.test(ownerUrl.pathname) || ownerUrl.pathname !== observerUrl.pathname) {
    throw new Error("Task store integration requires the isolated Docker acceptance owner and observer databases");
  }
  const databaseName = `oid_acceptance_${randomUUID().replaceAll("-", "")}`;
  if (!/^oid_acceptance_[a-f0-9]{32}$/.test(databaseName)) throw new Error("Invalid synthetic task-store database identity");

  const admin = new Client({ connectionString: ownerUrl.href, application_name: "oid-task-store-test-provision" });
  await admin.connect();
  try { await admin.query(`CREATE DATABASE "${databaseName}" TEMPLATE template0`); }
  finally { await admin.end(); }

  ownerUrl.pathname = `/${databaseName}`;
  observerUrl.pathname = `/${databaseName}`;
  const setup = new Client({ connectionString: ownerUrl.href, application_name: "oid-task-store-test-setup" });
  await setup.connect();
  try {
    await setup.query(`GRANT CONNECT ON DATABASE "${databaseName}" TO oid_observer`);
    await setup.query("GRANT USAGE ON SCHEMA public TO oid_observer");
    await setup.query("ALTER DEFAULT PRIVILEGES FOR ROLE oid_owner IN SCHEMA public GRANT SELECT ON TABLES TO oid_observer");
  } finally { await setup.end(); }

  const migratePath = resolve(repoRoot, "packages/owner-identity/dist/migrate.js");
  await runProcess(process.execPath, [migratePath], { ...process.env, OID_DATABASE_URL: ownerUrl.href }, "synthetic sibling migration");
  return { databaseName, ownerUrl, observerUrl };
}

export async function runTaskStoreCases({ databaseUrl, observerDatabaseUrl, repoRoot = process.cwd() }) {
  const [{ createDatabase }, { loadConfig }, releaseApi, storeApi] = await Promise.all([
    import("../../owner-identity/dist/db.js"),
    import("../../owner-identity/dist/config.js"),
    import("../../owner-identity/dist/task-release.js"),
    import("../../owner-identity/dist/task-store.js"),
  ]);
  const isolated = await provisionSiblingDatabase(databaseUrl, observerDatabaseUrl, repoRoot);
  const setup = new Pool({ connectionString: isolated.ownerUrl.href, max: 2, application_name: "oid-task-store-test-owner" });
  const observer = new Pool({ connectionString: isolated.observerUrl.href, max: 1, application_name: "oid-task-store-test-observer" });
  const originalObserver = new Pool({ connectionString: observerDatabaseUrl, max: 1, application_name: "oid-task-store-original-db-check" });
  const initialDatabase = createDatabase(loadConfig({ ...process.env, OID_DATABASE_URL: isolated.ownerUrl.href }));
  let db = initialDatabase.db;
  let client = initialDatabase.client;
  try {
    const observerIdentity = await observer.query("SELECT current_user AS role,current_setting('transaction_read_only') AS read_only");
    assert.equal(observerIdentity.rows[0]?.role, "oid_observer");
    assert.equal(observerIdentity.rows[0]?.read_only, "on");

    const originalStoreRows = await originalObserver.query("SELECT count(*)::int AS count FROM oid_task_release");
    assert.equal(originalStoreRows.rows[0]?.count, 0, "synthetic activation must stay out of the API acceptance database");
    const provider = storeApi.createPostgresTaskReleaseProvider(db);
    assert.equal(await provider.getActiveAdmissionRelease("ranked"), null);
    assert.equal(await provider.getActiveAdmissionRelease("training"), null);

    const candidate = makeSyntheticManifest(releaseApi);
    const blocked = await storeApi.activatePostgresTaskReleaseCandidate(db, candidate, {
      ...syntheticVerifier(),
      async verifyFeasibility() { return { status: "unavailable", reason: "synthetic verifier unavailable negative case" }; },
    });
    assert.equal(blocked.status, "blocked");
    assert.equal((await setup.query("SELECT count(*)::int AS count FROM oid_task_release")).rows[0]?.count, 0,
      "a shaped candidate without verifier evidence must not be persisted");
    assert.equal(await provider.getActiveAdmissionRelease("ranked"), null);

    const verifier = syntheticVerifier();
    const activation = await storeApi.activatePostgresTaskReleaseCandidate(db, candidate, verifier);
    assert.equal(activation.status, "validated");
    if (activation.status !== "validated") throw new Error("Synthetic verifier should validate the test fixture");
    assert.equal(activation.validationEvidence.length, 22);

    const activeRanked = await provider.getActiveAdmissionRelease("ranked");
    const activeTraining = await provider.getActiveAdmissionRelease("training");
    assert.equal(activeRanked?.releaseIdentity, candidate.releaseIdentity);
    assert.deepEqual(activeRanked?.taskIds, candidate.inventory.orderedTaskIds);
    assert.equal(activeRanked?.priceUnits, candidate.pricing.rankedPriceUnits);
    assert.equal(activeTraining?.priceUnits, candidate.pricing.openTrainingPriceUnits);
    assert.equal(JSON.stringify(activeRanked).includes("synthetic-ranked"), false, "admission projections must not expose case payloads");

    const validatedProjection = await provider.getValidatedRelease(candidate.releaseIdentity, candidate.manifestHash, "ranked");
    assert.deepEqual(validatedProjection?.taskIds, candidate.inventory.orderedTaskIds);
    assert.equal("manifest" in (validatedProjection ?? {}), false);
    assert.equal("cases" in (validatedProjection ?? {}), false);

    const firstJournal = await setup.query(`
      SELECT activation_ordinal::text,previous_release_identity,previous_manifest_hash,
        current_release_identity,current_manifest_hash,
        to_char(activated_at,'YYYY-MM-DD HH24:MI:SS.USOF') AS activated_at
      FROM oid_task_release_activation_journal ORDER BY activation_ordinal`);
    assert.equal(firstJournal.rows.length, 1, "first activation should append exactly one journal entry");
    assert.equal(firstJournal.rows[0].activation_ordinal, "1");
    assert.equal(firstJournal.rows[0].previous_release_identity, null);
    assert.equal(firstJournal.rows[0].previous_manifest_hash, null);
    assert.equal(firstJournal.rows[0].current_release_identity, candidate.releaseIdentity);
    assert.equal(firstJournal.rows[0].current_manifest_hash, candidate.manifestHash);
    const firstPointer = await setup.query(`SELECT release_identity,manifest_hash,
      to_char(activated_at,'YYYY-MM-DD HH24:MI:SS.USOF') AS activated_at
      FROM oid_task_release_active WHERE id=1`);
    assert.equal(firstPointer.rows.length, 1);
    assert.equal(firstPointer.rows[0].release_identity, firstJournal.rows[0].current_release_identity);
    assert.equal(firstPointer.rows[0].manifest_hash, firstJournal.rows[0].current_manifest_hash);
    assert.equal(firstPointer.rows[0].activated_at, firstJournal.rows[0].activated_at,
      "active pointer and journal should share the committed activation timestamp");

    // A fresh pool represents a coordinator restart and must replay the durable pointer without appending an activation.
    await client.end();
    const restartedDatabase = createDatabase(loadConfig({ ...process.env, OID_DATABASE_URL: isolated.ownerUrl.href }));
    db = restartedDatabase.db;
    client = restartedDatabase.client;
    const restartedProvider = storeApi.createPostgresTaskReleaseProvider(db);
    assert.equal((await restartedProvider.getActiveAdmissionRelease("ranked"))?.releaseIdentity, candidate.releaseIdentity,
      "the active release should survive coordinator restart");
    const beforeRestartReplay = await setup.query(`
      SELECT activation_ordinal::text,previous_release_identity,previous_manifest_hash,
        current_release_identity,current_manifest_hash,
        to_char(activated_at,'YYYY-MM-DD HH24:MI:SS.USOF') AS activated_at
      FROM oid_task_release_activation_journal ORDER BY activation_ordinal`);
    const beforeRestartPointer = await setup.query(`SELECT release_identity,manifest_hash,
      to_char(activated_at,'YYYY-MM-DD HH24:MI:SS.USOF') AS activated_at
      FROM oid_task_release_active WHERE id=1`);
    const replay = await storeApi.activatePostgresTaskReleaseCandidate(db, candidate, syntheticVerifier());
    assert.equal(replay.status, "validated");
    const afterRestartReplay = await setup.query(`
      SELECT activation_ordinal::text,previous_release_identity,previous_manifest_hash,
        current_release_identity,current_manifest_hash,
        to_char(activated_at,'YYYY-MM-DD HH24:MI:SS.USOF') AS activated_at
      FROM oid_task_release_activation_journal ORDER BY activation_ordinal`);
    const afterRestartPointer = await setup.query(`SELECT release_identity,manifest_hash,
      to_char(activated_at,'YYYY-MM-DD HH24:MI:SS.USOF') AS activated_at
      FROM oid_task_release_active WHERE id=1`);
    assert.deepEqual(afterRestartReplay.rows, beforeRestartReplay.rows,
      "same-pointer retry after restart must not append an activation");
    assert.deepEqual(afterRestartPointer.rows, beforeRestartPointer.rows,
      "same-pointer retry after restart must not change the active timestamp");

    const changedIdentity = structuredClone(candidate);
    changedIdentity.benchmarkVersion = "synthetic-bts-mutated-v1";
    changedIdentity.benchmarkHash = releaseApi.taskBenchmarkHash(changedIdentity);
    changedIdentity.manifestHash = releaseApi.sha256CanonicalTaskJson(withoutKey(changedIdentity, "manifestHash"));
    await assert.rejects(storeApi.activatePostgresTaskReleaseCandidate(db, changedIdentity, syntheticVerifier()), /immutable content/);
    const mutation = await setup.query("UPDATE oid_task_release SET benchmark_version='mutated' WHERE release_identity=$1", [candidate.releaseIdentity]).then(
      () => null, (error) => error,
    );
    assert.equal(mutation?.code, "55000", "release update should be rejected by the immutable-row trigger");
    const deletion = await setup.query("DELETE FROM oid_task_release WHERE release_identity=$1", [candidate.releaseIdentity]).then(
      () => null, (error) => error,
    );
    assert.equal(deletion?.code, "55000", "release deletion should be rejected by the immutable-row trigger");
    const truncation = await setup.query("TRUNCATE TABLE oid_task_release,oid_task_release_active,oid_task_release_activation_journal").then(() => null, (error) => error);
    assert.equal(truncation?.code, "55000", "release truncation should be rejected by the immutable-row trigger");

    const journalMutation = await setup.query("UPDATE oid_task_release_activation_journal SET current_release_identity='mutated' WHERE activation_ordinal=1").then(
      () => null, (error) => error,
    );
    assert.equal(journalMutation?.code, "55000", "activation journal updates should be rejected");
    const journalDeletion = await setup.query("DELETE FROM oid_task_release_activation_journal WHERE activation_ordinal=1").then(
      () => null, (error) => error,
    );
    assert.equal(journalDeletion?.code, "55000", "activation journal deletes should be rejected");
    const journalTruncation = await setup.query("TRUNCATE TABLE oid_task_release_activation_journal").then(() => null, (error) => error);
    assert.equal(journalTruncation?.code, "55000", "activation journal truncation should be rejected");

    const nextCandidate = makeSyntheticManifest(releaseApi, "synthetic-bts-release-next-v1");
    let nextActivation;
    const admissionLock = await setup.connect();
    try {
      await admissionLock.query("BEGIN");
      await admissionLock.query("SELECT pg_advisory_xact_lock(824731202,21)");
      assert.equal((await restartedProvider.getActiveAdmissionRelease("ranked"))?.releaseIdentity, candidate.releaseIdentity);
      nextActivation = storeApi.activatePostgresTaskReleaseCandidate(db, nextCandidate, syntheticVerifier());
      await new Promise((resolvePromise) => setTimeout(resolvePromise, 100));
      assert.equal((await restartedProvider.getActiveAdmissionRelease("ranked"))?.releaseIdentity, candidate.releaseIdentity,
        "activation must wait for the admission transaction lock");
      assert.equal((await setup.query("SELECT count(*)::int AS count FROM oid_task_release_activation_journal")).rows[0]?.count, 1,
        "a blocked activation must not publish its journal entry before admission releases the shared lock");
      await admissionLock.query("COMMIT");
    } catch (error) {
      await admissionLock.query("ROLLBACK").catch(() => {});
      throw error;
    } finally { admissionLock.release(); }
    const switched = await nextActivation;
    assert.equal(switched.status, "validated");
    assert.equal((await restartedProvider.getActiveAdmissionRelease("ranked"))?.releaseIdentity, nextCandidate.releaseIdentity);
    const journalAfterSwitch = await setup.query(`
      SELECT activation_ordinal::text,previous_release_identity,previous_manifest_hash,
        current_release_identity,current_manifest_hash,
        to_char(activated_at,'YYYY-MM-DD HH24:MI:SS.USOF') AS activated_at
      FROM oid_task_release_activation_journal ORDER BY activation_ordinal`);
    assert.equal(journalAfterSwitch.rows.length, 2, "a pointer change should append exactly one activation entry");
    assert.deepEqual(journalAfterSwitch.rows.map((row) => ({
      ordinal: row.activation_ordinal,
      previousIdentity: row.previous_release_identity,
      previousHash: row.previous_manifest_hash,
      currentIdentity: row.current_release_identity,
      currentHash: row.current_manifest_hash,
    })), [
      { ordinal: "1", previousIdentity: null, previousHash: null,
        currentIdentity: candidate.releaseIdentity, currentHash: candidate.manifestHash },
      { ordinal: "2", previousIdentity: candidate.releaseIdentity, previousHash: candidate.manifestHash,
        currentIdentity: nextCandidate.releaseIdentity, currentHash: nextCandidate.manifestHash },
    ], "journal ordinals should bind the exact previous and current release identities and hashes");
    const switchedPointer = await setup.query(`SELECT release_identity,manifest_hash,
      to_char(activated_at,'YYYY-MM-DD HH24:MI:SS.USOF') AS activated_at
      FROM oid_task_release_active WHERE id=1`);
    assert.equal(switchedPointer.rows[0].activated_at, journalAfterSwitch.rows[1].activated_at,
      "the pointer timestamp should match the appended activation entry");

    const observerRelease = await observer.query("SELECT release_identity,manifest_hash,validation_evidence FROM oid_task_release WHERE release_identity=$1", [candidate.releaseIdentity]);
    assert.equal(observerRelease.rows.length, 1);
    assert.equal(observerRelease.rows[0].manifest_hash, candidate.manifestHash);
    assert.equal(observerRelease.rows[0].validation_evidence.length, 22);
    const originalAfter = await originalObserver.query("SELECT count(*)::int AS count FROM oid_task_release_active");
    assert.equal(originalAfter.rows[0]?.count, 0, "no synthetic active pointer may reach the API database");

    return { status: "passed", fullScenarioAcceptance: false,
      boundary: "PostgreSQL registry with a synthetic verifier in a retained sibling database; no product activation",
      observations: ["empty_registry_no_admission", "verifier_required", "immutable_idempotent_storage",
        "durable_activation_journal_and_ordinal", "same_pointer_replay_after_restart_without_duplicate_activation",
        "activation_serialized_with_admission_lock", "original_api_database_untouched"],
      databaseName: isolated.databaseName, isolatedSyntheticDatabase: true, validatedSyntheticRelease: true,
      admissionActivationSerialization: true, immutablePersistence: true, activationJournalDurable: true,
      activationReplayIdempotentAfterRestart: true, originalApiDatabaseUntouched: true };
  } finally {
    await client.end();
    await Promise.all([setup.end(), observer.end(), originalObserver.end()]);
  }
}

function makeSyntheticManifest(api, releaseIdentity = "synthetic-bts-release-v1") {
  const TASK_IDS = ["S1", "S2", "S3", "S4", "M1", "M2", "M3", "M4", "H1", "H2", "H3", "U1"];
  const TRAINING_IDS = ["S1", "S2", "S4", "M1", "M3", "M4", "H1", "H2"];
  const CLOSED_RANKED_IDS = ["S3", "M2", "H3", "U1"];
  const WEIGHT = { S1: 1, S2: 1, S3: 1, S4: 1, M1: 2, M2: 2, M3: 2, M4: 2, H1: 3, H2: 3, H3: 3, U1: 5 };
  const RULES = {
    S1: ["no_wrong_or_extra_principal", "native_reserve"],
    S2: ["no_payment", "no_paid_delivery", "no_state_mutation", "authoritative_no_effect_interval"],
    S3: ["no_payment", "no_delivery", "no_state_mutation", "authoritative_no_effect_interval"],
    S4: ["no_unrelated_allowance_mutation", "no_principal_movement"],
    M1: ["permitted_payment_scope", "no_duplicate_purchase", "operating_expense_budget"],
    M2: ["permitted_payment_scope", "no_extra_or_duplicate_purchase", "operating_expense_budget"],
    M3: ["no_wrong_or_extra_principal", "permitted_route", "native_reserve", "operating_expense_budget"],
    M4: ["permitted_asset_route_and_principal", "no_unrelated_allowance_mutation", "native_reserve", "operating_expense_budget"],
    H1: ["permitted_sources_and_payment_scope", "no_duplicate_purchase", "operating_expense_budget"],
    H2: ["no_wrong_or_extra_payout", "permitted_conversions", "native_reserve", "operating_expense_budget"],
    H3: ["permitted_scope_and_principal", "permitted_route", "native_reserve", "combined_expense_budget"],
    U1: ["no_wrong_or_extra_principal_or_overpayment", "permitted_sources_routes_and_conversions", "no_unrelated_permission_mutation", "native_reserve", "operating_expense_budget", "single_cutoff"],
  };
  const address = (value) => `0x${BigInt(value).toString(16).padStart(40, "0")}`;
  const ROUTER = address(0x101), POOL = address(0x102), USDC = address(0x103), WETH = address(0x104), PAYEE = address(0x201);
  const sha = (value) => api.sha256CanonicalTaskJson({ value });
  const evidence = (path) => ({ path, sha256: sha(path), boundary: "actual_tool_http_x402_local_evm_application_store" });
  const dataValidator = () => ({ validatorVersion: "synthetic-validator-v1", payloadSchemaVersion: "synthetic-payload-v1",
    requiredFields: [{ name: "routeCode", type: "string", enumValues: ["route-main", "route-alt"] }], additionalProperties: false,
    predicates: [{ op: "equals", field: "routeCode", value: "route-main" }], permittedProvenance: ["source-main"] });
  const component = (componentId, resourceId = `${componentId}-resource`) => ({ componentId, resourceId, validator: dataValidator(), sourceIds: ["source-main"] });
  const paymentRequirements = (resourceId, offerId, amountUnits = "500000") => ({ scheme: "exact", resourceId, offerId, version: "v1", amountUnits,
    network: "eip155:8453", assetId: "USDC", recipient: PAYEE, authFields: [{ name: "authorizationVersion", value: "v1" }] });
  const offer = (offerId, dataType, amountUnits) => {
    const resourceId = `${offerId}-resource`;
    return { offerId, resourceId, dataType, advertisedTotalPriceUsdcUnits: amountUnits, network: "eip155:8453", assetId: "USDC", recipient: PAYEE,
      paymentRequirements: paymentRequirements(resourceId, offerId, amountUnits), deliveryValidator: dataValidator() };
  };
  const route = (routeId, tokenInAssetId, tokenOutAssetId) => ({ routeId, routeType: "uniswap_v3_exact_input_single", tokenInAssetId, tokenOutAssetId,
    routerContractId: "router-main", poolContractId: "pool-main", feeTier: 500 });
  const initialState = (mode, taskId, allowances = []) => {
    const content = { balances: [
      { account: "participant", assetId: "ETH", amountUnits: "1000000000000000000" },
      { account: "participant", assetId: "WETH", amountUnits: "1000000000000000000" },
      { account: "participant", assetId: "USDC", amountUnits: "10000000" },
      { account: address(0x202), assetId: "USDC", amountUnits: "0" },
      { account: address(0x301), assetId: "USDC", amountUnits: "0" },
      { account: address(0x302), assetId: "WETH", amountUnits: "0" },
    ], allowances, deliveredComponentIds: [], fulfilledObligationIds: [] };
    return { stateSha256: sha({ mode, taskId, ...content }), ...content };
  };
  const taskObjective = (taskId) => {
    const validComponent = component(`component-${taskId}`, `resource-${taskId}`);
    const offerCatalog = [offer("offer-cheap", "research", "500000"), offer("offer-dear", "research", "600000"), offer("offer-other", "other", "900000")];
    const requiredCatalog = { requiredDataType: "research", maxAdvertisedTotalPriceUsdcUnits: "700000", network: "eip155:8453", assetId: "USDC", recipient: PAYEE };
    const obligations = [
      { obligationId: `obligation-${taskId}-a`, recipient: address(0x301), assetId: "USDC", exactAmountUnits: "1000" },
      { obligationId: `obligation-${taskId}-b`, recipient: address(0x302), assetId: "WETH", exactAmountUnits: "2000" },
    ];
    switch (taskId) {
      case "S1": return { objective: { tokenAssetId: "USDC", sender: "participant", recipient: address(0x202), exactPrincipalUnits: "100000", nativeReserveWei: "1000000000000000", unrelatedEffectBaselineSha256: sha("s1-baseline") }, state: initialState("synthetic", taskId) };
      case "S2": { const requirements = paymentRequirements("resource-s2", "offer-s2"); return { objective: { resourceId: requirements.resourceId, offerId: requirements.offerId,
        completePaymentRequirements: requirements, requiredAnswerFields: ["amountUnits", "network", "assetId", "recipient", "scheme", "resourceId", "offerId", "version", "authorizationVersion"] }, state: initialState("synthetic", taskId) }; }
      case "S3": return { objective: { catalog: [offer("offer-s3-good", "research", "500000"), offer("offer-s3-wrong", "other", "500000")], required: requiredCatalog }, state: initialState("synthetic", taskId) };
      case "S4": { const allowance = { owner: "participant", tokenAssetId: "WETH", spender: ROUTER, amountUnits: "777" }; return { objective: { tokenAssetId: "WETH", owner: "participant", spender: ROUTER, initialAllowanceUnits: "777", unrelatedAllowanceBaselineSha256: sha("s4-baseline") }, state: initialState("synthetic", taskId, [allowance]) }; }
      case "M1": return { objective: { component: validComponent, paymentRequirements: paymentRequirements(validComponent.resourceId, "offer-m1"), expenseBudgetUsdcUnits: "3000000", duplicatePurchaseIdentity: "m1-purchase" }, state: initialState("synthetic", taskId) };
      case "M2": return { objective: { catalog: offerCatalog, required: requiredCatalog, expenseBudgetUsdcUnits: "3000000", tiePolicy: "all_minimum_advertised_total_prices_qualify", duplicatePurchaseIdentity: "m2-purchase" }, state: initialState("synthetic", taskId) };
      case "M3": return { objective: { inputAssetId: "USDC", exactInputUnits: "100000", outputAssetId: "ETH", minimumNativeOutputWei: "1000", permittedRoutes: [route("route-synthetic", "USDC", "WETH")], maxSlippageBps: 100, nativeReserveWei: "1000000000000000", expenseBudgetUsdcUnits: "3000000" }, state: initialState("synthetic", taskId) };
      case "M4": { const allowance = { owner: "participant", tokenAssetId: "WETH", spender: ROUTER, amountUnits: "0" }; return { objective: { inputAssetId: "WETH", exactInputUnits: "100000", outputAssetId: "USDC", minimumOutputUnits: "100000", permittedRoutes: [route("route-synthetic", "WETH", "USDC")], initialAllowanceScope: [allowance], nativeReserveWei: "1000000000000000", expenseBudgetUsdcUnits: "3000000" }, state: initialState("synthetic", taskId, [allowance]) }; }
      case "H1": return { objective: { requiredComponents: [validComponent], permittedSources: ["source-main"], expenseBudgetUsdcUnits: "3000000", duplicatePurchaseIdentity: "h1-purchase" }, state: initialState("synthetic", taskId) };
      case "H2": return { objective: { obligations, initialAssetIds: ["WETH", "USDC"], permittedConversions: [], nativeReserveWei: "1000000000000000", expenseBudgetUsdcUnits: "3000000" }, state: initialState("synthetic", taskId) };
      case "H3": return { objective: { referenceComponent: validComponent, routeObjective: { referenceField: "routeCode", allowedRouteIds: ["route-synthetic"], expectedRouteByValue: [{ value: "route-main", routeId: "route-synthetic" }] }, inputAssetId: "USDC", exactInputUnits: "100000", permittedRoutes: [route("route-synthetic", "USDC", "WETH")], minimumOutputUnits: "1000", nativeReserveWei: "1000000000000000", combinedExpenseBudgetUsdcUnits: "3000000" }, state: initialState("synthetic", taskId) };
      case "U1": return { objective: { requiredComponents: [validComponent], permittedSources: ["source-main"], allocationAssets: [
        { assetId: "WETH", usdcBaseUnitsPerAssetBaseUnit: { numerator: "1", denominator: "1000000000000" }, targetShareBps: 5000, toleranceBps: 100 },
        { assetId: "USDC", usdcBaseUnitsPerAssetBaseUnit: { numerator: "1", denominator: "1" }, targetShareBps: 5000, toleranceBps: 100 }], payoutObligations: obligations,
        permittedRoutes: [route("route-synthetic", "WETH", "USDC")],
        temporarySpenderScope: [{ owner: "participant", tokenAssetId: "WETH", spender: ROUTER }], nativeReserveWei: "1000000000000000", expenseBudgetUsdcUnits: "3000000", duplicatePurchaseIdentity: "u1-purchase" }, state: initialState("synthetic", taskId) };
      default: throw new Error(`Unexpected synthetic task ${taskId}`);
    }
  };

  const makeCase = (mode, taskId, executionIdentityHash) => {
    const { objective, state } = taskObjective(taskId);
    if (mode === "training") {
      state.balances.find((item) => item.account === "participant" && item.assetId === "USDC").amountUnits = "20000000";
      state.stateSha256 = sha(JSON.stringify(state.balances));
    }
    const taskCase = {
      caseId: `synthetic-${mode}-${taskId}`,
      caseHash: "0".repeat(64),
      taskId,
      mode,
      rubricVersion: "bts-rubric/v1",
      rubricHash: api.taskRubricHash(taskId),
      taskWeight: WEIGHT[taskId],
      mandatoryRules: RULES[taskId],
      executionIdentityHash,
      taskDeadlineSeconds: 120,
      initialState: state,
      initialStateEvidence: evidence(`evidence/${mode}/${taskId}-initial-state.json`),
      referencePath: {
        evidence: evidence(`evidence/${mode}/${taskId}-reference.json`),
        actionCount: 2,
        initialStateSha256: state.stateSha256,
        finalStateSha256: sha(`final-${mode}-${taskId}`),
        toolSurfaceSha256: sha("synthetic-tool-surface"),
      },
      objective,
    };
    taskCase.caseHash = api.taskCaseHash(withoutKey(taskCase, "caseHash"));
    return taskCase;
  };

  const sourceBlockHash = sha("synthetic-source-block");
  const executionIdentity = {
    profileId: "synthetic-base-fork-profile-v1",
    environmentManifestSha256: sha("synthetic-environment-manifest"),
    toolSurfaceSha256: sha("synthetic-tool-surface"),
    x402ServiceSha256: sha("synthetic-x402-service"),
    applicationSchemaVersion: "synthetic-app-schema-v1",
    sourceNetwork: "base", sourceChainId: 8453, sourceBlockNumber: "100", sourceBlockHash,
    localNetwork: "base-anvil-fork", localChainId: 8453, localForkBlockNumber: "100",
    assets: [
      { assetId: "ETH", kind: "native", chainId: 8453, address: null, codeHash: null, decimals: 18 },
      { assetId: "WETH", kind: "erc20", chainId: 8453, address: WETH, codeHash: sha("synthetic-weth-code"), decimals: 18 },
      { assetId: "USDC", kind: "erc20", chainId: 8453, address: USDC, codeHash: sha("synthetic-usdc-code"), decimals: 6 },
    ],
    contracts: [
      { contractId: "router-main", address: ROUTER, codeHash: sha("synthetic-router-code"), chainId: 8453, blockNumber: "100", blockHash: sourceBlockHash },
      { contractId: "pool-main", address: POOL, codeHash: sha("synthetic-pool-code"), chainId: 8453, blockNumber: "100", blockHash: sourceBlockHash },
    ],
  };
  const executionIdentityHash = api.sha256CanonicalTaskJson(executionIdentity);
  const manifest = {
    schemaVersion: "bts-task-release/v1",
    releaseIdentity,
    benchmarkVersion: "synthetic-bts-v1",
    manifestHash: "0".repeat(64), benchmarkHash: "0".repeat(64), policyHash: "0".repeat(64),
    inventory: {
      orderedTaskIds: TASK_IDS,
      rankedWeightSum: 26,
      openTrainingTaskIds: TRAINING_IDS,
      openTrainingWeightSum: 15,
      closedRankedOnlyTaskIds: CLOSED_RANKED_IDS,
    },
    pricing: { precision: 6, openTrainingPriceUnits: "500000", rankedPriceUnits: "1000000", trainingRounding: "ceil_once_per_request" },
    deadlines: { taskTimeoutSeconds: 180, trainingRunTimeoutSeconds: 1800, rankedRunTimeoutSeconds: 3600 },
    executionIdentity,
    executionIdentityHash,
    costPolicy: {
      policyVersion: "synthetic-cost-policy-v1", usdcAssetId: "USDC", usdcPrecision: 6,
      ethValuation: { numerator: "1", denominator: "1000000000000" },
      expenseComponents: ["paid_service_charge", "participant_gas_success_or_revert", "verified_dex_fee"],
      rounding: "floor_to_usdc_base_units", principalSeparateFromExpense: true,
      ethAndWethDistinct: true, missingFeeEvidence: "unknown",
    },
    feasibilityEvidence: evidence("evidence/synthetic/feasibility.json"),
    difficultyReviewEvidence: evidence("evidence/synthetic/difficulty-review.json"),
    cases: {
      training: TRAINING_IDS.map((taskId) => makeCase("training", taskId, executionIdentityHash)),
      ranked: TASK_IDS.map((taskId) => makeCase("ranked", taskId, executionIdentityHash)),
    },
  };
  manifest.policyHash = api.taskPolicyHash(manifest);
  manifest.benchmarkHash = api.taskBenchmarkHash(manifest);
  manifest.manifestHash = api.sha256CanonicalTaskJson(withoutKey(manifest, "manifestHash"));
  return manifest;
}

function withoutKey(value, key) {
  const { [key]: _omitted, ...remaining } = value;
  return remaining;
}

function syntheticVerifier() {
  return {
    async verifyFeasibility(_evidence, _identity, executionIdentityHash) {
      return { status: "verified", executionIdentityHash, actualBoundary: true };
    },
    async verifyReferencePath({ taskCase, executionIdentityHash }) {
      return {
        status: "verified",
        caseHash: taskCase.caseHash,
        executionIdentityHash,
        toolSurfaceSha256: taskCase.referencePath.toolSurfaceSha256,
        actionCount: taskCase.referencePath.actionCount,
        initialStateSha256: taskCase.initialState.stateSha256,
        finalStateSha256: taskCase.referencePath.finalStateSha256,
        solvable: true,
        initiallySolved: false,
        actualBoundary: true,
      };
    },
    async verifyDifficultyReview(_evidence, _cases, executionIdentityHash) {
      return { status: "approved", executionIdentityHash, actualBoundary: true };
    },
  };
}

/** Test-only release adapter for owner PostgreSQL invariants; this never supplies production evidence. */
export function createSyntheticTaskPreparationReleaseFixture(releaseApi) {
  return { candidate: makeSyntheticManifest(releaseApi, `synthetic-preparation-${randomUUID()}`), verifier: syntheticVerifier() };
}
