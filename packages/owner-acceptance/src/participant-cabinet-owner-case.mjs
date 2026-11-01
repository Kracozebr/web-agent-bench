import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { spawn } from "node:child_process";
import pg from "pg";
import { runGenuineTrainingSequenceOwnerCase, runGenuineRankedOwnerCase,
  writeGenuineTrainingSequenceCapture, writeGenuineRankedCapture } from "./genuine-s1-cases.mjs";
import { runParticipantCabinetCases } from "./participant-cabinet-cases.mjs";

const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
const fixtureHash = sha("PCU history-only synthetic fixture; no task execution, grade or benchmark evidence");
const fixtureStamp = "2001-01-01T00:00:00.123456Z";
const fixtureReason = "PCU history-only synthetic fixture; not a run/grade/grant acceptance claim";
const uuid = () => randomUUID();

async function rawHistory({ repoRoot, databaseName, runId }) {
  return new Promise((done, reject) => {
    const child = spawn(process.execPath, [resolve(repoRoot, "tools/capture_ber_replay_history.mjs"), databaseName, runId, "history"], {
      cwd: repoRoot, env: process.env, stdio: ["ignore", "pipe", "pipe"], windowsHide: true,
    });
    let output = "", bytes = 0;
    const timer = setTimeout(() => { child.kill(); reject(new Error("PCU read-only raw-history collector timed out")); }, 120000);
    child.stdout.on("data", (chunk) => { bytes += chunk.length; if (bytes > 65536) { child.kill(); reject(new Error("PCU raw-history output exceeded its bound")); } else output += chunk; });
    child.stderr.on("data", () => {}); // Never echo connection/error internals into evidence or chat.
    child.on("error", () => { clearTimeout(timer); reject(new Error("PCU raw-history collector could not start")); });
    child.on("close", (code) => {
      clearTimeout(timer);
      if (code !== 0) return reject(new Error("PCU read-only raw-history collector exited unsuccessfully"));
      try {
        const record = JSON.parse(output.trim().split(/\r?\n/).at(-1));
        assert.match(record.path, /^artifacts\/runs\/ber-independent-replay-history\/[a-f0-9-]+\/history\.json$/);
        assert.match(record.sha256, /^[a-f0-9]{64}$/);
        done({ path: record.path, sha256: record.sha256 });
      } catch { reject(new Error("PCU raw-history collector did not return a safe artifact reference")); }
    });
  });
}

async function fixtureAgent(page, publicOrigin) {
  const response = await page.request.post("/api/owner/agents", { headers: { origin: publicOrigin }, data: {
    operationId: uuid(), name: "PCU history-only fixture", description: fixtureReason,
  } });
  assert.equal(response.status(), 201, "History fixture agent must be created through the actual owner service");
  return (await response.json()).agent.id;
}

/** Explicit private setup only. These terminal records have no tasks, grade or execution evidence. */
async function seedHistoryPair(client, { ownerId, agentId, stamp = fixtureStamp }) {
  const intentId = uuid(), runId = uuid();
  const deadline = new Date(Date.parse(stamp) + 86400000).toISOString();
  await client.query(`INSERT INTO oid_run_launch_intent(id,owner_id,agent_id,operation_id,payload_hash,mode,task_ids,release_identity,
    benchmark_version,manifest_hash,benchmark_hash,policy_hash,quote_price_units,cash_ceiling_units,owner_policy_revision,agent_policy_revision,created_at,expires_at)
    VALUES($1,$2,$3,$4,$5,'training',ARRAY['S1'],'pcu-history-fixture/v1','history-fixture',$5,$5,$5,1,0,1,1,$6,$7)`,
  [intentId, ownerId, agentId, "pcu_history_" + intentId, fixtureHash, stamp, deadline]);
  await client.query(`INSERT INTO oid_benchmark_run(id,intent_id,owner_id,agent_id,mode,task_ids,release_identity,benchmark_version,
    manifest_hash,benchmark_hash,policy_hash,quote_price_units,cash_ceiling_units,access_generation,agent_policy_revision,status,queued_at,queue_deadline,finished_at,terminal_reason)
    VALUES($1,$2,$3,$4,'training',ARRAY['S1'],'pcu-history-fixture/v1','history-fixture',$5,$5,$5,1,0,1,1,'cancelled',$6,$7,$6,'owner_cancelled')`,
  [runId, intentId, ownerId, agentId, fixtureHash, stamp, deadline]);
  await client.query("UPDATE oid_run_launch_intent SET status='accepted',run_id=$2,accepted_at=$3 WHERE id=$1 AND release_identity='pcu-history-fixture/v1'", [intentId, runId, stamp]);
  return { runId, intentId };
}

async function seedHistoricalGrant(client, { ownerId, adminOwnerId, units, stamp = fixtureStamp }) {
  const grantId = uuid(), ledgerId = uuid(), operationId = "pcu_history_" + uuid();
  await client.query("INSERT INTO oid_bonus_grant(id,owner_id,amount_units,issued_by_owner_id,reason,operation_id,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)",
    [grantId, ownerId, String(units), adminOwnerId, fixtureReason, operationId, stamp]);
  await client.query(`INSERT INTO oid_ledger_entry(id,owner_id,bonus_grant_id,operation_id,entry_type,source_kind,amount_units,available_delta_units,reason,created_at)
    VALUES($1,$2,$3,$4,'bonus_grant','tester_bonus',$5,$5,$6,$7)`, [ledgerId, ownerId, grantId, operationId, String(units), fixtureReason, stamp]);
  return { grantId, ledgerId, units: String(units) };
}

async function seedFixtureDebitRefund(client, { ownerId, grantId }) {
  const operationId = "pcu_history_direction_" + uuid();
  const rows = [];
  for (const [type, available, reserved] of [["reserve", -10000, 10000], ["debit", 0, -10000], ["refund", 10000, 0]]) {
    const id = uuid();
    await client.query(`INSERT INTO oid_ledger_entry(id,owner_id,bonus_grant_id,operation_id,entry_type,source_kind,amount_units,available_delta_units,reserved_delta_units,reason,created_at)
      VALUES($1,$2,$3,$4,$5,'tester_bonus',10000,$6,$7,$8,$9)`, [id, ownerId, grantId, operationId, type, available, reserved, fixtureReason, fixtureStamp]);
    rows.push({ id, type, magnitudeUnits: "10000" });
  }
  return rows;
}

async function sourceInventory(repoRoot, paths) {
  return Object.fromEntries(await Promise.all(paths.map(async (path) => [path, sha(await readFile(resolve(repoRoot, path)))])));
}

function normalizeAdditionalOwner(value) {
  const page = value?.page ?? value?.ownerPage;
  const ownerId = value?.ownerId ?? value?.owner?.id ?? value?.owner?.owner?.id;
  assert.ok(page && ownerId, "Additional owner callback must return {page,ownerId}");
  return { ...value, page, ownerId };
}

/** Coordinated isolated acceptance bootstrap. All data writes stay in a fresh disposable database. */
export async function runParticipantCabinetOwnerCase(input) {
  const common = input.commonCapture ?? input;
  const repoRoot = input.repoRoot ?? common.repoRoot;
  const databaseUrl = input.databaseUrl ?? common.databaseUrl;
  const database = new URL(databaseUrl);
  assert.equal(database.hostname, "postgres"); assert.equal(database.username, "oid_owner");
  const databaseName = database.pathname.slice(1);
  assert.match(databaseName, /^oid_acceptance_[a-f0-9]{32}$/);
  const isolation = common.databaseIsolation ?? input.databaseIsolation;
  assert.equal(isolation?.databaseName, databaseName); assert.equal(isolation?.uniquePerCapture, true);
  assert.equal(typeof input.createAdditionalAdmittedOwner, "function");
  const declaredSources = common.sourceInputsBefore ?? common.sourceHashesBefore ?? {};
  const sourcePaths = [...new Set([...(Array.isArray(declaredSources) ? declaredSources.map((row) => row.path) : Object.keys(declaredSources)),
    "packages/owner-acceptance/src/participant-cabinet-owner-case.mjs", "packages/owner-acceptance/src/participant-cabinet-cases.mjs",
    "packages/owner-acceptance/src/participant-history-render.mjs",
    "tests/bdd/adapters/participant_cabinet_replay.py", "tests/bdd/adapters/participant_cabinet_ux.py"] )].sort();
  const beforeSources = await sourceInventory(repoRoot, sourcePaths);
  const provenance = async () => {
    const afterSources = await sourceInventory(repoRoot, sourcePaths);
    assert.deepEqual(afterSources, beforeSources, "Source changed during actual PCU acceptance");
    return { databaseIsolation: isolation, inputHashesBefore: beforeSources, inputHashesAfter: afterSources, sourceStableDuringRun: true };
  };
  const reportProgress = (stage) => input.onProgress?.({ stage });
  const genuineInput = { ...common.genuineCaptureInput, ...input, repoRoot, databaseUrl, automaticWorkerEvaluation: true,
    mode: "training", taskIds: ["S1", "M1", "H1"], bddProbes: false, primaryClientOnly: false };
  reportProgress("actual_training_start");
  const training = await runGenuineTrainingSequenceOwnerCase(genuineInput);
  assert.equal(training.runCompletion?.status, "verified", "Actual Training worker lifecycle did not finish");
  assert.equal(training.automaticWorkerEvaluationVerified, true, "Synthetic grades cannot establish Training diagnostics");
  const trainingArtifact = await writeGenuineTrainingSequenceCapture({ repositoryRoot: repoRoot, capture: training, provenance: await provenance() });
  const trainingRef = { path: trainingArtifact.directory + "/capture.json", sha256: trainingArtifact.sha256 };
  const trainingHistoryRef = await rawHistory({ repoRoot, databaseName, runId: training.runId });
  reportProgress("actual_training_completed");
  let ranked = null, rankedRef = null, rankedHistoryRef = null;
  if (input.runRanked !== false) {
    reportProgress("actual_ranked_start");
    ranked = await runGenuineRankedOwnerCase({ ...genuineInput, mode: "ranked" });
    assert.equal(ranked.runCompletion?.status, "verified", "Actual Ranked worker lifecycle did not finish");
    const artifact = await writeGenuineRankedCapture({ repositoryRoot: repoRoot, capture: ranked, provenance: await provenance() });
    rankedRef = { path: artifact.directory + "/capture.json", sha256: artifact.sha256 };
    rankedHistoryRef = await rawHistory({ repoRoot, databaseName, runId: ranked.runId });
    reportProgress("actual_ranked_completed");
  }
  const foreign = normalizeAdditionalOwner(await input.createAdditionalAdmittedOwner());
  const empty = normalizeAdditionalOwner(await input.createAdditionalAdmittedOwner());
  const ownerPage = genuineInput.ownerPage, ownerId = genuineInput.ownerId, adminPage = genuineInput.adminPage;
  const adminOwnerResponse = await adminPage.request.get("/api/owner");
  const adminOwnerId = (await adminOwnerResponse.json()).owner.id;
  const ownerAgent = await fixtureAgent(ownerPage, genuineInput.publicOrigin);
  const foreignAgent = await fixtureAgent(foreign.page, genuineInput.publicOrigin);
  const pool = new pg.Pool({ connectionString: databaseUrl, max: 1, application_name: "pcu-private-history-fixture-setup" });
  const fixtureRecords = { boundary: "private_history_only_fixture_not_task_execution_or_grade_proof", ownerId, foreignOwnerId: foreign.ownerId, agents: [ownerAgent, foreignAgent], pairs: [], grants: [] };
  const client = await pool.connect();
  let fixtureFailure = null;
  try {
    const actualDatabase = (await client.query("SELECT current_database() AS name")).rows[0].name;
    assert.equal(actualDatabase, databaseName);
    await client.query("BEGIN");
    for (const [fixtureOwnerId, agentId] of [[ownerId, ownerAgent], [foreign.ownerId, foreignAgent]]) {
      for (const units of [1, 9999, 1004999, 1005000, 10001, 10002]) {
        fixtureRecords.pairs.push(await seedHistoryPair(client, { ownerId: fixtureOwnerId, agentId }));
        const grant = await seedHistoricalGrant(client, { ownerId: fixtureOwnerId, adminOwnerId, units });
        fixtureRecords.grants.push(grant);
        if (units === 1005000) fixtureRecords.directionRows = [...(fixtureRecords.directionRows ?? []), ...await seedFixtureDebitRefund(client, { ownerId: fixtureOwnerId, grantId: grant.grantId })];
      }
    }
    // Fixtures append positive magnitudes; immutable ledger triggers stay enabled.
    const triggers = (await client.query("SELECT tgname,tgenabled FROM pg_trigger WHERE tgname IN ('oid_bonus_grant_immutable_trg','oid_ledger_entry_immutable_trg') ORDER BY tgname")).rows;
    assert.equal(triggers.length, 2); assert.ok(triggers.every((row) => row.tgenabled === "O"));
    const sums = (await client.query(`SELECT g.id::text,g.amount_units::text,
      COALESCE(SUM(e.available_delta_units),0)::text AS available,COALESCE(SUM(e.reserved_delta_units),0)::text AS reserved,
      COALESCE(SUM(e.expired_delta_units),0)::text AS expired,
      COUNT(*) FILTER(WHERE e.entry_type='bonus_grant')::integer AS grant_entries
      FROM oid_bonus_grant g LEFT JOIN oid_ledger_entry e ON e.owner_id=g.owner_id AND e.bonus_grant_id=g.id
      WHERE g.owner_id=ANY($1::uuid[]) GROUP BY g.id ORDER BY g.id`, [[ownerId, foreign.ownerId]])).rows;
    for (const row of sums) {
      const available = BigInt(row.available), reserved = BigInt(row.reserved), expired = BigInt(row.expired);
      assert.equal(row.grant_entries, 1, "Every grant has one append-only source ledger credit");
      assert.ok(available >= 0n && reserved >= 0n && expired >= 0n && available + reserved + expired <= BigInt(row.amount_units), "History-only fixture must preserve exact financial account sums");
    }
    fixtureRecords.financialInvariants = { triggers, sums };
    await client.query("COMMIT");
  } catch (failure) { await client.query("ROLLBACK").catch(() => {}); fixtureFailure = failure; }
  finally { client.release(); }
  if (fixtureFailure) { await pool.end(); throw fixtureFailure; }
  const onHistoryFirstPage = async (kind) => {
    if (kind === "runs" || kind === "intents") {
      const connection = await pool.connect();
      try { await connection.query("BEGIN"); fixtureRecords.pairs.push(await seedHistoryPair(connection, { ownerId, agentId: ownerAgent, stamp: new Date().toISOString() })); await connection.query("COMMIT"); }
      catch (failure) { await connection.query("ROLLBACK").catch(() => {}); throw failure; } finally { connection.release(); }
    } else {
      const response = await adminPage.request.post("/api/admin/bonus-grants", { headers: { origin: genuineInput.publicOrigin }, data: { operationId: uuid(), ownerId, amount: "0.000001", reason: fixtureReason } });
      assert.equal(response.status(), 200, "Concurrent bonus history setup must pass the actual financial domain service");
    }
  };
  try {
    reportProgress("actual_pcu_browser_cases_start");
    const result = await runParticipantCabinetCases({ ...genuineInput, ...input, ownerPage, ownerId, adminPage,
      foreignOwnerPage: foreign.page, emptyOwnerPage: empty.page, onHistoryFirstPage, getFinalProvenance: provenance,
      captureRoot: resolve(repoRoot, `artifacts/runs/participant-cabinet/${input.captureId ?? uuid()}`),
      training: { runId: training.runId, agentId: training.agent.agentId, taskIds: ["S1", "M1", "H1"], legacyConnection: true,
        sourceCaptureRef: trainingRef, historyRef: trainingHistoryRef },
      ranked: ranked ? { runId: ranked.runId, agentId: ranked.agent.agentId, sourceCaptureRef: rankedRef } : null });
    reportProgress("actual_pcu_browser_cases_completed");
    return { schemaVersion: "participant-cabinet-owner-case/v1", ...result, actualTraining: { runId: training.runId, capture: trainingRef, history: trainingHistoryRef },
      actualRanked: rankedRef ? { runId: ranked.runId, capture: rankedRef, history: rankedHistoryRef } : null, fixtureRecords, provenance: await provenance() };
  } finally { await pool.end(); }
}
