/**
 * Real local bridge capture for an isolated owner PostgreSQL fixture and BEF
 * env-a. It uses a synthetic release query source explicitly, and never binds
 * the capture to product activation or an external task score.
 */
import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import pg from 'pg';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';

const { Client, Pool } = pg;
const root = resolve(fileURLToPath(new URL('../../..', import.meta.url)));
const runIdPattern = /^[0-9a-f-]{36}$/i;
const hashPattern = /^[0-9a-f]{64}$/i;
const txHashPattern = /^0x[0-9a-f]{64}$/i;
const environmentId = 'bef-env-a';

function sha256(bytes) { return createHash('sha256').update(bytes).digest('hex'); }
function hashText(text) { return sha256(Buffer.from(text, 'utf8')); }
function id() { return randomUUID(); }

async function writeArtifact(directory, filename, value) {
  await mkdir(directory, { recursive: true });
  const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
  const absolute = resolve(directory, filename);
  await writeFile(absolute, bytes, { flag: 'wx', mode: 0o600 });
  return { path: relative(root, absolute).replaceAll('\\', '/'), sha256: sha256(bytes) };
}

async function runOwnerMigrations(databaseUrl, authSecret) {
  const childEnv = { ...process.env, OID_DATABASE_URL: databaseUrl, OID_AUTH_SECRET: authSecret };
  await new Promise((resolvePromise, reject) => {
    const child = spawn('pnpm', ['--filter', '@web-agent-bench/owner-identity', 'exec', 'tsx', 'src/migrate.ts'], {
      cwd: root, env: childEnv, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true,
    });
    let output = '';
    child.stdout.on('data', (chunk) => { output += String(chunk); });
    child.stderr.on('data', (chunk) => { output += String(chunk); });
    child.once('error', reject);
    child.once('exit', (code) => code === 0 ? resolvePromise() : reject(new Error(`owner_fixture_migration_failed_${code ?? 'signal'}_${hashText(output).slice(0, 12)}`)));
  });
}

async function createAcceptanceDatabase(baseUrl) {
  const ownerUrl = new URL(baseUrl);
  if (ownerUrl.hostname !== 'postgres' || ownerUrl.username !== 'oid_owner' || !/^\/owner_identity$/.test(ownerUrl.pathname)) {
    throw new Error('owner_fixture_requires_declared_docker_database');
  }
  const runId = id();
  const databaseName = `oid_acceptance_${runId.replaceAll('-', '')}`;
  const admin = new Client({ connectionString: ownerUrl.href });
  await admin.connect();
  try { await admin.query(`CREATE DATABASE "${databaseName}" TEMPLATE template0`); }
  finally { await admin.end(); }
  const setupBase = new Client({ connectionString: ownerUrl.href });
  await setupBase.connect();
  try { await setupBase.query(`GRANT CONNECT ON DATABASE "${databaseName}" TO oid_observer`); }
  finally { await setupBase.end(); }
  ownerUrl.pathname = `/${databaseName}`;
  const setupAcceptance = new Client({ connectionString: ownerUrl.href });
  await setupAcceptance.connect();
  try {
    await setupAcceptance.query('GRANT USAGE ON SCHEMA public TO oid_observer');
    await setupAcceptance.query('ALTER DEFAULT PRIVILEGES FOR ROLE oid_owner IN SCHEMA public GRANT SELECT ON TABLES TO oid_observer');
  } finally { await setupAcceptance.end(); }
  return { databaseUrl: ownerUrl.href, databaseName, runId };
}

async function jsonRequest(url, init = {}) {
  let response;
  try {
    response = await fetch(url, { ...init, redirect: 'error', signal: AbortSignal.timeout(60_000) });
  } catch { throw new Error('bef_admin_or_participant_transport_unavailable'); }
  const text = await response.text();
  let body = null;
  try { body = JSON.parse(text); } catch { /* retain only the response hash in diagnostics */ }
  if (!response.ok) {
    const code = body && typeof body.error === 'string' && /^[a-z0-9_]{1,80}$/.test(body.error) ? body.error : 'unclassified';
    throw new Error(`bef_http_${response.status}_${code}`);
  }
  return { status: response.status, body, rawSha256: hashText(text) };
}

function assertLocalBefApiUrl(value) {
  let url;
  try { url = new URL(value); } catch { throw new Error('bef_bridge_probe_dependencies_invalid'); }
  const allowedHosts = new Set(['localhost', '127.0.0.1', '[::1]', '::1', 'host.docker.internal', 'api', 'bef-api', 'benchmark-environment-api']);
  if (url.protocol !== 'http:' || !allowedHosts.has(url.hostname.toLowerCase()) || url.username || url.password ||
      url.search || url.hash || (url.pathname !== '' && url.pathname !== '/')) {
    throw new Error('bef_purchase_requires_private_local_api');
  }
  return url;
}

function assertPinnedLocalForkHealth(health, policy) {
  const envHealth = health.environments.find((item) => item?.envId === environmentId);
  const anvil = envHealth?.anvil;
  const versions = health.dependencyVersions;
  let chainId;
  let forkBlock;
  try {
    chainId = BigInt(anvil?.chainId);
    forkBlock = BigInt(anvil?.forkBlockNumber);
  } catch { throw new Error('bef_purchase_private_fork_health_invalid'); }
  if (!anvil || !envHealth?.facilitator?.address ||
      !String(anvil.clientVersion).toLowerCase().includes(`anvil/v${policy.localAnvil.anvilVersion}`.toLowerCase()) ||
      chainId !== BigInt(policy.localAnvil.chainId) ||
      String(anvil.executionNetwork).toLowerCase() !== policy.localAnvil.executionNetwork.toLowerCase() ||
      String(anvil.hardFork).toLowerCase() !== policy.localAnvil.hardFork.toLowerCase() ||
      forkBlock !== BigInt(policy.localAnvil.forkBlockNumber) ||
      String(anvil.forkBlockHash).toLowerCase() !== policy.localAnvil.forkBlockHash.toLowerCase() ||
      versions?.['@x402/core'] !== policy.sdkVersions.core || versions?.['@x402/evm'] !== policy.sdkVersions.evm ||
      versions?.viem !== policy.sdkVersions.viem) {
    throw new Error('bef_purchase_private_fork_health_mismatch');
  }
}

async function seedOwnerRun(pool, input) {
  const taskId = input.taskId ?? 'S1';
  const ownerId = id(), agentId = id(), userId = id(), intentId = id(), runId = id(), grantId = id();
  const resource = 'http://bef-bridge-fixture.invalid/api/agent';
  const releaseIdentity = `synthetic-bef-bridge-${runId}`;
  const manifestHash = hashText(`synthetic-release-manifest:${runId}`);
  const benchmarkHash = hashText(`synthetic-benchmark:${runId}`);
  const policyHash = hashText(`synthetic-policy:${runId}`);
  await pool.query("INSERT INTO oid_auth_user(id,name,email,email_verified) VALUES($1,'Local bridge fixture',$2,true)",
    [userId, `${userId}@example.invalid`]);
  await pool.query("INSERT INTO oid_owner(id,auth_user_id,admission_status,admitted_at) VALUES($1,$2,'admitted',clock_timestamp())", [ownerId, userId]);
  await pool.query("INSERT INTO oid_agent(id,owner_id,name) VALUES($1,$2,'Local BEF bridge fixture agent')", [agentId, ownerId]);
  await pool.query('INSERT INTO oid_agent_policy(agent_id,training,ranked) VALUES($1,true,false)', [agentId]);
  await pool.query(`INSERT INTO oid_agent_access_grant(id,owner_id,agent_id,operation_id,resource,role,access_generation,expires_at)
    VALUES($1,$2,$3,$4,$5,'agent',1,clock_timestamp()+interval '1 hour')`, [grantId, ownerId, agentId, id(), resource]);
  await pool.query(`INSERT INTO oid_run_launch_intent(id,owner_id,agent_id,operation_id,payload_hash,mode,task_ids,release_identity,
      benchmark_version,manifest_hash,benchmark_hash,policy_hash,quote_price_units,cash_ceiling_units,owner_policy_revision,
      agent_policy_revision,status,expires_at,accepted_at)
    VALUES($1,$2,$3,$4,$5,'training',ARRAY[$10],$6,'synthetic-bef-bridge-v1',$7,$8,$9,0,0,1,1,'accepted',
      clock_timestamp()+interval '1 hour',clock_timestamp())`,
  [intentId, ownerId, agentId, id(), hashText(`intent:${runId}`), releaseIdentity, manifestHash, benchmarkHash, policyHash, taskId]);
  await pool.query(`INSERT INTO oid_benchmark_run(id,intent_id,owner_id,agent_id,mode,task_ids,release_identity,benchmark_version,
      manifest_hash,benchmark_hash,policy_hash,quote_price_units,cash_ceiling_units,access_generation,agent_policy_revision,status,
      queued_at,queue_deadline,started_at,overall_deadline,environment_id,environment_evidence_hash)
    VALUES($1,$2,$3,$4,'training',ARRAY[$11],$5,'synthetic-bef-bridge-v1',$6,$7,$8,0,0,1,1,'running',clock_timestamp(),
      clock_timestamp()+interval '1 hour',clock_timestamp(),clock_timestamp()+interval '1 hour',$9,$10)`,
  [runId, intentId, ownerId, agentId, releaseIdentity, manifestHash, benchmarkHash, policyHash, input.envId, hashText(`bef-env-evidence:${runId}`), taskId]);
  await pool.query(`INSERT INTO oid_run_task(run_id,task_index,task_id,status,snapshot_json,started_at,deadline_at)
    VALUES($1,0,$2,'active','{}'::jsonb,clock_timestamp(),clock_timestamp()+interval '30 minutes')`, [runId, taskId]);
  return { ownerId, agentId, grantId, resource, runId, taskIndex: 0, taskId, mode: 'training', releaseIdentity, manifestHash };
}

function makePrincipal(fixture) {
  return {
    ownerId: fixture.ownerId, agentId: fixture.agentId, grantId: fixture.grantId,
    credentialId: id(), resource: fixture.resource, role: 'agent', accessGeneration: 1,
    accessRevision: 1, policyRevision: 1,
    permissions: { training: true, ranked: false, forumMessages: false, customTopics: false },
  };
}

function decodeJson(value) {
  if (typeof value !== 'string') return value;
  try { return JSON.parse(value); } catch { return null; }
}

export function validateAcceptanceDatabaseBindings({ databaseUrl, observerDatabaseUrl }) {
  let ownerUrl, observerUrl;
  try {
    ownerUrl = new URL(databaseUrl);
    observerUrl = new URL(observerDatabaseUrl);
  } catch { throw new Error('owner_acceptance_database_identity_invalid'); }
  const allowedProtocol = (url) => url.protocol === 'postgres:' || url.protocol === 'postgresql:';
  if (!allowedProtocol(ownerUrl) || !allowedProtocol(observerUrl) ||
      ownerUrl.hostname !== 'postgres' || observerUrl.hostname !== 'postgres' ||
      ownerUrl.username !== 'oid_owner' || observerUrl.username !== 'oid_observer' ||
      !/^\/oid_acceptance_[a-f0-9]{32}$/.test(ownerUrl.pathname) || ownerUrl.pathname !== observerUrl.pathname ||
      ownerUrl.port !== observerUrl.port || ownerUrl.search || ownerUrl.hash || observerUrl.search || observerUrl.hash) {
    throw new Error('owner_acceptance_database_identity_invalid');
  }
  return ownerUrl.pathname.slice(1);
}

function verifyMeasurement(measurement, input) {
  if (!measurement || typeof measurement !== 'object') throw new Error('bef_persisted_measurement_missing');
  const before = measurement.before;
  const after = measurement.after;
  if (!before || !after || !measurement.receipt || !measurement.effects ||
      before.payerUsdcUnits === undefined || after.payerUsdcUnits === undefined ||
      before.recipientUsdcUnits === undefined || after.recipientUsdcUnits === undefined) {
    throw new Error('bef_transfer_state_observation_incomplete');
  }
  if (BigInt(before.payerUsdcUnits) - BigInt(after.payerUsdcUnits) !== BigInt(input.amountUnits) ||
      BigInt(after.recipientUsdcUnits) - BigInt(before.recipientUsdcUnits) !== BigInt(input.amountUnits) ||
      measurement.receipt.status !== 'success' || measurement.receipt.transactionHash.toLowerCase() !== input.transactionHash.toLowerCase()) {
    throw new Error('bef_transfer_receipt_or_state_mismatch');
  }
  return {
    before: { payerUsdcUnits: before.payerUsdcUnits, recipientUsdcUnits: before.recipientUsdcUnits, blockNumber: before.blockNumber },
    after: { payerUsdcUnits: after.payerUsdcUnits, recipientUsdcUnits: after.recipientUsdcUnits, blockNumber: after.blockNumber },
    receipt: { transactionHash: measurement.receipt.transactionHash, status: measurement.receipt.status,
      gasUsed: measurement.receipt.gasUsed, effectiveGasPrice: measurement.receipt.effectiveGasPrice,
      logsCount: Array.isArray(measurement.receipt.logs) ? measurement.receipt.logs.length : null },
  };
}

async function captureReadOnlyBridgeActions(input) {
  const { createDatabase } = await import('../../owner-identity/dist/db.js');
  const { loadConfig } = await import('../../owner-identity/dist/config.js');
  const taskActionService = await import('../../owner-identity/dist/task-action-service.js');
  const { BefTaskExecutor } = await import('../../owner-identity/dist/bef-task-executor.js');
  const { canonicalTaskJson } = await import('../../owner-identity/dist/task-release.js');
  const created = createDatabase(loadConfig({ ...process.env, OID_DATABASE_URL: input.ownerUrl, OID_AUTH_SECRET: input.authSecret }));
  input.setOwnerDb(created.db, created.client);
  const principal = makePrincipal(input.fixture);
  const releaseSource = {
    async getValidatedReleaseRecord(releaseIdentity, manifestHash) {
      if (releaseIdentity !== input.fixture.releaseIdentity || manifestHash !== input.fixture.manifestHash) return null;
      return { releaseIdentity, manifestHash, manifest: { executionIdentity: {
        environmentManifestSha256: input.health.manifestSha256,
        x402ServiceSha256: input.health.applicationSourceSha256,
      } } };
    },
  };
  const evidenceReferences = [];
  const executor = new BefTaskExecutor({
    db: created.db,
    taskReleaseSource: releaseSource,
    participantApiByEnvironment: { [input.envId]: input.apiBaseUrl },
    evidenceSink: {
      async write(evidence) {
        const bytes = Buffer.from(JSON.stringify(evidence), 'utf8');
        const file = resolve(input.evidenceDirectory, `participant-tool-observation-${evidence.actionSequence}.json`);
        await writeFile(file, bytes, { flag: 'wx', mode: 0o600 });
        const ref = { path: relative(root, file).replaceAll('\\', '/'), sha256: sha256(bytes) };
        evidenceReferences.push(ref);
        return ref;
      },
    },
    requestTimeoutMs: 60_000,
    staleDeliveryMs: 90_000,
  });
  await executor.bindSession({
    runId: input.fixture.runId, taskIndex: 0, envId: input.envId,
    generationId: input.generationId, manifestHash: input.health.manifestSha256,
    applicationSourceHash: input.health.applicationSourceSha256, runToken: input.runToken,
  });

  const commands = [{ kind: 'inspect_catalog' }];
  const observations = [];
  for (let index = 0; index < commands.length; index += 1) {
    const command = commands[index];
    const admission = await taskActionService.admitTaskAction({ db: created.db }, principal, {
      runId: input.fixture.runId, taskIndex: 0, operationId: id().replaceAll('-', ''), command,
    });
    if (!admission.admitted) throw new Error('owner_fixture_read_action_not_admitted');
    const execution = await executor.executeNext(input.fixture.runId, 0);
    if (execution.status !== 'recorded' || execution.receiptStatus !== 'observed' || execution.actionId !== admission.actionId) {
      throw new Error(`bef_bridge_read_action_${execution.status}`);
    }
    const state = await taskActionService.getTaskActionState({ db: created.db }, principal, {
      runId: input.fixture.runId, actionId: admission.actionId,
    });
    const toolResponse = state.toolResponse;
    if (!toolResponse || state.status !== 'observed' || !state.evidencePath || state.transactionHash !== null) {
      throw new Error('owner_read_action_receipt_projection_incomplete');
    }
    const receipt = await input.ownerObserverPool.query(`SELECT receipt_status,evidence_hash,evidence_path,transaction_hash,tool_response_hash
      FROM oid_run_task_action_receipt WHERE action_id=$1`, [admission.actionId]);
    const stored = receipt.rows[0];
    if (!stored || stored.receipt_status !== 'observed' || stored.evidence_hash !== execution.evidenceHash ||
        stored.evidence_path !== execution.evidencePath || stored.transaction_hash !== null ||
        stored.tool_response_hash !== sha256(Buffer.from(canonicalTaskJson(toolResponse), 'utf8'))) {
      throw new Error('owner_read_action_receipt_persistence_mismatch');
    }
    const receiptArtifact = await writeArtifact(input.evidenceDirectory, `owner-read-action-receipt-${admission.actionSequence}.json`, {
      actionId: admission.actionId, runId: input.fixture.runId, taskIndex: 0,
      actionSequence: admission.actionSequence, command,
      receiptStatus: stored.receipt_status, evidenceHash: stored.evidence_hash,
      evidencePath: stored.evidence_path, transactionHash: stored.transaction_hash,
      toolResponseHash: stored.tool_response_hash,
    });
    observations.push({ actionId: admission.actionId, actionSequence: admission.actionSequence, command,
      status: execution.receiptStatus, evidenceHash: execution.evidenceHash, evidencePath: execution.evidencePath,
      toolResponseHash: stored.tool_response_hash, toolResponse });

    if (command.kind === 'inspect_catalog') {
      const catalog = toolResponse.catalog;
      if (!Array.isArray(catalog) || catalog.length < 2) throw new Error('bef_pinned_catalog_did_not_return_multiple_resources');
      const distinctResource = catalog.find((resource) => resource.resourceId !== 'bef-resource-v1');
      if (!distinctResource || !Array.isArray(distinctResource.offers) || distinctResource.offers.length < 1) {
        throw new Error('bef_distinct_resource_offer_not_present_in_catalog');
      }
      const selectedOffer = distinctResource.offers[0];
      commands.push({ kind: 'inspect_offer', resourceId: distinctResource.resourceId, offerId: selectedOffer.id });
    } else {
      if (toolResponse.resourceId !== command.resourceId ||
          !toolResponse.offers.some((offer) => offer.id === command.offerId)) {
        throw new Error('bef_pinned_offer_observation_does_not_match_catalog_selection');
      }
      const operation = await input.befPool.query(`SELECT env_id,generation_id::text,operation_kind,status,receipt_status,transaction_hash,response_sha256
        FROM bef_operation WHERE operation_id=$1`, [execution.befOperationId]);
      const row = operation.rows[0];
      if (!row || row.env_id !== input.envId || row.generation_id !== input.generationId || row.operation_kind !== 'offer' ||
          row.status !== 'accepted' || row.receipt_status !== 'not_submitted' || row.transaction_hash !== null) {
        throw new Error('bef_offer_read_operation_persistence_mismatch');
      }
      observations[observations.length - 1].befOperation = {
        operationId: execution.befOperationId, envId: row.env_id, generationId: row.generation_id,
        operationKind: row.operation_kind, status: row.status, receiptStatus: row.receipt_status,
        transactionHash: row.transaction_hash, responseSha256: row.response_sha256,
      };
    }
    observations[observations.length - 1].ownerReceiptEvidence = receiptArtifact;
    observations[observations.length - 1].participantToolEvidence = evidenceReferences.at(-1);
  }
  return observations;
}

async function readPinnedX402Policy(health, envId) {
  const manifestPath = resolve(root, 'infrastructure/benchmark-environment/manifest.json');
  const manifestBytes = await readFile(manifestPath);
  const manifest = JSON.parse(manifestBytes.toString('utf8'));
  const manifestHash = sha256(manifestBytes);
  if (manifestHash !== health.manifestSha256 || manifest.local?.identity !== 'private-anvil-fork' ||
      manifest.local.chainId !== 8453 || manifest.x402?.network !== 'eip155:8453' ||
      !Array.isArray(manifest.x402.catalog) || manifest.x402.catalog.length < 2) {
    throw new Error('bef_purchase_manifest_pin_mismatch');
  }
  const envHealth = health.environments.find((item) => item?.envId === envId);
  if (!envHealth?.anvil || !envHealth?.facilitator?.address) throw new Error('bef_purchase_local_identity_missing');
  const resources = manifest.x402.catalog.map((resource) => ({
    resourceId: resource.resourceId,
    resourceSha256: resource.resourceSha256,
    contentType: resource.contentType,
    ...(resource.dataType ? { dataType: resource.dataType } : {}),
    ...(resource.schema ? { schema: resource.schema } : {}),
    ...(resource.provenance ? { provenance: resource.provenance } : {}),
    offers: resource.offers.map((offer) => ({ id: offer.id, amount: offer.amount })),
  }));
  for (const resource of manifest.x402.catalog) {
    const bytes = await readFile(resolve(root, resource.resourcePath));
    if (sha256(bytes) !== resource.resourceSha256) throw new Error('bef_purchase_resource_fixture_hash_mismatch');
  }
  const policy = {
    manifestSha256: manifestHash,
    scheme: manifest.x402.scheme,
    network: manifest.x402.network,
    asset: manifest.x402.asset,
    assetTransferMethod: manifest.x402.assetTransferMethod,
    eip712Domain: manifest.x402.eip712Domain,
    maxTimeoutSeconds: manifest.x402.maxTimeoutSeconds,
    sdkVersions: {
      core: manifest.local.versions.x402Core,
      evm: manifest.local.versions.x402Evm,
      viem: manifest.local.versions.viem,
    },
    localAnvil: {
      identity: manifest.local.identity,
      chainId: manifest.local.chainId,
      anvilVersion: manifest.local.anvilVersion,
      executionNetwork: manifest.local.executionNetwork,
      hardFork: manifest.local.hardfork,
      forkBlockNumber: manifest.local.forkBlock,
      forkBlockHash: manifest.source.blockHash,
    },
    resources,
  };
  return { policy, manifest };
}

async function capturePurchaseBridgeAction(input) {
  const { createDatabase } = await import('../../owner-identity/dist/db.js');
  const { loadConfig } = await import('../../owner-identity/dist/config.js');
  const taskActionService = await import('../../owner-identity/dist/task-action-service.js');
  const { BefTaskExecutor } = await import('../../owner-identity/dist/bef-task-executor.js');
  const { createEphemeralX402TaskSigner } = await import('../../owner-identity/dist/task-action-x402.js');
  const { canonicalTaskJson } = await import('../../owner-identity/dist/task-release.js');
  const { policy, manifest } = input.pinnedX402 ?? await readPinnedX402Policy(input.health, input.envId);
  const resource = policy.resources[1];
  const offer = resource?.offers[0];
  if (!resource || !offer) throw new Error('bef_purchase_selected_fixture_missing');

  const created = createDatabase(loadConfig({ ...process.env, OID_DATABASE_URL: input.ownerUrl, OID_AUTH_SECRET: input.authSecret }));
  input.setOwnerDb(created.db, created.client);
  const principal = makePrincipal(input.fixture);
  const command = { kind: 'purchase', resourceId: resource.resourceId, offerId: offer.id };
  const admission = await taskActionService.admitTaskAction({ db: created.db }, principal, {
    runId: input.fixture.runId, taskIndex: 0, operationId: id().replaceAll('-', ''), command,
  });
  if (!admission.admitted) throw new Error('owner_fixture_purchase_action_not_admitted');

  const releaseSource = {
    async getValidatedReleaseRecord(releaseIdentity, manifestHash) {
      if (releaseIdentity !== input.fixture.releaseIdentity || manifestHash !== input.fixture.manifestHash) return null;
      return { releaseIdentity, manifestHash, manifest: { executionIdentity: {
        environmentManifestSha256: input.health.manifestSha256,
        x402ServiceSha256: input.health.applicationSourceSha256,
      } } };
    },
  };
  const evidenceFile = resolve(input.evidenceDirectory, 'participant-tool-observation.json');
  const executor = new BefTaskExecutor({
    db: created.db,
    taskReleaseSource: releaseSource,
    participantApiByEnvironment: { [input.envId]: input.apiBaseUrl },
    pinnedX402PolicyByEnvironment: { [input.envId]: policy },
    evidenceSink: {
      async write(evidence) {
        const bytes = Buffer.from(canonicalTaskJson(evidence), 'utf8');
        await writeFile(evidenceFile, bytes, { flag: 'wx', mode: 0o600 });
        return { path: relative(root, evidenceFile).replaceAll('\\', '/'), sha256: sha256(bytes) };
      },
    },
    requestTimeoutMs: 60_000,
    staleDeliveryMs: 90_000,
  });
  await executor.bindSession({
    runId: input.fixture.runId, taskIndex: 0, envId: input.envId,
    generationId: input.generationId, manifestHash: input.health.manifestSha256,
    applicationSourceHash: input.health.applicationSourceSha256, runToken: input.runToken,
    participantId: input.participantId, payerAddress: input.payerAddress,
    x402Signer: createEphemeralX402TaskSigner(input.privateKey, policy.network),
  });

  const execution = await executor.executeNext(input.fixture.runId, 0);
  executor.unbindSession(input.fixture.runId, 0);
  if (execution.status !== 'recorded' || execution.receiptStatus !== 'observed' || !execution.befOperationId || !execution.transactionHash) {
    throw new Error(`bef_bridge_purchase_${execution.status === 'recorded' ? execution.receiptStatus : execution.status}`);
  }
  const ownerState = await taskActionService.getTaskActionState({ db: created.db }, principal, {
    runId: input.fixture.runId, actionId: admission.actionId,
  });
  const toolResponse = ownerState.toolResponse;
  if (!toolResponse || ownerState.status !== 'observed' || !ownerState.evidencePath ||
      toolResponse.resourceId !== resource.resourceId || toolResponse.contentHash !== resource.resourceSha256 ||
      !toolResponse.contentBytes) throw new Error('owner_purchase_response_persistence_incomplete');
  const responseBytes = Buffer.from(toolResponse.contentBytes, 'base64');
  if (sha256(responseBytes) !== resource.resourceSha256) throw new Error('owner_purchase_content_hash_mismatch');

  const ownerReceiptRows = await input.ownerObserverPool.query(`SELECT receipt_status,evidence_hash,evidence_path,transaction_hash,
      tool_response_json,tool_response_hash FROM oid_run_task_action_receipt WHERE action_id=$1`, [admission.actionId]);
  const ownerReceipt = ownerReceiptRows.rows[0];
  if (!ownerReceipt || ownerReceipt.receipt_status !== 'observed' ||
      ownerReceipt.transaction_hash?.toLowerCase() !== execution.transactionHash.toLowerCase() ||
      ownerReceipt.evidence_hash !== execution.evidenceHash || ownerReceipt.evidence_path !== execution.evidencePath ||
      ownerReceipt.tool_response_hash !== sha256(Buffer.from(canonicalTaskJson(toolResponse), 'utf8'))) {
    throw new Error('owner_purchase_receipt_persistence_mismatch');
  }
  const ownerReceiptEvidence = await writeArtifact(input.evidenceDirectory, 'owner-action-receipt.json', {
    actionId: admission.actionId, runId: input.fixture.runId, taskIndex: 0,
    actionSequence: admission.actionSequence, receiptStatus: ownerReceipt.receipt_status,
    evidenceHash: ownerReceipt.evidence_hash, evidencePath: ownerReceipt.evidence_path,
    transactionHash: ownerReceipt.transaction_hash, toolResponseHash: ownerReceipt.tool_response_hash,
  });

  const operationRows = await input.befPool.query(`SELECT o.operation_id::text,o.env_id,o.generation_id::text,o.participant_id,
      o.operation_kind,o.status,o.receipt_status,o.transaction_hash,o.selected_resource_id,o.selected_resource_sha256,
      o.selected_offer_id,o.selected_amount_units::text,p.payer_address,p.network,p.asset_address,p.amount_units::text,
      p.facilitator_address,p.transaction_hash AS payment_transaction_hash,p.receipt_status AS payment_receipt_status,
      p.token_delta_units::text,d.resource_id AS delivered_resource_id,d.content_sha256,d.content_bytes
    FROM bef_operation o JOIN bef_payment p USING(operation_id) JOIN bef_delivery d USING(operation_id)
    WHERE o.operation_id=$1 AND o.env_id=$2 AND o.generation_id=$3`,
  [execution.befOperationId, input.envId, input.generationId]);
  const operation = operationRows.rows[0];
  if (!operation || operation.participant_id !== input.participantId || operation.operation_kind !== 'purchase' ||
      operation.status !== 'delivered' || operation.receipt_status !== 'success' ||
      operation.transaction_hash?.toLowerCase() !== execution.transactionHash.toLowerCase() ||
      operation.payment_transaction_hash?.toLowerCase() !== execution.transactionHash.toLowerCase() ||
      operation.payment_receipt_status !== 'success' || operation.selected_resource_id !== resource.resourceId ||
      operation.selected_resource_sha256 !== resource.resourceSha256 || operation.delivered_resource_id !== resource.resourceId ||
      operation.content_sha256 !== resource.resourceSha256 || operation.selected_offer_id !== offer.id ||
      operation.selected_amount_units !== offer.amount || operation.amount_units !== offer.amount ||
      operation.token_delta_units !== offer.amount || operation.payer_address?.toLowerCase() !== input.payerAddress.toLowerCase() ||
      operation.network !== policy.network || operation.asset_address.toLowerCase() !== policy.asset.toLowerCase()) {
    throw new Error('bef_purchase_operation_or_payment_persistence_mismatch');
  }
  if (Number(operation.content_bytes) !== responseBytes.byteLength) throw new Error('bef_purchase_delivery_length_mismatch');

  // Reusing the paid operation key with a different pinned resource/offer must
  // fail before payment handling; the request deliberately contains no payment header.
  const otherResource = manifest.x402.catalog[0];
  const otherOffer = otherResource?.offers[0];
  if (!otherResource || !otherOffer || otherResource.resourceId === resource.resourceId) {
    throw new Error('bef_purchase_wrong_resource_replay_fixture_invalid');
  }
  const replayRequestBody = JSON.stringify({ resourceId: otherResource.resourceId, offerId: otherOffer.id });
  const replayResponse = await fetch(new URL(`/tools/${input.envId}/purchase`, input.apiBaseUrl), {
    method: 'POST', redirect: 'error', signal: AbortSignal.timeout(60_000),
    headers: {
      authorization: `Bearer ${input.runToken}`, 'x-bef-generation': input.generationId,
      'idempotency-key': `task-action-${admission.actionId}`, accept: 'application/json', 'content-type': 'application/json',
    },
    body: replayRequestBody,
  });
  const replayBytes = Buffer.from(await replayResponse.arrayBuffer());
  let replayBody = null;
  try { replayBody = JSON.parse(replayBytes.toString('utf8')); } catch { /* only digest retained */ }
  if (replayResponse.status !== 409 || replayBody?.error !== 'idempotency_key_conflict') {
    throw new Error('bef_purchase_wrong_resource_replay_not_denied');
  }
  const noDuplicateRows = await input.befPool.query(`SELECT
      (SELECT count(*)::integer FROM bef_operation WHERE env_id=$1 AND generation_id=$2 AND operation_kind='purchase') AS purchase_operations,
      (SELECT count(*)::integer FROM bef_payment WHERE env_id=$1 AND generation_id=$2) AS payments`,
  [input.envId, input.generationId]);
  if (noDuplicateRows.rows[0]?.purchase_operations !== 1 || noDuplicateRows.rows[0]?.payments !== 1) {
    throw new Error('bef_purchase_wrong_resource_replay_created_extra_effect');
  }

  const participantBytes = await readFile(evidenceFile);
  if ([input.privateKey, input.runToken].some((secret) => participantBytes.includes(Buffer.from(secret)))) {
    throw new Error('bef_purchase_secret_in_evidence');
  }
  const paymentArtifact = await writeArtifact(input.evidenceDirectory, 'bef-purchase-operation.json', {
    operationId: operation.operation_id, envId: operation.env_id, generationId: operation.generation_id,
    participantId: operation.participant_id, operationKind: operation.operation_kind, status: operation.status,
    receiptStatus: operation.receipt_status, transactionHash: operation.transaction_hash,
    selectedResourceId: operation.selected_resource_id, selectedResourceSha256: operation.selected_resource_sha256,
    selectedOfferId: operation.selected_offer_id, selectedAmountUnits: operation.selected_amount_units,
    payerAddress: operation.payer_address, network: operation.network, assetAddress: operation.asset_address,
    facilitatorAddress: operation.facilitator_address, paymentReceiptStatus: operation.payment_receipt_status,
    paymentTokenDeltaUnits: operation.token_delta_units,
    deliveredResourceId: operation.delivered_resource_id, deliveredContentSha256: operation.content_sha256,
    deliveredContentBytes: Number(operation.content_bytes),
  });
  const replayArtifact = await writeArtifact(input.evidenceDirectory, 'wrong-resource-replay-denial.json', {
    method: 'POST', status: replayResponse.status, error: replayBody.error,
    requestSha256: sha256(Buffer.from(replayRequestBody, 'utf8')), responseSha256: sha256(replayBytes),
    paymentAuthorizationPresent: false,
  });
  const evidence = {
    participantTool: { path: relative(root, evidenceFile).replaceAll('\\', '/'), sha256: sha256(participantBytes) },
    ownerReceipt: ownerReceiptEvidence,
    befPurchaseOperation: paymentArtifact,
    wrongResourceReplay: replayArtifact,
  };
  return {
    actionId: admission.actionId, actionSequence: admission.actionSequence, command,
    receiptStatus: execution.receiptStatus, evidenceHash: execution.evidenceHash,
    evidencePath: execution.evidencePath, transactionHash: execution.transactionHash,
    befOperationId: execution.befOperationId, toolResponseHash: ownerReceipt.tool_response_hash,
    resourceSha256: resource.resourceSha256, contentBytes: responseBytes.byteLength,
    wrongResourceReplayStatus: replayResponse.status, wrongResourceReplayError: replayBody.error,
    evidence,
  };
}

export async function runBefTaskExecutorBridgeCapture(options) {
  const apiBaseUrl = options.apiBaseUrl ?? 'http://host.docker.internal:38783';
  assertLocalBefApiUrl(apiBaseUrl);
  const befDatabaseUrl = options.befDatabaseUrl;
  const adminKey = options.adminKey;
  const evidenceDirectory = resolve(options.evidenceDirectory ?? resolve(root, 'artifacts/runs/bts-task-action-executor-bridge', id()));
  const envId = options.envId ?? environmentId;
  const ownerUrl = options.databaseUrl;
  let ownerObserverUrl;
  try { ownerObserverUrl = validateAcceptanceDatabaseBindings({ databaseUrl: ownerUrl, observerDatabaseUrl: options.observerDatabaseUrl }); }
  catch { throw new Error('bef_bridge_probe_dependencies_invalid'); }
  if (!ownerUrl || !befDatabaseUrl || !adminKey || !/^https?:\/\//.test(apiBaseUrl) || envId !== environmentId) {
    throw new Error('bef_bridge_probe_dependencies_invalid');
  }
  const captureId = id();
  const summary = {
    schema: 'bef-task-executor-bridge-capture-v1', captureId, envId,
    actionSurface: options.mode === 'read-only' ? 'catalog_and_offer_inspection' : options.mode === 'purchase'
      ? 'x402_purchase_and_delivery' : 'transfer',
    classification: 'local_selected_tool_bridge_only',
    fixtureProvenance: {
      ownerRun: 'synthetic isolated acceptance fixture',
      releaseProvider: 'synthetic query-source pinned to observed local BEF health digests',
      ownerDatabase: options.databaseName ? `isolated acceptance database ${options.databaseName}; retained for inspection` : 'isolated acceptance database',
      productReleaseActivation: false,
    },
    outcome: 'unknown',
  };
  let generationId;
  let privateKey;
  let runToken;
  let ownerClient;
  let ownerPool;
  let ownerObserverPool;
  let befPool;
  let ownerDatabase;
  let ownerDbClient;
  let phase = 'health_request';
  try {
    await mkdir(evidenceDirectory, { recursive: true });
    const healthResult = await jsonRequest(new URL('/healthz', apiBaseUrl));
    const health = healthResult.body;
    if (!health || health.status !== 'ready' || health.boundary !== 'benchmark-environment-api' ||
        !hashPattern.test(health.manifestSha256) || !hashPattern.test(health.applicationSourceSha256) ||
        !Array.isArray(health.environments) || !health.environments.some((entry) => entry?.envId === envId)) {
      throw new Error('bef_api_health_identity_invalid');
    }
    let pinnedX402;
    if (options.mode === 'purchase') {
      phase = 'purchase_manifest_identity';
      pinnedX402 = await readPinnedX402Policy(health, envId);
      assertPinnedLocalForkHealth(health, pinnedX402.policy);
    }
    summary.manifestSha256 = health.manifestSha256;
    summary.applicationSourceSha256 = health.applicationSourceSha256;
    summary.healthResponseSha256 = healthResult.rawSha256;

    phase = 'environment_reset';
    const resetResult = await jsonRequest(new URL(`/internal/admin/environments/${envId}/reset`, apiBaseUrl), {
      method: 'POST', headers: { 'x-bef-admin-key': adminKey, 'content-type': 'application/json' }, body: '{}',
    });
    if (resetResult.body?.status !== 'reset' || resetResult.body?.envId !== envId ||
        resetResult.body?.manifestSha256 !== health.manifestSha256) throw new Error('bef_environment_reset_identity_mismatch');
    summary.reset = { status: 'reset', responseSha256: resetResult.rawSha256 };

    privateKey = generatePrivateKey();
    const payerAddress = privateKeyToAccount(privateKey).address;
    const participantId = `bef-task-executor-${captureId}`;
    phase = 'generation_create';
    const generationResult = await jsonRequest(new URL(`/internal/admin/environments/${envId}/generations`, apiBaseUrl), {
      method: 'POST', headers: { 'x-bef-admin-key': adminKey, 'content-type': 'application/json' },
      body: JSON.stringify({ participantId, payerAddress, payerPrivateKey: privateKey, resourceVariant: 'canonical' }),
    });
    const generation = generationResult.body;
    if (!generation || generation.envId !== envId || generation.participantId !== participantId ||
        typeof generation.generationId !== 'string' || !runIdPattern.test(generation.generationId) ||
        typeof generation.runToken !== 'string' || !/^[A-Za-z0-9_-]{32,128}$/.test(generation.runToken) ||
        generation.payerAddress?.toLowerCase() !== payerAddress.toLowerCase()) {
      throw new Error('bef_generation_identity_invalid');
    }
    generationId = generation.generationId;
    runToken = generation.runToken;
    summary.generationId = generationId;
    summary.participantId = participantId;
    summary.payerAddress = payerAddress;
    summary.generationResponseSha256 = generationResult.rawSha256;

    const authSecret = randomBytes(48).toString('base64url');
    phase = 'owner_migration';
    await runOwnerMigrations(ownerUrl, authSecret);
    ownerPool = new Pool({ connectionString: ownerUrl, max: 4, application_name: 'bef-task-executor-bridge-fixture' });
    phase = 'owner_observer_grants';
    await ownerPool.query('GRANT USAGE ON SCHEMA public TO oid_observer');
    await ownerPool.query('GRANT SELECT ON ALL TABLES IN SCHEMA public TO oid_observer');
    await ownerPool.query('ALTER DEFAULT PRIVILEGES FOR ROLE oid_owner IN SCHEMA public GRANT SELECT ON TABLES TO oid_observer');
    ownerObserverPool = new Pool({ connectionString: options.observerDatabaseUrl, max: 2, application_name: 'bef-task-executor-bridge-owner-observer' });
    phase = 'owner_observer_identity';
    await ownerObserverPool.query('BEGIN READ ONLY');
    const ownerIdentity = await ownerPool.query('SELECT current_database() AS database_name');
    const ownerObserverIdentity = await ownerObserverPool.query(`SELECT current_user AS role,
        current_setting('transaction_read_only') AS readonly,current_database() AS database_name`);
    if (ownerIdentity.rows[0]?.database_name !== ownerObserverUrl ||
        ownerObserverIdentity.rows[0]?.role !== 'oid_observer' || ownerObserverIdentity.rows[0]?.readonly !== 'on' ||
        ownerObserverIdentity.rows[0]?.database_name !== ownerObserverUrl) {
      throw new Error('owner_acceptance_database_identity_mismatch');
    }
    phase = 'owner_fixture_seed';
    const fixture = await seedOwnerRun(ownerPool, { envId, taskId: options.mode === 'read-only' ? 'S2' : options.mode === 'purchase' ? 'M1' : 'S1' });
    summary.ownerRunId = fixture.runId;
    if (options.mode === 'read-only') {
      phase = 'bef_read_action_observer';
      befPool = new Pool({ connectionString: befDatabaseUrl, max: 2, application_name: 'bef-task-executor-read-bridge-observer' });
      await befPool.query('BEGIN READ ONLY');
      const role = await befPool.query("SELECT current_user AS role,current_setting('transaction_read_only') AS readonly");
      if (role.rows[0]?.role !== 'bef_observer' || role.rows[0]?.readonly !== 'on') throw new Error('bef_database_observer_role_invalid');
      phase = 'bef_read_action_dispatch';
      const readActions = await captureReadOnlyBridgeActions({
        ownerUrl, authSecret, ownerObserverPool, befPool, fixture, envId, apiBaseUrl,
        generationId, runToken, health, evidenceDirectory,
        setOwnerDb(db, client) { ownerDatabase = db; ownerDbClient = client; },
      });
      const secrets = [privateKey, runToken];
      const { readFile } = await import('node:fs/promises');
      for (const action of readActions) {
        const retainedBytes = await readFile(resolve(root, action.participantToolEvidence.path));
        if (secrets.some((secret) => retainedBytes.includes(Buffer.from(secret)))) throw new Error('bef_read_bridge_secret_in_evidence');
      }
      summary.readActions = readActions;
      summary.outcome = 'observed';
      return summary;
    }
    if (options.mode === 'purchase') {
      phase = 'bef_purchase_observer';
      befPool = new Pool({ connectionString: befDatabaseUrl, max: 2, application_name: 'bef-task-executor-purchase-observer' });
      await befPool.query('BEGIN READ ONLY');
      const role = await befPool.query("SELECT current_user AS role,current_setting('transaction_read_only') AS readonly");
      if (role.rows[0]?.role !== 'bef_observer' || role.rows[0]?.readonly !== 'on') throw new Error('bef_database_observer_role_invalid');
      phase = 'owner_purchase_action_dispatch';
      const purchaseAction = await capturePurchaseBridgeAction({
        ownerUrl, authSecret, ownerObserverPool, befPool, fixture, envId, apiBaseUrl,
        generationId, runToken, privateKey, payerAddress, participantId, health, evidenceDirectory,
        pinnedX402,
        setOwnerDb(db, client) { ownerDatabase = db; ownerDbClient = client; },
      });
      const retained = await readFile(resolve(evidenceDirectory, 'participant-tool-observation.json'));
      if ([privateKey, runToken].some((secret) => retained.includes(Buffer.from(secret)))) {
        throw new Error('bef_purchase_secret_in_evidence');
      }
      summary.purchaseAction = purchaseAction;
      summary.outcome = 'observed';
      return summary;
    }
    const recipientKey = generatePrivateKey();
    const recipient = privateKeyToAccount(recipientKey).address;
    const amountUnits = '100000';
    const command = { kind: 'transfer', amountUnits, recipient, gasLimit: '100000' };
    const { createDatabase } = await import('../../owner-identity/dist/db.js');
    const { loadConfig } = await import('../../owner-identity/dist/config.js');
    const taskActionService = await import('../../owner-identity/dist/task-action-service.js');
    const { BefTaskExecutor } = await import('../../owner-identity/dist/bef-task-executor.js');
    const config = loadConfig({ ...process.env, OID_DATABASE_URL: ownerUrl, OID_AUTH_SECRET: authSecret });
    const created = createDatabase(config);
    ownerDatabase = created.db;
    ownerDbClient = created.client;
    const principal = makePrincipal(fixture);
    phase = 'owner_action_admission';
    const admission = await taskActionService.admitTaskAction({ db: ownerDatabase }, principal, {
      runId: fixture.runId, taskIndex: 0, operationId: id().replaceAll('-', ''), command,
    });
    if (!admission.admitted) throw new Error('owner_fixture_action_not_admitted');
    summary.ownerRunId = fixture.runId;
    summary.ownerActionId = admission.actionId;
    summary.ownerActionSequence = admission.actionSequence;
    const actionPayloadRows = await ownerObserverPool.query('SELECT payload_hash FROM oid_run_task_action WHERE id=$1', [admission.actionId]);
    summary.ownerActionPayloadHash = actionPayloadRows.rows[0]?.payload_hash ?? null;

    const releaseSource = {
      async getValidatedReleaseRecord(releaseIdentity, manifestHash) {
        if (releaseIdentity !== fixture.releaseIdentity || manifestHash !== fixture.manifestHash) return null;
        return {
          releaseIdentity, manifestHash,
          manifest: { executionIdentity: {
            environmentManifestSha256: health.manifestSha256,
            x402ServiceSha256: health.applicationSourceSha256,
          } },
        };
      },
    };
    let evidenceReference;
    const executor = new BefTaskExecutor({
      db: ownerDatabase,
      taskReleaseSource: releaseSource,
      participantApiByEnvironment: { [envId]: apiBaseUrl },
      evidenceSink: {
        async write(evidence) {
          const bytes = Buffer.from(JSON.stringify(evidence), 'utf8');
          const file = resolve(evidenceDirectory, 'participant-tool-observation.json');
          await writeFile(file, bytes, { flag: 'wx', mode: 0o600 });
          evidenceReference = {
            path: relative(root, file).replaceAll('\\', '/'), sha256: sha256(bytes),
          };
          return evidenceReference;
        },
      },
      requestTimeoutMs: 60_000,
      staleDeliveryMs: 90_000,
    });
    phase = 'executor_session_binding';
    await executor.bindSession({
      runId: fixture.runId, taskIndex: 0, envId, generationId,
      manifestHash: health.manifestSha256, applicationSourceHash: health.applicationSourceSha256, runToken,
    });
    phase = 'participant_dispatch';
    const execution = await executor.executeNext(fixture.runId, 0);
    summary.executorResult = execution;
    if (execution.status !== 'recorded') throw new Error(`bef_bridge_executor_${execution.status}`);

    const ownerReceiptRows = await ownerObserverPool.query(`SELECT receipt_status,evidence_hash,transaction_hash
      FROM oid_run_task_action_receipt WHERE action_id=$1`, [admission.actionId]);
    const ownerReceipt = ownerReceiptRows.rows[0];
    if (!ownerReceipt || ownerReceipt.receipt_status !== 'observed' ||
        ownerReceipt.transaction_hash?.toLowerCase() !== execution.transactionHash?.toLowerCase() ||
        ownerReceipt.evidence_hash !== execution.evidenceHash) throw new Error('owner_action_receipt_persistence_mismatch');
    const ownerReceiptEvidence = await writeArtifact(evidenceDirectory, 'owner-action-receipt.json', {
      actionId: admission.actionId, runId: fixture.runId, taskIndex: 0,
      receiptStatus: ownerReceipt.receipt_status, evidenceHash: ownerReceipt.evidence_hash,
      transactionHash: ownerReceipt.transaction_hash,
    });

    phase = 'bef_observer_identity';
    befPool = new Pool({ connectionString: befDatabaseUrl, max: 2, application_name: 'bef-task-executor-bridge-observer' });
    await befPool.query('BEGIN READ ONLY');
    const role = await befPool.query("SELECT current_user AS role,current_setting('transaction_read_only') AS readonly");
    if (role.rows[0]?.role !== 'bef_observer' || role.rows[0]?.readonly !== 'on') throw new Error('bef_database_observer_role_invalid');
    const operationRows = await befPool.query(`SELECT o.operation_id::text,o.env_id,o.generation_id::text,o.participant_id,
        o.operation_kind,o.status,o.receipt_status,o.transaction_hash,s.action_kind,s.outcome AS selected_outcome,
        s.transaction_hash AS selected_transaction_hash,s.measurement_json
      FROM bef_operation o LEFT JOIN bef_selected_execution s
        ON s.operation_id=o.operation_id AND s.env_id=o.env_id AND s.generation_id=o.generation_id
      WHERE o.operation_id=$1 AND o.env_id=$2 AND o.generation_id=$3`,
    [execution.befOperationId, envId, generationId]);
    const operation = operationRows.rows[0];
    const measurement = decodeJson(operation?.measurement_json);
    if (!operation || operation.participant_id !== participantId || operation.operation_kind !== 'transfer' ||
        operation.status !== 'settled' || operation.receipt_status !== 'success' || operation.selected_outcome !== 'success' ||
        operation.transaction_hash?.toLowerCase() !== execution.transactionHash?.toLowerCase() ||
        operation.selected_transaction_hash?.toLowerCase() !== execution.transactionHash?.toLowerCase()) {
      throw new Error('bef_operation_receipt_persistence_mismatch');
    }
    const stateEvidence = verifyMeasurement(measurement, { amountUnits, transactionHash: execution.transactionHash });
    const selectedExecutionEvidence = await writeArtifact(evidenceDirectory, 'bef-selected-execution-measurement.json', {
      operationId: operation.operation_id, envId: operation.env_id, generationId: operation.generation_id,
      participantId: operation.participant_id, operationKind: operation.operation_kind, operationStatus: operation.status,
      receiptStatus: operation.receipt_status, selectedActionKind: operation.action_kind,
      selectedExecutionOutcome: operation.selected_outcome, transactionHash: operation.transaction_hash,
      measurement,
    });
    const secrets = [privateKey, runToken];
    const retainedBytes = await import('node:fs/promises').then(({ readFile }) => readFile(resolve(evidenceDirectory, 'participant-tool-observation.json')));
    if (secrets.some((secret) => retainedBytes.includes(Buffer.from(secret)))) throw new Error('bef_bridge_secret_in_evidence');

    summary.outcome = 'observed';
    summary.operation = {
      operationId: operation.operation_id, envId: operation.env_id, generationId: operation.generation_id,
      operationKind: operation.operation_kind, status: operation.status, receiptStatus: operation.receipt_status,
      selectedExecutionOutcome: operation.selected_outcome, transactionHash: operation.transaction_hash,
    };
    summary.stateEvidence = stateEvidence;
    summary.evidence = {
      participantTool: evidenceReference,
      ownerReceipt: ownerReceiptEvidence,
      befSelectedExecution: selectedExecutionEvidence,
    };
    assert.equal(ownerReceipt.receipt_status, 'observed');
  } catch (error) {
    summary.outcome = 'unknown';
    const errorMessage = error instanceof Error ? error.message : '';
    const sqlState = error && typeof error === 'object' && typeof error.code === 'string' && /^[0-9A-Z]{5}$/.test(error.code)
      ? error.code.toLowerCase() : null;
    summary.failureCode = /^[a-z0-9_:-]{1,120}$/i.test(errorMessage) ? errorMessage
      : sqlState ? `postgres_${sqlState}` : 'bef_bridge_probe_failed';
    summary.failurePhase = phase;
  } finally {
    if (generationId) {
      try {
        await jsonRequest(new URL(`/internal/admin/environments/${envId}/generations/${generationId}/fence`, apiBaseUrl), {
          method: 'POST', headers: { 'x-bef-admin-key': adminKey, 'content-type': 'application/json' }, body: '{}',
        });
        summary.generationFenced = true;
      } catch { summary.generationFenced = false; }
    }
    await befPool?.end().catch(() => undefined);
    await ownerObserverPool?.end().catch(() => undefined);
    await ownerDbClient?.end().catch(() => undefined);
    await ownerPool?.end().catch(() => undefined);
    privateKey = undefined;
    runToken = undefined;
    const artifact = await writeArtifact(evidenceDirectory, 'capture-summary.json', summary).catch(() => null);
    if (artifact) summary.summaryArtifact = artifact;
  }
  return summary;
}

async function main() {
  const baseOwnerUrl = process.env.OID_DATABASE_URL;
  if (!baseOwnerUrl) throw new Error('owner_database_unavailable');
  const adminPath = resolve(root, 'infrastructure/benchmark-environment/.local/secrets/admin-key');
  const observerPasswordPath = resolve(root, 'infrastructure/benchmark-environment/.local/secrets/database-observer-password');
  const { readFile } = await import('node:fs/promises');
  const adminKey = (await readFile(adminPath, 'utf8')).trim();
  const observerPassword = (await readFile(observerPasswordPath, 'utf8')).trim();
  const ownerObserverUrl = new URL(process.env.OID_OBSERVER_DATABASE_URL ?? '');
  if (adminKey.length < 32 || observerPassword.length < 8) throw new Error('bef_local_capture_credentials_unavailable');
  const isolated = await createAcceptanceDatabase(baseOwnerUrl);
  const authSecret = randomBytes(48).toString('base64url');
  const ownerUrl = new URL(isolated.databaseUrl);
  const { databaseName } = isolated;
  ownerObserverUrl.pathname = `/${databaseName}`;
  const befDatabaseUrl = `postgres://bef_observer:${encodeURIComponent(observerPassword)}@host.docker.internal:55432/bef`;
  await runOwnerMigrations(ownerUrl.href, authSecret);
  const apiBaseUrl = process.env.BEF_API_BASE_URL ?? 'http://host.docker.internal:38783';
  const mode = process.argv.includes('--purchase') ? 'purchase' : process.argv.includes('--read-only') ? 'read-only' : 'transfer';
  const evidenceDirectory = resolve(root, mode === 'read-only'
    ? 'artifacts/runs/bts-read-action-executor-bridge' : mode === 'purchase'
      ? 'artifacts/runs/bts-x402-task-action-executor-bridge' : 'artifacts/runs/bts-task-action-executor-bridge', isolated.runId);
  const result = await runBefTaskExecutorBridgeCapture({
    databaseUrl: ownerUrl.href, observerDatabaseUrl: ownerObserverUrl.href, databaseName, apiBaseUrl, adminKey, befDatabaseUrl, evidenceDirectory,
    mode,
  });
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (result.outcome !== 'observed') process.exitCode = 2;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main().catch((error) => {
    const code = error instanceof Error && /^[a-z0-9_:-]{1,120}$/i.test(error.message) ? error.message : 'bef_bridge_capture_failed';
    process.stderr.write(`${code}\n`);
    process.exitCode = 2;
  });
}
