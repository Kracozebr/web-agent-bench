#!/usr/bin/env node
import { createHash, randomUUID } from 'node:crypto';
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createRequire } from 'node:module';
import {
  BefTaskPreparationAdapter,
  taskPreparationPublicPinsSha256,
} from '../../packages/owner-identity/src/bef-task-preparation.ts';
import { sha256CanonicalTaskJson, TaskCaseSchema } from '../../packages/owner-identity/src/task-release.ts';
import { CURRENT_TASK_RELEASE_POINTER_PATH, loadCurrentTaskReleasePins } from './current-task-release-pins.mjs';

const EXPECTED = Object.freeze({
  envId: 'bef-env-a',
  apiHostPort: '38783',
  sourceProxyHostPort: '18544',
  localRpcHostPort: '18545',
  databaseHostPort: '56432',
  manifestSha256: 'e18e51cc85255d78c31262acecb0a556b51624f4b007cad77e870cceae361810',
  applicationSourceSha256: 'b9b0ff9e251ce1f423b543409a3567029c1d4e703644a3b15c8e89f5fe6bc3f9',
  executionIdentitySha256: '72aeadc411180708f4498a03619a1708b88eb053753c60b3fb35fcb3eb5609e2',
  verificationSha256: '0d0032dd24f5a9e8c4bcccf9e80088287f719ec1299a4649ba9de0300825feb0',
  verificationPath: 'artifacts/runs/bts-runtime-feasibility-verification/5da32b24-3bbe-4e23-8969-ee954d7acf72/verification.json',
  witnessPath: 'artifacts/runs/bts-release-feasibility-witness/f28df42b-6341-467a-9be9-380e63ab4325/witness.json',
  rawManifestPath: 'artifacts/runs/bts-release-feasibility-witness/f28df42b-6341-467a-9be9-380e63ab4325/manifest.raw.json',
});

const root = process.cwd();
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const unknownReasonAllowlist = new Set([
  'adapter_outcome_unknown', 'adapter_call_failed', 'restart_reconciliation_required',
  'run_state_changed_before_preparation_completed', 'preparation_identity_mismatch', 'baseline_state_mismatch',
]);
const evidenceBoundary = 'actual_tool_http_x402_local_evm_application_store';
const secretPaths = {
  adminKey: 'infrastructure/benchmark-environment/.local/secrets/admin-key',
  observerPassword: 'infrastructure/benchmark-environment/.local/secrets/database-observer-password',
};
const ownerContextPaths = [
  'packages/owner-identity/src/bef-task-preparation.ts',
  'packages/owner-identity/src/task-preparation.ts',
  'packages/owner-identity/src/task-release.ts',
  'packages/owner-identity/src/task-case-assembler.ts',
  'packages/owner-identity/src/task-catalog.ts',
  'packages/owner-identity/src/task-feasibility-evidence.ts',
  'packages/owner-identity/src/task-action-x402.ts',
  'packages/owner-identity/src/task-execution-binding.ts',
  'packages/benchmark-environment/src/preparation-routes.ts',
  'packages/benchmark-environment/src/preparation-state.ts',
  'packages/benchmark-environment/src/admin-routes.ts',
  'packages/benchmark-environment/src/runtime.ts',
  'packages/benchmark-environment/src/probe/environment.ts',
  'packages/benchmark-environment/package.json',
  'packages/benchmark-environment/tsconfig.json',
  'package.json',
  'pnpm-workspace.yaml',
  'tsconfig.json',
  'infrastructure/benchmark-environment/manifest.json',
  'infrastructure/benchmark-environment/resource.json',
  'infrastructure/owner-identity/capture-bef-task-preparation.mjs',
  'infrastructure/owner-identity/current-task-release-pins.mjs',
  'infrastructure/owner-identity/verify-runtime-feasibility.mjs',
  'infrastructure/owner-identity/task-release-local-policy.json',
  EXPECTED.verificationPath,
  EXPECTED.witnessPath,
  EXPECTED.rawManifestPath,
  CURRENT_TASK_RELEASE_POINTER_PATH,
  'pnpm-lock.yaml',
];
const forbiddenEvidenceKeys = /^(?:adminKey|serviceKey|observerPassword|password|secret|payerPrivateKey|privateKey|runToken|runTokenSha256|tokenSha256|authorization|authorizationHeader)$/i;
const evidenceKeysByKind = Object.freeze({
  fixture: ['publicPinsSha256', 'environmentHealth', 'publicStatus', 'fundingReceipt'],
  baseline: ['publicPinsSha256', 'publicStatus', 'state', 'stateSha256', 'expectedStateSha256'],
  fence: ['publicPinsSha256', 'expectedOwnerGenerationId', 'actualBefGenerationId', 'before', 'after', 'fenceConfirmed', 'chainState'],
});

function requireCondition(condition, code) {
  if (!condition) throw new Error(code);
}

function errorCode(error) {
  if (typeof error?.code === 'string' && /^[0-9A-Z]{5}$/.test(error.code)) {
    return `postgres_${error.code.toLowerCase()}`;
  }
  const value = typeof error?.message === 'string' ? error.message : '';
  return /^[a-z0-9_]{1,80}$/.test(value) ? value : 'capture_failed';
}

function projectPreparationOutcome(outcome) {
  if (!outcome || typeof outcome !== 'object') return null;
  if (outcome.status === 'unknown') {
    return {
      status: 'unknown',
      reasonCode: unknownReasonAllowlist.has(outcome.reasonCode) ? outcome.reasonCode : 'unrecognized',
      generationId: typeof outcome.generationId === 'string' && uuidPattern.test(outcome.generationId)
        ? outcome.generationId.toLowerCase() : null,
    };
  }
  if (outcome.status === 'prepared') {
    const result = outcome.result && typeof outcome.result === 'object' ? outcome.result : {};
    return {
      status: 'prepared',
      generationId: typeof result.generationId === 'string' && uuidPattern.test(result.generationId)
        ? result.generationId.toLowerCase() : null,
    };
  }
  return { status: 'unrecognized', reasonCode: 'unrecognized', generationId: null };
}

function validateEvidenceShape(value, selectedTaskId) {
  requireCondition(value && typeof value === 'object' && !Array.isArray(value), 'evidence_shape_invalid');
  requireCondition(value.schemaVersion === 'owner-bef-task-preparation-evidence/v1', 'evidence_schema_invalid');
  requireCondition(Object.hasOwn(evidenceKeysByKind, value.kind), 'evidence_kind_invalid');
  const exactKeys = ['schemaVersion', 'kind', 'preparationId', 'environmentId', 'publicPinsSha256', 'evidence'];
  requireCondition(Object.keys(value).toSorted().join('|') === exactKeys.toSorted().join('|'), 'evidence_envelope_fields_invalid');
  const expectedKeys = [...evidenceKeysByKind[value.kind],
    ...(value.kind === 'fixture' && selectedTaskId === 'S4' && Object.hasOwn(value.evidence, 's4AllowanceFixture')
      ? ['s4AllowanceFixture'] : [])];
  requireCondition(Object.keys(value.evidence).toSorted().join('|') === expectedKeys.toSorted().join('|'), 'evidence_fields_invalid');
  const visit = (item) => {
    if (!item || typeof item !== 'object') return;
    if (Array.isArray(item)) { for (const child of item) visit(child); return; }
    for (const [key, child] of Object.entries(item)) {
      requireCondition(!forbiddenEvidenceKeys.test(key), 'evidence_secret_field_rejected');
      visit(child);
    }
  };
  visit(value);
  if (value.evidence.s4AllowanceFixture) {
    const fixture = value.evidence.s4AllowanceFixture;
    const allowed = ['stage', 'outcome', 'reasonCode', 'preparationId', 'generationId', 'operationId',
      'transactionHash', 'responseSha256', 'idempotencyKeySha256', 'action', 'preState', 'transaction',
      'receipt', 'block', 'gasCostWei', 'postState'];
    requireCondition(selectedTaskId === 'S4' && fixture && typeof fixture === 'object'
      && Object.keys(fixture).every((key) => allowed.includes(key))
      && fixture.stage === 'pre_task_fixture_setup' && ['observed', 'unknown'].includes(fixture.outcome)
      && fixture.preparationId === value.preparationId && uuidPattern.test(fixture.generationId)
      && (/^[0-9a-f]{64}$/.test(fixture.idempotencyKeySha256)
        || (fixture.outcome === 'unknown' && fixture.idempotencyKeySha256 === null)), 's4_fixture_evidence_invalid');
    requireCondition(fixture.action?.kind === 'approve' && fixture.action.tokenAssetId === 'USDC'
      && fixture.action.gasLimit === '100000'
      && Object.keys(fixture.action).toSorted().join('|') === ['kind', 'tokenAssetId', 'spender', 'amountUnits', 'gasLimit'].toSorted().join('|'),
    's4_fixture_action_shape_invalid');
    if (fixture.outcome === 'observed') requireCondition(uuidPattern.test(fixture.operationId)
      && /^0x[0-9a-f]{64}$/i.test(fixture.transactionHash) && fixture.preState && fixture.postState
      && fixture.transaction && fixture.receipt && fixture.block, 's4_fixture_observation_incomplete');
  }
}

async function snapshotSourceInputs(rootPath) {
  const paths = new Set(ownerContextPaths);
  for (const entry of await readdir(resolve(rootPath, 'packages/owner-identity/src'), { withFileTypes: true })) {
    if (entry.isFile() && /^bef-task-preparation-s4\.ts$/.test(entry.name)) {
      paths.add(`packages/owner-identity/src/${entry.name}`);
    }
  }
  const migrationDir = resolve(rootPath, 'infrastructure/benchmark-environment/migrations');
  for (const entry of await readdir(migrationDir, { withFileTypes: true })) {
    if (entry.isFile() && /^\d{3}_[a-z0-9_]+\.sql$/.test(entry.name)) {
      paths.add(`infrastructure/benchmark-environment/migrations/${entry.name}`);
    }
  }
  const catalogDir = resolve(rootPath, 'infrastructure/benchmark-environment/resources');
  for (const entry of await readdir(catalogDir, { withFileTypes: true })) {
    if (entry.isFile()) paths.add(`infrastructure/benchmark-environment/resources/${entry.name}`);
  }
  const walk = async (directory, relative) => {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const relativePath = `${relative}/${entry.name}`;
      if (entry.isDirectory()) {
        // A concurrent M2/M4 probe edit is outside the preparation adapter's
        // source boundary. The one probe utility imported below remains pinned
        // explicitly in ownerContextPaths.
        if (relative === 'packages/benchmark-environment/src' && entry.name === 'probe') continue;
        await walk(resolve(directory, entry.name), relativePath);
      }
      else if (entry.isFile() && /\.(?:ts|mts|cts)$/.test(entry.name) &&
          !(relative === 'packages/benchmark-environment/src' && entry.name === 'probe.ts')) paths.add(relativePath);
    }
  };
  await walk(resolve(rootPath, 'packages/benchmark-environment/src'), 'packages/benchmark-environment/src');
  return Promise.all([...paths].toSorted().map(async (path) => ({
    path,
    sha256: sha256(await readFile(resolve(rootPath, path))),
  })));
}

function projectResetIdentity(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const allowed = ['clientVersion', 'chainId', 'executionNetwork', 'hardFork', 'forkBlockNumber', 'forkBlockHash', 'manifestSha256', 'facilitatorRecovered'];
  return Object.fromEntries(allowed.filter((key) => Object.hasOwn(value, key)).map((key) => [key, value[key]]));
}

function projectFixtureFacts(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const safe = {};
  for (const key of ['amountUnits', 'payerTokenBefore', 'payerTokenAfter', 'donorTokenBefore', 'donorTokenAfter', 'payerNativeBalance']) {
    if (Object.hasOwn(value, key)) safe[key] = value[key];
  }
  const observation = value.receiptObservation;
  if (observation && typeof observation === 'object' && !Array.isArray(observation)) {
    safe.receiptObservation = {
      pollCount: observation.pollCount ?? null,
      nullReceiptCount: observation.nullReceiptCount ?? null,
      sourceProxyMethodDeniedCount: observation.sourceProxyMethodDeniedCount ?? null,
      firstUnavailableRpc: observation.firstUnavailableRpc && typeof observation.firstUnavailableRpc === 'object'
        ? { code: observation.firstUnavailableRpc.code ?? null, name: observation.firstUnavailableRpc.name ?? null,
          messageCode: observation.firstUnavailableRpc.messageCode ?? null }
        : null,
    };
  }
  return safe;
}

function projectPublicStatus(body) {
  requireCondition(body && body.schemaVersion === 'bef-preparation-status/v1', 'public_status_schema_invalid');
  const request = body.request && typeof body.request === 'object' ? {
    requestSha256: body.request.requestSha256 ?? null,
    publicPinsSha256: body.request.publicPinsSha256 ?? null,
    participantId: body.request.participantId ?? null,
    payerAddress: body.request.payerAddress ?? null,
    resourceVariant: body.request.resourceVariant ?? null,
    manifestSha256: body.request.manifestSha256 ?? null,
  } : null;
  const fixture = body.fixture && typeof body.fixture === 'object' ? {
    state: body.fixture.state ?? null,
    transactionHash: body.fixture.transactionHash ?? null,
    blockHash: body.fixture.blockHash ?? null,
    fixtureHash: body.fixture.fixtureHash ?? null,
    facts: projectFixtureFacts(body.fixture.facts),
  } : null;
  const baseline = body.baselineReset && typeof body.baselineReset === 'object' ? {
    identity: projectResetIdentity(body.baselineReset.identity),
    completedAt: body.baselineReset.completedAt ?? null,
  } : null;
  return {
    schemaVersion: body.schemaVersion,
    envId: body.envId,
    preparationId: body.preparationId,
    status: body.status,
    generationId: body.generationId ?? null,
    request,
    fixture,
    baselineReset: baseline,
    fenceConfirmedAt: body.fenceConfirmedAt ?? null,
  };
}

function publicStatusUrl(apiBase, preparationId) {
  return `${apiBase}/internal/admin/environments/${encodeURIComponent(EXPECTED.envId)}/preparations/${encodeURIComponent(preparationId)}`;
}

async function getPublicStatus(apiBase, preparationId, adminKey) {
  const response = await fetch(publicStatusUrl(apiBase, preparationId), {
    method: 'GET', headers: { 'x-bef-admin-key': adminKey }, cache: 'no-store', redirect: 'error',
    signal: AbortSignal.timeout(15_000),
  });
  let body = null;
  try { body = await response.json(); } catch { /* failure is reported as a status boundary code */ }
  requireCondition(response.status === 200, 'public_status_read_failed');
  const projected = projectPublicStatus(body);
  requireCondition(projected.envId === EXPECTED.envId && projected.preparationId === preparationId, 'public_status_identity_mismatch');
  return projected;
}

function publicFacts(value) {
  return value && typeof value === 'object' ? projectFixtureFacts(value) : null;
}

function makePool(observerPassword) {
  const require = createRequire(resolve(root, 'packages/benchmark-environment/package.json'));
  const { Pool } = require('pg');
  const url = new URL(`postgres://bef_observer@host.docker.internal:${EXPECTED.databaseHostPort}/bef`);
  url.password = observerPassword;
  return new Pool({ connectionString: url.toString(), max: 1, connectionTimeoutMillis: 5_000,
    idleTimeoutMillis: 5_000, statement_timeout: 8_000, query_timeout: 10_000,
    application_name: 'owner-bef-preparation-capture-readonly' });
}

async function readPublicDatabase(pool, preparationId, { preflight = false, setupOperationId = null } = {}) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    const session = await client.query(`SELECT current_user AS current_user, session_user AS session_user,
      current_database() AS database_name, current_setting('transaction_read_only') AS transaction_read_only`);
    const active = await client.query(`SELECT count(*)::text AS active_count FROM public.bef_generation
      WHERE env_id=$1 AND status='active'`, [EXPECTED.envId]);
    if (preflight) {
      const existing = await client.query(`SELECT preparation_id::text FROM public.bef_preparation WHERE preparation_id=$1`, [preparationId]);
      await client.query('COMMIT');
      const proof = session.rows[0];
      requireCondition(proof?.current_user === 'bef_observer' && proof?.session_user === 'bef_observer' && proof?.transaction_read_only === 'on', 'observer_readonly_role_invalid');
      return { session: proof, activeGenerationCount: Number(active.rows[0]?.active_count), preparationExists: existing.rowCount !== 0 };
    }

    const prepResult = await client.query(`SELECT preparation_id::text,env_id,trim(public_pins_sha256) AS public_pins_sha256,
        trim(request_sha256) AS request_sha256,participant_id,payer_address,resource_variant,trim(manifest_sha256) AS manifest_sha256,
        generation_id::text,status,fixture_state,fixture_transaction_hash,fixture_block_hash,trim(fixture_hash) AS fixture_hash,
        fixture_facts,reset_identity,reset_completed_at::text,fence_confirmed_at::text
      FROM public.bef_preparation WHERE preparation_id=$1 AND env_id=$2`, [preparationId, EXPECTED.envId]);
    const rawPrep = prepResult.rows[0] ?? null;
    let generation = null;
    let setup = null;
    if (rawPrep?.generation_id) {
      const generationResult = await client.query(`SELECT generation_id::text,env_id,participant_id,payer_address,resource_variant,
          trim(manifest_sha256) AS manifest_sha256,status,fixture_hash,fixture_transaction_hash,fixture_block_hash,
          fixture_token_delta_units::text,fixture_native_balance_wei::text,expires_at::text,created_at::text,fenced_at::text
        FROM public.bef_generation WHERE env_id=$1 AND generation_id=$2::uuid`, [EXPECTED.envId, rawPrep.generation_id]);
      generation = generationResult.rows[0] ?? null;
      if (setupOperationId) {
        requireCondition(uuidPattern.test(setupOperationId), 'setup_operation_id_invalid');
        const scope = [setupOperationId, EXPECTED.envId, rawPrep.generation_id];
        const operations = await client.query(`SELECT operation_id::text,env_id,generation_id::text,participant_id,
          operation_kind,status,receipt_status,transaction_hash,trim(response_sha256) AS response_sha256
          FROM public.bef_operation WHERE operation_id=$1 AND env_id=$2 AND generation_id=$3::uuid`, scope);
        const executions = await client.query(`SELECT operation_id::text,env_id,generation_id::text,action_kind,
          selected_action_json,transaction_intent_json,transaction_hash,outcome
          FROM public.bef_selected_execution WHERE operation_id=$1 AND env_id=$2 AND generation_id=$3::uuid`, scope);
        const events = await client.query(`SELECT event_sequence::text,event_id::text,operation_id::text,
          event_kind,transaction_hash,event_json FROM public.bef_selected_execution_event
          WHERE operation_id=$1 AND env_id=$2 AND generation_id=$3::uuid ORDER BY event_sequence`, scope);
        const costs = await client.query(`SELECT operation_id::text,transaction_hash,payer_address,payer_role,receipt_status,
          transaction_from,receipt_from,receipt_block_number::text,receipt_block_hash,
          gas_used::text,effective_gas_price_wei::text,gas_cost_wei::text,trim(manifest_sha256) AS manifest_sha256
          FROM public.bef_transaction_cost WHERE operation_id=$1 AND env_id=$2 AND generation_id=$3::uuid
          ORDER BY transaction_hash`, scope);
        const counts = await client.query(`SELECT
          (SELECT count(*)::text FROM public.bef_operation WHERE env_id=$1 AND generation_id=$2::uuid) AS operations,
          (SELECT count(*)::text FROM public.bef_selected_execution WHERE env_id=$1 AND generation_id=$2::uuid) AS selected_executions,
          (SELECT count(*)::text FROM public.bef_payment WHERE env_id=$1 AND generation_id=$2::uuid) AS payments,
          (SELECT count(*)::text FROM public.bef_delivery d JOIN public.bef_operation o USING(operation_id)
            WHERE o.env_id=$1 AND o.generation_id=$2::uuid) AS deliveries`,
        [EXPECTED.envId, rawPrep.generation_id]);
        setup = { operation: operations.rows, execution: executions.rows, events: events.rows,
          costs: costs.rows, generationCounts: counts.rows[0] };
      }
    }
    await client.query('COMMIT');
    const proof = session.rows[0];
    requireCondition(proof?.current_user === 'bef_observer' && proof?.session_user === 'bef_observer' && proof?.transaction_read_only === 'on', 'observer_readonly_role_invalid');
    const preparation = rawPrep ? {
      preparationId: rawPrep.preparation_id,
      envId: rawPrep.env_id,
      publicPinsSha256: rawPrep.public_pins_sha256,
      requestSha256: rawPrep.request_sha256,
      participantId: rawPrep.participant_id,
      payerAddress: rawPrep.payer_address,
      resourceVariant: rawPrep.resource_variant,
      manifestSha256: rawPrep.manifest_sha256,
      generationId: rawPrep.generation_id,
      status: rawPrep.status,
      fixtureState: rawPrep.fixture_state,
      fixtureTransactionHash: rawPrep.fixture_transaction_hash,
      fixtureBlockHash: rawPrep.fixture_block_hash,
      fixtureHash: rawPrep.fixture_hash,
      fixtureFacts: publicFacts(rawPrep.fixture_facts),
      resetIdentity: projectResetIdentity(rawPrep.reset_identity),
      resetCompletedAt: rawPrep.reset_completed_at,
      fenceConfirmedAt: rawPrep.fence_confirmed_at,
    } : null;
    return {
      session: proof,
      activeGenerationCount: Number(active.rows[0]?.active_count),
      preparation,
      generation,
      setup,
    };
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

function safeStatusMatchesDatabase(status, database) {
  const prep = database.preparation;
  return Boolean(prep && status.envId === prep.envId && status.preparationId === prep.preparationId &&
    status.status === prep.status && status.generationId === prep.generationId &&
    status.request?.requestSha256 === prep.requestSha256 && status.request?.publicPinsSha256 === prep.publicPinsSha256 &&
    status.request?.participantId === prep.participantId && status.request?.payerAddress?.toLowerCase() === prep.payerAddress?.toLowerCase() &&
    status.fixture?.state === prep.fixtureState && status.fixture?.transactionHash === prep.fixtureTransactionHash &&
    status.fixture?.blockHash === prep.fixtureBlockHash && status.fixture?.fixtureHash === prep.fixtureHash);
}

function generationMatchesPreparation(database) {
  const prep = database.preparation;
  const generation = database.generation;
  return Boolean(prep && generation && generation.generation_id === prep.generationId && generation.env_id === prep.envId &&
    generation.participant_id === prep.participantId && generation.payer_address?.toLowerCase() === prep.payerAddress?.toLowerCase() &&
    generation.resource_variant === prep.resourceVariant && generation.manifest_sha256 === prep.manifestSha256 &&
    generation.fixture_hash === prep.fixtureHash && generation.fixture_transaction_hash === prep.fixtureTransactionHash &&
    generation.fixture_block_hash === prep.fixtureBlockHash && Boolean(generation.expires_at));
}

function assertS4SetupDatabase(database, fixture, taskCase, preparationId) {
  requireCondition(fixture?.outcome === 'observed' && fixture.stage === 'pre_task_fixture_setup'
    && fixture.preparationId === preparationId && fixture.generationId === database.preparation?.generationId,
  's4_fixture_not_independently_joinable');
  requireCondition(fixture.action?.amountUnits === taskCase.objective.initialAllowanceUnits
    && fixture.action?.spender?.toLowerCase() === taskCase.objective.spender.toLowerCase()
    && fixture.postState?.baselineSha256 === taskCase.initialState.stateSha256, 's4_fixture_case_pin_mismatch');
  const setup = database.setup;
  requireCondition(setup && setup.operation.length === 1 && setup.execution.length === 1
    && setup.costs.length === 1 && setup.generationCounts.operations === '1'
    && setup.generationCounts.selected_executions === '1' && setup.generationCounts.payments === '0'
    && setup.generationCounts.deliveries === '0', 's4_setup_generation_census_invalid');
  const operation = setup.operation[0], execution = setup.execution[0], cost = setup.costs[0];
  const tx = fixture.transactionHash.toLowerCase();
  requireCondition(operation.operation_id === fixture.operationId && operation.operation_kind === 'approve'
    && operation.status === 'settled' && operation.receipt_status === 'success'
    && operation.transaction_hash?.toLowerCase() === tx
    && operation.participant_id === database.preparation.participantId
    && execution.operation_id === fixture.operationId && execution.action_kind === 'approve'
    && execution.outcome === 'success' && execution.transaction_hash?.toLowerCase() === tx,
  's4_setup_operation_binding_invalid');
  const selected = execution.selected_action_json;
  requireCondition(selected?.kind === 'approve' && selected.tokenAssetId === 'USDC'
    && selected.amountUnits === taskCase.objective.initialAllowanceUnits && selected.gasLimit === '100000',
  's4_setup_selected_action_invalid');
  const expectedInput = `0x095ea7b3${taskCase.objective.spender.slice(2).toLowerCase().padStart(64, '0')}${BigInt(taskCase.objective.initialAllowanceUnits).toString(16).padStart(64, '0')}`;
  const intent = execution.transaction_intent_json;
  requireCondition(intent?.hash?.toLowerCase() === tx && intent.from?.toLowerCase() === database.preparation.payerAddress.toLowerCase()
    && intent.to?.toLowerCase() === fixture.transaction.to.toLowerCase() && intent.input?.toLowerCase() === expectedInput
    && BigInt(intent.valueWei) === 0n && String(intent.chainId) === '8453' && intent.gasLimit === '100000',
  's4_setup_transaction_intent_invalid');
  requireCondition(cost.operation_id === fixture.operationId && cost.transaction_hash.toLowerCase() === tx
    && cost.payer_role === 'participant' && cost.payer_address.toLowerCase() === database.preparation.payerAddress.toLowerCase()
    && cost.transaction_from?.toLowerCase() === database.preparation.payerAddress.toLowerCase()
    && cost.receipt_from?.toLowerCase() === database.preparation.payerAddress.toLowerCase()
    && cost.receipt_status === 'success' && cost.manifest_sha256 === EXPECTED.manifestSha256
    && cost.receipt_block_hash.toLowerCase() === fixture.postState.blockHash.toLowerCase()
    && BigInt(cost.receipt_block_number) === BigInt(fixture.postState.blockNumber)
    && BigInt(cost.gas_used) === BigInt(fixture.receipt.gasUsed)
    && BigInt(cost.effective_gas_price_wei) === BigInt(fixture.receipt.effectiveGasPrice)
    && BigInt(cost.gas_cost_wei) === BigInt(cost.gas_used) * BigInt(cost.effective_gas_price_wei)
    && BigInt(cost.gas_cost_wei) === BigInt(fixture.gasCostWei), 's4_setup_cost_binding_invalid');
  requireCondition(setup.events.some((event) => event.event_kind === 'selected_action_bound'
    && sha256CanonicalTaskJson(event.event_json.selectedAction) === sha256CanonicalTaskJson(selected))
    && setup.events.some((event) => event.event_kind === 'original_tx_hash_bound'
      && event.transaction_hash?.toLowerCase() === tx && event.event_json.transactionIntent?.hash?.toLowerCase() === tx)
    && setup.events.some((event) => event.event_kind === 'receipt_finalized'
      && event.transaction_hash?.toLowerCase() === tx && event.event_json.outcome === 'success'), 's4_setup_events_missing');
}

function makeSyntheticRelease(identity, initialState, manifestSha256, selectedCase = null) {
  const initialStateSha256 = initialState.stateSha256;
  const releaseIdentity = selectedCase ? `synthetic-owner-preparation-capture-S4-${selectedCase.mode}-v1`
    : 'synthetic-owner-preparation-capture-v1';
  const caseId = selectedCase?.caseId ?? 'synthetic-preparation-baseline-S1';
  const caseHash = selectedCase?.caseHash ?? sha256CanonicalTaskJson({ classification: 'synthetic_preparation_capture_only', caseId,
    taskId: 'S1', initialStateSha256, executionIdentityHash: EXPECTED.executionIdentitySha256 });
  const manifestHash = sha256CanonicalTaskJson({ classification: 'synthetic_preparation_capture_only', releaseIdentity,
    executionIdentityHash: EXPECTED.executionIdentitySha256, environmentManifestSha256: manifestSha256,
    caseId, caseHash, initialStateSha256 });
  const taskCase = selectedCase ? structuredClone(selectedCase) : {
    taskId: 'S1', caseId, caseHash, executionIdentityHash: EXPECTED.executionIdentitySha256,
    initialState,
    objective: { classification: 'synthetic_preparation_capture_only' },
  };
  const release = {
    releaseIdentity,
    manifestHash,
    benchmarkVersion: 'synthetic-preparation-capture-v1',
    benchmarkHash: manifestHash,
    policyHash: manifestHash,
    manifest: {
      executionIdentity: identity,
      executionIdentityHash: EXPECTED.executionIdentitySha256,
      cases: { training: selectedCase?.mode === 'ranked' ? [] : [taskCase],
        ranked: selectedCase?.mode === 'ranked' ? [taskCase] : [] },
    },
  };
  const source = {
    classification: 'synthetic-owner-preparation-capture-only-not-validated-release',
    async getActiveAdmissionRelease() { return null; },
    async getValidatedReleaseRecord(requestedIdentity, requestedHash) {
      if (requestedIdentity !== releaseIdentity || requestedHash.toLowerCase() !== manifestHash.toLowerCase()) return null;
      return release;
    },
  };
  return { source, release, taskCase, releaseIdentity, manifestHash, caseId, caseHash, initialStateSha256 };
}

function makeDependencies({ apiBase, localRpc, sourceRpc, adminKey, manifest, releaseSource, evidenceSink, fetchImpl }) {
  return {
    apiBaseByEnvironment: { [EXPECTED.envId]: apiBase },
    observerRpcByEnvironment: { [EXPECTED.envId]: localRpc },
    sourceRpcUrl: sourceRpc,
    adminKey,
    anvilManifestPinByEnvironment: {
      [EXPECTED.envId]: {
        manifestSha256: EXPECTED.manifestSha256,
        executionNetwork: manifest.local.executionNetwork,
        hardFork: manifest.local.hardfork,
        anvilVersion: manifest.local.anvilVersion,
      },
    },
    releaseSource,
    evidenceSink,
    fetch: fetchImpl,
    requestTimeoutMs: 15_000,
  };
}

async function readPinnedInputs() {
  requireCondition(process.platform === 'linux' && root === '/workspace', 'docker_runtime_required');
  requireCondition(process.env.BEF_API_HOST_PORT === EXPECTED.apiHostPort, 'unexpected_api_host_port');
  const verificationBytes = await readFile(resolve(root, EXPECTED.verificationPath));
  requireCondition(sha256(verificationBytes) === EXPECTED.verificationSha256, 'verification_artifact_pin_mismatch');
  const verification = JSON.parse(verificationBytes.toString('utf8'));
  requireCondition(verification.schemaVersion === 'bts-runtime-feasibility-verification/v1' &&
    verification.classification === 'historical_readonly_feasibility_not_release_or_live_readiness' &&
    verification.sourceUnchanged === true && verification.result?.status === 'verified' && verification.result?.actualBoundary === true,
  'verification_artifact_invalid');
  const identity = verification.executionIdentity;
  requireCondition(sha256CanonicalTaskJson(identity) === EXPECTED.executionIdentitySha256 &&
    verification.executionIdentityHash === EXPECTED.executionIdentitySha256, 'execution_identity_pin_mismatch');
  const manifestBytes = await readFile(resolve(root, 'infrastructure/benchmark-environment/manifest.json'));
  const rawManifestBytes = await readFile(resolve(root, EXPECTED.rawManifestPath));
  requireCondition(sha256(manifestBytes) === EXPECTED.manifestSha256 && sha256(rawManifestBytes) === EXPECTED.manifestSha256,
    'manifest_pin_mismatch');
  const witnessBytes = await readFile(resolve(root, EXPECTED.witnessPath));
  requireCondition(sha256(witnessBytes) === verification.witness?.sha256, 'witness_artifact_pin_mismatch');
  const witness = JSON.parse(witnessBytes.toString('utf8'));
  requireCondition(witness.selectedPins?.expectedApplicationSourceSha256 === EXPECTED.applicationSourceSha256 &&
    witness.selectedPins?.expectedManifestSha256 === EXPECTED.manifestSha256, 'witness_selected_pin_mismatch');
  const manifest = JSON.parse(manifestBytes.toString('utf8'));
  requireCondition(identity.environmentManifestSha256 === EXPECTED.manifestSha256 &&
    identity.x402ServiceSha256 === EXPECTED.applicationSourceSha256 &&
    Number(identity.localChainId) === Number(manifest.local.chainId) &&
    identity.localNetwork === `eip155:${manifest.local.chainId}` &&
    identity.sourceNetwork === manifest.source.caip2 &&
    Number(identity.sourceChainId) === Number(manifest.source.chainId), 'execution_manifest_binding_mismatch');
  const { sourceDigests } = await import('../../packages/benchmark-environment/src/probe/environment.ts');
  const currentDigests = await sourceDigests(root);
  requireCondition(currentDigests.appSourceSha256 === EXPECTED.applicationSourceSha256, 'application_source_pin_mismatch');
  return { identity, manifest };
}

async function verifyRetainedS4Capture(path, expectedSha256) {
  requireCondition(/^artifacts\/runs\/owner-bef-task-preparation-capture\/[0-9a-f-]{36}\/capture\.json$/.test(path)
    && /^[0-9a-f]{64}$/.test(expectedSha256), 'retained_s4_capture_argument_invalid');
  const input = await readFile(resolve(root, path));
  requireCondition(sha256(input) === expectedSha256, 'retained_s4_capture_hash_mismatch');
  const capture = JSON.parse(input);
  requireCondition(capture.schemaVersion === 'owner-bef-task-preparation-capture/v1'
    && capture.syntheticProvider?.taskId === 'S4' && capture.syntheticProvider.mode === 'ranked'
    && uuidPattern.test(capture.preparationId) && uuidPattern.test(capture.captureId)
    && capture.adapterReplay.firstOutcome?.status === 'prepared' && capture.adapterReplay.sameGeneration
    && capture.adapterReplay.putAttempts === 1 && capture.fixtureApprovePostAttempts === 1
    && capture.fence?.confirmed && capture.s4FixtureEvidence?.outcome === 'observed', 'retained_s4_capture_not_joinable');
  const currentPins = await loadCurrentTaskReleasePins(root);
  for (const path of [currentPins.cases.path, currentPins.validation.path]) {
    if (!ownerContextPaths.includes(path)) ownerContextPaths.push(path);
  }
  const sourceBefore = await snapshotSourceInputs(root);
  await readPinnedInputs();
  const candidateBytes = await readFile(resolve(root, currentPins.cases.path));
  requireCondition(sha256(candidateBytes) === currentPins.cases.sha256, 'case_candidates_pin_mismatch');
  const candidates = JSON.parse(candidateBytes);
  const matches = candidates.cases.filter((row) => row.taskId === 'S4' && row.mode === capture.syntheticProvider.mode);
  requireCondition(matches.length === 1, 's4_case_inventory_mismatch');
  const taskCase = TaskCaseSchema.parse(matches[0]);
  requireCondition(taskCase.caseHash === capture.syntheticProvider.actualCaseInput?.caseHash
    && taskCase.initialState.stateSha256 === capture.pins.initialStateSha256, 'retained_s4_case_pin_mismatch');
  const evidenceFiles = [];
  for (const ref of capture.evidenceFiles) {
    requireCondition(ref.path.startsWith(`artifacts/runs/owner-bef-task-preparation-capture/${capture.captureId}/`)
      && /^adapter-(?:fixture|baseline|fence)-[1-9][0-9]*\.json$/.test(ref.path.split('/').at(-1))
      && /^[0-9a-f]{64}$/.test(ref.sha256), 'retained_s4_evidence_path_invalid');
    const bytes = await readFile(resolve(root, ref.path));
    requireCondition(bytes.length <= 8 * 1024 * 1024 && sha256(bytes) === ref.sha256, 'retained_s4_evidence_hash_mismatch');
    evidenceFiles.push(ref);
  }
  const observerPassword = (await readFile(resolve(root, secretPaths.observerPassword), 'utf8')).trim();
  requireCondition(observerPassword.length > 0, 'required_secret_unavailable');
  const pool = makePool(observerPassword);
  let database;
  try {
    database = await readPublicDatabase(pool, capture.preparationId, { setupOperationId: capture.s4FixtureEvidence.operationId });
  } finally { await pool.end().catch(() => {}); }
  requireCondition(database.preparation?.status === 'fenced' && database.generation?.status === 'fenced'
    && database.activeGenerationCount === 0 && generationMatchesPreparation(database)
    && database.preparation.generationId === capture.s4FixtureEvidence.generationId, 'retained_s4_original_not_fenced');
  assertS4SetupDatabase(database, capture.s4FixtureEvidence, taskCase, capture.preparationId);
  const sourceAfter = await snapshotSourceInputs(root);
  requireCondition(JSON.stringify(sourceBefore) === JSON.stringify(sourceAfter), 'reconciliation_source_changed');
  const captureId = randomUUID(), outputPrefix = `artifacts/runs/owner-bef-s4-preparation-reconciliation/${captureId}`;
  await mkdir(outputPrefix, { recursive: true });
  const value = { schemaVersion: 'owner-bef-s4-preparation-reconciliation/v1', captureId,
    classification: 'readonly_original_s4_preparation_database_reconciliation_not_fresh_preparation', status: 'verified',
    originalCapture: { path, sha256: expectedSha256 }, caseId: taskCase.caseId, caseHash: taskCase.caseHash,
    preparationId: capture.preparationId, generationId: capture.s4FixtureEvidence.generationId,
    setupOperationId: capture.s4FixtureEvidence.operationId, transactionHash: capture.s4FixtureEvidence.transactionHash,
    originalInitialStateMatched: true, originalEvidenceFilesVerified: evidenceFiles, database,
    sourceInputs: sourceBefore, sourceUnchanged: true,
    claims: { actorCalls: false, approvalResubmitted: false, freshPreparation: false, releaseActivation: false,
      ownerRunAcceptance: false, taskGrade: false, mainnetExecution: false } };
  const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
  requireCondition(!bytes.toString('utf8').includes(observerPassword), 'credential_echo_in_reconciliation');
  await writeFile(`${outputPrefix}/verification.json`, bytes, { flag: 'wx' });
  process.stdout.write(`${JSON.stringify({ outputPrefix, sha256: sha256(bytes), status: value.status,
    actorCalls: false, generationFenced: true, sourceUnchanged: true })}\n`);
}

async function main() {
  requireCondition(process.platform === 'linux' && root === '/workspace', 'docker_runtime_required');
  const args = process.argv.slice(2);
  if (args.length === 4 && args[0] === '--verify-retained-s4-capture' && args[2] === '--sha256') {
    await verifyRetainedS4Capture(args[1], args[3]);
    return;
  }
  const s4Mode = args.length === 5 && args[0] === '--capture-synthetic-local-bef-env-a'
    && args[1] === '--task-id' && args[2] === 'S4' && args[3] === '--mode'
    && args[4] === 'ranked' ? args[4] : null;
  requireCondition(!(args.length === 5 && args[0] === '--capture-synthetic-local-bef-env-a'
    && args[1] === '--task-id' && args[2] === 'S4' && args[3] === '--mode' && args[4] === 'training'),
  'training_task_not_open_in_current_release');
  requireCondition((args.length === 1 && args[0] === '--capture-synthetic-local-bef-env-a') || s4Mode,
    'explicit_capture_argument_required');
  const selectedTaskId = s4Mode ? 'S4' : 'S1';
  const currentPins = await loadCurrentTaskReleasePins(root);
  for (const path of [currentPins.cases.path, currentPins.validation.path]) {
    if (!ownerContextPaths.includes(path)) ownerContextPaths.push(path);
  }
  requireCondition(process.env.BEF_API_HOST_PORT === EXPECTED.apiHostPort, 'unexpected_api_host_port');

  const captureId = randomUUID();
  const preparationId = randomUUID();
  const outputPrefix = `artifacts/runs/owner-bef-task-preparation-capture/${captureId}`;
  const outputDir = resolve(root, outputPrefix);
  await mkdir(resolve(root, 'artifacts/runs/owner-bef-task-preparation-capture'), { recursive: true });
  await mkdir(outputDir, { recursive: false });
  const secretValues = {};
  for (const [name, path] of Object.entries(secretPaths)) {
    const value = (await readFile(resolve(root, path), 'utf8')).trim();
    requireCondition(value.length > 0, 'required_secret_unavailable');
    secretValues[name] = value;
  }

  const sourceBefore = await snapshotSourceInputs(root);
  const { identity, manifest } = await readPinnedInputs();
  const routerAddress = manifest.contracts.swapRouter02.address.toLowerCase();
  const balances = [
    { account: 'participant', assetId: 'ETH', amountUnits: '10000000000000000000' },
    { account: 'participant', assetId: 'USDC', amountUnits: '100000000' },
    { account: 'participant', assetId: 'WETH', amountUnits: '0' },
  ];
  const allowances = [
    { owner: 'participant', tokenAssetId: 'USDC', spender: routerAddress, amountUnits: '0' },
    { owner: 'participant', tokenAssetId: 'WETH', spender: routerAddress, amountUnits: '0' },
  ];
  let initialStateCore = { balances, allowances, deliveredComponentIds: [], fulfilledObligationIds: [] };
  let initialState = { stateSha256: sha256CanonicalTaskJson(initialStateCore), ...initialStateCore };
  let selectedCase = null;
  if (s4Mode) {
    const bytes = await readFile(resolve(root, currentPins.cases.path));
    requireCondition(sha256(bytes) === currentPins.cases.sha256, 'case_candidates_pin_mismatch');
    const candidates = JSON.parse(bytes);
    requireCondition(candidates.executionIdentityHash === EXPECTED.executionIdentitySha256
      && sha256CanonicalTaskJson(candidates.executionIdentity) === EXPECTED.executionIdentitySha256, 'case_candidates_identity_mismatch');
    const matches = candidates.cases.filter((item) => item.taskId === 'S4' && item.mode === s4Mode);
    requireCondition(matches.length === 1, 's4_case_inventory_mismatch');
    selectedCase = TaskCaseSchema.parse(matches[0]);
    initialState = structuredClone(selectedCase.initialState);
    const { stateSha256: _stateHash, ...core } = initialState;
    initialStateCore = core;
    requireCondition(sha256CanonicalTaskJson(core) === initialState.stateSha256, 's4_case_initial_hash_invalid');
  }
  const synthetic = makeSyntheticRelease(identity, initialState, EXPECTED.manifestSha256, selectedCase);
  const createdAt = new Date().toISOString();
  const intent = {
    preparationId,
    runId: randomUUID(),
    taskIndex: 0,
    claimId: randomUUID(),
    leaseId: randomUUID(),
    environmentId: EXPECTED.envId,
    releaseIdentity: synthetic.releaseIdentity,
    manifestHash: synthetic.manifestHash,
    taskId: selectedTaskId,
    caseId: synthetic.caseId,
    caseHash: synthetic.caseHash,
    initialStateSha256: synthetic.initialStateSha256,
    executionIdentityHash: EXPECTED.executionIdentitySha256,
    environmentManifestSha256: EXPECTED.manifestSha256,
    applicationSourceHash: EXPECTED.applicationSourceSha256,
    createdAt,
  };
  const publicPinsSha256 = taskPreparationPublicPinsSha256(intent);
  const apiBase = `http://host.docker.internal:${EXPECTED.apiHostPort}`;
  const localRpc = `http://host.docker.internal:${EXPECTED.localRpcHostPort}`;
  const sourceRpc = `http://host.docker.internal:${EXPECTED.sourceProxyHostPort}`;
  const evidenceFiles = [];
  let s4FixtureEvidence = null;
  const evidenceSink = {
    async write(value) {
      validateEvidenceShape(value, selectedTaskId);
      const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
      for (const secret of Object.values(secretValues)) {
        requireCondition(!bytes.toString('utf8').includes(secret), 'credential_echo_in_evidence');
      }
      const path = `${outputPrefix}/adapter-${value.kind}-${evidenceFiles.length + 1}.json`;
      await writeFile(resolve(root, path), bytes, { flag: 'wx' });
      const digest = sha256(bytes);
      evidenceFiles.push({ path, sha256: digest, kind: value.kind });
      if (value.kind === 'fixture' && value.evidence.s4AllowanceFixture) {
        s4FixtureEvidence = structuredClone(value.evidence.s4AllowanceFixture);
      }
      return { path, sha256: digest, boundary: evidenceBoundary };
    },
  };

  let putAttempts = 0;
  let fixtureApprovePostAttempts = 0;
  const countPutFetch = async (input, init = {}) => {
    const method = String(init.method ?? 'GET').toUpperCase();
    if (method === 'PUT') putAttempts += 1;
    if (method === 'POST' && String(input).endsWith(`/tools/${EXPECTED.envId}/approve`)) fixtureApprovePostAttempts++;
    return fetch(input, init);
  };
  const dependencies = makeDependencies({ apiBase, localRpc, sourceRpc, adminKey: secretValues.adminKey,
    manifest, releaseSource: synthetic.source, evidenceSink, fetchImpl: countPutFetch });
  const adapter = new BefTaskPreparationAdapter(dependencies);
  const pool = makePool(secretValues.observerPassword);
  let firstOutcome = null;
  let replayOutcome = null;
  let lateOutcome = null;
  let fence = null;
  let fenceError = null;
  let preparationBeforeFence = null;
  let databaseBeforeFence = null;
  let preparationAfterFence = null;
  let databaseAfterFence = null;
  let latePutAttempts = null;
  let failure = null;
  try {
    const preflight = await readPublicDatabase(pool, preparationId, { preflight: true });
    requireCondition(preflight.activeGenerationCount === 0 && !preflight.preparationExists, 'environment_preparation_preflight_not_clear');

    firstOutcome = await adapter.prepare({ intent, dispatchId: randomUUID() });
    requireCondition(firstOutcome.status === 'prepared', 'adapter_prepare_not_ready');
    replayOutcome = await adapter.prepare({ intent, dispatchId: randomUUID() });
    requireCondition(replayOutcome.status === 'prepared' &&
      replayOutcome.result.generationId === firstOutcome.result.generationId &&
      replayOutcome.result.participantId === firstOutcome.result.participantId &&
      replayOutcome.result.payerAddress === firstOutcome.result.payerAddress, 'same_adapter_replay_mismatch');
    requireCondition(putAttempts === 1, 'adapter_put_attempt_count_invalid');

    preparationBeforeFence = await getPublicStatus(apiBase, preparationId, secretValues.adminKey);
    databaseBeforeFence = await readPublicDatabase(pool, preparationId, { setupOperationId: s4FixtureEvidence?.operationId });
    requireCondition(preparationBeforeFence.status === 'ready' && preparationBeforeFence.fixture?.state === 'observed' &&
      preparationBeforeFence.generationId === firstOutcome.result.generationId, 'public_ready_status_invalid');
    requireCondition(safeStatusMatchesDatabase(preparationBeforeFence, databaseBeforeFence), 'pre_fence_get_database_mismatch');
    requireCondition(databaseBeforeFence.preparation?.publicPinsSha256 === publicPinsSha256 &&
      databaseBeforeFence.preparation?.manifestSha256 === EXPECTED.manifestSha256 &&
      databaseBeforeFence.preparation?.status === 'ready' && databaseBeforeFence.preparation?.fixtureState === 'observed' &&
      databaseBeforeFence.preparation?.generationId === firstOutcome.result.generationId, 'database_ready_record_invalid');
    requireCondition(databaseBeforeFence.generation?.generation_id === firstOutcome.result.generationId &&
      databaseBeforeFence.generation?.status === 'active' &&
      databaseBeforeFence.generation?.participant_id === firstOutcome.result.participantId &&
      databaseBeforeFence.generation?.payer_address?.toLowerCase() === firstOutcome.result.payerAddress?.toLowerCase() &&
      generationMatchesPreparation(databaseBeforeFence),
    'database_generation_identity_invalid');
    if (s4Mode) assertS4SetupDatabase(databaseBeforeFence, s4FixtureEvidence, selectedCase, preparationId);
  } catch (error) {
    failure = errorCode(error);
  } finally {
    try {
      fence = await adapter.fence({ intent, generationId: firstOutcome?.result?.generationId ?? firstOutcome?.generationId ?? null });
    } catch (error) {
      fenceError = errorCode(error);
    } finally {
      adapter.clearCredentials(preparationId);
    }

    if (fence) {
      try {
        preparationAfterFence = await getPublicStatus(apiBase, preparationId, secretValues.adminKey);
        databaseAfterFence = await readPublicDatabase(pool, preparationId, { setupOperationId: s4FixtureEvidence?.operationId });
        requireCondition(preparationAfterFence.status === 'fenced' && Boolean(preparationAfterFence.fenceConfirmedAt), 'public_fence_status_invalid');
        requireCondition(safeStatusMatchesDatabase(preparationAfterFence, databaseAfterFence), 'post_fence_get_database_mismatch');
        requireCondition(databaseAfterFence.preparation?.status === 'fenced' && Boolean(databaseAfterFence.preparation?.fenceConfirmedAt), 'database_fence_status_invalid');
        if (databaseAfterFence.generation) requireCondition(databaseAfterFence.generation.status === 'fenced' &&
          generationMatchesPreparation(databaseAfterFence), 'database_generation_not_fenced');
        if (s4Mode && s4FixtureEvidence?.outcome === 'observed') {
          assertS4SetupDatabase(databaseAfterFence, s4FixtureEvidence, selectedCase, preparationId);
        }

        let latePutCount = 0;
        const countLatePutFetch = async (input, init = {}) => {
          if (String(init.method ?? 'GET').toUpperCase() === 'PUT') latePutCount += 1;
          return fetch(input, init);
        };
        const lateAdapter = new BefTaskPreparationAdapter(makeDependencies({ apiBase, localRpc, sourceRpc,
          adminKey: secretValues.adminKey, manifest, releaseSource: synthetic.source, evidenceSink, fetchImpl: countLatePutFetch }));
        lateOutcome = await lateAdapter.prepare({ intent, dispatchId: randomUUID() });
        latePutAttempts = latePutCount;
        requireCondition(lateOutcome.status === 'unknown' && latePutCount === 0, 'late_prepare_not_denied_before_put');
        lateAdapter.clearCredentials(preparationId);
      } catch (error) {
        failure ??= errorCode(error);
      }
    }

    await pool.end().catch(() => {});
  }

  let sourceAfter = null;
  let sourceUnchanged = false;
  try {
    sourceAfter = await snapshotSourceInputs(root);
    sourceUnchanged = JSON.stringify(sourceBefore) === JSON.stringify(sourceAfter);
    requireCondition(sourceUnchanged, 'source_changed_during_capture');
  } catch (error) {
    failure ??= errorCode(error);
  }

  const capture = {
    schemaVersion: 'owner-bef-task-preparation-capture/v1',
    classification: 'synthetic_local_environment_preparation_bridge_capture_not_release_activation_or_task_acceptance',
    captureId,
    preparationId,
    environmentId: EXPECTED.envId,
    syntheticProvider: { classification: synthetic.source.classification, taskId: selectedTaskId,
      mode: s4Mode ?? 'training', caseId: synthetic.caseId,
      actualCaseInput: s4Mode ? { path: currentPins.cases.path, sha256: currentPins.cases.sha256,
        caseHash: selectedCase.caseHash } : null },
    currentReleaseValidation: currentPins.validation,
    pins: {
      environmentManifestSha256: EXPECTED.manifestSha256,
      applicationSourceSha256: EXPECTED.applicationSourceSha256,
      executionIdentitySha256: EXPECTED.executionIdentitySha256,
      publicPinsSha256,
      initialStateSha256: synthetic.initialStateSha256,
    },
    initialState: initialStateCore,
    s4FixtureEvidence,
    fixtureApprovePostAttempts,
    adapterReplay: {
      firstStatus: firstOutcome?.status ?? null,
      replayStatus: replayOutcome?.status ?? null,
      firstOutcome: projectPreparationOutcome(firstOutcome),
      replayOutcome: projectPreparationOutcome(replayOutcome),
      sameGeneration: Boolean(firstOutcome?.status === 'prepared' && replayOutcome?.status === 'prepared' &&
        firstOutcome.result.generationId === replayOutcome.result.generationId),
      putAttempts: putAttempts,
      boundary: 'one_adapter_instance_cache_and_original_generation_readonly_reconciliation; does not prove BEF PUT API idempotency',
    },
    readyObservation: preparationBeforeFence,
    databaseBeforeFence: databaseBeforeFence ? {
      session: databaseBeforeFence.session,
      activeGenerationCount: databaseBeforeFence.activeGenerationCount,
      preparation: databaseBeforeFence.preparation,
      generation: databaseBeforeFence.generation,
      setup: databaseBeforeFence.setup,
    } : null,
    fence: fence ? { confirmed: true, generationId: fence.generationId, evidence: fence.evidence } : { confirmed: false, errorCode: fenceError },
    fencedObservation: preparationAfterFence,
    databaseAfterFence: databaseAfterFence ? {
      session: databaseAfterFence.session,
      activeGenerationCount: databaseAfterFence.activeGenerationCount,
      preparation: databaseAfterFence.preparation,
      generation: databaseAfterFence.generation,
      setup: databaseAfterFence.setup,
    } : null,
    latePrepare: {
      status: lateOutcome?.status ?? null,
      reasonCode: lateOutcome?.status === 'unknown' ? lateOutcome.reasonCode : null,
      putAttempts: latePutAttempts,
      boundary: 'fresh adapter observes the durable public fenced status before issuing any PUT',
    },
    evidenceFiles,
    sourceBefore,
    sourceAfter,
    sourceUnchanged,
    claims: {
      syntheticCaptureOnly: true,
      releaseValidated: false,
      releaseActivated: false,
      ownerServerOrWorkerWired: false,
      taskAccepted: false,
      participantActions: false,
      taskGrade: false,
      liveChainOrMainnet: false,
      befPutApiIdempotencyProven: false,
    },
    failureCode: failure,
  };
  const bytes = Buffer.from(`${JSON.stringify(capture, null, 2)}\n`);
  for (const secret of Object.values(secretValues)) requireCondition(!bytes.toString('utf8').includes(secret), 'credential_echo_in_capture');
  await writeFile(resolve(outputDir, 'capture.json'), bytes, { flag: 'wx' });
  process.stdout.write(`${JSON.stringify({ outputPrefix, sha256: sha256(bytes), captureId, preparationId,
    status: failure ? 'incomplete' : 'fenced', putAttempts, fenceConfirmed: Boolean(fence), sourceUnchanged })}\n`);
  if (failure || !fence || !sourceUnchanged || putAttempts !== 1) process.exitCode = 2;
}

void main().catch((error) => {
  const code = errorCode(error);
  process.stderr.write(`owner_bef_preparation_capture_failed:${code}\n`);
  process.exitCode = 2;
});
