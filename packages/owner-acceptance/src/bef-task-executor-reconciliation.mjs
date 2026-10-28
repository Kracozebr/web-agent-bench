/**
 * Independently reconcile the first bridge capture's unknown receipt from its
 * retained BEF response and read-only BEF/owner database observations. This
 * never resubmits the participant command or resets an environment.
 */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import pg from 'pg';

const { Pool } = pg;
const root = resolve(fileURLToPath(new URL('../../..', import.meta.url)));
const captureRoot = resolve(root, 'artifacts/runs/bts-task-action-executor-bridge');
const captureId = '33313494-5f35-43ad-95ad-eb42c21ee7f5';
const databaseName = 'oid_acceptance_333134945f3543ad95adeb42c21ee7f5';
const txPattern = /^0x[0-9a-f]{64}$/i;
const hashPattern = /^[0-9a-f]{64}$/i;
let currentPhase = 'not_started';

function sha256(bytes) { return createHash('sha256').update(bytes).digest('hex'); }
function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    const entries = Object.entries(value).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0);
    return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`).join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}

function requireCaptureIdentity(summary, observation) {
  assert.equal(summary.envId, 'bef-env-a');
  assert.equal(summary.outcome, 'unknown');
  assert.equal(summary.ownerRunId, '80c99229-d3d4-4d0e-be6f-e62b0e658cc9');
  assert.equal(summary.ownerActionId, 'ef276d9e-3fb6-42e0-aa33-4e364846c5fe');
  assert.equal(summary.fixtureProvenance.productReleaseActivation, false);
  assert.match(summary.manifestSha256, hashPattern);
  assert.match(summary.applicationSourceSha256, hashPattern);
  assert.equal(observation.schema, 'bef-task-action-observation-v1');
  assert.equal(observation.actionId, summary.ownerActionId);
  assert.equal(observation.runId, summary.ownerRunId);
  assert.equal(observation.environmentId, summary.envId);
  assert.equal(observation.generationId, summary.generationId);
  assert.equal(observation.manifestSha256, summary.manifestSha256);
  assert.equal(observation.applicationSourceSha256, summary.applicationSourceSha256);
  assert.equal(observation.status, 'unknown');
  assert.equal(observation.httpStatus, 200);
  assert.equal(observation.reasonCode, 'participant_tool_observation_ambiguous');
  assert.match(observation.rawResponseSha256, hashPattern);
  assert.match(observation.transactionHash, txPattern);
  assert.equal(observation.befOperationId, summary.executorResult.befOperationId);
}

function verifyMatchedMeasurements(ownerAction, observation, operation, measurement) {
  const response = observation.participantToolResponse;
  assert.ok(response && typeof response === 'object');
  assert.equal(response.outcome, 'success');
  assert.equal(response.operationId, observation.befOperationId);
  assert.equal(response.receipt?.status, 'success');
  assert.equal(response.receipt?.transactionHash?.toLowerCase(), observation.transactionHash.toLowerCase());
  assert.equal(response.transaction?.hash?.toLowerCase(), observation.transactionHash.toLowerCase());
  assert.equal(operation.operation_kind, 'transfer');
  assert.equal(operation.status, 'settled');
  assert.equal(operation.receipt_status, 'success');
  assert.equal(operation.transaction_hash?.toLowerCase(), observation.transactionHash.toLowerCase());
  assert.equal(operation.selected_transaction_hash?.toLowerCase(), observation.transactionHash.toLowerCase());
  assert.equal(operation.action_kind, 'transfer');
  assert.equal(operation.selected_outcome, 'success');
  assert.equal(measurement?.receipt?.transactionHash?.toLowerCase(), observation.transactionHash.toLowerCase());
  assert.equal(measurement.receipt.status, response.receipt.status);
  assert.equal(measurement.receipt.gasUsed, response.receipt.gasUsed);
  assert.equal(measurement.receipt.effectiveGasPrice, response.receipt.effectiveGasPrice);
  assert.deepEqual(measurement.selectedAction, response.selectedAction);
  assert.deepEqual(measurement.before, response.before);
  assert.deepEqual(measurement.after, response.after);
  assert.deepEqual(measurement.effects, response.effects);
  assert.equal(ownerAction.action_kind, 'transfer');
  assert.equal(ownerAction.command_json?.kind, 'transfer');
  assert.equal(ownerAction.command_json?.amountUnits, response.selectedAction.amountUnits);
  assert.equal(ownerAction.command_json?.recipient?.toLowerCase(), response.selectedAction.recipient?.toLowerCase());
  assert.equal(ownerAction.command_json?.gasLimit, response.selectedAction.gasLimit);
  assert.equal(ownerAction.payload_hash, observation.commandSha256);
  assert.equal(ownerAction.operation_id, observation.ownerOperationId);
  assert.ok(['unknown', 'observed'].includes(ownerAction.receipt_status));
  assert.equal(ownerAction.transaction_hash?.toLowerCase(), observation.transactionHash.toLowerCase());
  assert.equal(ownerAction.transaction_hash?.toLowerCase(), observation.transactionHash.toLowerCase());
  assert.equal(BigInt(measurement.before.payerUsdcUnits) - BigInt(measurement.after.payerUsdcUnits), BigInt(ownerAction.command_json.amountUnits));
  assert.equal(BigInt(measurement.after.recipientUsdcUnits) - BigInt(measurement.before.recipientUsdcUnits), BigInt(ownerAction.command_json.amountUnits));
}

async function runOwnerMigrations(databaseUrl) {
  await new Promise((resolvePromise, reject) => {
    const child = spawn('pnpm', ['--filter', '@web-agent-bench/owner-identity', 'exec', 'tsx', 'src/migrate.ts'], {
      cwd: root,
      env: { ...process.env, OID_DATABASE_URL: databaseUrl },
      stdio: ['ignore', 'ignore', 'ignore'],
      windowsHide: true,
    });
    child.once('error', () => reject(new Error('owner_acceptance_migration_failed')));
    child.once('exit', (code) => code === 0 ? resolvePromise() : reject(new Error('owner_acceptance_migration_failed')));
  });
}

async function writeOrCompareEvidence(path, bytes) {
  try {
    await writeFile(path, bytes, { flag: 'wx', mode: 0o600 });
    return;
  } catch (error) {
    if (!error || typeof error !== 'object' || error.code !== 'EEXIST') throw error;
  }
  const existing = await readFile(path);
  if (!existing.equals(bytes)) throw new Error('reconciliation_evidence_conflict');
}

function safeQueryFailure(prefix, error) {
  const code = error && typeof error === 'object' && typeof error.code === 'string' && /^[0-9A-Z]{5}$/.test(error.code)
    ? error.code : 'unknown';
  const categories = {
    '42501': 'permission_denied', '42703': 'column_missing', '42P01': 'relation_missing',
    '3D000': 'database_missing', '28P01': 'authentication_failed',
  };
  return new Error(`${prefix}_${categories[code] ?? code.toLowerCase()}`);
}

async function main() {
  currentPhase = 'load_capture_artifacts';
  const directory = resolve(captureRoot, captureId);
  if (relative(captureRoot, directory).startsWith('..')) throw new Error('reconciliation_capture_path_invalid');
  const summaryBytes = await readFile(resolve(directory, 'capture-summary.json'));
  const observationBytes = await readFile(resolve(directory, 'participant-tool-observation.json'));
  const summary = JSON.parse(summaryBytes.toString('utf8'));
  const observation = JSON.parse(observationBytes.toString('utf8'));
  currentPhase = 'validate_capture_identity';
  requireCaptureIdentity(summary, observation);

  currentPhase = 'validate_owner_database_identity';
  const ownerBaseUrl = new URL(process.env.OID_DATABASE_URL ?? '');
  const ownerObserverBaseUrl = new URL(process.env.OID_OBSERVER_DATABASE_URL ?? '');
  ownerBaseUrl.pathname = `/${databaseName}`;
  ownerObserverBaseUrl.pathname = `/${databaseName}`;
  if (!['postgres:', 'postgresql:'].includes(ownerBaseUrl.protocol) || ownerBaseUrl.hostname !== 'postgres' || ownerBaseUrl.username !== 'oid_owner' ||
      ownerObserverBaseUrl.hostname !== 'postgres' || ownerObserverBaseUrl.username !== 'oid_observer' ||
      !['postgres:', 'postgresql:'].includes(ownerObserverBaseUrl.protocol) ||
      ownerBaseUrl.pathname !== `/${databaseName}` || ownerBaseUrl.pathname !== ownerObserverBaseUrl.pathname ||
      ownerBaseUrl.port !== ownerObserverBaseUrl.port || ownerBaseUrl.search || ownerBaseUrl.hash ||
      ownerObserverBaseUrl.search || ownerObserverBaseUrl.hash) {
    throw new Error('owner_acceptance_database_identity_invalid');
  }

  const observerPassword = (await readFile(resolve(root, 'infrastructure/benchmark-environment/.local/secrets/database-observer-password'), 'utf8')).trim();
  const befUrl = new URL(`postgres://bef_observer:${encodeURIComponent(observerPassword)}@host.docker.internal:55432/bef`);
  currentPhase = 'apply_isolated_owner_migrations';
  await runOwnerMigrations(ownerBaseUrl.href);
  const ownerSetup = new Pool({ connectionString: ownerBaseUrl.href, max: 1, application_name: 'bef-bridge-reconciliation-isolated-grants' });
  try {
    await ownerSetup.query('GRANT USAGE ON SCHEMA public TO oid_observer');
    await ownerSetup.query('GRANT SELECT ON ALL TABLES IN SCHEMA public TO oid_observer');
    await ownerSetup.query('ALTER DEFAULT PRIVILEGES FOR ROLE oid_owner IN SCHEMA public GRANT SELECT ON TABLES TO oid_observer');
  } finally { await ownerSetup.end(); }
  const ownerObserver = new Pool({ connectionString: ownerObserverBaseUrl.href, max: 1, application_name: 'bef-bridge-reconciliation-owner-observer' });
  const befObserver = new Pool({ connectionString: befUrl.href, max: 1, application_name: 'bef-bridge-reconciliation-bef-observer' });
  let ownerClient;
  try {
    currentPhase = 'verify_observer_identities';
    await ownerObserver.query('BEGIN READ ONLY');
    await befObserver.query('BEGIN READ ONLY');
    const ownerIdentity = (await ownerObserver.query(`SELECT current_user AS role,current_setting('transaction_read_only') AS readonly,
        current_database() AS database_name`)).rows[0];
    const befIdentity = (await befObserver.query(`SELECT current_user AS role,current_setting('transaction_read_only') AS readonly,
        current_database() AS database_name`)).rows[0];
    if (ownerIdentity?.role !== 'oid_observer') throw new Error('owner_observer_role_invalid');
    if (ownerIdentity?.readonly !== 'on') throw new Error('owner_observer_readonly_invalid');
    if (ownerIdentity?.database_name !== databaseName) throw new Error('owner_observer_database_mismatch');
    if (befIdentity?.role !== 'bef_observer') throw new Error('bef_observer_role_invalid');
    if (befIdentity?.readonly !== 'on') throw new Error('bef_observer_readonly_invalid');
    if (befIdentity?.database_name !== 'bef') throw new Error('bef_observer_database_mismatch');

    currentPhase = 'read_owner_action';
    let ownerRow;
    try {
      ownerRow = (await ownerObserver.query(`SELECT a.id::text AS action_id,a.run_id::text,a.task_index,a.task_id,
          a.action_sequence::text,a.operation_id,a.payload_hash,a.action_kind,a.command_json,
          r.receipt_status,r.receipt_revision,r.evidence_hash,r.transaction_hash,r.tool_response_hash
        FROM oid_run_task_action a JOIN oid_run_task_action_receipt r ON r.action_id=a.id
        WHERE a.id=$1 AND a.run_id=$2`, [summary.ownerActionId, summary.ownerRunId])).rows[0];
    } catch (error) { throw safeQueryFailure('owner_action_read', error); }
    if (!ownerRow) throw new Error('owner_action_not_found_in_acceptance_database');

    currentPhase = 'read_bef_operation';
    let befRow;
    try {
      befRow = (await befObserver.query(`SELECT o.operation_id::text,o.env_id,o.generation_id::text,o.participant_id,
          o.operation_kind,o.status,o.receipt_status,o.transaction_hash,s.action_kind,s.outcome AS selected_outcome,
          s.transaction_hash AS selected_transaction_hash,s.measurement_json
        FROM bef_operation o LEFT JOIN bef_selected_execution s
          ON s.operation_id=o.operation_id AND s.env_id=o.env_id AND s.generation_id=o.generation_id
        WHERE o.operation_id=$1 AND o.env_id=$2 AND o.generation_id=$3`,
      [observation.befOperationId, observation.environmentId, observation.generationId])).rows[0];
    } catch (error) { throw safeQueryFailure('bef_operation_read', error); }
    if (!befRow) throw new Error('bef_operation_not_found_in_observer_database');
    const measurement = typeof befRow.measurement_json === 'string' ? JSON.parse(befRow.measurement_json) : befRow.measurement_json;
    currentPhase = 'verify_independent_measurements';
    assert.equal(befRow.participant_id, summary.participantId);
    assert.equal(befRow.generation_id, summary.generationId);
    assert.equal(befRow.env_id, summary.envId);
    verifyMatchedMeasurements(ownerRow, observation, befRow, measurement);

    const reconciliation = {
      schema: 'bef-task-action-observation-reconciliation-v1',
      classification: 'local_selected_tool_bridge_only',
      sourceCapture: {
        directory: relative(root, directory).replaceAll('\\', '/'),
        captureSummarySha256: sha256(summaryBytes),
        participantObservationSha256: sha256(observationBytes),
        participantRawResponseSha256: observation.rawResponseSha256,
      },
      fixtureProvenance: summary.fixtureProvenance,
      ownerObserver: { role: ownerIdentity.role, readOnly: ownerIdentity.readonly, databaseName: ownerIdentity.database_name },
      befObserver: { role: befIdentity.role, readOnly: befIdentity.readonly, databaseName: befIdentity.database_name },
      ownerAction: {
        actionId: ownerRow.action_id, runId: ownerRow.run_id, taskIndex: ownerRow.task_index, taskId: ownerRow.task_id,
        actionSequence: ownerRow.action_sequence, operationId: ownerRow.operation_id, command: ownerRow.command_json,
        payloadHash: ownerRow.payload_hash, transactionHash: ownerRow.transaction_hash,
      },
      befOperation: {
        operationId: befRow.operation_id, envId: befRow.env_id, generationId: befRow.generation_id,
        participantId: befRow.participant_id, operationKind: befRow.operation_kind, status: befRow.status,
        receiptStatus: befRow.receipt_status, selectedExecutionOutcome: befRow.selected_outcome,
        transactionHash: befRow.transaction_hash, selectedTransactionHash: befRow.selected_transaction_hash,
      },
      participantResponse: observation.participantToolResponse,
      databaseMeasurement: measurement,
      resolution: 'observed',
      evidenceBoundary: 'Independent read-only database observations matched the retained selected-tool response; no participant request was resent.',
    };
    const evidencePath = resolve(directory, 'reconciliation-confirmation.json');
    const evidenceBytes = Buffer.from(`${JSON.stringify(reconciliation, null, 2)}\n`, 'utf8');
    currentPhase = 'persist_reconciliation_evidence';
    await writeOrCompareEvidence(evidencePath, evidenceBytes);
    const evidenceHash = sha256(evidenceBytes);
    await ownerObserver.query('COMMIT');
    await befObserver.query('COMMIT');

    const { createDatabase } = await import('../../owner-identity/dist/db.js');
    const { loadConfig } = await import('../../owner-identity/dist/config.js');
    const actionService = await import('../../owner-identity/dist/task-action-service.js');
    const { sha256CanonicalTaskJson } = await import('../../owner-identity/dist/task-release.js');
    const config = loadConfig({ ...process.env, OID_DATABASE_URL: ownerBaseUrl.href });
    const created = createDatabase(config);
    ownerClient = created.client;
    let replayed = false;
    if (ownerRow.receipt_status === 'observed') {
      replayed = true;
      const expectedToolResponseHash = sha256CanonicalTaskJson(observation.participantToolResponse);
      if (ownerRow.evidence_hash !== evidenceHash || ownerRow.tool_response_hash !== expectedToolResponseHash) {
        throw new Error('owner_action_receipt_conflict');
      }
    } else {
      currentPhase = 'record_observed_receipt';
      const result = await actionService.recordTaskActionReceipt({ db: created.db }, {
        actionId: ownerRow.action_id, status: 'observed', evidenceHash,
        transactionHash: observation.transactionHash.toLowerCase(), toolResponse: observation.participantToolResponse,
      });
      assert.equal(result.receiptStatus, 'observed');
    }

    await ownerObserver.query('BEGIN READ ONLY');
    currentPhase = 'verify_persisted_receipt';
    const finalRow = (await ownerObserver.query(`SELECT receipt_status,receipt_revision,evidence_hash,transaction_hash,tool_response_hash
      FROM oid_run_task_action_receipt WHERE action_id=$1`, [ownerRow.action_id])).rows[0];
    assert.equal(finalRow?.receipt_status, 'observed');
    assert.equal(finalRow?.evidence_hash, evidenceHash);
    assert.equal(finalRow?.transaction_hash?.toLowerCase(), observation.transactionHash.toLowerCase());
    assert.equal(finalRow?.tool_response_hash, sha256CanonicalTaskJson(observation.participantToolResponse));
    process.stdout.write(`${JSON.stringify({
      outcome: 'observed', actionId: ownerRow.action_id, transactionHash: observation.transactionHash,
      befOperationId: observation.befOperationId, evidencePath: relative(root, evidencePath).replaceAll('\\', '/'),
      evidenceSha256: evidenceHash, receiptRevision: finalRow.receipt_revision,
      ownerDatabase: databaseName, environmentId: summary.envId, generationId: summary.generationId,
      replayed,
      classification: 'local_selected_tool_bridge_only',
    })}\n`);
  } finally {
    await ownerClient?.end().catch(() => undefined);
    await ownerObserver.end().catch(() => undefined);
    await befObserver.end().catch(() => undefined);
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main().catch((error) => {
    const code = error instanceof Error && /^[a-z0-9_:-]{1,120}$/i.test(error.message) ? error.message : 'bef_bridge_reconciliation_failed';
    process.stderr.write(`${code}:${currentPhase}\n`);
    process.exitCode = 2;
  });
}
