import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import test from 'node:test';
import postgres from 'postgres';
import { drizzle } from 'drizzle-orm/postgres-js';
import { sql } from 'drizzle-orm';
import type { OwnerDatabase } from './db.js';
import { sha256CanonicalTaskJson } from './task-release.js';
import { loadAdmittedActionRows, validateAdmittedActionCensus } from './bef-admitted-action-census.js';

// AICODE-NOTE: Minimal synthetic SQL fixtures qualify the loader/snapshot boundary, not a
// participant, chain receipt, family effect, original Google DB, grade or native acceptance.
test('shared census reads current and latest receipt history in one actual PostgreSQL snapshot',
  { skip: process.env.OID_MCP_DIAGNOSTICS_PG_TEST !== '1' }, async t => {
    const source = process.env.OID_DATABASE_URL;
    assert.ok(source);
    const sourceUrl = new URL(source);
    assert.equal(sourceUrl.hostname, 'postgres');
    assert.equal(sourceUrl.username, 'oid_owner');
    assert.equal(sourceUrl.pathname, '/owner_identity');
    const name = 'oid_census_' + randomUUID().replaceAll('-', '');
    assert.match(name, /^oid_census_[a-f0-9]{32}$/);
    const target = new URL(source); target.pathname = '/' + name;
    const admin = postgres(source, { max: 1, connect_timeout: 10 });
    const owner = postgres(target.href, { max: 3, connect_timeout: 10 });
    const db = drizzle(owner) as unknown as OwnerDatabase;
    let created = false;
    const binding = { ownerId: randomUUID(), agentId: randomUUID(), runId: randomUUID(),
      environmentId: 'synthetic-isolated-env', releaseIdentity: 'synthetic-release', manifestHash: 'a'.repeat(64),
      caseId: 'synthetic-s1', caseHash: 'b'.repeat(64), rubricHash: 'c'.repeat(64), taskId: 'S1' as const };
    const execution = { preparationId: randomUUID(), leaseId: randomUUID(), generationId: randomUUID(),
      environmentId: binding.environmentId, environmentManifestHash: 'd'.repeat(64), applicationSourceHash: 'e'.repeat(64),
      executionIdentityHash: 'f'.repeat(64), initialStateSha256: '0'.repeat(64) };
    const actionId = randomUUID(), command = { kind: 'inspect_catalog' as const };
    const commandSha256 = sha256CanonicalTaskJson({ runId: binding.runId, taskIndex: 0, command });
    const payment = { scheme: 'exact', network: 'eip155:8453', asset: 'USDC', amount: '1',
      payTo: '0x0000000000000000000000000000000000000009', transferMethod: 'transfer' };
    const response = { operationId: randomUUID(), freeInspection: true, deliveryState: 'not_delivered',
      catalog: [{ resourceId: 'synthetic-resource', resourceSha256: '2'.repeat(64), contentType: 'application/json',
        offers: [{ id: 'synthetic-offer', payment }] }] };
    const responseHash = sha256CanonicalTaskJson(response);
    const document = { schema: 'bef-task-action-observation-v1', actionId, runId: binding.runId, taskIndex: 0,
      actionSequence: '1', ownerOperationId: 'synthetic_census_operation', actionKind: command.kind,
      commandSha256, environmentId: binding.environmentId, generationId: execution.generationId,
      manifestSha256: execution.environmentManifestHash, applicationSourceSha256: execution.applicationSourceHash,
      idempotencyKey: 'task-action-' + actionId, status: 'observed', httpStatus: 200,
      rawResponseSha256: '3'.repeat(64), participantToolResponse: response };
    const bytes = Buffer.from(JSON.stringify(document));
    const evidenceHash = createHash('sha256').update(bytes).digest('hex');
    const evidencePath = `artifacts/runs/owner-identity-bef-task-coordinator/action/${actionId}.json`;
    const censusInput = { binding, execution, taskIndex: 0,
      closure: { closureId: randomUUID(), operationId: 'synthetic_finish_operation', payloadHash: '1'.repeat(64),
        reason: 'agent_finish' as const, actionCutoffSequence: 1, reconciledActionSequence: 1 },
      readActionEvidence: async () => bytes };
    const actionTarget = { runId: binding.runId, taskIndex: 0 };
    try {
      await admin.unsafe('CREATE DATABASE ' + name); created = true;
      await owner.unsafe(`CREATE TABLE oid_run_task_action(
        id uuid PRIMARY KEY,run_id uuid NOT NULL,task_index integer NOT NULL,owner_id uuid NOT NULL,
        agent_id uuid NOT NULL,task_id text NOT NULL,environment_id text NOT NULL,action_sequence bigint NOT NULL,
        operation_id text NOT NULL,payload_hash text NOT NULL,action_kind text NOT NULL,command_json jsonb NOT NULL);
        CREATE TABLE oid_run_task_action_receipt(action_id uuid PRIMARY KEY,receipt_revision integer NOT NULL,
          receipt_status text NOT NULL,evidence_hash text,evidence_path text,transaction_hash text,
          tool_response_json jsonb,tool_response_hash text);
        CREATE TABLE oid_run_task_action_reconciliation(action_id uuid NOT NULL,revision integer NOT NULL,
          receipt_status text NOT NULL,evidence_hash text,evidence_path text,transaction_hash text,
          tool_response_json jsonb,tool_response_hash text,PRIMARY KEY(action_id,revision));`);
      await owner`INSERT INTO oid_run_task_action VALUES(${actionId},${binding.runId},0,${binding.ownerId},${binding.agentId},
        'S1',${binding.environmentId},1,'synthetic_census_operation',${commandSha256},'inspect_catalog',${JSON.stringify(command)}::jsonb)`;
      await owner`INSERT INTO oid_run_task_action_receipt VALUES(${actionId},1,'observed',${evidenceHash},${evidencePath},NULL,
        ${JSON.stringify(response)}::jsonb,${responseHash})`;
      await owner`INSERT INTO oid_run_task_action_reconciliation SELECT action_id,receipt_revision,receipt_status,
        evidence_hash,evidence_path,transaction_hash,tool_response_json,tool_response_hash FROM oid_run_task_action_receipt`;

      await t.test('caller repeatable-read snapshot cannot mix a newer receipt or reconciliation revision', async () => {
        await db.transaction(async tx => {
          await tx.execute(sql`SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY`);
          const first = await loadAdmittedActionRows(tx, actionTarget);
          assert.equal((await validateAdmittedActionCensus({ ...censusInput, rows: first })).entries.length, 1);
          await owner.begin(async writer => {
            await writer`UPDATE oid_run_task_action_receipt SET receipt_revision=2,receipt_status='unknown' WHERE action_id=${actionId}`;
            await writer`INSERT INTO oid_run_task_action_reconciliation SELECT action_id,receipt_revision,receipt_status,
              evidence_hash,evidence_path,transaction_hash,tool_response_json,tool_response_hash FROM oid_run_task_action_receipt`;
          });
          const repeated = await loadAdmittedActionRows(tx, actionTarget);
          assert.deepEqual(repeated, first);
          assert.equal((await validateAdmittedActionCensus({ ...censusInput, rows: repeated })).entries[0]!.receiptRevision, 1);
        });
        await db.transaction(async tx => {
          await tx.execute(sql`SET TRANSACTION READ ONLY`);
          const latest = await loadAdmittedActionRows(tx, actionTarget);
          assert.equal(latest[0]!.receipt_revision, 2);
          assert.equal(latest[0]!.history_revision, 2);
          await assert.rejects(validateAdmittedActionCensus({ ...censusInput, rows: latest }), /action_evidence_unavailable/);
        });
        await owner`DELETE FROM oid_run_task_action_reconciliation WHERE action_id=${actionId} AND revision=2`;
        await owner`UPDATE oid_run_task_action_receipt SET receipt_revision=1,receipt_status='observed' WHERE action_id=${actionId}`;
      });

      await t.test('stored-response tamper and missing reconciliation remain visible and cannot be graded', async () => {
        await owner`UPDATE oid_run_task_action_receipt SET tool_response_json='{"forged":true}'::jsonb WHERE action_id=${actionId}`;
        await db.transaction(async tx => {
          const rows = await loadAdmittedActionRows(tx, actionTarget);
          await assert.rejects(validateAdmittedActionCensus({ ...censusInput, rows }), /action_evidence_unavailable/);
        });
        await owner`UPDATE oid_run_task_action_receipt SET tool_response_json=${JSON.stringify(response)}::jsonb WHERE action_id=${actionId}`;
        await owner`DELETE FROM oid_run_task_action_reconciliation WHERE action_id=${actionId}`;
        await db.transaction(async tx => {
          const rows = await loadAdmittedActionRows(tx, actionTarget);
          assert.equal(rows.length, 1); assert.equal(rows[0]!.history_revision, null);
          await assert.rejects(validateAdmittedActionCensus({ ...censusInput, rows }), /action_evidence_unavailable/);
        });
      });

      await t.test('missing receipt is retained and actual overflow remains bounded to 257 rows', async () => {
        await owner`DELETE FROM oid_run_task_action_receipt WHERE action_id=${actionId}`;
        await db.transaction(async tx => {
          const rows = await loadAdmittedActionRows(tx, actionTarget);
          assert.equal(rows.length, 1); assert.equal(rows[0]!.receipt_revision, null);
          await assert.rejects(validateAdmittedActionCensus({ ...censusInput, rows }), /action_evidence_unavailable/);
        });
        await owner`INSERT INTO oid_run_task_action SELECT gen_random_uuid(),run_id,task_index,owner_id,agent_id,
          task_id,environment_id,g.n,'synthetic_extra_'||g.n,payload_hash,action_kind,command_json
          FROM oid_run_task_action CROSS JOIN generate_series(2,258) AS g(n) WHERE id=${actionId}`;
        await db.transaction(async tx => {
          const rows = await loadAdmittedActionRows(tx, actionTarget);
          assert.equal(rows.length, 257);
          assert.equal(rows[256]!.action_sequence, '257');
          await assert.rejects(validateAdmittedActionCensus({ ...censusInput, rows }), /owner_cutoff_mismatch/);
        });
      });
    } finally {
      await owner.end({ timeout: 5 });
      if (created) {
        assert.match(name, /^oid_census_[a-f0-9]{32}$/);
        assert.notEqual(name, sourceUrl.pathname.slice(1));
        await admin.unsafe('DROP DATABASE ' + name + ' WITH (FORCE)');
      }
      await admin.end({ timeout: 5 });
    }
  });
