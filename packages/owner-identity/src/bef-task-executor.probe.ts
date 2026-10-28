/**
 * Manual local bridge probe. It never provisions or resets a BEF generation;
 * the caller must supply an already prepared, in-memory participant binding
 * and one explicitly identified admitted PostgreSQL action.
 */
import { createHash } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { sql } from 'drizzle-orm';
import { loadConfig } from './config.js';
import { createDatabase } from './db.js';
import { BefTaskExecutor, type SafeTaskActionEvidence } from './bef-task-executor.js';
import { createPostgresTaskReleaseQuerySource } from './task-store.js';
import { canonicalTaskJson } from './task-release.js';

function required(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`required_local_probe_setting_missing:${name}`);
  return value;
}

const runId = required('BEF_TASK_EXECUTOR_RUN_ID');
const taskIndexText = required('BEF_TASK_EXECUTOR_TASK_INDEX');
const envId = required('BEF_TASK_EXECUTOR_ENV_ID');
const generationId = required('BEF_TASK_EXECUTOR_GENERATION_ID');
const actionId = required('BEF_TASK_EXECUTOR_ACTION_ID');
const apiUrl = required('BEF_TASK_EXECUTOR_API_URL');
const manifestHash = required('BEF_TASK_EXECUTOR_MANIFEST_HASH');
const applicationSourceHash = required('BEF_TASK_EXECUTOR_APPLICATION_SOURCE_HASH');
const runToken = required('BEF_TASK_EXECUTOR_RUN_TOKEN');
if (!/^\d+$/.test(taskIndexText)) throw new Error('local_probe_task_index_invalid');
const taskIndex = Number(taskIndexText);
if (!Number.isSafeInteger(taskIndex) || taskIndex < 0 || taskIndex > 11) throw new Error('local_probe_task_index_invalid');
if (!/^[0-9a-f-]{36}$/i.test(runId) || !/^[0-9a-f-]{36}$/i.test(generationId) || !/^[0-9a-f-]{36}$/i.test(actionId)) {
  throw new Error('local_probe_identity_invalid');
}

const { db, client } = createDatabase(loadConfig(process.env));
try {
  const pending = await db.execute(sql`SELECT a.id,a.environment_id,o.status AS outbox_status,r.receipt_status
    FROM oid_run_task_action a JOIN oid_run_task_action_outbox o ON o.action_id=a.id
    JOIN oid_run_task_action_receipt r ON r.action_id=a.id
    WHERE a.run_id=${runId} AND a.task_index=${taskIndex} AND r.receipt_status='pending'
    ORDER BY a.action_sequence LIMIT 1`) as unknown as Array<{
      id: string; environment_id: string; outbox_status: string; receipt_status: string;
    }>;
  const candidate = pending[0];
  if (!candidate || candidate.id !== actionId || candidate.environment_id !== envId || candidate.outbox_status !== 'pending') {
    throw new Error('local_probe_expected_oldest_pending_action_mismatch');
  }

  const evidenceDirectory = resolve('artifacts/runs/bef-task-executor', runId, actionId);
  const executor = new BefTaskExecutor({
    db,
    taskReleaseSource: createPostgresTaskReleaseQuerySource(db),
    participantApiByEnvironment: { [envId]: apiUrl },
    evidenceSink: {
      async write(evidence: SafeTaskActionEvidence) {
        await mkdir(evidenceDirectory, { recursive: true });
        const bytes = Buffer.from(canonicalTaskJson(evidence), 'utf8');
        const filePath = resolve(evidenceDirectory, 'participant-tool-observation.json');
        await writeFile(filePath, bytes, { flag: 'wx', mode: 0o600 });
        return {
          path: `artifacts/runs/bef-task-executor/${runId}/${actionId}/participant-tool-observation.json`,
          sha256: createHash('sha256').update(bytes).digest('hex'),
        };
      },
    },
  });
  await executor.bindSession({
    runId, taskIndex, envId, generationId, manifestHash, applicationSourceHash, runToken,
  });
  const result = await executor.executeNext(runId, taskIndex);
  if (result.status !== 'recorded' || result.actionId !== actionId) throw new Error('local_probe_action_not_recorded');
  process.stdout.write(`${JSON.stringify({
    probe: 'bef-task-executor-local-action', status: result.status, actionId: result.actionId,
    receiptStatus: result.receiptStatus, evidenceHash: result.evidenceHash, evidencePath: result.evidencePath,
    transactionHash: result.transactionHash ?? null, befOperationId: result.befOperationId ?? null,
    classification: 'local_selected_tool_bridge_only',
  })}\n`);
} finally {
  await client.end();
}
