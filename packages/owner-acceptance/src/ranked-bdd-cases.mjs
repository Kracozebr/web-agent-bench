import assert from 'node:assert/strict';
import { constants as fsConstants } from 'node:fs';
import { createHash, randomUUID } from 'node:crypto';
import { mkdir, mkdtemp, open, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path';

const SCENARIO_ID = 'BTS-SC-009';
const TASK_IDS = Object.freeze(['S1', 'S2', 'S3', 'S4', 'M1', 'M2', 'M3', 'M4', 'H1', 'H2', 'H3', 'U1']);
const COORDINATOR_EVIDENCE_ROOT = 'artifacts/runs/owner-identity-bef-task-coordinator/';
const OBSERVATION_PREFIX = `${COORDINATOR_EVIDENCE_ROOT}observation/`;
const ACTION_PREFIX = `${COORDINATOR_EVIDENCE_ROOT}action/`;
const PREPARATION_PREFIX = `${COORDINATOR_EVIDENCE_ROOT}preparation/`;
const EVIDENCE_BOUNDARY = 'actual_tool_http_x402_local_evm_application_store';
const MAX_VIEW_FILES = 512;
const MAX_VIEW_FILE_BYTES = 8 * 1024 * 1024;
const MAX_VIEW_TOTAL_BYTES = 128 * 1024 * 1024;

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function sortedJson(value) {
  if (Array.isArray(value)) return value.map(sortedJson);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sortedJson(value[key])]));
  }
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(sortedJson(value));
}

function requireInputs(input) {
  if (!input || typeof input !== 'object' ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(input.runId ?? '') ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(input.ownerId ?? '') ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(input.agentId ?? '') ||
      typeof input.publicOrigin !== 'string' || !/^https?:\/\//.test(input.publicOrigin) ||
      typeof input.agentBearer !== 'string' || input.agentBearer.length < 16 ||
      !input.observerPool || typeof input.observerPool.connect !== 'function' ||
      !input.db || typeof input.db.transaction !== 'function' ||
      !input.taskReleaseSource || typeof input.taskReleaseSource.getValidatedReleaseRecord !== 'function' ||
      !input.evidenceSource || typeof input.evidenceSource.load !== 'function' ||
      typeof input.restartApi !== 'function' ||
      !input.ownerPage?.request || typeof input.ownerPage.request.get !== 'function') {
    const error = new Error('BTS-SC-009 integration probe dependencies are incomplete');
    error.code = 'ranked_bdd_probe_dependencies_incomplete';
    throw error;
  }
}

async function readonlySnapshot(observerPool, { runId, ownerId, agentId }) {
  const client = await observerPool.connect();
  try {
    await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    const identityResult = await client.query(`SELECT current_user AS role,current_database() AS database_name,
      current_setting('transaction_read_only') AS read_only`);
    const identity = identityResult.rows[0];
    assert.equal(identity?.role, 'oid_observer', 'snapshot must use the independent observer role');
    assert.equal(identity?.read_only, 'on', 'snapshot transaction must be read-only');

    const runResult = await client.query(`SELECT id::text,owner_id::text,agent_id::text,mode,status,task_ids,
        release_identity,benchmark_version,manifest_hash,benchmark_hash,policy_hash,quote_price_units::text,
        started_at::text,finished_at::text,terminal_reason,cancellation_reason,cancellation_requested_at::text
      FROM oid_benchmark_run WHERE id=$1`, [runId]);
    const taskResult = await client.query(`SELECT task_index,task_id,status,closure_status,closure_id::text,
        closure_operation_id,closure_payload_hash,closure_reason,action_cutoff_sequence::text,
        reconciled_action_sequence::text,finished_at::text
      FROM oid_run_task WHERE run_id=$1 ORDER BY task_index`, [runId]);
    const evaluationsResult = await client.query(`SELECT task_index,task_id,closure_id::text,case_hash,rubric_hash,input_hash,result_hash,
        result_json,result_json->>'status' AS result_status,result_json->>'outcome' AS outcome,
        result_json->'credit' AS credit,observation_evidence->'references' AS evidence_references
      FROM oid_run_task_evaluation WHERE run_id=$1 ORDER BY task_index`, [runId]);
    const bundlesResult = await client.query(`SELECT task_index,bundle_hash,action_cutoff_sequence::text,
        reconciled_action_sequence::text,observation_cutoff_sequence::text
      FROM oid_run_task_observation_bundle WHERE run_id=$1 ORDER BY task_index`, [runId]);
    const eventsResult = await client.query(`SELECT sequence::text,event_type,source,payload_hash,payload_json
      FROM oid_run_event WHERE run_id=$1 ORDER BY sequence`, [runId]);
    const actionsResult = await client.query(`SELECT a.id::text,a.task_index,a.action_sequence::text,a.operation_id,a.payload_hash
      FROM oid_run_task_action a WHERE a.run_id=$1 ORDER BY a.task_index,a.action_sequence`, [runId]);
    const closuresResult = await client.query(`SELECT id::text,task_index,operation_id,payload_hash,reason,action_cutoff_sequence::text
      FROM oid_run_task_closure WHERE run_id=$1 ORDER BY task_index`, [runId]);
    const reservationsResult = await client.query(`SELECT source_kind,bonus_grant_id::text,cash_provenance,amount_units::text,state
      FROM oid_run_reservation WHERE run_id=$1 ORDER BY source_kind,bonus_grant_id,cash_provenance`, [runId]);
    const budgetResult = await client.query(`SELECT mode,utc_day,amount_units::text,state
      FROM oid_run_budget_hold WHERE run_id=$1`, [runId]);
    const claimResult = await client.query(`SELECT claim_id::text,status,released_at::text
      FROM oid_run_dispatch_claim WHERE run_id=$1`, [runId]);
    const slotsResult = await client.query(`SELECT count(*)::int AS count FROM oid_run_execution_slot WHERE run_id=$1`, [runId]);
    const ledgerResult = await client.query(`SELECT id::text,operation_id,entry_type,source_kind,amount_units::text,
        available_delta_units::text,reserved_delta_units::text,expired_delta_units::text
      FROM oid_ledger_entry WHERE owner_id=$1 AND operation_id=ANY($2::text[]) ORDER BY operation_id,id`,
    [ownerId, [`runacc_${runId.replaceAll('-', '')}`, `rundeb_${runId.replaceAll('-', '')}`, `runrel_${runId.replaceAll('-', '')}`]]);
    const snapshotResult = await client.query(`SELECT snapshot_hash,snapshot_json,created_at::text FROM oid_ranked_run_version_snapshot WHERE run_id=$1`, [runId]);
    const handoffResult = await client.query(`SELECT handoff_hash,handoff_json,aggregate_hash,completion_event_hash,version_snapshot_hash
      FROM oid_ranked_run_handoff WHERE run_id=$1`, [runId]);
    const rankedResult = await client.query(`SELECT aggregate_hash,aggregate_json,aggregate_json->'overall' AS overall,aggregate_json->'tiers' AS tiers,
        version_snapshot_hash,created_at::text
      FROM oid_ranked_verified_result WHERE run_id=$1`, [runId]);
    const bestResult = await client.query(`SELECT benchmark_version,run_id::text,updated_at::text
      FROM oid_ranked_best_result WHERE agent_id=$1 AND run_id=$2 ORDER BY benchmark_version`, [agentId, runId]);
    const markerResult = await client.query(`SELECT owner_id::text,source_kind,source_id,source_hash,occurred_at::text
      FROM oid_agent_first_public_action WHERE agent_id=$1`, [agentId]);
    const result = {
      observer: { role: identity.role, database: identity.database_name, readOnly: identity.read_only },
      run: runResult.rows,
      tasks: taskResult.rows,
      evaluations: evaluationsResult.rows,
      observationBundles: bundlesResult.rows,
      events: eventsResult.rows,
      actions: actionsResult.rows,
      closures: closuresResult.rows,
      reservations: reservationsResult.rows,
      budgetHolds: budgetResult.rows,
      dispatchClaims: claimResult.rows,
      executionSlotCount: slotsResult.rows[0]?.count,
      rankedLedgerEntries: ledgerResult.rows,
      versionSnapshots: snapshotResult.rows,
      rankedHandoffs: handoffResult.rows,
      rankedResults: rankedResult.rows,
      bestResults: bestResult.rows,
      firstPublicActionMarkers: markerResult.rows,
    };
    await client.query('COMMIT');
    return { ...result, sha256: sha256(canonicalJson(result)) };
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

function validateCompletedRankedSnapshot(snapshot, { runId, ownerId, agentId }) {
  const run = snapshot.run[0];
  assert.equal(snapshot.run.length, 1, 'one retained run row is required');
  assert.equal(run.id, runId);
  assert.equal(run.owner_id, ownerId);
  assert.equal(run.agent_id, agentId);
  assert.equal(run.mode, 'ranked');
  assert.equal(run.status, 'completed');
  assert.equal(run.cancellation_reason, null);
  assert.equal(run.cancellation_requested_at, null);
  assert.deepEqual(run.task_ids, TASK_IDS);
  assert.equal(snapshot.tasks.length, TASK_IDS.length);
  assert.equal(snapshot.evaluations.length, TASK_IDS.length);
  assert.equal(snapshot.observationBundles.length, TASK_IDS.length);
  assert.deepEqual(snapshot.tasks.map((row) => row.task_id), TASK_IDS);
  assert.deepEqual(snapshot.evaluations.map((row) => row.task_id), TASK_IDS);
  assert.ok(snapshot.tasks.every((row, index) => row.status === (snapshot.evaluations[index].outcome === 'failed' ? 'failed' : 'completed') &&
    row.closure_status === 'closed' && row.closure_id));
  assert.ok(snapshot.evaluations.every((row) => row.result_status === 'known' && row.result_hash && row.input_hash));
  assert.ok(snapshot.evaluations.every((row) => /^[0-9a-f]{64}$/.test(row.case_hash) &&
    /^[0-9a-f]{64}$/.test(row.rubric_hash) && Array.isArray(row.evidence_references) &&
    row.evidence_references.every((ref) => ref && typeof ref.path === 'string' && /^[0-9a-f]{64}$/.test(ref.sha256))));
  assert.ok(snapshot.observationBundles.every((row, index) => row.task_index === index &&
    /^[0-9a-f]{64}$/.test(row.bundle_hash) && BigInt(row.reconciled_action_sequence) >= BigInt(row.action_cutoff_sequence) &&
    BigInt(row.observation_cutoff_sequence) >= 0n &&
    row.action_cutoff_sequence === snapshot.tasks[index].action_cutoff_sequence &&
    row.reconciled_action_sequence === snapshot.tasks[index].reconciled_action_sequence &&
    snapshot.evaluations[index].closure_id === snapshot.tasks[index].closure_id));
  assert.equal(snapshot.events.filter((row) => row.event_type === 'run.completed').length, 1);
  assert.equal(snapshot.events.filter((row) => row.event_type === 'run.ranked_eligible').length, 1);
  const completionEvent = snapshot.events.find((row) => row.event_type === 'run.completed');
  const eligibilityEvent = snapshot.events.find((row) => row.event_type === 'run.ranked_eligible');
  assert.equal(completionEvent.source, 'coordinator');
  assert.equal(eligibilityEvent.source, 'coordinator');
  assert.ok(BigInt(eligibilityEvent.sequence) > BigInt(completionEvent.sequence));
  assert.equal(snapshot.events.filter((row) => row.event_type === 'task.evaluated').length, 12);
  assert.equal(snapshot.events.filter((row) => row.event_type === 'task.terminalized').length, 11);
  assert.equal(snapshot.rankedHandoffs.length, 1);
  assert.equal(snapshot.rankedResults.length, 1);
  assert.equal(snapshot.versionSnapshots.length, 1);
  assert.equal(snapshot.rankedHandoffs[0].version_snapshot_hash, snapshot.versionSnapshots[0].snapshot_hash);
  assert.equal(snapshot.rankedHandoffs[0].aggregate_hash, snapshot.rankedResults[0].aggregate_hash);
  assert.equal(snapshot.rankedHandoffs[0].completion_event_hash, completionEvent.payload_hash);
  assert.equal(eligibilityEvent.payload_hash, snapshot.rankedHandoffs[0].handoff_hash);
  assert.equal(snapshot.bestResults.length, 1);
  assert.equal(snapshot.bestResults[0].run_id, runId);
  assert.equal(snapshot.firstPublicActionMarkers.length, 1);
  assert.equal(snapshot.dispatchClaims.length, 1);
  assert.equal(snapshot.dispatchClaims[0].status, 'released');
  assert.equal(snapshot.executionSlotCount, 0);
  assert.equal(snapshot.reservations.length, 1);
  assert.equal(snapshot.reservations[0].state, 'debited');
  assert.equal(snapshot.budgetHolds.length, 1);
  assert.equal(snapshot.budgetHolds[0].state, 'charged');
  const reserveEntries = snapshot.rankedLedgerEntries.filter((row) => row.entry_type === 'reserve');
  const debitEntries = snapshot.rankedLedgerEntries.filter((row) => row.entry_type === 'debit');
  const releaseEntries = snapshot.rankedLedgerEntries.filter((row) => row.entry_type === 'release');
  assert.equal(reserveEntries.length, 1);
  assert.equal(debitEntries.length, 1);
  assert.equal(releaseEntries.length, 0);
  assert.equal(reserveEntries[0].amount_units, run.quote_price_units);
  assert.equal(debitEntries[0].amount_units, run.quote_price_units);
  assert.equal(snapshot.budgetHolds[0].amount_units, run.quote_price_units);
  assert.equal(reserveEntries[0].source_kind, debitEntries[0].source_kind);
  assert.equal(snapshot.firstPublicActionMarkers[0].owner_id, ownerId);
  assert.equal(snapshot.firstPublicActionMarkers[0].source_kind, 'ranked_run');
  assert.equal(snapshot.firstPublicActionMarkers[0].source_id, runId);
}

function assertUnchanged(before, after, checkName) {
  assert.equal(after.sha256, before.sha256, `${checkName} must leave the retained run and billing proof unchanged`);
  return { name: checkName, status: 'verified', beforeSha256: before.sha256, afterSha256: after.sha256,
    unchanged: true, eventCount: before.events.length, taskCount: before.tasks.length,
    evaluationCount: before.evaluations.length, actionCount: before.actions.length,
    closureCount: before.closures.length, ledgerOperationCount: before.rankedLedgerEntries.length,
    debitEntryCount: before.rankedLedgerEntries.filter((row) => row.entry_type === 'debit').length,
    reservationCount: before.reservations.length, handoffCount: before.rankedHandoffs.length,
    resultCount: before.rankedResults.length, eligibilityEventCount: before.events.filter((row) => row.event_type === 'run.ranked_eligible').length };
}

function failCode(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

function exactEvidenceReference(value) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).sort().join('|') === 'boundary|path|sha256' &&
    value.boundary === EVIDENCE_BOUNDARY && typeof value.path === 'string' &&
    /^[0-9a-f]{64}$/i.test(value.sha256));
}

function safeCoordinatorPath(reference, runId, taskIndex) {
  if (!exactEvidenceReference(reference) || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(runId) ||
      !Number.isSafeInteger(taskIndex) || taskIndex < 0 || taskIndex >= TASK_IDS.length ||
      reference.path.length > 512 || reference.path.includes('\\') || reference.path.includes(':') ||
      reference.path.startsWith('/') || reference.path.split('/').some((part) => !part || part === '.' || part === '..') ||
      !reference.path.startsWith(COORDINATOR_EVIDENCE_ROOT)) {
    throw failCode('ranked_bdd_evidence_view_reference_invalid');
  }
  const suffix = reference.path.slice(COORDINATOR_EVIDENCE_ROOT.length).split('/');
  if (reference.path.startsWith(OBSERVATION_PREFIX)) {
    // Observation captures use exactly observation/<run>/<task>/<hash>.json.
    if (suffix.length !== 4 || suffix[0] !== 'observation' || suffix[1] !== runId ||
        suffix[2] !== TASK_IDS[taskIndex] || !/^[0-9a-f]{64}\.json$/i.test(suffix[3] ?? '')) {
      throw failCode('ranked_bdd_evidence_view_cross_run_reference');
    }
    return { category: 'observation', taskId: TASK_IDS[taskIndex] };
  }
  if (reference.path.startsWith(ACTION_PREFIX)) {
    if (suffix.length !== 2 || suffix[0] !== 'action' || !/^[0-9a-f-]{36}-[0-9a-f-]{36}\.json$/i.test(suffix[1])) {
      throw failCode('ranked_bdd_evidence_view_action_path_invalid');
    }
    return { category: 'action' };
  }
  if (reference.path.startsWith(PREPARATION_PREFIX)) {
    if (suffix.length !== 2 || suffix[0] !== 'preparation' || !/^[0-9a-f-]{36}-[0-9a-f-]{36}\.json$/i.test(suffix[1])) {
      throw failCode('ranked_bdd_evidence_view_preparation_path_invalid');
    }
    return { category: 'preparation' };
  }
  throw failCode('ranked_bdd_evidence_view_namespace_invalid');
}

async function readBoundedPinnedFile(root, reference, taskIndex, runId, totalState) {
  const kind = safeCoordinatorPath(reference, runId, taskIndex);
  const candidate = resolve(root, ...reference.path.split('/'));
  let actual;
  try { actual = await realpath(candidate); }
  catch { throw failCode('ranked_bdd_evidence_view_source_file_unavailable'); }
  const rel = relative(root, actual);
  if (!rel || rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel)) {
    throw failCode('ranked_bdd_evidence_view_source_path_escape');
  }
  let handle;
  try { handle = await open(actual, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0)); }
  catch { throw failCode('ranked_bdd_evidence_view_source_file_unavailable'); }
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.size <= 0 || before.size > MAX_VIEW_FILE_BYTES) {
      throw failCode('ranked_bdd_evidence_view_file_size_invalid');
    }
    totalState.bytes += before.size;
    if (totalState.bytes > MAX_VIEW_TOTAL_BYTES) throw failCode('ranked_bdd_evidence_view_total_size_invalid');
    const bytes = Buffer.alloc(before.size + 1);
    let offset = 0;
    while (offset < bytes.length) {
      const read = await handle.read(bytes, offset, bytes.length - offset, offset);
      if (read.bytesRead === 0) break;
      offset += read.bytesRead;
    }
    const after = await handle.stat();
    const resolvedAgain = await realpath(candidate).catch(() => '');
    const content = bytes.subarray(0, offset);
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size ||
        before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs || offset !== before.size || resolvedAgain !== actual) {
      throw failCode('ranked_bdd_evidence_view_source_changed');
    }
    if (sha256(content).toLowerCase() !== reference.sha256.toLowerCase()) {
      throw failCode('ranked_bdd_evidence_view_source_hash_mismatch');
    }
    if (kind.category === 'action') {
      let parsed;
      try { parsed = JSON.parse(content.toString('utf8')); } catch { throw failCode('ranked_bdd_evidence_view_action_json_invalid'); }
      if (parsed?.runId?.toLowerCase?.() !== runId || parsed?.taskIndex !== taskIndex) {
        throw failCode('ranked_bdd_evidence_view_action_binding_mismatch');
      }
    }
    return content;
  } finally { await handle.close(); }
}

function evidenceReferencesInside(value) {
  const found = [];
  const stack = [{ value, depth: 0 }];
  let visited = 0;
  while (stack.length) {
    const current = stack.pop();
    visited += 1;
    if (visited > 250_000 || current.depth > 96) throw failCode('ranked_bdd_evidence_view_json_complexity_exceeded');
    if (!current.value || typeof current.value !== 'object') continue;
    if (!Array.isArray(current.value) && exactEvidenceReference(current.value)) {
      found.push(current.value);
      continue;
    }
    const children = Array.isArray(current.value) ? current.value : Object.values(current.value);
    for (const child of children) stack.push({ value: child, depth: current.depth + 1 });
  }
  return found;
}

async function createEvidenceViewDirectory() {
  const temporaryRoot = await realpath(tmpdir());
  const viewRoot = await mkdtemp(resolve(temporaryRoot, 'bts-sc009-evidence-view-'));
  const viewReal = await realpath(viewRoot);
  const rel = relative(temporaryRoot, viewReal);
  if (!rel || rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel) || !rel.startsWith('bts-sc009-evidence-view-')) {
    await rm(viewRoot, { recursive: true, force: true });
    throw failCode('ranked_bdd_evidence_view_temp_path_invalid');
  }
  return { temporaryRoot, viewRoot: viewReal };
}

/** Copy only hash-verified coordinator evidence reachable from the real ranked task refs into a bounded temp view. */
export async function createBoundedEvidenceStoreView({ evidenceRoot, runId, evidenceReferencesByTask, omittedReference }) {
  if (typeof evidenceRoot !== 'string' || !Array.isArray(evidenceReferencesByTask) || !exactEvidenceReference(omittedReference)) {
    throw failCode('ranked_bdd_evidence_view_inputs_invalid');
  }
  const normalizedRunId = runId?.toLowerCase?.();
  const sourceRoot = await realpath(evidenceRoot).catch(() => { throw failCode('ranked_bdd_evidence_view_source_root_unavailable'); });
  const queue = [];
  for (const task of evidenceReferencesByTask) {
    if (!task || !Array.isArray(task.references)) throw failCode('ranked_bdd_evidence_view_reference_inventory_invalid');
    for (const reference of task.references) {
      safeCoordinatorPath(reference, normalizedRunId, task.taskIndex);
      queue.push({ reference, taskIndex: task.taskIndex });
    }
  }
  const files = new Map();
  const totalState = { bytes: 0 };
  for (let index = 0; index < queue.length; index += 1) {
    const item = queue[index];
    const prior = files.get(item.reference.path);
    if (prior) {
      if (prior.reference.sha256.toLowerCase() !== item.reference.sha256.toLowerCase()) {
        throw failCode('ranked_bdd_evidence_view_hash_conflict');
      }
      continue;
    }
    if (files.size >= MAX_VIEW_FILES) throw failCode('ranked_bdd_evidence_view_file_count_exceeded');
    const bytes = await readBoundedPinnedFile(sourceRoot, item.reference, item.taskIndex, normalizedRunId, totalState);
    files.set(item.reference.path, { reference: structuredClone(item.reference), taskIndex: item.taskIndex, bytes });
    try {
      const parsed = JSON.parse(bytes.toString('utf8'));
      for (const childReference of evidenceReferencesInside(parsed)) {
        safeCoordinatorPath(childReference, normalizedRunId, item.taskIndex);
        queue.push({ reference: childReference, taskIndex: item.taskIndex });
      }
    } catch (error) {
      if (error?.code?.startsWith?.('ranked_bdd_evidence_view_')) throw error;
      // Every non-JSON payload is copied only if explicitly referenced; the sealed reader remains authoritative.
    }
  }
  const omitted = files.get(omittedReference.path);
  const omittedKind = safeCoordinatorPath(omittedReference, normalizedRunId, 11);
  if (!omitted || omitted.reference.sha256.toLowerCase() !== omittedReference.sha256.toLowerCase() ||
      omitted.taskIndex !== 11 || omittedKind.category !== 'observation' || !omittedReference.path.includes('/U1/')) {
    throw failCode('ranked_bdd_evidence_view_omitted_capture_not_reachable_u1');
  }

  const { temporaryRoot, viewRoot } = await createEvidenceViewDirectory();
  let restored = false;
  const writeViewFile = async (path, bytes) => {
    const destination = resolve(viewRoot, ...path.split('/'));
    const rel = relative(viewRoot, destination);
    if (isAbsolute(rel) || rel === '..' || rel.startsWith(`..${sep}`)) throw failCode('ranked_bdd_evidence_view_output_path_escape');
    await mkdir(dirname(destination), { recursive: true, mode: 0o700 });
    await writeFile(destination, bytes, { flag: 'wx', mode: 0o600 });
  };
  try {
    for (const [path, entry] of files) {
      if (path === omittedReference.path) continue;
      await writeViewFile(path, entry.bytes);
    }
  } catch (error) {
    await rm(viewRoot, { recursive: true, force: true }).catch(() => undefined);
    if (error?.code?.startsWith?.('ranked_bdd_evidence_view_')) throw error;
    throw failCode('ranked_bdd_evidence_view_write_failed');
  }
  const indexRows = [...files.entries()].map(([path, entry]) => ({ path, sha256: entry.reference.sha256.toLowerCase(), byteLength: entry.bytes.length }))
    .sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0);
  return {
    viewRoot,
    summary: { fileCount: files.size, bytes: totalState.bytes, inventorySha256: sha256(canonicalJson(indexRows)),
      omitted: { path: omittedReference.path, sha256: omittedReference.sha256.toLowerCase(), byteLength: omitted.bytes.length } },
    async restoreOmitted() {
      if (restored) throw failCode('ranked_bdd_evidence_view_omitted_already_restored');
      await writeViewFile(omittedReference.path, omitted.bytes);
      const actual = await readFile(resolve(viewRoot, ...omittedReference.path.split('/')));
      if (!actual.equals(omitted.bytes) || sha256(actual).toLowerCase() !== omittedReference.sha256.toLowerCase()) {
        throw failCode('ranked_bdd_evidence_view_restore_mismatch');
      }
      restored = true;
      return { sha256: sha256(actual), byteLength: actual.length };
    },
    async verifyOriginalOmitted() {
      const actual = await readBoundedPinnedFile(sourceRoot, omittedReference, 11, normalizedRunId, { bytes: 0 });
      return actual.equals(omitted.bytes);
    },
    async dispose() {
      const rel = relative(temporaryRoot, viewRoot);
      if (!rel || rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel) || !rel.startsWith('bts-sc009-evidence-view-')) {
        throw failCode('ranked_bdd_evidence_view_cleanup_path_invalid');
      }
      await rm(viewRoot, { recursive: true, force: true });
    },
  };
}

async function forgedAgentFinish({ publicOrigin, runId, taskIndex, agentBearer, fetchImpl }) {
  const body = {
    operationId: randomUUID(),
    score: { numerator: '1', denominator: '1' },
    credit: { numerator: '1', denominator: '1' },
    outcome: 'passed',
    result: { taskId: TASK_IDS[taskIndex], status: 'known', outcome: 'passed' },
    resultHash: '0'.repeat(64),
  };
  const bodyBytes = JSON.stringify(body);
  const response = await fetchImpl(new URL(`/api/agent/runs/${runId}/tasks/${taskIndex}/finish`, publicOrigin), {
    method: 'POST',
    redirect: 'manual',
    headers: { authorization: `Bearer ${agentBearer}`, 'content-type': 'application/json', accept: 'application/json' },
    body: bodyBytes,
  });
  const responseText = await response.text();
  let errorCode = null;
  try {
    const payload = JSON.parse(responseText);
    const candidate = payload?.error?.code;
    if (typeof candidate === 'string' && /^[A-Z0-9_]{1,96}$/.test(candidate)) errorCode = candidate;
  } catch { /* Response bytes are represented only by their digest below. */ }
  assert.equal(response.status, 400, 'agent-supplied grade fields must be rejected by the real strict finish endpoint');
  assert.equal(errorCode, 'INVALID_REQUEST');
  return { method: 'POST', path: `/api/agent/runs/${runId}/tasks/${taskIndex}/finish`, httpStatus: response.status,
    errorCode, rejectedFields: ['score', 'credit', 'outcome', 'result', 'resultHash'], requestSha256: sha256(bodyBytes),
    responseSha256: sha256(responseText), actionOrGradeAccepted: false };
}

async function readOwnerResults(ownerPage, runId, evaluations) {
  const response = await ownerPage.request.get(`/api/owner/runs/${runId}/results`, { timeout: 15_000 });
  const responseText = await response.text();
  assert.equal(response.status(), 200, 'owner results endpoint must remain available after service restart');
  let payload;
  try { payload = JSON.parse(responseText); } catch {
    const error = new Error('owner results endpoint returned non-JSON data');
    error.code = 'ranked_bdd_results_response_invalid';
    throw error;
  }
  assert.equal(payload.status, 'available');
  assert.ok(Array.isArray(payload.tasks));
  assert.equal(payload.tasks.length, TASK_IDS.length);
  assert.deepEqual(payload.tasks.map((row) => row.taskId), TASK_IDS);
  assert.deepEqual(payload.tasks.map(({ taskId, status, outcome, credit }) => ({ taskId, status, outcome, credit })),
    evaluations.map(({ task_id: taskId, result_status: status, outcome, credit }) => ({ taskId, status, outcome, credit })),
    'owner results projection must match all retained evaluation outcomes and exact credits');
  return { httpStatus: response.status(), status: payload.status,
    tasks: payload.tasks.map(({ taskId, status, outcome, credit }) => ({ taskId, status, outcome, credit })),
    responseSha256: sha256(responseText) };
}

function safeEvidenceError(error) {
  const code = typeof error?.code === 'string' ? error.code : typeof error?.message === 'string' ? error.message : '';
  return /^[A-Z][A-Z0-9_]{1,95}$/.test(code) ? code : 'RANKED_EVIDENCE_PROBE_FAILED';
}

async function runUnknownEvidenceReconstructionProbe(input, target, completedSnapshot, persistedFinishedAt) {
  const evidenceRoot = input.evidenceRoot ?? input.evidenceSource?.deps?.evidenceRoot;
  if (typeof evidenceRoot !== 'string' || !evidenceRoot) {
    return { status: 'not_run', reasonCode: 'ranked_evidence_root_not_supplied', faultClassification: 'missing_original_raw_evidence_in_temp_view' };
  }
  const evidenceReferencesByTask = completedSnapshot.evaluations.map((evaluation) => ({
    taskIndex: evaluation.task_index,
    references: evaluation.evidence_references,
  }));
  const u1References = evidenceReferencesByTask.find((entry) => entry.taskIndex === 11)?.references;
  const omittedReference = Array.isArray(u1References) ? u1References[0] : null;
  if (!exactEvidenceReference(omittedReference) || !omittedReference.path.startsWith(`${OBSERVATION_PREFIX}${target.runId}/U1/`)) {
    return { status: 'not_run', reasonCode: 'ranked_u1_capture_reference_not_identified', faultClassification: 'missing_original_raw_evidence_in_temp_view' };
  }

  let view;
  try {
    view = await createBoundedEvidenceStoreView({ evidenceRoot, runId: target.runId, evidenceReferencesByTask, omittedReference });
  } catch (error) {
    return { status: 'not_run', reasonCode: safeEvidenceError(error), faultClassification: 'missing_original_raw_evidence_in_temp_view' };
  }

  let output;
  let cleanupErrorCode = null;
  try {
    const { TaskSealedEvidenceSource } = await import('../../owner-identity/dist/task-sealed-evidence-source.js');
    const { completeKnownRankedRun } = await import('../../owner-identity/dist/task-run-completion.js');
    const isolatedEvidenceSource = new TaskSealedEvidenceSource({ taskReleaseSource: input.taskReleaseSource, evidenceRoot: view.viewRoot,
      maxEvidenceFileBytes: MAX_VIEW_FILE_BYTES, maxEvidenceTotalBytes: 32 * 1024 * 1024 });
    const deps = { db: input.db, taskReleaseSource: input.taskReleaseSource, evidenceSource: isolatedEvidenceSource };
    const before = await readonlySnapshot(input.observerPool, target);
    let deniedError = null;
    try {
      await completeKnownRankedRun(deps, { runId: target.runId });
    } catch (error) {
      deniedError = { code: safeEvidenceError(error), status: Number.isInteger(error?.status) ? error.status : null };
    }
    const afterDenial = await readonlySnapshot(input.observerPool, target);
    const denialUnchanged = before.sha256 === afterDenial.sha256;
    const denialExpected = deniedError?.code === 'TASK_EVIDENCE_FILE_UNAVAILABLE' && deniedError.status === 503;

    let restored = null;
    let recoveryResult = null;
    let recoveryError = null;
    try {
      restored = await view.restoreOmitted();
      recoveryResult = await completeKnownRankedRun(deps, { runId: target.runId });
    } catch (error) {
      recoveryError = safeEvidenceError(error);
    }
    const afterRecovery = await readonlySnapshot(input.observerPool, target);
    const recoveryUnchanged = before.sha256 === afterRecovery.sha256;
    const recoveryReplayed = recoveryResult?.runId === target.runId && recoveryResult.status === 'completed' &&
      recoveryResult.finishedAt === persistedFinishedAt && recoveryResult.replayed === true;
    const originalOmittedFileIntact = await view.verifyOriginalOmitted().catch(() => false);
    const verified = denialExpected && denialUnchanged && recoveryReplayed && recoveryUnchanged && originalOmittedFileIntact;
    output = {
      status: verified ? 'verified' : 'failed',
      faultClassification: 'one_hash_verified_original_u1_capture_omitted_only_from_temporary_evidence_view',
      limitation: 'This proves unavailable raw evidence blocks replay; it does not create or claim a separately persisted unknown task grade.',
      omittedReference: { path: view.summary.omitted.path, sha256: view.summary.omitted.sha256, byteLength: view.summary.omitted.byteLength },
      temporaryView: { fileCount: view.summary.fileCount, copiedAndOmittedBytes: view.summary.bytes,
        reachableInventorySha256: view.summary.inventorySha256, restoredHash: restored?.sha256 ?? null,
        restoredByteLength: restored?.byteLength ?? null, originalOmittedFileIntact },
      rejection: { errorCode: deniedError?.code ?? null, httpStatus: deniedError?.status ?? null,
        expectedErrorCode: 'TASK_EVIDENCE_FILE_UNAVAILABLE', databaseUnchanged: denialUnchanged,
        beforeSha256: before.sha256, afterSha256: afterDenial.sha256 },
      recovery: { replayed: recoveryReplayed, errorCode: recoveryError,
        databaseUnchanged: recoveryUnchanged, beforeSha256: before.sha256, afterSha256: afterRecovery.sha256 },
      databaseSnapshots: { before, afterDenial, afterRecovery },
    };
  } catch (error) {
    output = { status: 'failed', faultClassification: 'one_hash_verified_original_u1_capture_omitted_only_from_temporary_evidence_view',
      reasonCode: safeEvidenceError(error) };
  } finally {
    await view.dispose().catch((error) => { cleanupErrorCode = safeEvidenceError(error); });
  }
  if (cleanupErrorCode) return { ...output, status: 'failed', cleanupErrorCode };
  return output;
}

/**
 * BTS-SC-009 live integration probe. The passed DB/source objects must come from the already
 * admitted real ranked run; this function does not create runs, seed outcomes, or invoke task actions.
 * The one deliberate mutation-shaped request is a strict-schema forged grade, expected to be rejected.
 */
export async function runRankedBddCases(input) {
  requireInputs(input);
  const fetchImpl = input.fetchImpl ?? globalThis.fetch;
  if (typeof fetchImpl !== 'function') throw new TypeError('fetch is required for the public agent endpoint probe');
  const target = { runId: input.runId.toLowerCase(), ownerId: input.ownerId.toLowerCase(), agentId: input.agentId.toLowerCase() };
  const checks = [];
  const before = await readonlySnapshot(input.observerPool, target);
  validateCompletedRankedSnapshot(before, target);

  const retainedRelease = await input.taskReleaseSource.getValidatedReleaseRecord(
    before.run[0].release_identity, before.run[0].manifest_hash);
  assert.equal(retainedRelease?.manifest?.manifestHash, before.run[0].manifest_hash,
    'the exact admitted release manifest must be available for independent BDD derivation');

  const { completeKnownRankedRun } = await import('../../owner-identity/dist/task-run-completion.js');
  const completionDependencies = { db: input.db, taskReleaseSource: input.taskReleaseSource, evidenceSource: input.evidenceSource };
  const persistedFinishedAt = new Date(before.run[0].finished_at).toISOString();
  const replayBeforeRestart = await completeKnownRankedRun(completionDependencies, { runId: target.runId });
  assert.deepEqual(replayBeforeRestart, { runId: target.runId, status: 'completed', finishedAt: persistedFinishedAt, replayed: true });
  const afterReplay = await readonlySnapshot(input.observerPool, target);
  checks.push(assertUnchanged(before, afterReplay, 'completed_ranked_run_replay'));

  const unknownOutcomeProbe = await runUnknownEvidenceReconstructionProbe(input, target, before, persistedFinishedAt);
  checks.push({ name: 'unknown_or_unavailable_evidence_reconstruction_denied', ...unknownOutcomeProbe });

  const forgedFinish = await forgedAgentFinish({ publicOrigin: input.publicOrigin, runId: target.runId,
    taskIndex: TASK_IDS.length - 1, agentBearer: input.agentBearer, fetchImpl });
  const afterForgery = await readonlySnapshot(input.observerPool, target);
  checks.push({ name: 'agent_forged_score_denied', status: 'verified', ...forgedFinish,
    database: assertUnchanged(before, afterForgery, 'forged_agent_finish') });

  await input.restartApi();
  const health = await fetchImpl(new URL('/healthz', input.publicOrigin), { method: 'GET', redirect: 'manual' });
  assert.equal(health.ok, true, 'restarted owner API must become healthy');
  const replayAfterRestart = await completeKnownRankedRun(completionDependencies, { runId: target.runId });
  assert.deepEqual(replayAfterRestart, { runId: target.runId, status: 'completed', finishedAt: persistedFinishedAt, replayed: true });
  const ownerResults = await readOwnerResults(input.ownerPage, target.runId, before.evaluations);
  const afterRestart = await readonlySnapshot(input.observerPool, target);
  checks.push({ name: 'ranked_completion_replay_after_api_restart', status: 'verified',
    replayed: replayAfterRestart.replayed, healthStatus: health.status, ownerResults,
    database: assertUnchanged(before, afterRestart, 'completed_run_restart_replay') });

  return {
    schemaVersion: 'bts-sc-009-ranked-integration-probe/v1',
    scenarioId: SCENARIO_ID,
    status: 'blocked',
    blockedReasonCode: 'persisted_unknown_outcome_variant_uncovered',
    coveredVariants: ['completed_run_replay', 'completed_run_replay_after_api_restart', 'forged_agent_grade_rejected',
      ...(unknownOutcomeProbe.status === 'verified' ? ['unavailable_original_evidence_blocks_ranked_replay'] : [])],
    unverifiedVariants: ['distinct_persisted_unknown_task_outcome_without_a_new_ranked_run'],
    unknownOutcomeGap: { status: unknownOutcomeProbe.status,
      testedBoundary: unknownOutcomeProbe.faultClassification ?? null,
      limitation: unknownOutcomeProbe.limitation ?? 'A separate persisted unknown task result was not created or tested; no evaluation or result row was synthesized.' },
    run: { runId: target.runId, ownerId: target.ownerId, agentId: target.agentId, mode: 'ranked',
      finishedAt: before.run[0].finished_at, benchmarkVersion: before.run[0].benchmark_version,
      manifestHash: before.run[0].manifest_hash, taskIds: before.run[0].task_ids,
      outcomes: before.evaluations.map(({ task_index: taskIndex, task_id: taskId, result_status, outcome, credit }) =>
        ({ taskIndex, taskId, status: result_status, outcome, credit })),
      taskEvidence: before.evaluations.map((evaluation, index) => ({ taskIndex: evaluation.task_index,
        taskId: evaluation.task_id, caseHash: evaluation.case_hash, rubricHash: evaluation.rubric_hash,
        inputHash: evaluation.input_hash, resultHash: evaluation.result_hash,
        bundleHash: before.observationBundles[index].bundle_hash,
        actionCutoffSequence: before.observationBundles[index].action_cutoff_sequence,
        reconciledActionSequence: before.observationBundles[index].reconciled_action_sequence,
        observationCutoffSequence: before.observationBundles[index].observation_cutoff_sequence,
        rawPathsHashes: evaluation.evidence_references })),
      immutableCounts: { events: before.events.length, tasks: before.tasks.length, evaluations: before.evaluations.length,
        actions: before.actions.length, closures: before.closures.length, observationBundles: before.observationBundles.length,
        ledgerRows: before.rankedLedgerEntries.length,
        reservations: before.reservations.length, handoffs: before.rankedHandoffs.length, results: before.rankedResults.length } },
    rankedOutcome: { aggregateHash: before.rankedResults[0].aggregate_hash,
      exactOverall: before.rankedResults[0].overall, exactTiers: before.rankedResults[0].tiers,
      handoffHash: before.rankedHandoffs[0].handoff_hash, versionSnapshotHash: before.versionSnapshots[0].snapshot_hash,
      bestRunId: before.bestResults[0].run_id },
    release: { manifest: structuredClone(retainedRelease.manifest) },
    // These are the actual read-only query projections used by the probe.
    // Keeping them lets Python recompute hashes and state equality instead of
    // treating the probe's check labels or row counts as proof.
    databaseSnapshots: {
      before,
      afterCompletedRunReplay: afterReplay,
      ...(unknownOutcomeProbe.databaseSnapshots ?? {}),
      afterForgedGrade: afterForgery,
      afterRestartReplay: afterRestart,
    },
    beforeSha256: before.sha256,
    checks,
    boundary: 'local_ranked_run_database_and_authenticated_http; no participant actions or new charges',
  };
}
