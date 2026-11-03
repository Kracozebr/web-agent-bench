import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import test from 'node:test';
import { makeAdmittedActionsCaptureFixture } from './task-admitted-actions-capture-packet.fixture.js';
import { composeAdmittedActionObservationCandidates, projectAdmittedActionFamilyCandidates } from './task-admitted-actions-capture-packet.js';
import { canonicalTaskJson, sha256CanonicalTaskJson, type EvidenceReference, type TaskReleaseQuerySource } from './task-release.js';
import { TaskSealedEvidenceSource } from './task-sealed-evidence-source.js';

// Real retained bytes + a synthetic owner-row adapter test sealed replay, not physical chain/native execution.
async function fixture(rejectedSwap=false) {
  const root = await mkdtemp(resolve(tmpdir(), 'admitted-sealed-'));
  const f = await makeAdmittedActionsCaptureFixture({rejectedSwap});
  const binding = f.packet.binding, execution = f.packet.execution, closure = f.packet.closure;
  const initialProjection = { balances: f.taskCase.initialState.balances, allowances: f.taskCase.initialState.allowances,
    deliveredComponentIds: f.taskCase.initialState.deliveredComponentIds, fulfilledObligationIds: f.taskCase.initialState.fulfilledObligationIds };
  const stateHash = sha256CanonicalTaskJson(initialProjection);
  f.taskCase.initialState.stateSha256 = stateHash;
  execution.initialStateSha256 = stateHash;
  f.census.execution.initialStateSha256 = stateHash;
  const claimId = '20000000-0000-4000-8000-000000000099', createdAt = '2026-11-02T12:00:00.000Z';
  const publicPinsSha256 = sha256CanonicalTaskJson({ preparationId: execution.preparationId, runId: binding.runId, taskIndex: 0,
    claimId, leaseId: execution.leaseId, environmentId: binding.environmentId, releaseIdentity: binding.releaseIdentity,
    manifestHash: binding.manifestHash, taskId: binding.taskId, caseId: binding.caseId, caseHash: binding.caseHash,
    initialStateSha256: stateHash, executionIdentityHash: execution.executionIdentityHash,
    environmentManifestSha256: execution.environmentManifestHash, applicationSourceHash: execution.applicationSourceHash, createdAt });
  const retained = new Map<string, Buffer>();
  async function write(path: string, value: unknown, raw = false): Promise<EvidenceReference> {
    const bytes = raw ? Buffer.from(value as Uint8Array) : Buffer.from(canonicalTaskJson(value));
    const absolute = resolve(root, ...path.split('/'));
    await mkdir(dirname(absolute), { recursive: true }); await writeFile(absolute, bytes);
    retained.set(path, bytes);
    return { path, sha256: createHash('sha256').update(bytes).digest('hex'), boundary: 'actual_tool_http_x402_local_evm_application_store' };
  }
  const base = { schemaVersion: 'owner-bef-task-preparation-evidence/v1', preparationId: execution.preparationId,
    environmentId: binding.environmentId, publicPinsSha256 };
  const fixtureDoc = { ...base, kind: 'fixture', evidence: {
    environmentHealth: { boundary: 'benchmark-environment-api', environmentId: binding.environmentId,
      environmentManifestSha256: execution.environmentManifestHash, applicationSourceSha256: execution.applicationSourceHash },
    publicStatus: { schemaVersion: 'bef-preparation-status/v1', envId: binding.environmentId,
      preparationId: execution.preparationId, status: 'ready', generationId: execution.generationId } } };
  const baselineDoc = { ...base, kind: 'baseline', evidence: { stateSha256: stateHash, expectedStateSha256: stateHash,
    state: { sameBlock: true, blockNumber: '0x' + BigInt(f.chain.rpc.baseline.blockNumber).toString(16),
      blockHash: f.chain.rpc.baseline.blockHash, projection: initialProjection, reads: [] } } };
  const fixtureRef = await write('artifacts/runs/owner-identity-bef-task-coordinator/preparation/generic-fixture.json', fixtureDoc);
  const baselineRef = await write('artifacts/runs/owner-identity-bef-task-coordinator/preparation/generic-baseline.json', baselineDoc);
  for (const packet of [f.paid, f.chain]) {
    packet.preparation.fixtureEvidence = fixtureRef; packet.preparation.baselineEvidence = baselineRef;
  }
  await write('infrastructure/benchmark-environment/manifest.json', f.context.environmentManifest, true);
  for(const [path,bytes] of f.files)if(path.startsWith('artifacts/runs/owner-identity-bef-task-coordinator/action/'))await write(path,bytes,true);
  f.packet.children.paid.evidence = await write(f.packet.children.paid.evidence.path, f.paid);
  f.packet.children.chain.evidence = await write(f.packet.children.chain.evidence.path, f.chain);
  const projected = projectAdmittedActionFamilyCandidates(f.packet, f.options);
  f.packet.children.paid.boundary.observationCutoffSequence = projected.paid.observationCutoffSequence;
  f.packet.children.chain.boundary.observationCutoffSequence = projected.chain.observationCutoffSequence;
  const rootRef = await write(f.root.path, f.packet);
  const candidate = composeAdmittedActionObservationCandidates(f.packet, projected.paid, projected.chain, rootRef, f.options);
  const { environmentId: _environmentId, ...bundleExecution } = execution;
  const bundle = { schemaVersion: 'bts-task-observation-bundle/v1', binding, closure, execution: bundleExecution,
    cutoff: { observationSequence: candidate.observationCutoffSequence, status: 'authoritative', evidence: rootRef },
    observations: candidate.observations! };
  const row: Record<string, unknown> = {
    run_id: binding.runId, owner_id: binding.ownerId, agent_id: binding.agentId, mode: 'training', task_ids: ['S1'],
    release_identity: binding.releaseIdentity, manifest_hash: binding.manifestHash, environment_id: binding.environmentId,
    task_id: binding.taskId, task_index: 0, closure_id: closure.closureId, closure_status: 'closed',
    action_cutoff_sequence: String(closure.actionCutoffSequence), reconciled_action_sequence: String(closure.actionCutoffSequence), closure_operation_id: closure.operationId,
    closure_payload_hash: closure.payloadHash, closure_reason: closure.reason, closure_answer_json: null, closure_action_cutoff_sequence: String(closure.actionCutoffSequence),
    bundle_owner_id: binding.ownerId, bundle_agent_id: binding.agentId, bundle_closure_id: closure.closureId,
    bundle_closure_operation_id: closure.operationId, bundle_closure_payload_hash: closure.payloadHash, bundle_closure_reason: closure.reason,
    bundle_task_id: binding.taskId, bundle_release_identity: binding.releaseIdentity, bundle_manifest_hash: binding.manifestHash,
    bundle_case_id: binding.caseId, bundle_case_hash: binding.caseHash, bundle_rubric_hash: binding.rubricHash,
    bundle_environment_id: binding.environmentId, preparation_id: execution.preparationId, lease_id: execution.leaseId,
    generation_id: execution.generationId, environment_manifest_hash: execution.environmentManifestHash,
    application_source_hash: execution.applicationSourceHash, execution_identity_hash: execution.executionIdentityHash,
    initial_state_sha256: stateHash, bundle_action_cutoff_sequence: String(closure.actionCutoffSequence), bundle_reconciled_action_sequence: String(closure.actionCutoffSequence),
    observation_cutoff_sequence: candidate.observationCutoffSequence, cutoff_evidence: rootRef,
    bundle_hash: sha256CanonicalTaskJson(bundle), bundle_json: bundle,
    prepared_preparation_id: execution.preparationId, prepared_lease_id: execution.leaseId,
    prepared_environment_id: binding.environmentId, prepared_release_identity: binding.releaseIdentity,
    prepared_manifest_hash: binding.manifestHash, prepared_task_id: binding.taskId, prepared_case_id: binding.caseId,
    prepared_case_hash: binding.caseHash, prepared_initial_state_sha256: stateHash,
    prepared_environment_manifest_hash: execution.environmentManifestHash, prepared_application_source_hash: execution.applicationSourceHash,
    prepared_execution_identity_hash: execution.executionIdentityHash, prepared_claim_id: claimId, prepared_created_at: createdAt,
    lease_state: 'fenced', execution_environment_id: binding.environmentId, execution_generation_id: execution.generationId,
    execution_manifest_hash: execution.environmentManifestHash, execution_application_source_hash: execution.applicationSourceHash,
    execution_participant_id: (f.chain.bef.before.generation as Record<string, unknown>).participant_id,
    execution_payer_address: f.chain.rpc.participant,
    has_ready_generation: true,
  };
  let queries = 0;
  const tx = { async execute() { return ++queries === 1 ? [row] : f.actionRows; } };
  const release = { releaseIdentity: binding.releaseIdentity, manifestHash: binding.manifestHash, manifest: {
    releaseIdentity: binding.releaseIdentity, manifestHash: binding.manifestHash, executionIdentity: f.context.executionIdentity,
    costPolicy: { ethValuation: f.context.ethValuation }, cases: { training: [f.taskCase], ranked: [f.taskCase] } } };
  const source = new TaskSealedEvidenceSource({ evidenceRoot: root, taskReleaseSource: {
    async getValidatedReleaseRecord(_identity: string, _hash: string, selectedTx: unknown) {
      assert.equal(selectedTx, tx); return release;
    },
  } as unknown as TaskReleaseQuerySource });
  const load = () => source.load({ runId: binding.runId, taskIndex: 0, closureId: closure.closureId }, tx as never);
  return { ...f, root, retained, fixtureDoc, baselineDoc, fixtureRef, baselineRef, bundle, row, write, load,
    queryCount: () => queries };
}

test('sealed generic root independently replays actual retained children and preparation bytes through the caller transaction', async () => {
  const f = await fixture();
  try {
    const result = await f.load();
    assert.ok(result);
    assert.deepEqual(result.observations, f.bundle.observations);
    assert.ok(f.queryCount() >= 4);
    assert.equal(result.run.taskId, 'S1');
    assert.equal(result.observations!.transfers.length, 0);
  } finally { await rm(f.root, { recursive: true, force: true }); }
});

test('sealed generic root replays deterministic contract-recipient denial from retained original action/history/code, without invented effects',async()=>{
 const f=await fixture(true);try{const result=await f.load();assert.ok(result);assert.deepEqual(result.observations,f.bundle.observations);assert.equal(result.observations!.trades.length,0);assert.equal(result.observations!.expenses.length,0);}finally{await rm(f.root,{recursive:true,force:true});}
});
test('sealed deterministic denial rejects changed latest receipt/history or lost original action evidence',async()=>{
 for(const variant of ['history','tx','evidence'] as const){const f=await fixture(true);try{
  if(variant==='history')f.actionRows[0]!.history_evidence_hash='f'.repeat(64);
  if(variant==='tx'){f.actionRows[0]!.transaction_hash='0x'+'f'.repeat(64);f.actionRows[0]!.history_transaction_hash=f.actionRows[0]!.transaction_hash;}
  if(variant==='evidence')await rm(resolve(f.root,...f.actionRows[0]!.evidence_path!.split('/')));
  await assert.rejects(f.load());
 }finally{await rm(f.root,{recursive:true,force:true});}}
});

test('a rehashed database bundle cannot invent facts absent from independently reprojected family sources', async () => {
  const f = await fixture();
  try {
    f.bundle.observations.finalStates[0]!.balances[0]!.amountUnits = '123';
    f.row.bundle_hash = sha256CanonicalTaskJson(f.bundle);
    await assert.rejects(f.load(), /Sealed observations differ from independent family replay/);
  } finally { await rm(f.root, { recursive: true, force: true }); }
});

test('actual PostgreSQL timestamp text and equivalent timezone encodings reproduce canonical preparation pins', async () => {
  for (const databaseValue of ['2026-11-02 12:00:00+00', '2026-11-02 15:00:00+03', new Date('2026-11-02T12:00:00.000Z')]) {
    const f = await fixture();
    try {
      f.row.prepared_created_at = databaseValue;
      const result = await f.load();
      assert.ok(result);
      assert.deepEqual(result.observations, f.bundle.observations);
    } finally { await rm(f.root, { recursive: true, force: true }); }
  }
});

test('a changed or invalid preparation timestamp cannot be hidden by timestamp normalization', async () => {
  for (const databaseValue of ['2026-11-02 12:00:01+00', 'not-a-timestamp']) {
    const f = await fixture();
    try {
      f.row.prepared_created_at = databaseValue;
      await assert.rejects(f.load(), /Retained preparation bytes do not match their durable pins|durable preparation pins are unavailable/);
    } finally { await rm(f.root, { recursive: true, force: true }); }
  }
});

test('missing retained preparation or changed technical manifest never falls back to legacy or a known zero', async () => {
  for (const missing of ['baseline', 'manifest']) {
    const f = await fixture();
    try {
      const path = missing === 'baseline' ? f.baselineRef.path : 'infrastructure/benchmark-environment/manifest.json';
      if (missing === 'baseline') await rm(resolve(f.root, ...path.split('/')));
      else await writeFile(resolve(f.root, ...path.split('/')), '{}');
      await assert.rejects(f.load(), /Retained family evidence is unavailable|Retained family evidence does not match its hash/);
    } finally { await rm(f.root, { recursive: true, force: true }); }
  }
});
