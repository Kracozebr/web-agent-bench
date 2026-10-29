import assert from 'node:assert/strict';
import test from 'node:test';
import { hasExactRecoveredOwnerLineage, recoveredActionEvidenceIsOwnerBound, recoverySourceEvidenceEnvelope, recoverySourceEvidenceForFacts,
  recoverySourceEvidenceMatchesFacts, type RecoveredOwnerLineageRow, type RecoverySourceFacts } from './bef-recovery-observation.js';

const H1 = '1'.repeat(64);
const H2 = '2'.repeat(64);
const RUN = '10000000-0000-4000-8000-000000000001';
const ACTION = '10000000-0000-4000-8000-000000000002';
const OWNER = '10000000-0000-4000-8000-000000000003';
const AGENT = '10000000-0000-4000-8000-000000000004';
const ENV = 'bef-env-a';
const OP = '10000000-0000-4000-8000-000000000005';
const TX = `0x${'a'.repeat(64)}`;

function facts(): RecoverySourceFacts {
  const selectedAction = { kind: 'transfer', amountUnits: '10', recipient: '0x0000000000000000000000000000000000000001', gasLimit: '21000' };
  return {
    operation: {
      operationId: OP, environmentId: ENV, generationId: '10000000-0000-4000-8000-000000000006',
      participantId: '10000000-0000-4000-8000-000000000007', idempotencyKeySha256: H1, requestSha256: H2,
      operationKind: 'transfer', status: 'settled', transactionHash: TX, receiptStatus: 'success', responseSha256: null,
    },
    generationManifestSha256: H1, environmentManifestSha256: H2,
    selectedExecution: { actionKind: 'transfer', selectedAction, outcome: 'success', transactionHash: TX, measurementSha256: H2 },
    selectedActionBoundEvents: [{ eventKind: 'selected_action_bound', actionKind: 'transfer', requestSha256: H2,
      selectedAction, eventJsonSha256: H1 }],
  };
}

function lineage(): RecoveredOwnerLineageRow {
  const started = new Date('2026-10-29T10:00:00.000Z');
  return {
    recovery_action_id: ACTION, recovery_run_id: RUN, recovery_owner_id: OWNER, recovery_agent_id: AGENT,
    recovery_task_index: 2, recovery_environment_id: ENV, recovery_operation_id: 'owner-op-12345678', recovery_payload_hash: H1,
    recovery_incident_evidence_hash: H2, recovery_started_at: started, recovery_deadline_at: new Date(started.getTime() + 180_000),
    recovery_clock_excluded_ms: 900, recovery_status: 'recovered', recovery_latest_evidence_hash: H1,
    recovery_observation_count: 1, recovery_observation_clock_excluded_ms: '900',
    recovery_matching_observation_at: new Date(started.getTime() + 800), recovery_observed_evidence_matches: true,
    recovery_started_event_matches: true, recovery_observed_event_matches: true,
  };
}

test('recovered source proof binds the exact operation, selected event, measurement and nullable BEF response hash', () => {
  const sourceFacts = facts();
  const proof = recoverySourceEvidenceForFacts(sourceFacts);
  assert.ok(proof);
  assert.equal(proof.sourceResponseSha256, null);
  assert.equal(recoverySourceEvidenceMatchesFacts(proof, sourceFacts), true);

  const wrongOperation = structuredClone(sourceFacts);
  wrongOperation.operation.operationId = '10000000-0000-4000-8000-000000000099';
  assert.equal(recoverySourceEvidenceMatchesFacts(proof, wrongOperation), false);
  const wrongRequest = structuredClone(sourceFacts);
  wrongRequest.selectedActionBoundEvents[0]!.requestSha256 = H1;
  assert.equal(recoverySourceEvidenceMatchesFacts(proof, wrongRequest), false);
  const wrongAction = structuredClone(sourceFacts);
  wrongAction.selectedActionBoundEvents[0]!.selectedAction = {
    ...(wrongAction.selectedExecution.selectedAction as Record<string, unknown>), amountUnits: '11',
  };
  assert.equal(recoverySourceEvidenceForFacts(wrongAction), null);
  const duplicateBoundEvent = structuredClone(sourceFacts);
  duplicateBoundEvent.selectedActionBoundEvents.push(duplicateBoundEvent.selectedActionBoundEvents[0]!);
  assert.equal(recoverySourceEvidenceForFacts(duplicateBoundEvent), null);
  const wrongMeasurement = structuredClone(sourceFacts);
  wrongMeasurement.selectedExecution.measurementSha256 = H1;
  assert.equal(recoverySourceEvidenceMatchesFacts(proof, wrongMeasurement), false);
  const wrongResponseHash = structuredClone(sourceFacts);
  wrongResponseHash.operation.responseSha256 = H1;
  assert.equal(recoverySourceEvidenceMatchesFacts(proof, wrongResponseHash), false);
});

test('source-backed action envelope has no fabricated HTTP status or wire digest', () => {
  const proof = recoverySourceEvidenceForFacts(facts());
  assert.ok(proof);
  const valid = { status: 'observed', reasonCode: 'platform_recovery_original_operation_terminal', recoverySource: proof };
  assert.equal(recoverySourceEvidenceEnvelope(valid), true);
  assert.equal(recoverySourceEvidenceEnvelope({ ...valid, httpStatus: 200 }), false);
  assert.equal(recoverySourceEvidenceEnvelope({ ...valid, rawResponseSha256: H1 }), false);
  assert.equal(recoverySourceEvidenceEnvelope({ ...valid, reasonCode: 'participant_claimed_success' }), false);
  assert.equal(recoverySourceEvidenceEnvelope({ ...valid, recoverySource: { ...proof, extra: true } }), false);
});

test('recovered owner lineage binds exact identities, evidence events, receipt and the fixed window', () => {
  const row = lineage();
  const binding = { actionId: ACTION, runId: RUN, ownerId: OWNER, agentId: AGENT, taskIndex: 2,
    environmentId: ENV, operationId: 'owner-op-12345678', payloadHash: H1, evidenceHash: H1 };
  assert.equal(hasExactRecoveredOwnerLineage(row, binding), true);
  for (const [key, value] of [
    ['recovery_action_id', '10000000-0000-4000-8000-000000000099'],
    ['recovery_run_id', '10000000-0000-4000-8000-000000000099'],
    ['recovery_owner_id', '10000000-0000-4000-8000-000000000099'],
    ['recovery_agent_id', '10000000-0000-4000-8000-000000000099'],
    ['recovery_task_index', 3], ['recovery_environment_id', 'bef-env-other'],
    ['recovery_operation_id', 'owner-op-other'], ['recovery_payload_hash', H2],
    ['recovery_latest_evidence_hash', H2], ['recovery_observed_event_matches', false],
    ['recovery_observed_evidence_matches', false], ['recovery_started_event_matches', false],
    ['recovery_status', 'unknown'], ['recovery_observation_count', undefined],
    ['recovery_observation_clock_excluded_ms', '901'],
  ] as const) {
    assert.equal(hasExactRecoveredOwnerLineage({ ...row, [key]: value }, binding), false, key);
  }
  const startedAt = row.recovery_started_at instanceof Date
    ? row.recovery_started_at.getTime() : Date.parse(String(row.recovery_started_at));
  const beforeStart = new Date(startedAt - 1);
  assert.equal(hasExactRecoveredOwnerLineage({ ...row, recovery_matching_observation_at: beforeStart }, binding), false);
  assert.equal(hasExactRecoveredOwnerLineage(row, { ...binding, evidenceHash: H2 }), false);
});

test('recovered packet is accepted only when its source proof and original owner lineage both match', () => {
  const proof = recoverySourceEvidenceForFacts(facts());
  assert.ok(proof);
  const row = lineage();
  const binding = { actionId: ACTION, runId: RUN, ownerId: OWNER, agentId: AGENT, taskIndex: 2,
    environmentId: ENV, operationId: 'owner-op-12345678', payloadHash: H1, evidenceHash: H1 };
  const packet = { status: 'observed', reasonCode: 'platform_recovery_original_operation_terminal', recoverySource: proof };
  assert.equal(recoveredActionEvidenceIsOwnerBound(packet, row, binding), true);
  assert.equal(recoveredActionEvidenceIsOwnerBound({ ...packet, httpStatus: 200 }, row, binding), false);
  assert.equal(recoveredActionEvidenceIsOwnerBound(packet, { ...row, recovery_operation_id: 'different-owner-operation' }, binding), false);
  assert.equal(recoveredActionEvidenceIsOwnerBound(packet, { ...row, recovery_status: 'unknown' }, binding), false);
});
