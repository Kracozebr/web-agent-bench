import {makeRejectedSwapFamilyFixture} from './task-rejected-swap-proof.fixture.js';
import {canonicalTaskJson} from './task-release.js';
import type {BefReadOnlyPostgresPort} from './bef-observation-ports.js';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import {
  classifyBefRecoveryOperation,
  readBefRecoveryOperation,
  makeRecoveryEvidencePacket,
  recoverySourceSnapshotHash,
  selectRecoveryTransactionIdentity,
  type BetaPlatformRecoveryActionBinding,
  type BefRecoveryOperationSnapshot,
} from './beta-platform-recovery-authority.js';

const RUN_ID = '11111111-1111-4111-8111-111111111111';
const ACTION_ID = '22222222-2222-4222-8222-222222222222';
const OWNER_ID = '33333333-3333-4333-8333-333333333333';
const AGENT_ID = '44444444-4444-4444-8444-444444444444';
const GRANT_ID = '55555555-5555-4555-8555-555555555555';
const OPERATION_ID = '66666666-6666-4666-8666-666666666666';
const GENERATION_ID = '77777777-7777-4777-8777-777777777777';
const TX_HASH = `0x${'a'.repeat(64)}`;
const MANIFEST_HASH = 'b'.repeat(64);
const PAYLOAD_HASH = 'c'.repeat(64);
const REQUEST_HASH = 'd'.repeat(64);
const IDEMPOTENCY_HASH = createHash('sha256').update(`task-action-${ACTION_ID}`).digest('hex');
const RECIPIENT = '0x2222222222222222222222222222222222222222';
const COMMAND = { kind: 'transfer', amountUnits: '125', recipient: RECIPIENT, gasLimit: '21000' } as const;
const SELECTED = { kind: 'transfer', amountUnits: '125', recipient: RECIPIENT, gasLimit: '21000' };
const MEASURED_SELECTED = { kind: 'transfer', token: '0x3333333333333333333333333333333333333333',
  amountUnits: '125', recipient: RECIPIENT, gasLimit: '21000' };

function actionBinding(command: Record<string, unknown> = COMMAND): BetaPlatformRecoveryActionBinding {
  return {
    actionId: ACTION_ID, runId: RUN_ID, ownerId: OWNER_ID, agentId: AGENT_ID, taskIndex: 0, taskId: 'S1',
    accessGeneration: 4, grantId: GRANT_ID, environmentId: 'bef-test', ownerOperationId: 'task-operation-123',
    payloadHash: PAYLOAD_HASH, actionSequence: '1', actionKind: 'transfer', command, acceptedAt: '2026-10-29T00:00:00.000Z',
    runStatus: 'running', runStartedAt: '2026-10-29T00:00:00.000Z', runDeadline: '2026-10-29T00:02:00.000Z',
    receiptStatus: 'pending', receiptEvidenceHash: null, receiptEvidencePath: null, receiptTransactionHash: null,
    outboxStatus: 'delivered', preparationId: '88888888-8888-4888-8888-888888888888',
    leaseId: '99999999-9999-4999-8999-999999999999', generationId: GENERATION_ID, participantId: 'participant-1',
    manifestSha256: MANIFEST_HASH, applicationSourceSha256: 'e'.repeat(64), preparationStatus: 'ready', leaseStatus: 'leased',
  };
}

function sourceSnapshot(overrides: Partial<BefRecoveryOperationSnapshot> = {}): BefRecoveryOperationSnapshot {
  return {
    operationId: OPERATION_ID, environmentId: 'bef-test', generationId: GENERATION_ID, participantId: 'participant-1',
    idempotencyKeySha256: IDEMPOTENCY_HASH, requestSha256: REQUEST_HASH, operationKind: 'transfer',
    status: 'settled', transactionHash: TX_HASH, receiptStatus: 'success', responseSha256: null,
    generationStatus: 'active', generationManifestSha256: MANIFEST_HASH, environmentManifestSha256: MANIFEST_HASH,
    selectedActionKind: 'transfer', selectedAction: SELECTED, selectedActionEventCount: 1,
    selectedActionEventKind: 'transfer', selectedActionEventAction: SELECTED,
    selectedActionEventRequestSha256: REQUEST_HASH, selectedActionEventSha256: 'f'.repeat(64),
    selectedOutcome: 'success', selectedTransactionHash: TX_HASH,
    selectedMeasurement: {
      receipt: { transactionHash: TX_HASH, status: 'success', gasUsed: '21000', effectiveGasPrice: '7' },
      transaction: { hash: TX_HASH }, selectedAction: MEASURED_SELECTED, before: { blockNumber: '1' },
      after: { blockNumber: '2' }, effects: { payerNativeWei: '-1' }, fee: { principalUnits: '125' },
    },
    deliveryContentSha256: null, paymentTransactionHash: null, paymentReceiptStatus: null,
    ...overrides,
  };
}

test('recovery binds a selected execution to the original command and reconstructs only its safe tool response', () => {
  const classified = classifyBefRecoveryOperation(actionBinding(), sourceSnapshot());
  assert.equal(classified.status, 'observed');
  assert.equal(classified.transactionHash, TX_HASH);
  assert.equal(classified.outcome, 'success');
  assert.equal(classified.receiptStatus, 'success');
  assert.equal(classified.receiptGasUsed, '21000');
  assert.equal(classified.receiptEffectiveGasPriceWei, '7');
  assert.equal(classified.toolResponse?.operationId, OPERATION_ID);
  assert.equal(classified.toolResponse?.outcome, 'success');
  assert.deepEqual(classified.toolResponse?.selectedAction, MEASURED_SELECTED);
  assert.deepEqual(classified.toolResponse?.receipt, {
    transactionHash: TX_HASH, status: 'success', gasUsed: '21000', effectiveGasPrice: '7',
  });
});

test('recovery recognizes a source-bound reverted execution without treating it as success', () => {
  const source = sourceSnapshot({
    status: 'reverted', receiptStatus: 'reverted', selectedOutcome: 'reverted',
    selectedMeasurement: {
      receipt: { transactionHash: TX_HASH, status: 'reverted', gasUsed: '21000', effectiveGasPrice: '7' },
      transaction: { hash: TX_HASH }, selectedAction: MEASURED_SELECTED,
    },
  });
  const classified = classifyBefRecoveryOperation(actionBinding(), source);
  assert.equal(classified.status, 'observed');
  assert.equal(classified.outcome, 'reverted');
  assert.equal(classified.receiptStatus, 'reverted');
  assert.equal(classified.toolResponse?.outcome, 'reverted');
});

test('recovery leaves unknown a changed request, duplicate binding event, or selected input mismatch', () => {
  const action = actionBinding();
  assert.equal(classifyBefRecoveryOperation(action, sourceSnapshot({
    selectedActionEventRequestSha256: '9'.repeat(64),
  })).status, 'unknown');
  assert.equal(classifyBefRecoveryOperation(action, sourceSnapshot({ selectedActionEventCount: 2 })).status, 'unknown');
  assert.equal(classifyBefRecoveryOperation(action, sourceSnapshot({
    selectedAction: { ...SELECTED, amountUnits: '126' },
    selectedActionEventAction: { ...SELECTED, amountUnits: '126' },
  })).status, 'unknown');
  assert.equal(classifyBefRecoveryOperation(actionBinding({ ...COMMAND, amountUnits: '126' }), sourceSnapshot()).status, 'unknown');
});

test('recovery leaves unknown mismatched terminal receipt and measurement bindings', () => {
  const action = actionBinding();
  assert.equal(classifyBefRecoveryOperation(action, sourceSnapshot({ receiptStatus: 'reverted' })).status, 'unknown');
  assert.equal(classifyBefRecoveryOperation(action, sourceSnapshot({
    selectedMeasurement: { receipt: { transactionHash: TX_HASH, status: 'success', gasUsed: '21000', effectiveGasPrice: '7' },
      transaction: { hash: `0x${'0'.repeat(64)}` }, selectedAction: MEASURED_SELECTED },
  })).status, 'unknown');
});

test('recovery leaves unknown a missing immutable event digest or malformed source gas', () => {
  assert.equal(classifyBefRecoveryOperation(actionBinding(), sourceSnapshot({ selectedActionEventSha256: null })).status, 'unknown');
  assert.equal(classifyBefRecoveryOperation(actionBinding(), sourceSnapshot({
    selectedMeasurement: {
      receipt: { transactionHash: TX_HASH, status: 'success', gasUsed: '1e3', effectiveGasPrice: '7' },
      transaction: { hash: TX_HASH }, selectedAction: MEASURED_SELECTED,
    },
  })).status, 'unknown');
});

test('recovery snapshot binding survives a later generation fence but changes with terminal operation evidence', () => {
  const original = sourceSnapshot({ generationStatus: 'active' });
  assert.equal(recoverySourceSnapshotHash(original), recoverySourceSnapshotHash({ ...original, generationStatus: 'fenced' }));
  assert.notEqual(recoverySourceSnapshotHash(original), recoverySourceSnapshotHash({ ...original,
    selectedMeasurement: { changedAfterCommit: true } }));
});

test('unknown recovery preserves the known original hash when source hashes are absent or identical', () => {
  const action = { ...actionBinding(), receiptStatus: 'unknown' as const, receiptTransactionHash: TX_HASH };
  for (const source of [null, { transactionHash: null, selectedTransactionHash: null },
    { transactionHash: TX_HASH, selectedTransactionHash: null },
    { transactionHash: TX_HASH, selectedTransactionHash: TX_HASH },
    { transactionHash: TX_HASH.toUpperCase().replace('0X', '0x'), selectedTransactionHash: TX_HASH }]) {
    assert.deepEqual(selectRecoveryTransactionIdentity(action, source, {}), { status: 'consistent', transactionHash: TX_HASH });
  }
  const ambiguous = classifyBefRecoveryOperation(action, sourceSnapshot({ status: 'settlement_unknown',
    receiptStatus: 'unknown', selectedOutcome: 'settlement_unknown', selectedMeasurement: null }));
  assert.deepEqual(ambiguous, { status: 'unknown' }, 'retaining identity must not claim an observed effect');
  assert.deepEqual(selectRecoveryTransactionIdentity(action, sourceSnapshot(), ambiguous),
    { status: 'consistent', transactionHash: TX_HASH });
});

test('any contradictory operation, selected or classified hash fails closed instead of replacing the original', () => {
  const action = { receiptTransactionHash: TX_HASH }, other = '0x' + '9'.repeat(64);
  for (const [source, classification] of [
    [{ transactionHash: other, selectedTransactionHash: other }, {}],
    [{ transactionHash: TX_HASH, selectedTransactionHash: other }, {}],
    [{ transactionHash: TX_HASH, selectedTransactionHash: TX_HASH }, { transactionHash: other }],
    [{ transactionHash: 'not-a-hash', selectedTransactionHash: null }, {}],
  ] as const) assert.deepEqual(selectRecoveryTransactionIdentity(action, source, classification), { status: 'conflict' });
  assert.deepEqual(selectRecoveryTransactionIdentity({ receiptTransactionHash: null },
    { transactionHash: TX_HASH, selectedTransactionHash: other }, {}), { status: 'conflict' });
});

test('unclassified raw source hash cannot create a new authoritative receipt identity', () => {
  assert.deepEqual(selectRecoveryTransactionIdentity({ receiptTransactionHash: null },
    { transactionHash: TX_HASH, selectedTransactionHash: TX_HASH }, {}), { status: 'consistent' });
  assert.deepEqual(selectRecoveryTransactionIdentity({ receiptTransactionHash: null }, sourceSnapshot(),
    classifyBefRecoveryOperation(actionBinding(), sourceSnapshot())), { status: 'consistent', transactionHash: TX_HASH });
});

test('foreign source classification cannot mint transaction authority even when it exposes a valid hash', () => {
  for (const source of [sourceSnapshot({ environmentId: 'foreign-environment' }),
    sourceSnapshot({ generationId: '99999999-9999-4999-8999-999999999999' }),
    sourceSnapshot({ idempotencyKeySha256: '0'.repeat(64) }), sourceSnapshot({ status: 'identity_conflict' })]) {
    for (const original of [null, TX_HASH]) {
      const action = { ...actionBinding(), receiptStatus: 'unknown' as const, receiptTransactionHash: original };
      const classification = classifyBefRecoveryOperation(action, source);
      assert.deepEqual(classification, { status: 'unknown' });
      assert.deepEqual(selectRecoveryTransactionIdentity(action, source, classification),
        { status: 'consistent', ...(original ? { transactionHash: original } : {}) });
    }
  }
});

function rejectedGuardFixture(){
 const f=makeRejectedSwapFamilyFixture(),op=f.source.operation as Record<string,unknown>,selected=f.source.selectedExecution as Record<string,unknown>,events=f.source.selectedEvents as Array<Record<string,unknown>>;
 const action={...actionBinding(f.command),actionKind:'swap' as const,actionId:f.action.actionId,environmentId:f.guard.environmentId,generationId:f.guard.generationId,participantId:String(op.participantId),manifestSha256:f.packet.execution.environmentManifestHash};
 const bound=events[0]!.eventPayload as Record<string,unknown>;
 const source=sourceSnapshot({operationId:f.guard.operationId,environmentId:action.environmentId,generationId:action.generationId,participantId:action.participantId,
  idempotencyKeySha256:String(op.idempotencyKeySha256),requestSha256:f.guard.requestSha256,operationKind:'swap',status:'rejected',receiptStatus:'not_submitted',transactionHash:null,
  generationManifestSha256:action.manifestSha256,environmentManifestSha256:action.manifestSha256,selectedActionKind:'swap',selectedAction:selected.selectedAction,
  selectedActionEventCount:1,selectedActionEventKind:'swap',selectedActionEventAction:bound.selectedAction,selectedActionEventRequestSha256:f.guard.requestSha256,
  selectedActionEventSha256:createHash('sha256').update(canonicalTaskJson(bound)).digest('hex'),selectedOutcome:'rejected',selectedTransactionHash:null,selectedMeasurement:null,
  recipientCodeGuard:{eventCount:2,costsCount:0,paymentsCount:0,deliveriesCount:0,selectedReasonCode:'selected_recipient_must_be_eoa',selectedPrestate:null,selectedTransactionIntent:null,
   events:events.map(e=>({eventId:e.eventId,eventSequence:e.eventSequence,operationId:f.guard.operationId,environmentId:action.environmentId,generationId:action.generationId,eventKind:e.eventKind,transactionHash:e.transactionHash,eventJson:e.eventPayload}))}});
 return{f,action,source};
}
test('legacy recovery source hash is unchanged and legacy transfer rejection has no new marker',()=>{
 assert.equal(recoverySourceSnapshotHash(sourceSnapshot()),'51df02b2eb4cc2d8f22a49e287ca3859fe7f09a67206bc1653196972576b480d');
 const legacy=sourceSnapshot({status:'rejected',receiptStatus:'not_submitted',transactionHash:null,selectedOutcome:'rejected',selectedTransactionHash:null,selectedMeasurement:null});
 assert.deepEqual(classifyBefRecoveryOperation(actionBinding(),legacy),{status:'rejected_before_execution'});assert.equal(Object.hasOwn(legacy,'recipientCodeGuard'),false);
 const packet=makeRecoveryEvidencePacket(actionBinding(),{status:'rejected_before_execution',reasonCode:'platform_recovery_original_operation_terminal'});assert.equal(Object.hasOwn(packet,'rejectionProof'),false);
});
test('only actual two-event bound recipient guard yields a provisional recovery marker, with no grading or transaction authority',()=>{
 const {action,source,f}=rejectedGuardFixture(),classification=classifyBefRecoveryOperation(action,source);assert.deepEqual(classification,{status:'rejected_before_execution',rejectionProof:f.marker});assert.equal(classification.transactionHash,undefined);
 const packet=makeRecoveryEvidencePacket(action,{status:classification.status,reasonCode:'platform_recovery_original_operation_terminal',befOperationId:source.operationId,rejectionProof:classification.rejectionProof});assert.deepEqual(packet.rejectionProof,f.marker);assert.equal(packet.transactionHash,undefined);assert.equal(packet.outcome,undefined);assert.equal(packet.participantToolResponse,undefined);
 const {recipientCodeGuard,...legacy}=source;assert.deepEqual(classifyBefRecoveryOperation(action,legacy),{status:'unknown'});assert.notEqual(recoverySourceSnapshotHash(source),recoverySourceSnapshotHash(legacy));assert.equal(recoverySourceSnapshotHash(source),recoverySourceSnapshotHash({...source,generationStatus:'fenced'}));
});
test('guard metadata/code/partition contradictions and infra/legacy swap rejection never mint a marker',()=>{
 for(const mutate of [s=>{s.recipientCodeGuard!.costsCount=1;},s=>{s.recipientCodeGuard!.eventCount=3;},s=>{s.recipientCodeGuard!.paymentsCount=1;},s=>{s.recipientCodeGuard!.deliveriesCount=1;},s=>{s.recipientCodeGuard!.selectedPrestate={};},s=>{s.recipientCodeGuard!.selectedTransactionIntent={};},s=>{s.recipientCodeGuard!.selectedReasonCode='recipient_code_observation_unavailable';},s=>{(s.recipientCodeGuard!.events as Array<Record<string,unknown>>)[1]!.transactionHash=TX_HASH;},s=>{const e=s.recipientCodeGuard!.events as Array<Record<string,unknown>>;(e[1]!.eventJson as Record<string,unknown>).recipientCodeObservation={...(e[1]!.eventJson as Record<string,unknown>).recipientCodeObservation as object,code:'0x'};},s=>{const e=s.recipientCodeGuard!.events as Array<Record<string,unknown>>;e[1]!.generationId=GENERATION_ID;}] as Array<(source:BefRecoveryOperationSnapshot)=>void>){const {action,source}=rejectedGuardFixture();mutate(source);assert.deepEqual(classifyBefRecoveryOperation(action,source),{status:'unknown'});}
});
test('a known original transaction is preserved as unknown even if a source guard claims no broadcast',()=>{
 const {action,source}=rejectedGuardFixture(),original={...action,receiptStatus:'unknown' as const,receiptTransactionHash:TX_HASH};const classification=classifyBefRecoveryOperation(original,source);assert.deepEqual(classification,{status:'unknown'});assert.deepEqual(selectRecoveryTransactionIdentity(original,source,classification),{status:'consistent',transactionHash:TX_HASH});
});
test('source read adds guard fields only for actual guard preimages and keeps legacy source objects unchanged',async()=>{
 const old=sourceSnapshot(),bound={actionKind:old.selectedActionKind,selectedAction:old.selectedAction,requestSha256:old.requestSha256};
 const row={operation_id:old.operationId,env_id:old.environmentId,generation_id:old.generationId,participant_id:old.participantId,idempotency_key_sha256:old.idempotencyKeySha256,request_sha256:old.requestSha256,operation_kind:old.operationKind,status:old.status,transaction_hash:old.transactionHash,receipt_status:old.receiptStatus,response_sha256:null,generation_status:'active',generation_manifest_sha256:old.generationManifestSha256,environment_manifest_sha256:old.environmentManifestSha256,selected_action_kind:old.selectedActionKind,selected_action_json:old.selectedAction,selected_action_event_count:1,selected_action_event_kind:old.selectedActionKind,selected_action_event_action:old.selectedAction,selected_action_event_request_sha256:old.requestSha256,selected_action_event_json:bound,selected_outcome:old.selectedOutcome,selected_transaction_hash:old.selectedTransactionHash,selected_measurement_json:old.selectedMeasurement,delivery_content_sha256:null,payment_transaction_hash:null,payment_receipt_status:null,selected_reason_code:null,selected_prestate_json:{},selected_transaction_intent_json:{},guard_event_count:0,guard_events:null,guard_costs_count:1};
 const port={environmentId:old.environmentId,withRepeatableRead:async cb=>cb(async()=>[row]),readFenceProof:async()=>({generation:null,preparation:null})} as BefReadOnlyPostgresPort;
 const actual=await readBefRecoveryOperation(port,actionBinding());const expected={...old,selectedActionEventSha256:createHash('sha256').update(canonicalTaskJson(bound)).digest('hex')};assert.deepEqual(actual,expected);assert.equal(Object.hasOwn(actual!,'recipientCodeGuard'),false);assert.equal(recoverySourceSnapshotHash(actual!),recoverySourceSnapshotHash(expected));
});
