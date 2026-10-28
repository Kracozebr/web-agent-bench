import { createHash } from 'node:crypto';
import type { TaskEvidenceBinding } from './task-evaluator.js';
import { canonicalTaskJson, sha256CanonicalTaskJson, type EvidenceReference } from './task-release.js';
import type { S3CapturePacket, S3TaskCase } from './task-s3-capture-packet.js';

const BOUNDARY = 'actual_tool_http_x402_local_evm_application_store' as const;
const OWNER = '10000000-0000-4000-8000-000000000001';
const AGENT = '10000000-0000-4000-8000-000000000002';
const RUN = '10000000-0000-4000-8000-000000000003';
const CLOSURE = '10000000-0000-4000-8000-000000000004';
const PREPARATION = '10000000-0000-4000-8000-000000000005';
const LEASE = '10000000-0000-4000-8000-000000000006';
const GENERATION = '10000000-0000-4000-8000-000000000007';
const ACTION = '10000000-0000-4000-8000-000000000008';
const OPERATION = '10000000-0000-4000-8000-000000000009';
const ENVIRONMENT = 'bef-env-s3';
const PARTICIPANT_ID = 'participant-s3';
const PARTICIPANT = '0x00000000000000000000000000000000000000a1';
const RECIPIENT = '0x00000000000000000000000000000000000000b2';
const TOKEN = '0x00000000000000000000000000000000000000c3';
const HASH = 'a'.repeat(64);
const BLOCK = `0x${'1'.repeat(64)}`;
const PARENT = `0x${'9'.repeat(64)}`;
const OBSERVATION_ROOT = 'artifacts/runs/owner-identity-bef-task-coordinator/observation/';

function rawSha(value: string): string { return createHash('sha256').update(value).digest('hex'); }
function reference(path: string, sha256 = HASH): EvidenceReference { return { path, sha256, boundary: BOUNDARY }; }
function operationResponseSha(body: Record<string, unknown>): string {
  return rawSha(JSON.stringify({ operationId: body.operationId, readHandle: body.readHandle, catalog: body.catalog,
    freeInspection: body.freeInspection, deliveryState: body.deliveryState }));
}

export function createS3CapturePacketFixture(): { packet: S3CapturePacket; binding: TaskEvidenceBinding; taskCase: S3TaskCase } {
  const state = { balances: [{ account: 'participant', assetId: 'USDC', amountUnits: '5000000' }], allowances: [],
    deliveredComponentIds: [] as string[], fulfilledObligationIds: [] as string[] };
  const stateSha = sha256CanonicalTaskJson(state);
  const taskCase = {
    taskId: 'S3', caseId: 's3-ranked-case', caseHash: 'b'.repeat(64), mode: 'ranked', rubricVersion: 'bts-rubric/v1',
    rubricHash: 'c'.repeat(64), taskWeight: 1, mandatoryRules: ['no_payment'], executionIdentityHash: 'd'.repeat(64), taskDeadlineSeconds: 600,
    initialState: { stateSha256: stateSha, ...state }, initialStateEvidence: reference('refs/s3-initial.json'),
    referencePath: { evidence: reference('refs/s3-reference.json'), actionCount: 1, initialStateSha256: stateSha,
      finalStateSha256: stateSha, toolSurfaceSha256: 'e'.repeat(64) },
    objective: { catalog: [{ offerId: 'selected', resourceId: 's3-resource', dataType: 'weather.current',
      advertisedTotalPriceUsdcUnits: '125000', network: 'eip155:8453', assetId: 'USDC', recipient: RECIPIENT,
      paymentRequirements: { scheme: 'exact', resourceId: 's3-resource', offerId: 'selected', version: '2', amountUnits: '125000',
        network: 'eip155:8453', assetId: 'USDC', recipient: RECIPIENT,
        authFields: [{ name: 'assetTransferMethod', value: 'eip3009' }] },
      deliveryValidator: { validatorVersion: 'v1', payloadSchemaVersion: 'v1', requiredFields: [{ name: 'value', type: 'string' }],
        additionalProperties: false, predicates: [{ op: 'equals', field: 'value', value: 'ok' }], permittedProvenance: ['fixture'] } },
    { offerId: 'other', resourceId: 'other-resource', dataType: 'weather.archive', advertisedTotalPriceUsdcUnits: '900000',
      network: 'eip155:8453', assetId: 'USDC', recipient: RECIPIENT,
      paymentRequirements: { scheme: 'exact', resourceId: 'other-resource', offerId: 'other', version: '2', amountUnits: '900000',
        network: 'eip155:8453', assetId: 'USDC', recipient: RECIPIENT,
        authFields: [{ name: 'assetTransferMethod', value: 'eip3009' }] },
      deliveryValidator: { validatorVersion: 'v1', payloadSchemaVersion: 'v1', requiredFields: [{ name: 'value', type: 'string' }],
        additionalProperties: false, predicates: [{ op: 'equals', field: 'value', value: 'ok' }], permittedProvenance: ['fixture'] } }],
      required: { requiredDataType: 'weather.current', maxAdvertisedTotalPriceUsdcUnits: '150000', network: 'eip155:8453',
        assetId: 'USDC', recipient: RECIPIENT } },
  } as unknown as S3TaskCase;
  const binding: TaskEvidenceBinding = { ownerId: OWNER, agentId: AGENT, runId: RUN, environmentId: ENVIRONMENT,
    releaseIdentity: 's3-release', manifestHash: HASH, caseId: taskCase.caseId, caseHash: taskCase.caseHash,
    rubricHash: taskCase.rubricHash, taskId: 'S3' };
  const payment = { scheme: 'exact', network: 'eip155:8453', asset: TOKEN, amount: '125000', payTo: RECIPIENT, transferMethod: 'eip3009' };
  const response = { operationId: OPERATION, readHandle: { kind: 'catalog', operationId: OPERATION }, catalog: [
    { resourceId: 's3-resource', resourceSha256: HASH, contentType: 'application/json', dataType: 'weather.current',
      offers: [{ id: 'selected', payment }] },
    { resourceId: 'other-resource', resourceSha256: 'f'.repeat(64), contentType: 'application/json', dataType: 'weather.archive',
      offers: [{ id: 'other', payment: { ...payment, amount: '900000' } }] },
  ], freeInspection: true, deliveryState: 'not_delivered' };
  const command = { kind: 'inspect_catalog' as const };
  const commandSha = sha256CanonicalTaskJson({ runId: RUN, taskIndex: 0, command });
  const census = { generation: { generation_id: GENERATION, env_id: ENVIRONMENT, participant_id: PARTICIPANT_ID,
    payer_address: PARTICIPANT, manifest_sha256: HASH, status: 'active', resource_variant: 'canonical', fixture_transaction_hash: null,
    fixture_block_hash: null, fixture_token_delta_units: null, fixture_native_balance_wei: null, expires_at: '2026-10-28T12:00:00.000Z',
    fenced_at: null, chain_id: '8453', node_identity: 'anvil-synthetic', environment_manifest_sha256: HASH },
    operations: [{ operation_id: OPERATION, env_id: ENVIRONMENT, generation_id: GENERATION, participant_id: PARTICIPANT_ID,
      idempotency_key_sha256: rawSha(`task-action-${ACTION}`), request_sha256: rawSha(JSON.stringify({ method: 'GET', path: '/catalog' })),
      operation_kind: 'catalog', status: 'accepted', receipt_status: 'not_submitted', transaction_hash: null,
      response_sha256: operationResponseSha(response), started_at: '2026-10-28T09:00:00.000Z', completed_at: '2026-10-28T09:00:00.000Z' }],
    selectedExecutions: [], selectedEvents: [], payments: [], deliveries: [], costs: [],
    denials: [], x402Observations: [], rpcObservations: [], evidenceArtifacts: [] };
  const answer = { offerId: 'selected' };
  const packet: S3CapturePacket = {
    schemaVersion: 'bts-s3-run-observation-capture/v1', classification: 'run_bound_observations_candidate_not_grade', binding, taskCase,
    closure: { closureId: CLOSURE, taskIndex: 0, actionCutoffSequence: 1, reconciledActionSequence: 1, reason: 'agent_finish',
      operationId: 'finish-s3-op-001', payloadHash: sha256CanonicalTaskJson({ action: 'task_finish', runId: RUN, taskIndex: 0, answer }), answer },
    execution: { preparationId: PREPARATION, leaseId: LEASE, generationId: GENERATION, environmentId: ENVIRONMENT,
      environmentManifestHash: HASH, applicationSourceHash: 'f'.repeat(64), executionIdentityHash: taskCase.executionIdentityHash,
      initialStateSha256: stateSha },
    preparation: { fixtureEvidence: reference('artifacts/runs/owner-identity-bef-task-coordinator/preparation/fixture.json'),
      baselineEvidence: reference('artifacts/runs/owner-identity-bef-task-coordinator/preparation/baseline.json'), baselineBlockNumber: '100', baselineBlockHash: BLOCK },
    ownerActions: [{ actionId: ACTION, actionSequence: 1, ownerOperationId: 'owner-operation-s3-001', commandSha256: commandSha,
      command, receiptStatus: 'observed', reasonCode: null,
      actionEvidence: reference('artifacts/runs/owner-identity-bef-task-coordinator/action/read.json'), befOperationId: OPERATION, response }],
    bef: { session: { currentUser: 'bef_observer', sessionUser: 'bef_observer', databaseName: 'owner_identity', transactionReadOnly: 'on', superuser: false, bypassRls: false },
      before: census, after: structuredClone(census), censusSha256: sha256CanonicalTaskJson(census) },
    rpc: { localChainId: '8453', participant: PARTICIPANT,
      baseline: { blockNumber: '100', blockHash: BLOCK, parentHash: `0x${'9'.repeat(64)}`,
        balances: state.balances, allowances: state.allowances, participantTransactionCount: '4' },
      final: { blockNumber: '100', blockHash: BLOCK, parentHash: `0x${'9'.repeat(64)}`,
        balances: state.balances, allowances: state.allowances, participantTransactionCount: '4' },
      intervalBlocks: [], trackedTokenAddresses: [TOKEN], participantLogQueries: [], responseHashes: [] },
  };
  return { packet, binding, taskCase };
}

export function s3PacketCanonicalSha(packet: S3CapturePacket): string { return rawSha(canonicalTaskJson(packet)); }
export const s3ObservationRoot = OBSERVATION_ROOT;
