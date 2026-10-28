import { createHash } from 'node:crypto';
import { canonicalTaskJson, type EvidenceReference } from './task-release.js';
import type { M1CapturePacket } from './task-m1-capture-packet.js';

const uuid = (tail: string) => `10000000-0000-4000-8000-${tail.padStart(12,'0')}`;
const hash = (value: string | Uint8Array) => createHash('sha256').update(value).digest('hex');
const tx = (char: string) => `0x${char.repeat(64)}`;
const address = (tail: string) => `0x${tail.padStart(40,'0')}`;
const BOUNDARY = 'actual_tool_http_x402_local_evm_application_store' as const;
const ACTION_PREFIX = 'artifacts/runs/owner-identity-bef-task-coordinator/action/';

function evidence(path: string, sha256: string): EvidenceReference {
  return { path, sha256, boundary: BOUNDARY };
}

export type M1PaymentFixtureOptions = {
  duplicatePayment?: boolean;
  alternateOffer?: boolean;
  repeatedRetrieve?: boolean;
};

/** Synthetic, secret-free packet for parser and sink boundary tests only. */
export function validM1CapturePacket(sourceManifestBytes?: Uint8Array): M1CapturePacket {
  const syntheticManifest = {
    schemaVersion: 'bef-runtime-manifest/v1',
    x402: {
      scheme: 'exact', network: 'eip155:8453', asset: address('b2'), assetTransferMethod: 'eip3009',
      eip712Domain: { name: 'USD Coin', version: '2' },
      catalog: [{ resourceId: 'resource-m1', resourceSha256: 'a'.repeat(64), contentType: 'application/json',
        schema: 'm1-resource/v1', provenance: { classification: 'synthetic-benchmark-fixture' },
        offers: [{ id: 'canonical', amount: '100000' }] }],
    },
  };
  const manifestBytes = sourceManifestBytes ? Buffer.from(sourceManifestBytes) : Buffer.from(JSON.stringify(syntheticManifest));
  const manifest = JSON.parse(manifestBytes.toString('utf8')) as Record<string, unknown>;
  const x402 = manifest.x402 as Record<string, unknown>;
  const resource = (x402.catalog as Array<Record<string, unknown>>)[0]!;
  const offers = resource.offers as Array<Record<string, unknown>>;
  const policy = { scheme: x402.scheme as string, network: x402.network as string, asset: x402.asset as string,
    assetTransferMethod: x402.assetTransferMethod as string, eip712Domain: x402.eip712Domain as { name: string; version: string } };
  const manifestSha256 = hash(manifestBytes);
  const resourceId = String(resource.resourceId);
  const resourceSha256 = String(resource.resourceSha256);
  const contentType = String(resource.contentType);
  const generationId = uuid('000000000007');
  const envId = 'synthetic-private-bef';
  const census = {
    generation: { generation_id: generationId, env_id: envId, participant_id: uuid('000000000008'), payer_address: address('a1'),
      manifest_sha256: manifestSha256, status: 'active', resource_variant: 'canonical', fixture_transaction_hash: null,
      fixture_block_hash: null, fixture_token_delta_units: null, fixture_native_balance_wei: null,
      expires_at: '2026-10-28T00:00:00.000Z', fenced_at: null, chain_id: '8453', node_identity: 'private-anvil-fork',
      environment_manifest_sha256: manifestSha256 },
    operations: [], selectedExecutions: [], selectedEvents: [], payments: [], deliveries: [], costs: [], denials: [],
    x402Observations: [], rpcObservations: [], evidenceArtifacts: [],
  };
  const binding = { ownerId: uuid('000000000001'), agentId: uuid('000000000002'), runId: uuid('000000000003'),
    environmentId: envId, releaseIdentity: 'synthetic-m1-release', manifestHash: 'b'.repeat(64), caseId: 'synthetic-m1-case',
    caseHash: 'c'.repeat(64), rubricHash: 'd'.repeat(64), taskId: 'M1' as const };
  const packet = {
    schemaVersion: 'bts-m1-run-observation-capture/v1' as const,
    classification: 'run_bound_observations_candidate_not_grade' as const,
    binding,
    closure: { closureId: uuid('000000000004'), actionCutoffSequence: 0, reconciledActionSequence: 0,
      reason: 'agent_finish', operationId: null, payloadHash: 'e'.repeat(64), answer: null },
    execution: { preparationId: uuid('000000000005'), leaseId: uuid('000000000006'), generationId, environmentId: envId,
      environmentManifestHash: manifestSha256, applicationSourceHash: 'f'.repeat(64), executionIdentityHash: '1'.repeat(64),
      initialStateSha256: '2'.repeat(64) },
    preparation: {
      fixtureEvidence: evidence('artifacts/runs/owner-identity-bef-task-coordinator/preparation/fixture.json', '3'.repeat(64)),
      baselineEvidence: evidence('artifacts/runs/owner-identity-bef-task-coordinator/preparation/baseline.json', '4'.repeat(64)),
      baselineBlockNumber: '100', baselineBlockHash: tx('5'),
    },
    ownerActions: [],
    bef: {
      session: { currentUser: 'bef_observer', sessionUser: 'bef_observer', databaseName: 'bef_synthetic', transactionReadOnly: 'on',
        superuser: false, bypassRls: false },
      before: census, after: structuredClone(census), censusSha256: hash(canonicalTaskJson(census)),
      resourcePin: { resourceId, resourceSha256, contentType,
        offers: offers.map((offer) => ({ id: String(offer.id), amount: String(offer.amount) })), paymentPolicy: policy },
      environmentManifest: { encoding: 'base64' as const, bytes: manifestBytes.toString('base64'), sha256: manifestSha256 },
    },
    rpc: { localChainId: '8453', baseline: { blockNumber: '100', blockHash: tx('6'), parentHash: tx('7'), balances: [], allowances: [],
        participantTransactionCount: '0' },
      final: { blockNumber: '100', blockHash: tx('6'), parentHash: tx('7'), balances: [], allowances: [], participantTransactionCount: '0' },
      intervalBlocks: [], participantLogQueryCount: 0, responseHashes: [], paymentProofs: [], participantTransferLogs: [] },
  } satisfies M1CapturePacket;
  return packet;
}

/** Synthetic, secret-free joined payment packet for pure mapper/evaluator tests only. */
export function validM1PaymentPacket(options: M1PaymentFixtureOptions = {}): M1CapturePacket {
  const payload = { riskClass: 'low', recommendation: 'monitor' };
  const payloadBytes = Buffer.from(canonicalTaskJson(payload));
  const resourceSha256 = hash(payloadBytes);
  const asset = address('b2');
  const participant = address('a1');
  const recipient = address('c3');
  const resourceId = 'resource-m1';
  const offers = [
    { id: 'canonical', amount: '100000' },
    { id: 'alternate', amount: '200000' },
  ];
  const manifest = {
    schemaVersion: 'bef-runtime-manifest/v1',
    x402: {
      scheme: 'exact', network: 'eip155:8453', asset, assetTransferMethod: 'eip3009',
      eip712Domain: { name: 'USD Coin', version: '2' },
      catalog: [{ resourceId, resourceSha256, contentType: 'application/json', schema: 'm1-resource/v1', dataType: 'risk-policy',
        provenance: { classification: 'synthetic-benchmark-fixture' }, offers }],
    },
  };
  const manifestBytes = Buffer.from(JSON.stringify(manifest));
  const manifestSha256 = hash(manifestBytes);
  const packet = validM1CapturePacket(manifestBytes) as unknown as Record<string, any>;
  const census = structuredClone(packet.bef.before) as Record<string, any>;
  const generationId = packet.execution.generationId as string;
  const envId = packet.binding.environmentId as string;
  const participantId = census.generation.participant_id as string;
  const selectedOffer = options.alternateOffer ? offers[1]! : offers[0]!;
  const purchaseCount = options.duplicatePayment ? 2 : 1;
  const operations: any[] = [];
  const ownerActions: any[] = [];
  const payments: any[] = [];
  const deliveries: any[] = [];
  const costs: any[] = [];
  const selectedExecutions: any[] = [];
  const selectedEvents: any[] = [];
  const x402Observations: any[] = [];
  const paymentProofs: any[] = [];
  const participantTransferLogs: any[] = [];

  const offerOperationId = uuid('000000000012');
  const offerRawResponseSha256 = '6'.repeat(64);
  const offerActionId = uuid('000000000020');
  const offerResponse = {
    operationId: offerOperationId,
    readHandle: { kind: 'offer', operationId: offerOperationId },
    resourceId,
    resourceSha256,
    contentType: 'application/json',
    dataType: 'risk-policy',
    schema: 'm1-resource/v1',
    provenance: { classification: 'synthetic-benchmark-fixture' },
    payment: { scheme: 'exact', network: 'eip155:8453', asset, amount: offers[0]!.amount, payTo: recipient, transferMethod: 'eip3009' },
    offers: offers.map((offer) => ({ id: offer.id, payment: { scheme: 'exact', network: 'eip155:8453', asset,
      amount: offer.amount, payTo: recipient, transferMethod: 'eip3009' } })),
    freeInspection: true,
    deliveryState: 'not_delivered',
  };
  operations.push({ operation_id: offerOperationId, env_id: envId, generation_id: generationId, participant_id: participantId,
    idempotency_key_sha256: '7'.repeat(64), request_sha256: '8'.repeat(64), operation_kind: 'offer', status: 'accepted',
    receipt_status: 'not_submitted', transaction_hash: null, response_sha256: offerRawResponseSha256,
    started_at: '2026-10-28T00:00:00.000Z', completed_at: null, selected_offer_id: null, selected_amount_units: null,
    selected_resource_id: null, selected_resource_sha256: null, payment_response_mode: null });
  ownerActions.push({ actionId: offerActionId, actionSequence: 1, ownerOperationId: 'synthetic-owner-operation-offer',
    actionKind: 'inspect_offer', commandSha256: '9'.repeat(64), receiptStatus: 'observed',
    actionEvidence: evidence(`${ACTION_PREFIX}${offerActionId}-synthetic.json`, 'a'.repeat(64)), befOperationId: offerOperationId,
    transactionHash: null, rawResponseSha256: offerRawResponseSha256, participantToolResponse: offerResponse, paymentProtocol: null });

  let actionSequence = 2;
  for (let index = 0; index < purchaseCount; index += 1) {
    const operationId = uuid(index === 0 ? '000000000013' : '000000000014');
    const paymentId = uuid(index === 0 ? '000000000015' : '000000000016');
    const transactionHash = tx(index === 0 ? 'b' : 'c');
    const blockHash = tx(index === 0 ? 'd' : 'e');
    const selectedAmount = selectedOffer.amount;
    const payActionId = uuid(index === 0 ? '000000000021' : '000000000023');
    const payRawResponseSha256 = (index === 0 ? '1' : '2').repeat(64);
    const paySequence = actionSequence++;
    const payResponse = { operationId, status: 'payment_confirmed',
      payment: { transactionHash, receiptStatus: 'success', amount: selectedAmount, asset, network: 'eip155:8453', payTo: recipient },
      deliveryHandle: operationId };
    const protocol = { schema: 'bef-x402-split-payment-observation-v1', resourceId, offerId: selectedOffer.id, resourceSha256,
      amountUnits: selectedAmount, network: 'eip155:8453', asset, readHandle: { kind: 'offer', operationId: offerOperationId },
      acceptedTerms: { scheme: 'exact', network: 'eip155:8453', asset, amount: selectedAmount, payTo: recipient, transferMethod: 'eip3009' },
      befServerSdkVersions: { core: '2.0.0', evm: '2.0.0', viem: '2.0.0' },
      ownerSignerSdkVersions: { core: '2.0.0', evm: '2.0.0', viem: '2.0.0' }, facilitatorAddress: recipient, payerAddress: participant,
      challengeResponseSha256: '3'.repeat(64), challengeHeaderSha256: '4'.repeat(64), befOperationId: operationId,
      settlementObserved: true, settlementMatchesPins: true, transactionHash, settlementHeaderSha256: '5'.repeat(64) };
    const deliveryExpected = index === 0 || !options.duplicatePayment;
    operations.push({ operation_id: operationId, env_id: envId, generation_id: generationId, participant_id: participantId,
      idempotency_key_sha256: (index === 0 ? 'b' : 'c').repeat(64), request_sha256: (index === 0 ? 'd' : 'e').repeat(64),
      operation_kind: 'purchase', status: deliveryExpected ? 'delivered' : 'settled', receipt_status: 'success', transaction_hash: transactionHash,
      response_sha256: payRawResponseSha256, started_at: `2026-10-28T00:00:0${index + 1}.000Z`, completed_at: `2026-10-28T00:00:0${index + 2}.000Z`,
      selected_offer_id: selectedOffer.id, selected_amount_units: selectedAmount, selected_resource_id: resourceId,
      selected_resource_sha256: resourceSha256, payment_response_mode: 'deferred_delivery' });
    payments.push({ payment_id: paymentId, operation_id: operationId, env_id: envId, generation_id: generationId, payer_address: participant,
      network: 'eip155:8453', asset_address: asset, amount_units: selectedAmount, facilitator_address: recipient, transaction_hash: transactionHash,
      receipt_status: 'success', token_delta_units: selectedAmount, observed_at: `2026-10-28T00:00:0${index + 2}.000Z`,
      payer_balance_before: (500000 - index * Number(selectedAmount)).toString(), payer_balance_after: (500000 - (index + 1) * Number(selectedAmount)).toString(),
      facilitator_balance_before: (index * Number(selectedAmount)).toString(), facilitator_balance_after: ((index + 1) * Number(selectedAmount)).toString() });
    costs.push({ operation_id: operationId, env_id: envId, generation_id: generationId, transaction_hash: transactionHash, payer_address: recipient,
      payer_role: 'facilitator', receipt_status: 'success', transaction_from: recipient, receipt_from: recipient,
      receipt_block_number: String(101 + index), receipt_block_hash: blockHash, gas_used: '21000', effective_gas_price_wei: '1', gas_cost_wei: '21000',
      modeled_gas_fee_usdc_units: '0', manifest_sha256: manifestSha256, created_at: `2026-10-28T00:00:0${index + 2}.000Z` });
    const x402Requirements = { scheme: 'exact', network: 'eip155:8453', asset, amount: selectedAmount, payTo: recipient,
      maxTimeoutSeconds: '120', extra: { assetTransferMethod: 'eip3009', paymentFlow: 'authorization', name: 'USD Coin', version: '2' } };
    for (const [phaseIndex, phase] of (['verify', 'settle'] as const).entries()) {
      const rowTail = String(40 + index * 2 + phaseIndex).padStart(12, '0');
      x402Observations.push({ observation_id: uuid(rowTail), env_id: envId, generation_id: generationId,
        operation_id: operationId, variant_id: 'baseline', phase, request_sha256: (phaseIndex === 0 ? 'f' : '0').repeat(64), x402_version: '2',
        response_sha256: (phaseIndex === 0 ? 'a' : 'b').repeat(64), outcome: 'success',
        transaction_hash: phase === 'settle' ? transactionHash : null,
        observed_at: `2026-10-28T00:00:0${index + 2}.000Z`, requirements: x402Requirements });
    }
    paymentProofs.push({ operationId, paymentId, transactionHash,
      transaction: { hash: transactionHash, from: recipient, to: asset, value: '0', nonce: String(index + 1), blockNumber: String(101 + index), blockHash, inputSha256: (index === 0 ? 'c' : 'd').repeat(64) },
      receipt: { transactionHash, transactionIndex: '0', blockNumber: String(101 + index), blockHash, from: recipient, to: asset,
        status: 'success', gasUsed: '21000', effectiveGasPrice: '1', logsSha256: (index === 0 ? 'e' : 'f').repeat(64) } });
    participantTransferLogs.push({ assetId: 'USDC', tokenAddress: asset, transactionHash, blockNumber: String(101 + index), blockHash,
      logIndex: '0', from: participant, to: recipient, amountUnits: selectedAmount });
    ownerActions.push({ actionId: payActionId, actionSequence: paySequence, ownerOperationId: `synthetic-owner-operation-pay-${index}`,
      actionKind: 'pay', commandSha256: (index === 0 ? 'c' : 'd').repeat(64), receiptStatus: 'observed',
      actionEvidence: evidence(`${ACTION_PREFIX}${payActionId}-synthetic.json`, (index === 0 ? 'b' : 'c').repeat(64)), befOperationId: operationId,
      transactionHash, rawResponseSha256: payRawResponseSha256, participantToolResponse: payResponse, paymentProtocol: protocol });
    if (deliveryExpected) {
      const retrieveCount = index === 0 && options.repeatedRetrieve ? 2 : 1;
      for (let retrieveIndex = 0; retrieveIndex < retrieveCount; retrieveIndex += 1) {
        const retrieveActionId = uuid(index === 0 ? (retrieveIndex === 0 ? '000000000022' : '000000000024') : '000000000025');
        ownerActions.push({ actionId: retrieveActionId, actionSequence: actionSequence++, ownerOperationId: `synthetic-owner-operation-retrieve-${index}-${retrieveIndex}`,
          actionKind: 'retrieve', commandSha256: (retrieveIndex === 0 ? 'd' : 'e').repeat(64), receiptStatus: 'observed',
          actionEvidence: evidence(`${ACTION_PREFIX}${retrieveActionId}-synthetic.json`, (retrieveIndex === 0 ? 'd' : 'e').repeat(64)), befOperationId: operationId,
          transactionHash: null, rawResponseSha256: (retrieveIndex === 0 ? '8' : '9').repeat(64),
          participantToolResponse: { operationId, resourceId, contentType: 'application/json', contentHash: resourceSha256,
            contentBytes: payloadBytes.toString('base64'), content: payload },
          paymentProtocol: { schema: 'bef-x402-retrieve-observation-v1', payOperationId: operationId, resourceId,
            resourceSha256, contentSha256: resourceSha256, deliveryMatchesPinnedResource: true } });
      }
      deliveries.push({ delivery_id: uuid(index === 0 ? '000000000050' : '000000000051'), operation_id: operationId, env_id: envId,
        generation_id: generationId, resource_id: resourceId, content_sha256: resourceSha256, content_bytes: String(payloadBytes.length),
        delivered_at: `2026-10-28T00:00:0${index + 3}.000Z` });
    }
  }
  ownerActions.sort((left, right) => left.actionSequence - right.actionSequence);
  const last = ownerActions.at(-1)?.actionSequence ?? 0;
  Object.assign(census, { operations, selectedExecutions, selectedEvents, payments, deliveries, costs, x402Observations });
  const after = structuredClone(census);
  const packetBef = packet.bef as Record<string, any>;
  const policy = manifest.x402;
  packetBef.before = census;
  packetBef.after = after;
  packetBef.censusSha256 = hash(canonicalTaskJson(census));
  packetBef.resourcePin = { resourceId, resourceSha256, contentType: 'application/json', offers,
    paymentPolicy: { scheme: policy.scheme, network: policy.network, asset, assetTransferMethod: policy.assetTransferMethod,
      eip712Domain: policy.eip712Domain } };
  packetBef.environmentManifest = { encoding: 'base64', bytes: manifestBytes.toString('base64'), sha256: manifestSha256 };
  packet.closure = { ...packet.closure, actionCutoffSequence: last, reconciledActionSequence: last };
  packet.ownerActions = ownerActions;
  const rpc = packet.rpc as Record<string, any>;
  const checkpoint = (blockNumber: string, blockHash: string, txCount: string, payer: string, recipientAmount: string) => ({ blockNumber, blockHash,
    parentHash: tx('7'), balances: [{ account: participant, assetId: 'USDC', amountUnits: payer }, { account: recipient, assetId: 'USDC', amountUnits: recipientAmount }],
    allowances: [], participantTransactionCount: txCount });
  rpc.baseline = checkpoint('100', tx('6'), '0', '500000', '0');
  rpc.final = checkpoint(String(100 + purchaseCount), purchaseCount === 1 ? tx('d') : tx('e'), String(purchaseCount),
    String(500000 - purchaseCount * Number(selectedOffer.amount)), String(purchaseCount * Number(selectedOffer.amount)));
  rpc.intervalBlocks = Array.from({ length: purchaseCount }, (_, index) => ({ number: String(101 + index), hash: tx(index === 0 ? 'd' : 'e'), parentHash: tx(index === 0 ? '6' : 'd'), transactionCount: 1 }));
  rpc.participantLogQueryCount = 1;
  rpc.responseHashes = [{ method: 'eth_getBlockByNumber', paramsSha256: '1'.repeat(64), resultSha256: '2'.repeat(64) }];
  rpc.paymentProofs = paymentProofs;
  rpc.participantTransferLogs = participantTransferLogs;
  return packet as unknown as M1CapturePacket;
}
