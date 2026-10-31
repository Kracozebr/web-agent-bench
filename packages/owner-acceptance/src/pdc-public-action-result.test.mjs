import assert from 'node:assert/strict';
import test from 'node:test';
import { publicActorResultFromMcpReceipt, s2PublicDisclosureGap, isKnownS2DisclosureGap } from './pdc-public-action-result.mjs';

test('public paid actor receives the exact observed inspection receipt and original submitted command', () => {
  const command = { kind: 'inspect_offer', resourceId: 'public-resource' };
  const receipt = { actionId: 'synthetic-action', runId: 'synthetic-run', taskIndex: 1, taskId: 'M1', actionSequence: '1',
    status: 'observed', receiptRevision: 1, evidenceHash: 'a'.repeat(64), evidencePath: 'retained/action.json',
    transactionHash: null, toolResponse: { freeInspection: true } };
  const result = publicActorResultFromMcpReceipt(receipt, command, false);
  assert.equal(result.apiPayload, receipt);
  assert.equal(result.action.receiptStatus, receipt.status);
  assert.equal(result.action.kind, result.action.command.kind);
  assert.deepEqual(result.action.command, command);
  assert.equal(result.action.evidenceHash, receipt.evidenceHash);
  command.resourceId = 'later-mutated';
  assert.equal(result.action.command.resourceId, 'public-resource');
});

test('only the independently observed three-field S2 disclosure gap permits the actual known 7/10 result', () => {
  const task = { taskId: 'S2', conditions: { resourceId: 'public-resource', offerId: 'canonical', requiredAnswerFields:
    ['amountUnits','network','assetId','recipient','scheme','resourceId','offerId','version','assetTransferMethod','paymentFlow','name'] },
    execution: { assets: [{ address: '0x123', chainId: 8453, assetId: 'USDC' }] } };
  const receipt = { status: 'observed', actionId: 'inspection-action', toolResponse: { resourceId: 'public-resource', freeInspection: true,
    offers: [{ id: 'canonical', payment: { amount: '100000', network: 'eip155:8453', asset: '0x123', payTo: 'recipient', scheme: 'exact', transferMethod: 'eip3009' } }] } };
  const gap = s2PublicDisclosureGap(task, receipt, { mcpRecordIndex: 2 });
  assert.deepEqual(gap.missingFields, ['version','paymentFlow','name']);
  assert.equal(Object.hasOwn(receipt.toolResponse.offers[0].payment, 'name'), false, 'hidden values are never invented');
  const grade = { result_status: 'known', task_id: 'S2', outcome: 'partial', credit: { numerator: '7', denominator: '10' } };
  assert.equal(isKnownS2DisclosureGap(grade, gap), true);
  for (const mutated of [{ ...grade, task_id: 'S3' }, { ...grade, result_status: 'unknown' },
    { ...grade, credit: { numerator: '6', denominator: '10' } }]) assert.equal(isKnownS2DisclosureGap(mutated, gap), false);
  receipt.toolResponse.offers[0].payment.name = 'Publicly disclosed';
  assert.equal(isKnownS2DisclosureGap(grade, s2PublicDisclosureGap(task, receipt, { mcpRecordIndex: 2 })), false);
});

test('public actor adapter cannot promote uncertain actions or invent missing payment transaction evidence', () => {
  for (const status of ['pending', 'unknown', 'rejected_before_execution']) assert.throws(() =>
    publicActorResultFromMcpReceipt({ actionId: 'synthetic-action', status, transactionHash: null }, { kind: 'pay' }, true));
  assert.throws(() => publicActorResultFromMcpReceipt({ actionId: 'synthetic-action', status: 'observed', transactionHash: null }, { kind: 'pay' }, true));
  const hash = '0x' + '1'.repeat(64);
  assert.equal(publicActorResultFromMcpReceipt({ actionId: 'synthetic-action', status: 'observed', transactionHash: hash },
    { kind: 'pay' }, true).action.transactionHash, hash);
});
