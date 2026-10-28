import assert from 'node:assert/strict';
import test from 'node:test';
import { deriveMinimumActionProof } from './task-difficulty-evidence-v2.js';
import type { TaskReleaseManifest } from './task-release.js';
import type { V2Action, V2ReferenceContext } from './task-reference-evidence-v2-types.js';

const router = '0x2626664c2603336e57b271c5c0b26f421741e481';
const ethRate = { numerator: '239', denominator: '100000000000' };
const asContext = (value: object) => value as unknown as V2ReferenceContext;
const toolManifest = { tools: { reads: ['offer', 'catalog', 'retrieve'], writes: ['pay', 'transfer', 'approve', 'swap', 'wrap', 'unwrap'],
  participantProtocol: 'separate_payment_delivery_v2' } };
const emptyState = { balances: [{ account: 'participant', assetId: 'ETH', amountUnits: '10000000000000000000' },
  { account: 'participant', assetId: 'USDC', amountUnits: '100000000' }, { account: 'participant', assetId: 'WETH', amountUnits: '0' }],
  allowances: [{ owner: 'participant', tokenAssetId: 'USDC', spender: router, amountUnits: '0' }],
  deliveredComponentIds: [], fulfilledObligationIds: [] };
const makeActions = (kinds: string[]): V2Action[] => kinds.map((kind, index) => ({ kind,
  operationId: `op-${index}`, rawResponsePath: `raw/${index}.json`, rawResponseSha256: 'a'.repeat(64) }));
const policy = { usdcAssetId: 'USDC', usdcPrecision: 6, ethValuation: ethRate,
  expenseComponents: ['paid_service_charge', 'participant_gas_success_or_revert', 'verified_dex_fee'],
  rounding: 'floor_to_usdc_base_units', principalSeparateFromExpense: true, ethAndWethDistinct: true,
  missingFeeEvidence: 'unknown' } as unknown as TaskReleaseManifest['costPolicy'];

function u1Context(expenseBudgetUsdcUnits = '470000'): V2ReferenceContext {
  const kinds = ['inspect_catalog', 'pay', 'retrieve', 'pay', 'retrieve', 'transfer', 'transfer', 'approve', 'swap', 'unwrap'];
  return asContext({ taskCase: { taskId: 'U1', objective: {
    requiredComponents: [{ componentId: 'component-1', resourceId: 'resource-1' },
      { componentId: 'component-2', resourceId: 'resource-2' }],
    payoutObligations: [{ obligationId: 'payout-1', recipient: '0x0000000000000000000000000000000000000001', assetId: 'USDC', exactAmountUnits: '100000' },
      { obligationId: 'payout-2', recipient: '0x0000000000000000000000000000000000000002', assetId: 'USDC', exactAmountUnits: '200000' }],
    permittedRoutes: [{ routerContractId: 'router', tokenInAssetId: 'USDC', tokenOutAssetId: 'WETH' }],
    allocationAssets: [{ assetId: 'USDC', usdcBaseUnitsPerAssetBaseUnit: { numerator: '1', denominator: '1' }, targetShareBps: 40, toleranceBps: 1 },
      { assetId: 'ETH', usdcBaseUnitsPerAssetBaseUnit: ethRate, targetShareBps: 9960, toleranceBps: 1 },
      { assetId: 'WETH', usdcBaseUnitsPerAssetBaseUnit: ethRate, targetShareBps: 0, toleranceBps: 0 }],
    temporarySpenderScope: [{ owner: 'participant', tokenAssetId: 'USDC', spender: router }],
    expenseBudgetUsdcUnits, duplicatePurchaseIdentity: 'one_public_purchase_operation_per_resource',
  }, initialState: emptyState }, identity: { contracts: [{ contractId: 'router', address: router }] },
  probe: { participantToolProtocol: 'separate_payment_delivery_v2' }, manifest: toolManifest,
  actions: makeActions(kinds) });
}

test('U1 lower bound assigns the full 470000-unit expense budget against USDC', () => {
  const proof = deriveMinimumActionProof(u1Context(), policy);
  assert.equal(proof.minimum, 10);
  assert.equal(proof.allocationWitness?.minimumUsdcBeforeConversionEvenAtFullExpenseBudget, '99230000');
  assert.equal(proof.allocationWitness?.expenseBudgetUsdcUnits, '470000');
  assert.equal(proof.allocationWitness?.payoutTotalUsdcUnits, '300000');
});

test('U1 lower bound rejects a budget that can remove the allocation excess', () => {
  assert.throws(() => deriveMinimumActionProof(u1Context('99600000'), policy),
    { message: 'minimum_u1_full_expense_budget_not_pinned' });
});

test('M4 lower bound requires zero task-start WETH and zero router allowance', () => {
  const taskCase = { taskId: 'M4', objective: { inputAssetId: 'WETH', exactInputUnits: '1000', outputAssetId: 'USDC',
    minimumOutputUnits: '1', permittedRoutes: [{ routerContractId: 'router', tokenInAssetId: 'WETH', tokenOutAssetId: 'USDC' }] },
    initialState: { balances: [{ account: 'participant', assetId: 'WETH', amountUnits: '0' }],
      allowances: [{ owner: 'participant', tokenAssetId: 'WETH', spender: router, amountUnits: '0' }] } };
  const context = asContext({ taskCase, identity: { contracts: [{ contractId: 'router', address: router }] },
    probe: { participantToolProtocol: 'separate_payment_delivery_v2' }, manifest: toolManifest,
    actions: makeActions(['wrap', 'approve', 'swap']) });
  assert.equal(deriveMinimumActionProof(context).minimum, 3);
  taskCase.initialState.balances[0]!.amountUnits = '1';
  assert.throws(() => deriveMinimumActionProof(context), { message: 'minimum_weth_wrap_not_required' });
});

test('H2 lower bound counts distinct recipients and rejects batch/conversion shortcuts', () => {
  const obligations = Array.from({ length: 6 }, (_, index) => ({ obligationId: `p-${index}`,
    recipient: `0x${(index + 1).toString(16).padStart(40, '0')}`, assetId: 'USDC', exactAmountUnits: '1' }));
  const context = asContext({ taskCase: { taskId: 'H2', objective: { obligations, permittedConversions: [] } },
    probe: { participantToolProtocol: 'separate_payment_delivery_v2' }, manifest: toolManifest,
    actions: makeActions(Array(6).fill('transfer')) });
  assert.equal(deriveMinimumActionProof(context).minimum, 6);
  const batchContext = asContext({ ...context, manifest: { tools: { ...toolManifest.tools, writes: [...toolManifest.tools.writes, 'batch'] } } });
  assert.throws(() => deriveMinimumActionProof(batchContext), { message: 'minimum_participant_protocol_not_sealed' });
});
