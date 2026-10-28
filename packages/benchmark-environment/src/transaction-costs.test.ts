import assert from 'node:assert/strict';
import test from 'node:test';
import {
  finalizeTransactionCost,
  insertUnknownTransactionCost,
  modeledGasFeeUsdcUnits,
  type CostIdentity,
  type CostQueryClient,
  type FinalCostObservation,
} from './transaction-costs.js';

const RATE_NUM = '15020514483295716381154243967034954650524622599204';
const RATE_DEN = '6277101735386680763835789423207666416102355444464034512896';
const POLICY = {
  baseFeeWei: '1003980019', priorityFeeWei: '1000000', ethUsdcRateNumerator: RATE_NUM,
  ethUsdcRateDenominator: RATE_DEN, rounding: 'floor-to-6-decimal-usdc-units',
  baseL1Fee: 'unmodelled', principalSeparateFromExpense: true,
} as const;
const HASH = `0x${'a'.repeat(64)}`;
const BLOCK_HASH = `0x${'b'.repeat(64)}`;
const PARENT_HASH = `0x${'c'.repeat(64)}`;
const PAYER = `0x${'1'.repeat(40)}`;
const OTHER = `0x${'2'.repeat(40)}`;
const MANIFEST = 'd'.repeat(64);

function identity(payerRole: CostIdentity['payerRole'] = 'participant'): CostIdentity {
  return {
    operationId: '11111111-1111-4111-8111-111111111111',
    envId: 'bef-a', generationId: '22222222-2222-4222-8222-222222222222',
    transactionHash: HASH, payerAddress: PAYER, payerRole, manifestSha256: MANIFEST,
    feePolicy: POLICY,
    selectedPrincipalAsset: payerRole === 'participant' ? 'WETH' : null,
    selectedPrincipalUnits: payerRole === 'participant' ? '10000000000000000' : null,
  };
}

function observation(status: 'success' | 'reverted' = 'success'): FinalCostObservation {
  return {
    transaction: {
      hash: HASH, from: PAYER, blockHash: BLOCK_HASH, blockNumber: '52982199', value: '0',
      maxFeePerGas: '1004980019', maxPriorityFeePerGas: '1000000',
    },
    receipt: {
      transactionHash: HASH, from: PAYER, status, blockHash: BLOCK_HASH, blockNumber: 52982199n,
      gasUsed: '102832', effectiveGasPrice: '1004980019',
    },
    receiptBlockBaseFeePerGas: '1003980019',
    payerBlock: {
      hash: BLOCK_HASH, number: '52982199', parentHash: PARENT_HASH, baseFeePerGas: '1003980019',
      transactions: [{ hash: HASH, from: PAYER }],
    },
  };
}

class MemoryCostClient implements CostQueryClient {
  row: Record<string, unknown> | null = null;
  operationStatus = 'settling';
  updateCount = 0;
  constructor(private readonly role: CostIdentity['payerRole']) {}

  async query<Row = Record<string, unknown>>(sql: string, values: readonly unknown[] = []) {
    if (sql.includes('FROM bef_operation o') && sql.includes('generation_manifest_sha256')) {
      return { rows: [{ env_id: 'bef-a', generation_id: identity(this.role).generationId,
        status: this.operationStatus, transaction_hash: HASH, generation_payer_address: PAYER,
        generation_manifest_sha256: MANIFEST, facilitator_address: this.role === 'facilitator' ? PAYER : null,
        payment_transaction_hash: this.role === 'facilitator' ? HASH : null } as Row], rowCount: 1 };
    }
    if (sql.includes('INSERT INTO bef_transaction_cost')) {
      if (!this.row) {
        this.row = {
          operation_id: values[0], env_id: values[1], generation_id: values[2], transaction_hash: values[3],
          payer_address: values[4], payer_role: values[5], receipt_status: 'unknown',
          fee_rate_numerator: values[6], fee_rate_denominator: values[7], fee_policy_snapshot: JSON.parse(String(values[8])),
          manifest_sha256: values[9], selected_principal_asset: values[10], selected_principal_units: values[11],
          observed_principal_units: null, base_l1_fee_status: 'unmodelled',
          gas_used: null, effective_gas_price_wei: null, gas_cost_wei: null, modeled_gas_fee_usdc_units: null,
          receipt_evidence_json: null, receipt_evidence_sha256: null,
        };
      }
      return { rows: [], rowCount: 1 };
    }
    if (sql.includes('SELECT env_id,generation_id,transaction_hash,payer_address,payer_role')) {
      return { rows: this.row ? [this.row as Row] : [], rowCount: this.row ? 1 : 0 };
    }
    if (sql.includes('UPDATE bef_transaction_cost')) {
      this.updateCount += 1;
      if (!this.row || this.row.receipt_status !== 'unknown') return { rows: [], rowCount: 0 };
      const [
        , , receiptStatus, transactionFrom, receiptFrom, blockNumber, blockHash, parentHash, senders,
        gasUsed, price, cost, modeled, observedPrincipal, beforeWei, beforeNumber, beforeHash,
        afterWei, afterNumber, afterHash, evidenceJson, evidenceSha,
      ] = values;
      Object.assign(this.row, {
        receipt_status: receiptStatus, transaction_from: transactionFrom, receipt_from: receiptFrom,
        receipt_block_number: blockNumber, receipt_block_hash: blockHash, receipt_block_parent_hash: parentHash,
        block_transaction_senders: senders == null ? null : JSON.parse(String(senders)),
        gas_used: gasUsed, effective_gas_price_wei: price, gas_cost_wei: cost,
        modeled_gas_fee_usdc_units: modeled, observed_principal_units: observedPrincipal,
        payer_native_balance_before_wei: beforeWei, payer_native_balance_before_block_number: beforeNumber,
        payer_native_balance_before_block_hash: beforeHash, payer_native_balance_after_wei: afterWei,
        payer_native_balance_after_block_number: afterNumber, payer_native_balance_after_block_hash: afterHash,
        receipt_evidence_json: evidenceJson == null ? null : JSON.parse(String(evidenceJson)),
        receipt_evidence_sha256: evidenceSha,
      });
      return { rows: [{ operation_id: this.row.operation_id } as Row], rowCount: 1 };
    }
    if (sql.includes('SELECT * FROM bef_transaction_cost')) {
      return { rows: this.row ? [this.row as Row] : [], rowCount: this.row ? 1 : 0 };
    }
    throw new Error(`unexpected SQL in draft test: ${sql.slice(0, 80)}`);
  }
}

function facilitatorObservation(): FinalCostObservation {
  return {
    ...observation('reverted'),
    payerBlock: {
      hash: BLOCK_HASH, number: '52982199', parentHash: PARENT_HASH, baseFeePerGas: '1003980019',
      transactions: [{ hash: HASH, from: PAYER }],
    },
    payerNativeBalanceBefore: { blockHash: PARENT_HASH, blockNumber: '52982198', balanceWei: '1000000000000000' },
    payerNativeBalanceAfter: {
      blockHash: BLOCK_HASH, blockNumber: '52982199',
      balanceWei: (1000000000000000n - 102832n * 1004980019n).toString(),
    },
  };
}

test('pinned conversion uses direct USDC-base-units-per-wei rational', () => {
  assert.equal(modeledGasFeeUsdcUnits('102832', '1004980019', POLICY), '247292');
});

test('USDC transfer principal stays separate from receipt-backed gas expense', async () => {
  const client = new MemoryCostClient('participant');
  const key: CostIdentity = { ...identity(), selectedPrincipalAsset: 'USDC', selectedPrincipalUnits: '777' };
  await insertUnknownTransactionCost(client, key);
  await finalizeTransactionCost(client, key, observation('success'));

  assert.equal(client.row?.selected_principal_asset, 'USDC');
  assert.equal(client.row?.selected_principal_units, '777');
  assert.equal(client.row?.observed_principal_units, '777');
  assert.equal(client.row?.gas_cost_wei, '103344105313808');
  assert.equal(client.row?.modeled_gas_fee_usdc_units, modeledGasFeeUsdcUnits('102832', '1004980019', POLICY));
});

test('unknown cost row keeps every cost null until a bound receipt is observed', async () => {
  const client = new MemoryCostClient('participant');
  await insertUnknownTransactionCost(client, identity());
  assert.equal(client.row?.receipt_status, 'unknown');
  assert.equal(client.row?.gas_cost_wei, null);
  assert.equal(client.row?.modeled_gas_fee_usdc_units, null);
  assert.equal(client.row?.observed_principal_units, null);
});

test('receipt-backed execution cannot be finalized with zero gas or a zero gas price', async () => {
  const client = new MemoryCostClient('participant');
  const key = identity();
  await insertUnknownTransactionCost(client, key);
  await assert.rejects(finalizeTransactionCost(client, key, {
    ...observation(), receipt: { ...observation().receipt, gasUsed: '0' },
  }), /transaction_cost_zero_execution_charge_invalid/);
  await assert.rejects(finalizeTransactionCost(client, key, {
    ...observation(), receipt: { ...observation().receipt, effectiveGasPrice: '0' },
  }), /transaction_cost_zero_execution_charge_invalid/);
  assert.equal(client.row?.receipt_status, 'unknown');
  assert.equal(client.row?.gas_cost_wei, null);
});

test('a matching stored policy and receipt cannot hide a different transaction priority fee', async () => {
  const client = new MemoryCostClient('participant');
  const key = identity();
  await insertUnknownTransactionCost(client, key);
  await assert.rejects(finalizeTransactionCost(client, key, {
    ...observation(),
    transaction: { ...observation().transaction, maxPriorityFeePerGas: '1000000000' },
  }), /transaction_cost_fee_policy_receipt_conflict/);
  await assert.rejects(finalizeTransactionCost(client, key, {
    ...observation(),
    transaction: { ...observation().transaction, maxFeePerGas: '1004980020' },
  }), /transaction_cost_fee_policy_receipt_conflict/);
  await assert.rejects(finalizeTransactionCost(client, key, {
    ...observation(), receiptBlockBaseFeePerGas: '1003980020',
  }), /transaction_cost_fee_policy_receipt_conflict/);
  assert.equal(client.row?.receipt_status, 'unknown');
});

test('a declining receipt-block base fee is charged at its observed EIP-1559 effective price', async () => {
  const client = new MemoryCostClient('participant');
  const key: CostIdentity = { ...identity(), feePolicy: { ...POLICY, baseFeeWei: '5000000' } };
  const actualBaseFee = '4375195';
  const effectiveGasPrice = '5375195';
  const finalObservation = observation('reverted');
  finalObservation.transaction.maxFeePerGas = '6000000';
  finalObservation.receipt.effectiveGasPrice = effectiveGasPrice;
  finalObservation.receiptBlockBaseFeePerGas = actualBaseFee;
  finalObservation.payerBlock!.baseFeePerGas = actualBaseFee;
  await insertUnknownTransactionCost(client, key);
  await finalizeTransactionCost(client, key, finalObservation);
  assert.equal(client.row?.receipt_status, 'reverted');
  assert.equal(client.row?.effective_gas_price_wei, effectiveGasPrice);
  const receiptEvidence = client.row?.receipt_evidence_json as Record<string, unknown> | undefined;
  assert.equal((receiptEvidence?.receipt as Record<string, unknown> | undefined)?.blockBaseFeePerGasWei, actualBaseFee);

  const conflicting = new MemoryCostClient('participant');
  const mutatedPrice = { ...finalObservation, receipt: { ...finalObservation.receipt, effectiveGasPrice: '5375196' } };
  await insertUnknownTransactionCost(conflicting, key);
  await assert.rejects(finalizeTransactionCost(conflicting, key, mutatedPrice),
    /transaction_cost_fee_policy_receipt_conflict/);
  assert.equal(conflicting.row?.receipt_status, 'unknown');
  assert.equal(conflicting.row?.gas_cost_wei, null);
});

test('reverted participant receipt finalizes gas cost while observed principal is zero', async () => {
  const client = new MemoryCostClient('participant');
  const key = identity();
  await insertUnknownTransactionCost(client, key);
  await finalizeTransactionCost(client, key, observation('reverted'));
  assert.equal(client.row?.receipt_status, 'reverted');
  assert.equal(client.row?.gas_cost_wei, String(102832n * 1004980019n));
  assert.equal(client.row?.modeled_gas_fee_usdc_units, '247292');
  assert.equal(client.row?.selected_principal_units, '10000000000000000');
  assert.equal(client.row?.observed_principal_units, '0');
  await finalizeTransactionCost(client, key, observation('reverted'));
  const conflictingPolicy = { ...POLICY, priorityFeeWei: '1000001' };
  await assert.rejects(finalizeTransactionCost(client, { ...key, feePolicy: conflictingPolicy }, observation('reverted')),
    /transaction_cost_fee_policy_receipt_conflict/);
  await assert.rejects(finalizeTransactionCost(client, key, {
    ...observation('reverted'), receipt: { ...observation('reverted').receipt, effectiveGasPrice: '1004980020' },
  }), /transaction_cost_fee_policy_receipt_conflict/);
  await assert.rejects(finalizeTransactionCost(client, key, observation('success')), /transaction_cost_terminal_conflict/);
});

test('facilitator cost requires receipt-block sender and adjacent historical native balances', async () => {
  const client = new MemoryCostClient('facilitator');
  const key = identity('facilitator');
  await insertUnknownTransactionCost(client, key);
  await finalizeTransactionCost(client, key, facilitatorObservation());
  assert.equal(client.row?.payer_role, 'facilitator');
  assert.equal(client.row?.selected_principal_units, null);
  assert.equal(client.row?.observed_principal_units, null);
  assert.equal(client.row?.payer_native_balance_before_block_number, '52982198');
  assert.equal(client.row?.payer_native_balance_after_block_number, '52982199');

  const wrongPriority = new MemoryCostClient('facilitator');
  await insertUnknownTransactionCost(wrongPriority, key);
  await assert.rejects(finalizeTransactionCost(wrongPriority, key, {
    ...facilitatorObservation(),
    transaction: { ...facilitatorObservation().transaction, maxPriorityFeePerGas: '1000000000' },
  }), /transaction_cost_fee_policy_receipt_conflict/);
  assert.equal(wrongPriority.row?.receipt_status, 'unknown');

  const incomplete = new MemoryCostClient('facilitator');
  await insertUnknownTransactionCost(incomplete, key);
  const badProof = facilitatorObservation();
  badProof.payerBlock!.transactions = [{ hash: HASH, from: OTHER }];
  await assert.rejects(finalizeTransactionCost(incomplete, key, badProof), /transaction_cost_same_block_sender_proof_invalid/);
  const badBalance = facilitatorObservation();
  badBalance.payerNativeBalanceAfter = { blockHash: BLOCK_HASH, blockNumber: '52982199', balanceWei: '1' };
  await assert.rejects(finalizeTransactionCost(incomplete, key, badBalance), /transaction_cost_historical_balance_binding_invalid/);
  assert.equal(incomplete.row?.receipt_status, 'unknown');
  assert.equal(incomplete.row?.gas_cost_wei, null);
});

test('delivered operations permit only exact final-cost replay and never finalize an unknown row', async () => {
  const key = identity();
  const finalized = new MemoryCostClient('participant');
  await insertUnknownTransactionCost(finalized, key);
  await finalizeTransactionCost(finalized, key, observation());
  const beforeReplay = structuredClone(finalized.row);
  const updatesBeforeReplay = finalized.updateCount;
  finalized.operationStatus = 'delivered';
  await finalizeTransactionCost(finalized, key, observation());
  assert.equal(finalized.updateCount, updatesBeforeReplay, 'delivered replay must not update the durable cost row');
  assert.deepEqual(finalized.row, beforeReplay);

  const unknown = new MemoryCostClient('participant');
  await insertUnknownTransactionCost(unknown, key);
  unknown.operationStatus = 'delivered';
  await assert.rejects(finalizeTransactionCost(unknown, key, observation()), /transaction_cost_terminal_conflict/);
  assert.equal(unknown.updateCount, 0, 'delivered operation must not finalize a cost row');
  assert.equal(unknown.row?.receipt_status, 'unknown');
  assert.equal(unknown.row?.gas_cost_wei, null);
});
