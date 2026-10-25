import { createHash } from 'node:crypto';

/**
 * Candidate SC-008 persistence module. It is intentionally outside src/ until
 * the parent lifts the source freeze. Callers use their existing transaction
 * client, so cost evidence commits atomically with the operation transition.
 */

export type CostRole = 'participant' | 'facilitator';
export type CostReceiptStatus = 'success' | 'reverted';

export type FeePolicySnapshot = {
  baseFeeWei: string;
  priorityFeeWei: string;
  ethUsdcRateNumerator: string;
  ethUsdcRateDenominator: string;
  rounding: 'floor-to-6-decimal-usdc-units';
  baseL1Fee: 'unmodelled';
  principalSeparateFromExpense: true;
};

export type CostIdentity = {
  operationId: string;
  envId: string;
  generationId: string;
  transactionHash: string;
  payerAddress: string;
  payerRole: CostRole;
  manifestSha256: string;
  feePolicy: FeePolicySnapshot;
  selectedPrincipalAsset: 'ETH' | 'WETH' | null;
  selectedPrincipalUnits: string | null;
};

export type CostTransactionObservation = {
  hash: unknown;
  from: unknown;
  blockHash: unknown;
  blockNumber: unknown;
  value: unknown;
  maxFeePerGas: unknown;
  maxPriorityFeePerGas: unknown;
};

export type CostReceiptObservation = {
  transactionHash: unknown;
  from: unknown;
  status: unknown;
  blockHash: unknown;
  blockNumber: unknown;
  gasUsed: unknown;
  effectiveGasPrice: unknown;
};

export type CostBlockObservation = {
  hash: unknown;
  number: unknown;
  parentHash: unknown;
  baseFeePerGas: unknown;
  transactions: unknown;
};

export type CostNativeBalanceObservation = {
  blockHash: unknown;
  blockNumber: unknown;
  balanceWei: unknown;
};

export type FinalCostObservation = {
  transaction: CostTransactionObservation;
  receipt: CostReceiptObservation;
  receiptBlockBaseFeePerGas: unknown;
  /** Required for facilitator payer rows; optional for participant rows. */
  payerBlock?: CostBlockObservation;
  payerNativeBalanceBefore?: CostNativeBalanceObservation;
  payerNativeBalanceAfter?: CostNativeBalanceObservation;
};

export type CostQueryClient = {
  query<Row = Record<string, unknown>>(
    text: string,
    values?: readonly unknown[],
  ): Promise<{ rows: Row[]; rowCount: number | null }>;
};

type NormalizedFinal = {
  receiptStatus: CostReceiptStatus;
  transactionFrom: string;
  receiptFrom: string;
  receiptBlockNumber: string;
  receiptBlockHash: string;
  receiptBlockParentHash: string | null;
  blockTransactionSenders: Array<{ hash: string; from: string }> | null;
  gasUsed: string;
  effectiveGasPriceWei: string;
  gasCostWei: string;
  modeledGasFeeUsdcUnits: string;
  observedPrincipalUnits: string | null;
  payerNativeBalanceBeforeWei: string | null;
  payerNativeBalanceBeforeBlockNumber: string | null;
  payerNativeBalanceBeforeBlockHash: string | null;
  payerNativeBalanceAfterWei: string | null;
  payerNativeBalanceAfterBlockNumber: string | null;
  payerNativeBalanceAfterBlockHash: string | null;
  receiptEvidenceJson: Record<string, unknown>;
  receiptEvidenceSha256: string;
};

const ADDRESS = /^0x[0-9a-f]{40}$/i;
const HASH = /^0x[0-9a-f]{64}$/i;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function fail(code: string): never { throw new Error(code); }
function lower(value: string): string { return value.toLowerCase(); }

function uint(value: unknown, code = 'transaction_cost_observation_invalid'): bigint {
  if (typeof value === 'bigint') return value >= 0n ? value : fail(code);
  if (typeof value === 'number') return Number.isSafeInteger(value) && value >= 0 ? BigInt(value) : fail(code);
  if (typeof value === 'string') {
    const decimal = DECIMAL.test(value) ? value : /^0x[0-9a-f]+$/i.test(value) ? BigInt(value).toString() : null;
    if (decimal !== null) return BigInt(decimal);
  }
  return fail(code);
}

function address(value: unknown, code = 'transaction_cost_observation_invalid'): string {
  return typeof value === 'string' && ADDRESS.test(value) ? lower(value) : fail(code);
}

function hash(value: unknown, code = 'transaction_cost_observation_invalid'): string {
  return typeof value === 'string' && HASH.test(value) ? lower(value) : fail(code);
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>).sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0);
    return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${stableJson(item)}`).join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}

function validateFeePolicy(policy: FeePolicySnapshot): void {
  const expectedKeys = [
    'baseFeeWei', 'priorityFeeWei', 'ethUsdcRateNumerator', 'ethUsdcRateDenominator',
    'rounding', 'baseL1Fee', 'principalSeparateFromExpense',
  ];
  const actualKeys = policy && typeof policy === 'object' && !Array.isArray(policy) ? Object.keys(policy).sort() : [];
  if (actualKeys.length !== expectedKeys.length || expectedKeys.some((key) => !actualKeys.includes(key)) ||
      typeof policy.baseFeeWei !== 'string' || typeof policy.priorityFeeWei !== 'string' ||
      typeof policy.ethUsdcRateNumerator !== 'string' || typeof policy.ethUsdcRateDenominator !== 'string' ||
      typeof policy.rounding !== 'string' || typeof policy.baseL1Fee !== 'string' ||
      typeof policy.principalSeparateFromExpense !== 'boolean' ||
      !DECIMAL.test(policy.baseFeeWei) || !DECIMAL.test(policy.priorityFeeWei) ||
      !DECIMAL.test(policy.ethUsdcRateNumerator) || BigInt(policy.ethUsdcRateNumerator) <= 0n ||
      !DECIMAL.test(policy.ethUsdcRateDenominator) || BigInt(policy.ethUsdcRateDenominator) <= 0n ||
      policy.rounding !== 'floor-to-6-decimal-usdc-units' || policy.baseL1Fee !== 'unmodelled' ||
      policy.principalSeparateFromExpense !== true) fail('transaction_cost_fee_policy_invalid');
}

function validateIdentity(identity: CostIdentity): void {
  if (!UUID.test(identity.operationId) || !UUID.test(identity.generationId) ||
      !identity.envId || identity.envId.length > 128 || !HASH.test(identity.transactionHash) ||
      !ADDRESS.test(identity.payerAddress) || !/^[0-9a-f]{64}$/.test(identity.manifestSha256) ||
      !['participant', 'facilitator'].includes(identity.payerRole)) fail('transaction_cost_identity_invalid');
  validateFeePolicy(identity.feePolicy);
  if (identity.payerRole === 'facilitator') {
    if (identity.selectedPrincipalAsset !== null || identity.selectedPrincipalUnits !== null) {
      fail('transaction_cost_facilitator_principal_invalid');
    }
  } else if (identity.selectedPrincipalUnits === null || !DECIMAL.test(identity.selectedPrincipalUnits) ||
      (identity.selectedPrincipalAsset !== null && !['ETH', 'WETH'].includes(identity.selectedPrincipalAsset))) {
    fail('transaction_cost_participant_principal_invalid');
  }
}

function blockTransactions(value: unknown): Array<{ hash: string; from: string }> {
  if (!Array.isArray(value)) return fail('transaction_cost_block_transactions_invalid');
  const projected: Array<{ hash: string; from: string }> = [];
  const seen = new Set<string>();
  for (const item of value) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) return fail('transaction_cost_block_transactions_invalid');
    const row = item as Record<string, unknown>;
    const txHash = hash(row.hash);
    const from = address(row.from);
    if (seen.has(txHash)) return fail('transaction_cost_block_transactions_conflict');
    seen.add(txHash);
    projected.push({ hash: txHash, from });
  }
  return projected;
}

function normalizeFinal(identity: CostIdentity, observation: FinalCostObservation): NormalizedFinal {
  validateIdentity(identity);
  const txHash = hash(observation.transaction.hash);
  const txFrom = address(observation.transaction.from);
  const txBlockHash = hash(observation.transaction.blockHash);
  const txBlockNumber = uint(observation.transaction.blockNumber).toString();
  const transactionValue = uint(observation.transaction.value).toString();
  const transactionMaxFeePerGas = uint(observation.transaction.maxFeePerGas).toString();
  const transactionMaxPriorityFeePerGas = uint(observation.transaction.maxPriorityFeePerGas).toString();
  const receiptHash = hash(observation.receipt.transactionHash);
  const receiptFrom = address(observation.receipt.from);
  const receiptBlockHash = hash(observation.receipt.blockHash);
  const receiptBlockNumber = uint(observation.receipt.blockNumber).toString();
  const gasUsed = uint(observation.receipt.gasUsed).toString();
  const effectiveGasPriceWei = uint(observation.receipt.effectiveGasPrice).toString();
  const status = observation.receipt.status;
  if (status !== 'success' && status !== 'reverted') return fail('transaction_cost_receipt_status_invalid');
  if (BigInt(gasUsed) === 0n || BigInt(effectiveGasPriceWei) === 0n) {
    return fail('transaction_cost_zero_execution_charge_invalid');
  }
  if (txHash !== lower(identity.transactionHash) || receiptHash !== txHash ||
      txFrom !== lower(identity.payerAddress) || receiptFrom !== txFrom ||
      txBlockHash !== receiptBlockHash || txBlockNumber !== receiptBlockNumber) {
    return fail('transaction_cost_sender_or_receipt_binding_conflict');
  }

  const blockBaseFeePerGas = uint(observation.receiptBlockBaseFeePerGas).toString();
  const policyBaseFee = BigInt(identity.feePolicy.baseFeeWei);
  const policyPriorityFee = BigInt(identity.feePolicy.priorityFeeWei);
  const transactionMaxFee = BigInt(transactionMaxFeePerGas);
  const transactionPriorityFee = BigInt(transactionMaxPriorityFeePerGas);
  const blockBaseFee = BigInt(blockBaseFeePerGas);
  const expectedTransactionValue = identity.payerRole === 'facilitator' ? 0n
    : identity.selectedPrincipalAsset === 'ETH' ? BigInt(identity.selectedPrincipalUnits!) : 0n;
  // AICODE-NOTE: baseFeeWei pins the starting local fee ceiling and transaction cap; mined receipt blocks may have a lower observed base fee.
  if (transactionValue !== expectedTransactionValue.toString() ||
      transactionPriorityFee !== policyPriorityFee ||
      blockBaseFee > policyBaseFee ||
      transactionMaxFee !== policyBaseFee + policyPriorityFee ||
      transactionPriorityFee > transactionMaxFee ||
      BigInt(effectiveGasPriceWei) !== (transactionMaxFee < blockBaseFee + transactionPriorityFee
        ? transactionMaxFee : blockBaseFee + transactionPriorityFee)) {
    return fail('transaction_cost_fee_policy_receipt_conflict');
  }

  let receiptBlockParentHash: string | null = null;
  let senders: Array<{ hash: string; from: string }> | null = null;
  let beforeBalance: string | null = null;
  let beforeBlockNumber: string | null = null;
  let beforeBlockHash: string | null = null;
  let afterBalance: string | null = null;
  let afterBlockNumber: string | null = null;
  let afterBlockHash: string | null = null;
  {
    const proof = observation.payerBlock;
    if (!proof) return fail('transaction_cost_receipt_block_proof_missing');
    const proofNumber = uint(proof.number).toString();
    const proofHash = hash(proof.hash);
    const proofParent = hash(proof.parentHash);
    senders = blockTransactions(proof.transactions);
    const matching = senders.filter((entry) => entry.hash === txHash);
    const payerTransactions = senders.filter((entry) => entry.from === lower(identity.payerAddress));
    if (proofNumber !== receiptBlockNumber || proofHash !== receiptBlockHash || senders.length !== 1 || matching.length !== 1 ||
        matching[0]!.from !== txFrom || payerTransactions.length !== 1 ||
        uint(proof.baseFeePerGas).toString() !== blockBaseFeePerGas) {
      return fail('transaction_cost_same_block_sender_proof_invalid');
    }
    if (identity.payerRole === 'facilitator') {
      const before = observation.payerNativeBalanceBefore;
      const after = observation.payerNativeBalanceAfter;
      if (!before || !after) return fail('transaction_cost_facilitator_payer_proof_missing');
      const beforeNumber = uint(before.blockNumber).toString();
      const beforeHashValue = hash(before.blockHash);
      const beforeWei = uint(before.balanceWei).toString();
      const afterNumberValue = uint(after.blockNumber).toString();
      const afterHashValue = hash(after.blockHash);
      const afterWeiValue = uint(after.balanceWei).toString();
      if (BigInt(receiptBlockNumber) === 0n || BigInt(beforeNumber) !== BigInt(receiptBlockNumber) - 1n ||
          beforeHashValue !== proofParent || afterNumberValue !== receiptBlockNumber ||
          afterHashValue !== receiptBlockHash || BigInt(beforeWei) - BigInt(afterWeiValue) !== BigInt(gasUsed) * BigInt(effectiveGasPriceWei)) {
        return fail('transaction_cost_historical_balance_binding_invalid');
      }
      receiptBlockParentHash = proofParent;
      beforeBalance = beforeWei;
      beforeBlockNumber = beforeNumber;
      beforeBlockHash = beforeHashValue;
      afterBalance = afterWeiValue;
      afterBlockNumber = afterNumberValue;
      afterBlockHash = afterHashValue;
    } else if (observation.payerNativeBalanceBefore !== undefined || observation.payerNativeBalanceAfter !== undefined) {
      return fail('transaction_cost_participant_balance_proof_unexpected');
    }
    receiptBlockParentHash = proofParent;
  }

  const gasCostWei = (BigInt(gasUsed) * BigInt(effectiveGasPriceWei)).toString();
  const modeledGasFeeUsdcUnits = (
    BigInt(gasCostWei) * BigInt(identity.feePolicy.ethUsdcRateNumerator) /
    BigInt(identity.feePolicy.ethUsdcRateDenominator)
  ).toString();
  const observedPrincipalUnits = identity.payerRole === 'facilitator' ? null
    : status === 'success' ? identity.selectedPrincipalUnits : '0';
  const receiptEvidenceJson: Record<string, unknown> = {
    transaction: {
      hash: txHash, from: txFrom, blockHash: txBlockHash, blockNumber: txBlockNumber,
      valueWei: transactionValue, maxFeePerGasWei: transactionMaxFeePerGas,
      maxPriorityFeePerGasWei: transactionMaxPriorityFeePerGas,
    },
    receipt: {
      transactionHash: receiptHash, from: receiptFrom, status, blockHash: receiptBlockHash,
      blockNumber: receiptBlockNumber, gasUsed, effectiveGasPriceWei, blockBaseFeePerGasWei: blockBaseFeePerGas,
    },
    ...(senders ? {
      payerBlock: { hash: receiptBlockHash, number: receiptBlockNumber, parentHash: receiptBlockParentHash, transactions: senders },
      payerNativeBalanceBefore: { blockHash: beforeBlockHash, blockNumber: beforeBlockNumber, balanceWei: beforeBalance },
      payerNativeBalanceAfter: { blockHash: afterBlockHash, blockNumber: afterBlockNumber, balanceWei: afterBalance },
    } : {}),
  };
  return {
    receiptStatus: status,
    transactionFrom: txFrom,
    receiptFrom,
    receiptBlockNumber,
    receiptBlockHash,
    receiptBlockParentHash,
    blockTransactionSenders: senders,
    gasUsed,
    effectiveGasPriceWei,
    gasCostWei,
    modeledGasFeeUsdcUnits,
    observedPrincipalUnits,
    payerNativeBalanceBeforeWei: beforeBalance,
    payerNativeBalanceBeforeBlockNumber: beforeBlockNumber,
    payerNativeBalanceBeforeBlockHash: beforeBlockHash,
    payerNativeBalanceAfterWei: afterBalance,
    payerNativeBalanceAfterBlockNumber: afterBlockNumber,
    payerNativeBalanceAfterBlockHash: afterBlockHash,
    receiptEvidenceJson,
    receiptEvidenceSha256: createSha256(stableJson(receiptEvidenceJson)),
  };
}

function createSha256(value: string): string { return createHash('sha256').update(value, 'utf8').digest('hex'); }

function feeIdentityValues(identity: CostIdentity): unknown[] {
  return [
    identity.operationId, identity.envId, identity.generationId, lower(identity.transactionHash),
    lower(identity.payerAddress), identity.payerRole,
    identity.feePolicy.ethUsdcRateNumerator, identity.feePolicy.ethUsdcRateDenominator,
    JSON.stringify(identity.feePolicy), identity.manifestSha256,
    identity.selectedPrincipalAsset, identity.selectedPrincipalUnits,
  ];
}

async function assertDurablePayerBinding(
  client: CostQueryClient,
  identity: CostIdentity,
  requireUnresolved: boolean,
): Promise<string> {
  const result = await client.query<{
    env_id: string; generation_id: string; status: string; transaction_hash: string | null;
    generation_payer_address: string; facilitator_address: string | null; payment_transaction_hash: string | null;
    generation_manifest_sha256: string | null;
  }>(
    `SELECT o.env_id,o.generation_id,o.status,o.transaction_hash,
            g.payer_address AS generation_payer_address,g.manifest_sha256 AS generation_manifest_sha256,
            p.facilitator_address,
            p.transaction_hash AS payment_transaction_hash
       FROM bef_operation o
       JOIN bef_generation g ON g.env_id=o.env_id AND g.generation_id=o.generation_id
       LEFT JOIN bef_payment p ON p.operation_id=o.operation_id AND p.env_id=o.env_id AND p.generation_id=o.generation_id
      WHERE o.operation_id=$1 AND o.env_id=$2 AND o.generation_id=$3
      FOR UPDATE OF o,g`,
    [identity.operationId, identity.envId, identity.generationId],
  );
  const row = result.rows[0];
  const allowedStatuses = requireUnresolved ? ['settling', 'settlement_unknown']
    : ['settling', 'settlement_unknown', 'settled', 'reverted', 'delivered'];
  if (!row || row.env_id !== identity.envId || row.generation_id !== identity.generationId ||
      !allowedStatuses.includes(row.status) ||
      row.generation_manifest_sha256?.trim().toLowerCase() !== identity.manifestSha256 ||
      row.transaction_hash?.toLowerCase() !== identity.transactionHash.toLowerCase()) {
    fail('transaction_cost_operation_binding_conflict');
  }
  if (identity.payerRole === 'participant') {
    if (row.generation_payer_address.toLowerCase() !== identity.payerAddress.toLowerCase()) {
      fail('transaction_cost_participant_payer_conflict');
    }
  } else if (!row.facilitator_address || row.facilitator_address.toLowerCase() !== identity.payerAddress.toLowerCase() ||
      row.payment_transaction_hash?.toLowerCase() !== identity.transactionHash.toLowerCase()) {
    fail('transaction_cost_facilitator_payer_conflict');
  }
  return row.status;
}

/** Insert the null-cost marker after the original hash is durably bound, before broadcast. */
export async function insertUnknownTransactionCost(client: CostQueryClient, identity: CostIdentity): Promise<void> {
  validateIdentity(identity);
  await assertDurablePayerBinding(client, identity, true);
  const values = feeIdentityValues(identity);
  await client.query(
    `INSERT INTO bef_transaction_cost(
       operation_id,env_id,generation_id,transaction_hash,payer_address,payer_role,receipt_status,
       fee_rate_numerator,fee_rate_denominator,fee_policy_snapshot,manifest_sha256,
       selected_principal_asset,selected_principal_units,observed_principal_units,base_l1_fee_status
     ) VALUES($1,$2,$3,$4,$5,$6,'unknown',$7,$8,$9::jsonb,$10,$11,$12,NULL,'unmodelled')
     ON CONFLICT(operation_id,transaction_hash) DO NOTHING`,
    values,
  );
  const existing = await client.query<{
    env_id: string; generation_id: string; transaction_hash: string; payer_address: string;
    payer_role: CostRole; fee_rate_numerator: string; fee_rate_denominator: string;
    fee_policy_snapshot: unknown; manifest_sha256: string; selected_principal_asset: string | null;
    selected_principal_units: string | null;
  }>(
    `SELECT env_id,generation_id,transaction_hash,payer_address,payer_role,fee_rate_numerator,
            fee_rate_denominator,fee_policy_snapshot,manifest_sha256,selected_principal_asset,selected_principal_units
       FROM bef_transaction_cost WHERE operation_id=$1 AND transaction_hash=$2 FOR UPDATE`,
    [identity.operationId, lower(identity.transactionHash)],
  );
  const row = existing.rows[0];
  if (!row || row.env_id !== identity.envId || row.generation_id !== identity.generationId ||
      row.transaction_hash.toLowerCase() !== identity.transactionHash.toLowerCase() ||
      row.payer_address.toLowerCase() !== identity.payerAddress.toLowerCase() || row.payer_role !== identity.payerRole ||
      String(row.fee_rate_numerator) !== identity.feePolicy.ethUsdcRateNumerator ||
      String(row.fee_rate_denominator) !== identity.feePolicy.ethUsdcRateDenominator ||
      stableJson(row.fee_policy_snapshot) !== stableJson(identity.feePolicy) ||
      row.manifest_sha256.trim() !== identity.manifestSha256 ||
      row.selected_principal_asset !== identity.selectedPrincipalAsset ||
      (row.selected_principal_units === null ? null : String(row.selected_principal_units)) !== identity.selectedPrincipalUnits) {
    fail('transaction_cost_identity_replay_conflict');
  }
}

/** Finalize only a previously recorded hash after strict original-receipt proof. */
export async function finalizeTransactionCost(
  client: CostQueryClient,
  identity: CostIdentity,
  observation: FinalCostObservation,
): Promise<void> {
  validateIdentity(identity);
  const durableOperationStatus = await assertDurablePayerBinding(client, identity, false);
  const final = normalizeFinal(identity, observation);
  const updated = durableOperationStatus === 'delivered' ? null : await client.query(
    `UPDATE bef_transaction_cost
        SET receipt_status=$3,transaction_from=$4,receipt_from=$5,receipt_block_number=$6,
            receipt_block_hash=$7,receipt_block_parent_hash=$8,block_transaction_senders=$9::jsonb,
            gas_used=$10,effective_gas_price_wei=$11,gas_cost_wei=$12,modeled_gas_fee_usdc_units=$13,
            observed_principal_units=$14,payer_native_balance_before_wei=$15,
            payer_native_balance_before_block_number=$16,payer_native_balance_before_block_hash=$17,
            payer_native_balance_after_wei=$18,payer_native_balance_after_block_number=$19,
            payer_native_balance_after_block_hash=$20,receipt_evidence_json=$21::jsonb,
            receipt_evidence_sha256=$22
      WHERE operation_id=$1 AND transaction_hash=$2 AND receipt_status='unknown'
        AND lower(payer_address)=lower($23) AND payer_role=$24
        AND fee_rate_numerator=$25 AND fee_rate_denominator=$26
        AND manifest_sha256=$27 AND selected_principal_asset IS NOT DISTINCT FROM $28
        AND selected_principal_units IS NOT DISTINCT FROM $29
        AND fee_policy_snapshot=$30::jsonb AND base_l1_fee_status='unmodelled'
      RETURNING operation_id`,
    [
      identity.operationId, lower(identity.transactionHash), final.receiptStatus, final.transactionFrom, final.receiptFrom,
      final.receiptBlockNumber, final.receiptBlockHash, final.receiptBlockParentHash,
      final.blockTransactionSenders ? JSON.stringify(final.blockTransactionSenders) : null,
      final.gasUsed, final.effectiveGasPriceWei, final.gasCostWei, final.modeledGasFeeUsdcUnits,
      final.observedPrincipalUnits, final.payerNativeBalanceBeforeWei, final.payerNativeBalanceBeforeBlockNumber,
      final.payerNativeBalanceBeforeBlockHash, final.payerNativeBalanceAfterWei, final.payerNativeBalanceAfterBlockNumber,
      final.payerNativeBalanceAfterBlockHash, JSON.stringify(final.receiptEvidenceJson), final.receiptEvidenceSha256,
      lower(identity.payerAddress), identity.payerRole, identity.feePolicy.ethUsdcRateNumerator,
      identity.feePolicy.ethUsdcRateDenominator, identity.manifestSha256, identity.selectedPrincipalAsset,
      identity.selectedPrincipalUnits, JSON.stringify(identity.feePolicy),
    ],
  );
  if (updated?.rowCount === 1) return;
  const existing = await client.query<Record<string, unknown>>(
    `SELECT * FROM bef_transaction_cost WHERE operation_id=$1 AND transaction_hash=$2 FOR UPDATE`,
    [identity.operationId, lower(identity.transactionHash)],
  );
  const row = existing.rows[0];
  if (!row ||
      row.env_id !== identity.envId || row.generation_id !== identity.generationId ||
      row.transaction_hash?.toString().toLowerCase() !== identity.transactionHash.toLowerCase() ||
      row.payer_address?.toString().toLowerCase() !== identity.payerAddress.toLowerCase() ||
      row.payer_role !== identity.payerRole ||
      String(row.fee_rate_numerator) !== identity.feePolicy.ethUsdcRateNumerator ||
      String(row.fee_rate_denominator) !== identity.feePolicy.ethUsdcRateDenominator ||
      row.manifest_sha256?.toString().trim().toLowerCase() !== identity.manifestSha256.toLowerCase() ||
      row.selected_principal_asset !== identity.selectedPrincipalAsset ||
      (row.selected_principal_units === null ? null : String(row.selected_principal_units)) !== identity.selectedPrincipalUnits ||
      stableJson(row.fee_policy_snapshot) !== stableJson(identity.feePolicy) ||
      row.base_l1_fee_status !== 'unmodelled' ||
      row.receipt_status !== final.receiptStatus ||
      row.transaction_from?.toString().toLowerCase() !== final.transactionFrom ||
      row.receipt_from?.toString().toLowerCase() !== final.receiptFrom ||
      String(row.receipt_block_number) !== final.receiptBlockNumber ||
      row.receipt_block_hash?.toString().toLowerCase() !== final.receiptBlockHash ||
      (row.receipt_block_parent_hash?.toString().toLowerCase() ?? null) !== final.receiptBlockParentHash ||
      String(row.gas_used) !== final.gasUsed ||
      String(row.effective_gas_price_wei) !== final.effectiveGasPriceWei ||
      String(row.gas_cost_wei) !== final.gasCostWei ||
      String(row.modeled_gas_fee_usdc_units) !== final.modeledGasFeeUsdcUnits ||
      (row.observed_principal_units === null ? null : String(row.observed_principal_units)) !== final.observedPrincipalUnits ||
      String(row.receipt_evidence_sha256) !== final.receiptEvidenceSha256 ||
      stableJson(row.receipt_evidence_json) !== stableJson(final.receiptEvidenceJson)) {
    fail('transaction_cost_terminal_conflict');
  }
}

export function modeledGasFeeUsdcUnits(gasUsed: unknown, effectiveGasPriceWei: unknown, policy: FeePolicySnapshot): string {
  const gas = uint(gasUsed);
  const price = uint(effectiveGasPriceWei);
  validateFeePolicy(policy);
  return (gas * price * BigInt(policy.ethUsdcRateNumerator) / BigInt(policy.ethUsdcRateDenominator)).toString();
}
