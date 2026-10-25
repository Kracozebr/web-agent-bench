/** SC-008 public local-proxy evidence collector for one bound hash. */
import type { ProbeContext } from './runner.js';

function object(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

function quantity(value: unknown, name: string): bigint {
  if (typeof value !== 'string' || !/^0x(?:0|[1-9a-f][0-9a-f]*)$/i.test(value)) {
    throw new Error(`probe_sc008_cost_${name}_invalid`);
  }
  return BigInt(value);
}

async function read<T>(
  ctx: ProbeContext,
  input: { operationId: string; variantId: string; method: string; params: unknown[]; label: string },
): Promise<T> {
  const result = await ctx.rpc.call<T>({
    url: ctx.env.localRpcUrl,
    endpointBoundary: 'local-chain-readonly-proxy',
    environmentId: ctx.env.envId,
    method: input.method,
    params: input.params,
    operationId: input.operationId,
    variantId: input.variantId,
    label: input.label,
  });
  return result.result;
}

export async function observeSc008OriginalCostRpc(
  ctx: ProbeContext,
  input: {
    operationId: string;
    variantId: string;
    transactionHash: `0x${string}`;
    facilitatorPayer?: `0x${string}`;
    participantPayer?: `0x${string}`;
    /** Use skip when another strict collector already recorded the receipt for this variant. */
    receiptMode?: 'read' | 'skip';
    /** Required with a skipped receipt when collecting facilitator block/balance history. */
    receiptBlockNumber?: string;
    label: string;
  },
): Promise<{ transaction: unknown; receipt: unknown; blockHistory?: Record<string, unknown>; sponsorHistory?: Record<string, unknown>; participantHistory?: Record<string, unknown> }> {
  const [transaction, receipt] = await Promise.all([
    read<unknown>(ctx, {
      operationId: input.operationId, variantId: input.variantId,
      method: 'eth_getTransactionByHash', params: [input.transactionHash], label: `${input.label}-transaction`,
    }),
    input.receiptMode === 'skip' ? Promise.resolve(null) : read<unknown>(ctx, {
      operationId: input.operationId, variantId: input.variantId,
      method: 'eth_getTransactionReceipt', params: [input.transactionHash], label: `${input.label}-receipt`,
    }),
  ]);
  const receiptRecord = object(receipt);
  if (!receiptRecord && input.receiptMode === 'skip' && typeof input.receiptBlockNumber !== 'string') {
    return { transaction, receipt };
  }
  const blockNumber = receiptRecord
    ? quantity(receiptRecord.blockNumber, 'receipt_block_number')
    : typeof input.receiptBlockNumber === 'string' && /^(?:0|[1-9][0-9]*)$/.test(input.receiptBlockNumber)
      ? BigInt(input.receiptBlockNumber)
      : (() => { throw new Error('probe_sc008_cost_receipt_block_number_missing'); })();
  if (blockNumber < 1n) throw new Error('probe_sc008_cost_receipt_block_number_invalid');
  const numberTag = `0x${blockNumber.toString(16)}`;
  const beforeNumberTag = `0x${(blockNumber - 1n).toString(16)}`;
  const [block, beforeBlock] = await Promise.all([
    read<unknown>(ctx, {
      operationId: input.operationId, variantId: input.variantId,
      method: 'eth_getBlockByNumber', params: [numberTag, true], label: `${input.label}-payer-block`,
    }),
    read<unknown>(ctx, {
      operationId: input.operationId, variantId: input.variantId,
      method: 'eth_getBlockByNumber', params: [beforeNumberTag, false], label: `${input.label}-payer-parent-block`,
    }),
  ]);
  const blockRecord = object(block);
  const parentRecord = object(beforeBlock);
  if (!blockRecord || !parentRecord || quantity(blockRecord.number, 'receipt_block_number') !== blockNumber ||
      quantity(parentRecord.number, 'receipt_parent_block_number') !== blockNumber - 1n ||
      typeof blockRecord.hash !== 'string' || !/^0x[0-9a-f]{64}$/i.test(blockRecord.hash) ||
      typeof blockRecord.parentHash !== 'string' || !/^0x[0-9a-f]{64}$/i.test(blockRecord.parentHash) ||
      quantity(blockRecord.baseFeePerGas, 'receipt_block_base_fee') < 0n ||
      typeof parentRecord.hash !== 'string' || blockRecord.parentHash.toLowerCase() !== parentRecord.hash.toLowerCase()) {
    throw new Error('probe_sc008_cost_receipt_block_invalid');
  }
  let sponsorHistory: Record<string, unknown> | undefined;
  if (input.facilitatorPayer) {
    const [beforeBalance, afterBalance] = await Promise.all([
      read<unknown>(ctx, {
        operationId: input.operationId, variantId: input.variantId,
        method: 'eth_getBalance', params: [input.facilitatorPayer, beforeNumberTag], label: `${input.label}-payer-balance-before`,
      }),
      read<unknown>(ctx, {
        operationId: input.operationId, variantId: input.variantId,
        method: 'eth_getBalance', params: [input.facilitatorPayer, numberTag], label: `${input.label}-payer-balance-after`,
      }),
    ]);
    if (typeof beforeBalance !== 'string' || typeof afterBalance !== 'string') {
      throw new Error('probe_sc008_cost_facilitator_history_incomplete');
    }
    quantity(beforeBalance, 'payer_balance_before');
    quantity(afterBalance, 'payer_balance_after');
    sponsorHistory = { block, beforeBlock, beforeBalance, afterBalance };
  }
  let participantHistory: Record<string, unknown> | undefined;
  if (input.participantPayer) {
    const [beforeBalance, afterBalance] = await Promise.all([
      read<unknown>(ctx, {
        operationId: input.operationId, variantId: input.variantId,
        method: 'eth_getBalance', params: [input.participantPayer, beforeNumberTag], label: `${input.label}-participant-native-balance-before`,
      }),
      read<unknown>(ctx, {
        operationId: input.operationId, variantId: input.variantId,
        method: 'eth_getBalance', params: [input.participantPayer, numberTag], label: `${input.label}-participant-native-balance-after`,
      }),
    ]);
    if (typeof beforeBalance !== 'string' || typeof afterBalance !== 'string') {
      throw new Error('probe_sc008_cost_participant_native_history_incomplete');
    }
    quantity(beforeBalance, 'participant_balance_before');
    quantity(afterBalance, 'participant_balance_after');
    participantHistory = {
      payer: input.participantPayer,
      beforeBalance,
      afterBalance,
      beforeBlockHash: parentRecord.hash,
      beforeBlockNumber: beforeNumberTag,
      afterBlockHash: blockRecord.hash,
      afterBlockNumber: numberTag,
    };
  }
  return {
    transaction, receipt, blockHistory: { block, beforeBlock },
    ...(sponsorHistory ? { sponsorHistory } : {}),
    ...(participantHistory ? { participantHistory } : {}),
  };
}
