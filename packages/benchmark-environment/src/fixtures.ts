import { randomUUID, createHash } from 'node:crypto';
import {
  createPublicClient,
  createWalletClient,
  decodeEventLog,
  encodeFunctionData,
  http,
  MethodNotFoundRpcError,
  parseAbi,
  RpcRequestError,
  TransactionReceiptNotFoundError,
  type TransactionReceipt,
  type Address,
  type Hex,
} from 'viem';
import { base } from 'viem/chains';
import { AdminRpcFailure, adminRpc, assertAnvilIdentity, setAnvilBalance, type AdminRpcDiagnostic } from './chain.js';
import type { RuntimeManifest } from './manifest.js';

const transferAbi = parseAbi([
  'event Transfer(address indexed from,address indexed to,uint256 value)',
  'function transfer(address to,uint256 amount) returns (bool)',
] as const);
const balanceAbi = parseAbi(['function balanceOf(address) view returns (uint256)'] as const);

export type FixtureEnvironment = {
  id: string;
  adminRpcUrl: string;
  observerRpcUrl: string;
};

export type FixtureResult = {
  transactionHash: Hex;
  blockHash: Hex;
  amountUnits: string;
  payerTokenBefore: string;
  payerTokenAfter: string;
  donorTokenBefore: string;
  donorTokenAfter: string;
  payerNativeBalance: string;
  receiptObservation: ReceiptObservation;
  fixtureHash: string;
};

export type SafeRpcDiagnostic = {
  code: number;
  name: 'MethodNotFoundRpcError';
  messageCode: 'method_unavailable_during_fork_receipt_lookup';
};

export type ReceiptObservation = {
  pollCount: number;
  nullReceiptCount: number;
  sourceProxyMethodDeniedCount: number;
  firstUnavailableRpc: SafeRpcDiagnostic | null;
};

export type FixtureFailurePhase =
  | 'identity'
  | 'read_token_before'
  | 'validate_donor_funds'
  | 'set_donor_balance'
  | 'set_payer_balance'
  | 'impersonate'
  | 'pin_funding_timestamp'
  | 'reset_donor_balance'
  | 'send_transfer'
  | 'persist_transaction_hash'
  | 'stop_impersonating'
  | 'wait_receipt'
  | 'validate_receipt'
  | 'read_token_after'
  | 'validate_effects';

export class GenerationFixtureFailure extends Error {
  constructor(
    readonly phase: FixtureFailurePhase,
    readonly causeClass: string | null = null,
    readonly rpcDiagnostic: SafeRpcDiagnostic | null = null,
    readonly receiptObservation: ReceiptObservation | null = null,
    readonly adminRpcDiagnostic: AdminRpcDiagnostic | null = null,
  ) {
    super(`generation_fixture_${phase}`);
    this.name = 'GenerationFixtureFailure';
  }
}

const safeCauseNames = new Set([
  'AdminRpcFailure',
  'AbortError',
  'AggregateError',
  'BaseError',
  'Error',
  'FixtureReceiptPollTimeoutError',
  'HttpRequestError',
  'InternalRpcError',
  'InvalidInputRpcError',
  'MethodNotFoundRpcError',
  'MethodNotSupportedRpcError',
  'RequestError',
  'RpcRequestError',
  'TimeoutError',
  'TransactionNotFoundError',
  'TransactionReceiptNotFoundError',
  'TypeError',
  'UnknownRpcError',
  'WaitForTransactionReceiptTimeoutError',
]);

function safeCauseClass(error: unknown): string | null {
  const names: string[] = [];
  let current: unknown = error;
  for (let depth = 0; depth < 4 && current && typeof current === 'object'; depth += 1) {
    const record = current as { name?: unknown; cause?: unknown; constructor?: { name?: unknown } };
    const candidate = typeof record.name === 'string'
      ? record.name
      : typeof record.constructor?.name === 'string'
        ? record.constructor.name
        : 'OtherError';
    names.push(safeCauseNames.has(candidate) ? candidate : 'OtherError');
    current = record.cause;
  }
  return names.length ? names.join('>') : null;
}

function sourceProxyReceiptUnavailable(error: unknown): error is MethodNotFoundRpcError {
  if (!(error instanceof MethodNotFoundRpcError) || error.code !== -32601) return false;
  const upstream = error.cause;
  return upstream instanceof RpcRequestError && upstream.code === -32601;
}

function safeRpcDiagnostic(error: unknown): SafeRpcDiagnostic | null {
  if (!sourceProxyReceiptUnavailable(error)) return null;
  // Only emit the fixed code/name/category for the observed source-proxy denial.
  // The upstream message and RPC URL can contain arbitrary provider data and stay private.
  return { code: -32601, name: 'MethodNotFoundRpcError', messageCode: 'method_unavailable_during_fork_receipt_lookup' };
}

async function atFixturePhase<T>(phase: FixtureFailurePhase, work: () => Promise<T>): Promise<T> {
  try {
    return await work();
  } catch (error) {
    const receiptObservation = error instanceof FixtureReceiptPollTimeoutError ? error.observation : null;
    throw new GenerationFixtureFailure(phase, safeCauseClass(error), safeRpcDiagnostic(error), receiptObservation,
      error instanceof AdminRpcFailure ? error.diagnostic : null);
  }
}

class FixtureReceiptPollTimeoutError extends Error {
  constructor(readonly observation: ReceiptObservation) {
    super('The original fixture transaction receipt was not observed before the bounded deadline');
    this.name = 'FixtureReceiptPollTimeoutError';
  }
}

type OriginalReceiptReader = {
  getTransactionReceipt(input: { hash: Hex }): Promise<TransactionReceipt>;
};

async function pollForOriginalReceipt(
  publicClient: OriginalReceiptReader,
  transactionHash: Hex,
): Promise<{ receipt: TransactionReceipt; observation: ReceiptObservation }> {
  const deadline = Date.now() + 30_000;
  const observation: ReceiptObservation = {
    pollCount: 0,
    nullReceiptCount: 0,
    sourceProxyMethodDeniedCount: 0,
    firstUnavailableRpc: null,
  };
  while (true) {
    observation.pollCount += 1;
    try {
      // AICODE-NOTE: Retry only the read for this exact already-broadcast hash.
      // Anvil may ask the pinned upstream for a receipt while the local tx is not
      // visible yet; the source proxy correctly denies that unpinned receipt read.
      // Never create a replacement authorization or send a second fixture transfer.
      return { receipt: await publicClient.getTransactionReceipt({ hash: transactionHash }), observation };
    } catch (error) {
      if (error instanceof TransactionReceiptNotFoundError) {
        observation.nullReceiptCount += 1;
      } else if (sourceProxyReceiptUnavailable(error)) {
        observation.sourceProxyMethodDeniedCount += 1;
        observation.firstUnavailableRpc ??= safeRpcDiagnostic(error);
      } else {
        throw error;
      }
      if (Date.now() >= deadline) throw new FixtureReceiptPollTimeoutError(observation);
      await new Promise<void>((resolve) => setTimeout(resolve, 250));
    }
  }
}

function hexQuantity(value: string): Hex {
  return `0x${BigInt(value).toString(16)}`;
}

type PinnedSourceBlock = Pick<RuntimeManifest['source'], 'blockNumber' | 'blockHash' | 'blockTimestamp'>;

/** The fixture transfer may only be mined as the first block after its pinned source fork. */
export function pinnedFixtureFundingTimestamp(source: PinnedSourceBlock, head: unknown): bigint {
  if (!head || typeof head !== 'object' || Array.isArray(head)) {
    throw new Error('fixture_funding_head_not_pinned');
  }
  const block = head as Record<string, unknown>;
  if (typeof block.number !== 'string' || block.number.toLowerCase() !== source.blockNumber.toLowerCase()
    || typeof block.hash !== 'string' || block.hash.toLowerCase() !== source.blockHash.toLowerCase()
    || typeof block.timestamp !== 'string' || block.timestamp.toLowerCase() !== source.blockTimestamp.toLowerCase()) {
    throw new Error('fixture_funding_head_not_pinned');
  }
  const nextTimestamp = BigInt(source.blockTimestamp) + 1n;
  if (nextTimestamp > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('fixture_funding_timestamp_invalid');
  return nextTimestamp;
}

export async function fundGenerationFixture(
  manifest: RuntimeManifest,
  environment: FixtureEnvironment,
  payerAddress: Address,
  options: { onTransactionHash?: (transactionHash: Hex) => Promise<void> } = {},
): Promise<FixtureResult> {
  const amount = BigInt(manifest.funding.maxUsdcUnitsPerGeneration);
  if (amount <= 0n || amount > BigInt(manifest.funding.maxUsdcUnitsPerGeneration)) throw new Error('Generation fixture amount exceeds its manifest bound');
  await atFixturePhase('identity', () => assertAnvilIdentity(environment.adminRpcUrl, manifest));

  const donor = manifest.funding.donor as Address;
  const token = manifest.contracts.usdc.address as Address;
  const publicClient = createPublicClient({ chain: base, transport: http(environment.observerRpcUrl, { timeout: 15_000, retryCount: 0 }) });
  const { donorTokenBefore, payerTokenBefore } = await atFixturePhase('read_token_before', async () => ({
    donorTokenBefore: BigInt(await publicClient.readContract({ address: token, abi: balanceAbi, functionName: 'balanceOf', args: [donor] })),
    payerTokenBefore: BigInt(await publicClient.readContract({ address: token, abi: balanceAbi, functionName: 'balanceOf', args: [payerAddress] })),
  }));
  if (donorTokenBefore < amount) throw new GenerationFixtureFailure('validate_donor_funds');

  const nativeForGas = hexQuantity(manifest.funding.donorNativeEthWeiForGas);
  const payerNative = hexQuantity(manifest.funding.nativeEthWeiPerGeneration);
  await atFixturePhase('set_donor_balance', () => setAnvilBalance(environment.adminRpcUrl, donor, nativeForGas));
  await atFixturePhase('set_payer_balance', () => setAnvilBalance(environment.adminRpcUrl, payerAddress, payerNative));

  let impersonated = false;
  let transactionHash: Hex | null = null;
  let fundingTimestamp: bigint | null = null;
  try {
    const started = await atFixturePhase('impersonate', () => adminRpc(environment.adminRpcUrl, 'anvil_impersonateAccount', [donor]));
    if (started !== null) throw new GenerationFixtureFailure('impersonate');
    impersonated = true;
    fundingTimestamp = await atFixturePhase('pin_funding_timestamp', async () => {
      const head = await adminRpc(environment.adminRpcUrl, 'eth_getBlockByNumber', ['latest', false]);
      const timestamp = pinnedFixtureFundingTimestamp(manifest.source, head);
      const result = await adminRpc(environment.adminRpcUrl, 'evm_setNextBlockTimestamp', [Number(timestamp)]);
      if (result !== null) throw new Error('fixture_funding_timestamp_not_acknowledged');
      return timestamp;
    });
    const wallet = createWalletClient({ account: donor, chain: base, transport: http(environment.adminRpcUrl, { timeout: 20_000, retryCount: 0 }) });
    const data = encodeFunctionData({ abi: transferAbi, functionName: 'transfer', args: [payerAddress, amount] });
    transactionHash = await atFixturePhase('send_transfer', () => wallet.sendTransaction({
      account: donor,
      to: token,
      data,
      gas: 100_000n,
      maxFeePerGas: BigInt(manifest.feePolicy.baseFeeWei) + BigInt(manifest.feePolicy.priorityFeeWei),
      maxPriorityFeePerGas: BigInt(manifest.feePolicy.priorityFeeWei),
    }));
    // AICODE-NOTE: Preparation callers persist this original hash before receipt
    // polling. If observation is interrupted, reconcile this hash read-only; never resend.
    if (options.onTransactionHash) {
      await atFixturePhase('persist_transaction_hash', () => options.onTransactionHash!(transactionHash!));
    }
  } finally {
    if (impersonated) {
      const stopped = await atFixturePhase('stop_impersonating', () => adminRpc(environment.adminRpcUrl, 'anvil_stopImpersonatingAccount', [donor]));
      if (stopped !== null) throw new GenerationFixtureFailure('stop_impersonating');
    }
  }
  if (!transactionHash) throw new GenerationFixtureFailure('send_transfer');
  if (fundingTimestamp === null) throw new GenerationFixtureFailure('pin_funding_timestamp');

  const { receipt, observation: receiptObservation } = await atFixturePhase('wait_receipt', () => pollForOriginalReceipt(publicClient, transactionHash!));
  if (receipt.status !== 'success' || !receipt.blockHash) throw new GenerationFixtureFailure('validate_receipt');
  const transfer = receipt.logs.some((log) => {
    if (log.address.toLowerCase() !== token.toLowerCase()) return false;
    try {
      const decoded = decodeEventLog({ abi: transferAbi, eventName: 'Transfer', data: log.data, topics: log.topics }) as { args: unknown };
      const args = decoded.args as unknown as { from: Address; to: Address; value: bigint };
      return args.from.toLowerCase() === donor.toLowerCase()
        && args.to.toLowerCase() === payerAddress.toLowerCase()
        && args.value === amount;
    } catch {
      return false;
    }
  });
  const { payerTokenAfter, donorTokenAfter, payerNativeBalance } = await atFixturePhase('read_token_after', async () => ({
    payerTokenAfter: BigInt(await publicClient.readContract({ address: token, abi: balanceAbi, functionName: 'balanceOf', args: [payerAddress] })),
    donorTokenAfter: BigInt(await publicClient.readContract({ address: token, abi: balanceAbi, functionName: 'balanceOf', args: [donor] })),
    payerNativeBalance: BigInt(await publicClient.getBalance({ address: payerAddress, blockTag: 'latest' })),
  }));
  if (!transfer || payerTokenAfter - payerTokenBefore !== amount || donorTokenBefore - donorTokenAfter !== amount ||
      payerNativeBalance !== BigInt(manifest.funding.nativeEthWeiPerGeneration)) {
    throw new GenerationFixtureFailure('validate_effects');
  }
  // AICODE-NOTE: The transfer receipt retains the real donor gas cost. Resetting only the donor's
  // native balance is private fixture preparation so every trial begins from the same baseline;
  // it is not a live-chain gas refund and does not rewrite the recorded transaction effects.
  await atFixturePhase('reset_donor_balance', async () => {
    await setAnvilBalance(environment.adminRpcUrl, donor, nativeForGas);
    const [fundingHead, donorNativeBalance] = await Promise.all([
      publicClient.getBlock({ blockTag: 'latest' }),
      publicClient.getBalance({ address: donor, blockTag: 'latest' }),
    ]);
    if (fundingHead.hash?.toLowerCase() !== receipt.blockHash.toLowerCase()
      || fundingHead.number !== receipt.blockNumber
      || fundingHead.timestamp !== fundingTimestamp
      || donorNativeBalance !== BigInt(manifest.funding.donorNativeEthWeiForGas)) {
      throw new Error('fixture_post_funding_baseline_mismatch');
    }
  });
  const stableFixture = {
    sourceBlockHash: manifest.source.blockHash.toLowerCase(),
    donor: donor.toLowerCase(),
    token: token.toLowerCase(),
    amountUnits: amount.toString(),
    payerNativeWei: manifest.funding.nativeEthWeiPerGeneration,
    donorGasWei: manifest.funding.donorNativeEthWeiForGas,
  };
  const fixtureHash = createHash('sha256').update(JSON.stringify(stableFixture)).digest('hex');
  return {
    transactionHash,
    blockHash: receipt.blockHash,
    amountUnits: amount.toString(),
    payerTokenBefore: payerTokenBefore.toString(),
    payerTokenAfter: payerTokenAfter.toString(),
    donorTokenBefore: donorTokenBefore.toString(),
    donorTokenAfter: donorTokenAfter.toString(),
    payerNativeBalance: payerNativeBalance.toString(),
    receiptObservation,
    fixtureHash,
  };
}

/**
 * Read only the original fixture transaction after an interrupted preparation.
 * This never submits a transfer and never restores a generation's capability.
 */
export async function observeOriginalGenerationFixtureReceipt(
  manifest: RuntimeManifest,
  environment: FixtureEnvironment,
  payerAddress: Address,
  transactionHash: Hex,
): Promise<{ transactionHash: Hex; blockHash: Hex; amountUnits: string; receiptObservation: ReceiptObservation }> {
  const publicClient = createPublicClient({
    chain: base,
    transport: http(environment.observerRpcUrl, { timeout: 15_000, retryCount: 0 }),
  });
  const { receipt, observation: receiptObservation } = await atFixturePhase(
    'wait_receipt',
    () => pollForOriginalReceipt(publicClient, transactionHash),
  );
  if (receipt.status !== 'success' || !receipt.blockHash || receipt.transactionHash.toLowerCase() !== transactionHash.toLowerCase()) {
    throw new GenerationFixtureFailure('validate_receipt');
  }
  const donor = manifest.funding.donor as Address;
  const token = manifest.contracts.usdc.address as Address;
  const amount = BigInt(manifest.funding.maxUsdcUnitsPerGeneration);
  const transferObserved = receipt.logs.some((log) => {
    if (log.address.toLowerCase() !== token.toLowerCase()) return false;
    try {
      const decoded = decodeEventLog({ abi: transferAbi, eventName: 'Transfer', data: log.data, topics: log.topics }) as { args: unknown };
      const args = decoded.args as unknown as { from: Address; to: Address; value: bigint };
      return args.from.toLowerCase() === donor.toLowerCase()
        && args.to.toLowerCase() === payerAddress.toLowerCase()
        && args.value === amount;
    } catch {
      return false;
    }
  });
  if (!transferObserved) throw new GenerationFixtureFailure('validate_effects');
  return {
    transactionHash,
    blockHash: receipt.blockHash,
    amountUnits: amount.toString(),
    receiptObservation,
  };
}

export function newGenerationId(): string {
  return randomUUID();
}
