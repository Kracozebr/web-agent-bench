import { randomUUID, timingSafeEqual } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { AsyncLocalStorage } from 'node:async_hooks';
import Fastify, { type FastifyRequest } from 'fastify';
import { x402Facilitator } from '@x402/core/facilitator';
import { InMemoryPendingSettlementStore } from '@x402/core/facilitator';
import { ExactEvmScheme } from '@x402/evm/exact/facilitator';
import { toFacilitatorEvmSigner } from '@x402/evm';
import { base } from 'viem/chains';
import {
  createWalletClient,
  decodeEventLog,
  encodeFunctionData,
  http,
  keccak256,
  MethodNotFoundRpcError,
  parseAbi,
  publicActions,
  RpcRequestError,
  TransactionReceiptNotFoundError,
  createPublicClient,
  type Address,
  type Hex,
  type TransactionReceipt,
  type VerifyTypedDataParameters,
} from 'viem';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { z } from 'zod';
import pg from 'pg';
import { assertAnvilIdentity, adminRpc, setAnvilBalance } from './chain.js';
import { readFacilitatorConfig, readRuntimeValue } from './config.js';
import { poolFor, sha256, withEnvironmentAdvisoryLock, withTransaction } from './db.js';
import { canonicalJson, loadManifest, type RuntimeManifest } from './manifest.js';
import { Sc006ReceiptReadFaults } from './sc006-receipt-fault.js';
import {
  finalizeTransactionCost,
  insertUnknownTransactionCost,
  type CostIdentity,
  type FeePolicySnapshot,
  type FinalCostObservation,
} from './transaction-costs.js';
import {
  RECORD_UNKNOWN_SETTLEMENT_OPERATION_SQL,
  RECORD_UNKNOWN_SETTLEMENT_PAYMENT_SQL,
} from './settlement-unknown-sql.js';
import { durableOfferRequirementsMatch, selectedPinnedResourceOffer } from './offers.js';
import { recordPrivateVerificationStarted } from './facilitator-verification.js';
import { buildSafeRequest } from './facilitator-observation.js';

type RequestContext = {
  envId: string;
  operationId: string;
  generationId: string;
  variantId: string;
  requestSha256: string;
  knownReceipt?: TransactionReceipt;
};
const settlementContext = new AsyncLocalStorage<RequestContext>();
const originalReceiptReadContext = new AsyncLocalStorage<Pick<RequestContext, 'envId' | 'operationId' | 'generationId'>>();
let facilitatorStartupPhase = 'manifest_load';
const receiptReadFaults = new Sc006ReceiptReadFaults();
const reconciliationTokenAbi = parseAbi([
  'event Transfer(address indexed from,address indexed to,uint256 value)',
  'function balanceOf(address) view returns (uint256)',
] as const);

const sameSecret = (candidate: unknown, expected: string): boolean => {
  if (typeof candidate !== 'string') return false;
  const left = Buffer.from(candidate);
  const right = Buffer.from(expected);
  return left.length === right.length && timingSafeEqual(left, right);
};

const isRecord = (value: unknown): value is Record<string, unknown> => Boolean(value && typeof value === 'object' && !Array.isArray(value));

function isForkReceiptMethodUnavailable(error: unknown): boolean {
  if (!(error instanceof MethodNotFoundRpcError) || error.code !== -32601) return false;
  const cause = error.cause;
  return cause instanceof RpcRequestError && cause.code === -32601;
}

async function waitForOriginalReceipt<T>(readOriginalHash: () => Promise<T>, timeoutMs: number): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  while (true) {
    try {
      return await readOriginalHash();
    } catch (error) {
      // AICODE-NOTE: Anvil can briefly delegate an as-yet-unindexed receipt lookup
      // to the pinned source proxy. Retry only these two observed not-found cases
      // for the SDK-returned hash; never scan for replacements or rebroadcast.
      if (!(error instanceof TransactionReceiptNotFoundError) && !isForkReceiptMethodUnavailable(error)) {
        throw new Error('original_transaction_receipt_lookup_failed');
      }
      const remaining = deadline - Date.now();
      if (remaining <= 0) throw new Error('original_transaction_receipt_unavailable');
      await new Promise<void>((resolve) => setTimeout(resolve, Math.min(250, remaining)));
    }
  }
}

const localObserverFetch: typeof fetch = async (input, init) => {
  const context = originalReceiptReadContext.getStore() ?? settlementContext.getStore();
  const faultResponse = receiptReadFaults.intercept(context, init?.body);
  if (faultResponse) return faultResponse;
  return fetch(input, init);
};

function hexQuantity(value: bigint): Hex {
  return `0x${value.toString(16)}`;
}

function isOriginalTransfer(
  receipt: TransactionReceipt,
  asset: Address,
  payer: Address,
  payTo: Address,
  amount: bigint,
): boolean {
  let matches = 0;
  for (const log of receipt.logs) {
    if (log.address.toLowerCase() !== asset.toLowerCase()) continue;
    try {
      const decoded = decodeEventLog({ abi: reconciliationTokenAbi, eventName: 'Transfer', data: log.data, topics: log.topics }) as { args: unknown };
      const args = decoded.args as { from: Address; to: Address; value: bigint };
      if (args.from.toLowerCase() === payer.toLowerCase() && args.to.toLowerCase() === payTo.toLowerCase() && args.value === amount) matches += 1;
    } catch {
      continue;
    }
  }
  return matches === 1;
}

function receiptObservation(receipt: TransactionReceipt, transactionHash: Hex): Record<string, unknown> {
  return {
    method: 'eth_getTransactionReceipt',
    params: [transactionHash],
    result: {
      transactionHash: receipt.transactionHash,
      from: receipt.from,
      to: receipt.to,
      blockHash: receipt.blockHash,
      blockNumber: hexQuantity(receipt.blockNumber),
      status: receipt.status === 'success' ? '0x1' : '0x0',
      gasUsed: hexQuantity(receipt.gasUsed),
      logs: receipt.logs.map((log) => ({ address: log.address, topics: log.topics, data: log.data })),
    },
  };
}

function tokenBalanceObservation(asset: Address, owner: Address, blockNumber: bigint, balance: bigint): Record<string, unknown> {
  return {
    method: 'eth_call',
    params: [
      { to: asset, data: encodeFunctionData({ abi: reconciliationTokenAbi, functionName: 'balanceOf', args: [owner] }) },
      hexQuantity(blockNumber),
    ],
    result: `0x${balance.toString(16).padStart(64, '0')}`,
  };
}

function safeProtocolResponse(value: unknown): Record<string, unknown> {
  if (!isRecord(value)) return { errorReason: 'facilitator_error' };
  const safe: Record<string, unknown> = {};
  if (typeof value.isValid === 'boolean') {
    safe.isValid = value.isValid;
    if (!value.isValid) {
      safe.invalidReason = 'verification_rejected';
      safe.invalidMessage = 'verification_rejected';
    }
  }
  if (typeof value.success === 'boolean') {
    safe.success = value.success;
    if (!value.success) {
      const category = value.errorReason === 'settlement_pending' ? 'settlement_pending' : 'settlement_failed';
      safe.errorReason = category;
      safe.errorMessage = category;
    }
  }
  if (typeof value.transaction === 'string' && /^0x[0-9a-f]{64}$/i.test(value.transaction)) safe.transaction = value.transaction;
  if (typeof value.network === 'string' && /^eip155:[1-9][0-9]*$/.test(value.network)) safe.network = value.network;
  if (typeof value.payer === 'string' && /^0x[0-9a-f]{40}$/i.test(value.payer)) safe.payer = value.payer.toLowerCase();
  return safe;
}
const FacilitatorRequest = z.object({
  x402Version: z.literal(2).optional(),
  paymentPayload: z.record(z.string(), z.unknown()),
  paymentRequirements: z.object({
    scheme: z.string(),
    network: z.string(),
    asset: z.string(),
    amount: z.string(),
    payTo: z.string(),
    maxTimeoutSeconds: z.number().int().positive(),
    extra: z.record(z.string(), z.unknown()).optional(),
  }).passthrough(),
}).strict();

function requestContext(request: FastifyRequest, config: { envId: string; serviceKey: string }, pool: pg.Pool): Promise<RequestContext | null> {
  const operationId = request.headers['x-bef-operation-id'];
  const generationId = request.headers['x-bef-generation'];
  const variantId = request.headers['x-bef-variant-id'];
  const requestSha256 = request.headers['x-bef-request-sha256'];
  if (!sameSecret(request.headers['x-bef-service-key'], config.serviceKey) ||
      typeof operationId !== 'string' || !z.string().uuid().safeParse(operationId).success ||
      typeof generationId !== 'string' || !z.string().uuid().safeParse(generationId).success ||
      typeof variantId !== 'string' || variantId.length > 64 ||
      typeof requestSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(requestSha256)) return Promise.resolve(null);
  return pool.query(
    `SELECT 1 FROM bef_generation g JOIN bef_operation o USING(env_id,generation_id)
      WHERE g.env_id=$1 AND g.generation_id=$2 AND g.status='active' AND g.expires_at>clock_timestamp()
        AND o.operation_id=$3 AND o.request_sha256=$4`,
    [config.envId, generationId, operationId, requestSha256],
  ).then((result) => result.rowCount ? { envId: config.envId, operationId, generationId, variantId, requestSha256 } : null);
}

function payloadDetails(payload: Record<string, unknown>): { payer: string | null; authorization: Record<string, unknown>; signature: string } {
  const root = isRecord(payload.payload) ? payload.payload : {};
  const authorization = isRecord(root.authorization) ? root.authorization : root;
  const signature = typeof root.signature === 'string' ? root.signature : typeof payload.signature === 'string' ? payload.signature : '';
  const from = authorization.from;
  return {
    payer: typeof from === 'string' && /^0x[0-9a-f]{40}$/i.test(from) ? from.toLowerCase() : null,
    authorization,
    signature,
  };
}

async function recordX402(pool: pg.Pool, context: RequestContext, phase: 'verify' | 'settle', body: z.infer<typeof FacilitatorRequest>, response: unknown, outcome: 'success' | 'rejected' | 'unknown' | 'error', transactionHash: string | null): Promise<void> {
  const request = buildSafeRequest(body, context.requestSha256);
  const safeResponse = safeProtocolResponse(response);
  const requestJson = JSON.stringify(request);
  const requestSha256 = sha256(canonicalJson(JSON.parse(requestJson) as Record<string, unknown>));
  const responseJson = JSON.stringify(safeResponse);
  await pool.query(
    `INSERT INTO bef_x402_observation(observation_id,env_id,generation_id,operation_id,variant_id,phase,request_sha256,safe_request,response_sha256,safe_response,outcome,transaction_hash)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10::jsonb,$11,$12)`,
    [randomUUID(), context.envId, context.generationId, context.operationId, context.variantId, phase,
      requestSha256, requestJson, sha256(canonicalJson(safeResponse)), responseJson, outcome, transactionHash],
  );
}

async function bindPayment(pool: pg.Pool, context: RequestContext, body: z.infer<typeof FacilitatorRequest>, facilitatorAddress: string): Promise<void> {
  const details = payloadDetails(body.paymentPayload);
  const generation = await pool.query<{ payer_address: string }>(
    `SELECT payer_address FROM bef_generation WHERE env_id=$1 AND generation_id=$2 AND status='active' AND expires_at>clock_timestamp()`,
    [context.envId, context.generationId],
  );
  if (!generation.rowCount || !details.payer || generation.rows[0]?.payer_address.toLowerCase() !== details.payer.toLowerCase()) {
    throw new Error('Payment payer is not the generation-scoped participant');
  }
  const authorizationHash = sha256(JSON.stringify({ authorization: details.authorization, signature: details.signature }));
  const operation = await pool.query(
    `UPDATE bef_operation SET authorization_sha256=$2,status='settling'
      WHERE operation_id=$1 AND env_id=$3 AND generation_id=$4 AND status IN ('awaiting_payment','verifying')
        AND (authorization_sha256 IS NULL OR authorization_sha256=$2)
      RETURNING operation_id`,
    [context.operationId, authorizationHash, context.envId, context.generationId],
  );
  if (!operation.rowCount) throw new Error('Payment does not match the durable operation authorization');
  const payment = await pool.query(
    `INSERT INTO bef_payment(payment_id,operation_id,env_id,generation_id,authorization_sha256,payer_address,network,asset_address,amount_units,facilitator_address,transaction_hash,receipt_status)
     SELECT $1,o.operation_id,o.env_id,o.generation_id,$2,$3,$4,$5,$6,$7,o.transaction_hash,o.receipt_status
       FROM bef_operation o WHERE o.operation_id=$8 AND o.env_id=$9 AND o.generation_id=$10
     ON CONFLICT(operation_id) DO UPDATE SET
       payer_address=COALESCE(bef_payment.payer_address,EXCLUDED.payer_address),
       facilitator_address=EXCLUDED.facilitator_address,
       transaction_hash=COALESCE(bef_payment.transaction_hash,EXCLUDED.transaction_hash)
     WHERE bef_payment.authorization_sha256=EXCLUDED.authorization_sha256
     RETURNING payment_id`,
    [randomUUID(), authorizationHash, details.payer, body.paymentRequirements.network, body.paymentRequirements.asset.toLowerCase(),
      body.paymentRequirements.amount, facilitatorAddress.toLowerCase(), context.operationId, context.envId, context.generationId],
  );
  if (!payment.rowCount) throw new Error('Payment authorization conflicts with the durable operation');
}

function facilitatorCostIdentity(
  context: RequestContext,
  transactionHash: string,
  payerAddress: string,
  manifestSha256: string,
  feePolicy: FeePolicySnapshot,
): CostIdentity {
  return {
    operationId: context.operationId,
    envId: context.envId,
    generationId: context.generationId,
    transactionHash,
    payerAddress,
    payerRole: 'facilitator',
    manifestSha256,
    feePolicy,
    selectedPrincipalAsset: null,
    selectedPrincipalUnits: null,
  };
}

async function persistBroadcastHash(
  pool: pg.Pool,
  context: RequestContext,
  txHash: string,
  payerAddress: string,
  manifestSha256: string,
  feePolicy: FeePolicySnapshot,
): Promise<void> {
  if (!/^0x[0-9a-f]{64}$/i.test(txHash)) throw new Error('Facilitator transaction hash is invalid');
  await withEnvironmentAdvisoryLock(pool, context.envId, () => withTransaction(pool, async (client) => {
    const operation = await client.query(
      `UPDATE bef_operation SET transaction_hash=$2,receipt_status='unknown',status='settling'
        WHERE operation_id=$1 AND env_id=$3 AND generation_id=$4 AND status='settling'
          AND receipt_status <> 'success' AND (transaction_hash IS NULL OR transaction_hash=$2)
        RETURNING operation_id`,
      [context.operationId, txHash, context.envId, context.generationId],
    );
    if (!operation.rowCount) throw new Error('Transaction hash conflicts with the durable operation');
    const payment = await client.query(
      `UPDATE bef_payment SET transaction_hash=$2,receipt_status='unknown',observed_at=clock_timestamp()
        WHERE operation_id=$1 AND env_id=$3 AND generation_id=$4
          AND (transaction_hash IS NULL OR transaction_hash=$2) AND receipt_status <> 'success'
        RETURNING operation_id`,
      [context.operationId, txHash, context.envId, context.generationId],
    );
    if (!payment.rowCount) throw new Error('Facilitator transaction hash has no matching durable payment');
    await insertUnknownTransactionCost(client, facilitatorCostIdentity(
      context, txHash, payerAddress, manifestSha256, feePolicy,
    ));
  }));
}

function supportedRequestChecks(body: z.infer<typeof FacilitatorRequest>, manifest: RuntimeManifest, facilitatorAddress: string, selectedAmount: string): { supported: boolean; checks: Record<string, boolean> } {
  const requirements = body.paymentRequirements;
  const acceptedValue = body.paymentPayload.accepted;
  const accepted = isRecord(acceptedValue) ? acceptedValue : {};
  const acceptedExtra = isRecord(accepted.extra) ? accepted.extra : {};
  const auth = payloadDetails(body.paymentPayload).authorization;
  const equalAddress = (left: unknown, right: unknown): boolean =>
    typeof left === 'string' && typeof right === 'string' && /^0x[0-9a-f]{40}$/i.test(left) && /^0x[0-9a-f]{40}$/i.test(right) && left.toLowerCase() === right.toLowerCase();
  const checks: Record<string, boolean> = {
    requestVersionMatchesPayload: body.x402Version === undefined || body.x402Version === body.paymentPayload.x402Version,
    payloadVersionV2: body.paymentPayload.x402Version === 2,
    acceptedIsRecord: isRecord(acceptedValue),
    acceptedSchemeMatchesRequirement: accepted.scheme === requirements.scheme,
    acceptedNetworkMatchesRequirement: accepted.network === requirements.network,
    acceptedAssetMatchesRequirement: equalAddress(accepted.asset, requirements.asset),
    acceptedAmountMatchesRequirement: accepted.amount === requirements.amount,
    acceptedPayToMatchesRequirement: equalAddress(accepted.payTo, requirements.payTo),
    acceptedExtraIsRecord: isRecord(accepted.extra),
    acceptedTransferMethodPinned: acceptedExtra.assetTransferMethod === manifest.x402.assetTransferMethod,
    acceptedPaymentFlowAuthorization: acceptedExtra.paymentFlow === 'authorization',
    acceptedDomainNamePinned: acceptedExtra.name === manifest.x402.eip712Domain.name,
    acceptedDomainVersionPinned: acceptedExtra.version === manifest.x402.eip712Domain.version,
    requirementNetworkPinned: requirements.network === manifest.x402.network,
    requirementSchemePinned: requirements.scheme === manifest.x402.scheme,
    requirementAssetPinned: equalAddress(requirements.asset, manifest.x402.asset),
    requirementAmountPinned: requirements.amount === selectedAmount,
    requirementPayToIsFacilitator: equalAddress(requirements.payTo, facilitatorAddress),
    requirementTimeoutBounded: requirements.maxTimeoutSeconds <= manifest.x402.maxTimeoutSeconds,
    requirementTransferMethodPinned: requirements.extra?.assetTransferMethod === manifest.x402.assetTransferMethod,
    requirementPaymentFlowAuthorization: requirements.extra?.paymentFlow === 'authorization',
    requirementDomainNamePinned: requirements.extra?.name === manifest.x402.eip712Domain.name,
    requirementDomainVersionPinned: requirements.extra?.version === manifest.x402.eip712Domain.version,
    authorizationFromIsAddress: typeof auth.from === 'string' && /^0x[0-9a-f]{40}$/i.test(auth.from),
    authorizationToMatchesRequirement: equalAddress(auth.to, requirements.payTo),
    authorizationValueMatchesAmount: typeof auth.value === 'string' && auth.value === requirements.amount,
    authorizationValidAfterIsString: typeof auth.validAfter === 'string',
    authorizationValidBeforeIsString: typeof auth.validBefore === 'string',
    authorizationNonceIsHex32: typeof auth.nonce === 'string' && /^0x[0-9a-f]{64}$/i.test(auth.nonce),
  };
  return { supported: Object.values(checks).every(Boolean), checks };
}

async function setPrivateNativeBalance(rpcUrl: string, address: `0x${string}`, value: string): Promise<void> {
  await setAnvilBalance(rpcUrl, address, value);
}

export async function startFacilitator(): Promise<void> {
  facilitatorStartupPhase = 'manifest_validation';
  const { manifest, sha256: manifestSha256 } = await loadManifest();
  const config = readFacilitatorConfig(manifest);
  const nodeVersion = process.version;
  if (nodeVersion !== `v${manifest.local.nodeVersion}`) throw new Error('Facilitator Node version does not match the manifest');
  facilitatorStartupPhase = 'dependency_validation';
  const readInstalledVersion = async (name: string): Promise<string> => {
    const metadata = JSON.parse(await readFile(resolve(process.cwd(), 'packages/benchmark-environment/node_modules', name, 'package.json'), 'utf8')) as { version?: unknown };
    if (typeof metadata.version !== 'string') throw new Error(`Facilitator installed dependency metadata unavailable: ${name}`);
    return metadata.version;
  };
  const dependencyVersions = {
    x402Core: await readInstalledVersion('@x402/core'),
    x402Evm: await readInstalledVersion('@x402/evm'),
    x402Fastify: await readInstalledVersion('@x402/fastify'),
    viem: await readInstalledVersion('viem'),
  };
  if (dependencyVersions.x402Core !== manifest.local.versions.x402Core ||
      dependencyVersions.x402Evm !== manifest.local.versions.x402Evm ||
      dependencyVersions.x402Fastify !== manifest.local.versions.x402Fastify ||
      dependencyVersions.viem !== manifest.local.versions.viem) {
    throw new Error('Facilitator installed dependencies differ from the manifest pins');
  }
  facilitatorStartupPhase = 'database_connection';
  const connectionString = readRuntimeValue('BEF_DATABASE_URL', 1);
  if (new URL(connectionString).hostname !== manifest.local.databaseHost) throw new Error('Facilitator database host is not the manifest-declared local service');
  const database = poolFor(connectionString);
  await database.query('SELECT 1');
  const privateKey = generatePrivateKey();
  const account = privateKeyToAccount(privateKey);
  facilitatorStartupPhase = 'anvil_identity';
  await assertAnvilIdentity(config.rpcUrl, manifest);
  const fundFacilitator = async (): Promise<void> => {
    await assertAnvilIdentity(config.rpcUrl, manifest);
    const balance = '0x' + BigInt(manifest.funding.facilitatorNativeEthWei).toString(16);
    await setPrivateNativeBalance(config.rpcUrl, account.address, balance);
  };
  facilitatorStartupPhase = 'private_funding';
  await fundFacilitator();

  facilitatorStartupPhase = 'protocol_initialization';
  const pendingSettlementStore = new InMemoryPendingSettlementStore();
  const activeSettlementRequests = new Set<string>();
  const fetchFn: typeof fetch = async (input, init) => {
    let parsed: unknown;
    try { parsed = JSON.parse(typeof init?.body === 'string' ? init.body : 'null'); } catch { parsed = null; }
    const requests = Array.isArray(parsed) ? parsed : [parsed];
    for (const item of requests) {
      if (!isRecord(item) || typeof item.method !== 'string') continue;
      if (item.method === 'eth_sendRawTransaction') {
        const context = settlementContext.getStore();
        const params = item.params;
        if (!context || !activeSettlementRequests.has(context.operationId) || !Array.isArray(params) ||
            typeof params[0] !== 'string' || !/^0x[0-9a-f]+$/i.test(params[0])) throw new Error('Unscoped local facilitator broadcast was blocked');
        await assertAnvilIdentity(config.rpcUrl, manifest);
        const transactionHash = keccak256(params[0] as Hex);
        await persistBroadcastHash(database, context, transactionHash, account.address, manifestSha256, manifest.feePolicy);
        receiptReadFaults.recordBroadcast(context, transactionHash);
      } else if (item.method.startsWith('eth_send')) {
        throw new Error('Only a locally signed facilitator transaction is permitted');
      }
    }
    return fetch(input, init);
  };
  const wallet = createWalletClient({ account, chain: base, transport: http(config.rpcUrl, { fetchFn, timeout: 30_000, retryCount: 0 }) });
  const signerClient = wallet.extend(publicActions);
  const localObserver = createPublicClient({ chain: base, transport: http(config.rpcUrl, { timeout: 30_000, retryCount: 0, fetchFn: localObserverFetch }) });
  const observeFacilitatorCost = async (
    transactionHash: Hex,
    payerAddress: Address,
    receipt: TransactionReceipt,
  ): Promise<FinalCostObservation | null> => {
    if (receipt.transactionHash.toLowerCase() !== transactionHash.toLowerCase() ||
        receipt.from.toLowerCase() !== payerAddress.toLowerCase() || receipt.blockNumber < 1n) {
      throw new Error('Facilitator receipt identity conflict');
    }
    let transaction;
    let receiptBlock;
    let beforeBlock;
    let beforeBalance: bigint;
    let afterBalance: bigint;
    try {
      transaction = await localObserver.getTransaction({ hash: transactionHash });
      if (transaction.hash.toLowerCase() !== transactionHash.toLowerCase() ||
          transaction.from.toLowerCase() !== payerAddress.toLowerCase() ||
          transaction.blockNumber !== receipt.blockNumber || transaction.blockHash?.toLowerCase() !== receipt.blockHash.toLowerCase()) {
        throw new Error('Facilitator transaction and receipt binding conflict');
      }
      const beforeNumber = receipt.blockNumber - 1n;
      [receiptBlock, beforeBlock, beforeBalance, afterBalance] = await Promise.all([
        localObserver.getBlock({ blockNumber: receipt.blockNumber, includeTransactions: true }),
        localObserver.getBlock({ blockNumber: beforeNumber }),
        localObserver.getBalance({ address: payerAddress, blockNumber: beforeNumber }),
        localObserver.getBalance({ address: payerAddress, blockNumber: receipt.blockNumber }),
      ]);
    } catch (error) {
      if (error instanceof Error && /binding conflict/.test(error.message)) throw error;
      return null;
    }
    if (!receiptBlock.hash || !receiptBlock.parentHash || receiptBlock.baseFeePerGas === null ||
        receiptBlock.hash.toLowerCase() !== receipt.blockHash.toLowerCase() ||
        receiptBlock.number !== receipt.blockNumber || beforeBlock.number !== receipt.blockNumber - 1n ||
        beforeBlock.hash.toLowerCase() !== receiptBlock.parentHash.toLowerCase()) {
      throw new Error('Facilitator historical block identity conflict');
    }
    const transactions = receiptBlock.transactions.map((entry) => {
      if (typeof entry === 'string') throw new Error('Facilitator receipt block transactions are not expanded');
      return { hash: entry.hash, from: entry.from };
    });
    return {
      transaction: {
        hash: transaction.hash,
        from: transaction.from,
        blockHash: transaction.blockHash,
        blockNumber: transaction.blockNumber,
        value: transaction.value,
        maxFeePerGas: transaction.maxFeePerGas,
        maxPriorityFeePerGas: transaction.maxPriorityFeePerGas,
      },
      receipt: {
        transactionHash: receipt.transactionHash,
        from: receipt.from,
        status: receipt.status,
        blockHash: receipt.blockHash,
        blockNumber: receipt.blockNumber,
        gasUsed: receipt.gasUsed,
        effectiveGasPrice: receipt.effectiveGasPrice,
      },
      receiptBlockBaseFeePerGas: receiptBlock.baseFeePerGas,
      payerBlock: {
        hash: receiptBlock.hash,
        number: receiptBlock.number,
        parentHash: receiptBlock.parentHash,
        baseFeePerGas: receiptBlock.baseFeePerGas,
        transactions,
      },
      payerNativeBalanceBefore: {
        blockHash: beforeBlock.hash,
        blockNumber: beforeBlock.number,
        balanceWei: beforeBalance,
      },
      payerNativeBalanceAfter: {
        blockHash: receiptBlock.hash,
        blockNumber: receiptBlock.number,
        balanceWei: afterBalance,
      },
    };
  };
  const finalizeFacilitatorCost = async (
    context: RequestContext,
    transactionHash: Hex,
    payerAddress: Address,
    receipt: TransactionReceipt,
  ): Promise<boolean> => {
    const observation = await observeFacilitatorCost(transactionHash, payerAddress, receipt);
    if (!observation) return false;
    const identity = facilitatorCostIdentity(context, transactionHash, payerAddress, manifestSha256, manifest.feePolicy);
    await withEnvironmentAdvisoryLock(database, context.envId, () => withTransaction(database, (client) =>
      finalizeTransactionCost(client, identity, observation)));
    return true;
  };
  const signer = toFacilitatorEvmSigner({
    address: account.address,
    readContract: signerClient.readContract,
    verifyTypedData: (args) => signerClient.verifyTypedData(args as VerifyTypedDataParameters),
    writeContract: (args) => signerClient.writeContract({
      ...args,
      maxFeePerGas: BigInt(manifest.feePolicy.baseFeeWei) + BigInt(manifest.feePolicy.priorityFeeWei),
      maxPriorityFeePerGas: BigInt(manifest.feePolicy.priorityFeeWei),
    } as Parameters<typeof signerClient.writeContract>[0]),
    sendTransaction: (args) => signerClient.sendTransaction({
      ...args,
      maxFeePerGas: BigInt(manifest.feePolicy.baseFeeWei) + BigInt(manifest.feePolicy.priorityFeeWei),
      maxPriorityFeePerGas: BigInt(manifest.feePolicy.priorityFeeWei),
    } as Parameters<typeof signerClient.sendTransaction>[0]),
    waitForTransactionReceipt: async (args) => {
      const receipt = await waitForOriginalReceipt(
        () => localObserver.getTransactionReceipt({ hash: args.hash }),
        manifest.x402.confirmationTimeoutMs,
      );
      const context = settlementContext.getStore();
      if (!context || receipt.transactionHash.toLowerCase() !== args.hash.toLowerCase()) {
        throw new Error('Facilitator receipt is not scoped to the active settlement');
      }
      if (context.knownReceipt && context.knownReceipt.transactionHash.toLowerCase() !== receipt.transactionHash.toLowerCase()) {
        throw new Error('Facilitator captured conflicting receipts');
      }
      context.knownReceipt = receipt;
      return receipt;
    },
    getCode: signerClient.getCode,
  }, { confirmationTimeoutMs: manifest.x402.confirmationTimeoutMs });
  const facilitator = new x402Facilitator().register(manifest.x402.network, new ExactEvmScheme(signer, { eip6492AllowedFactories: [], pendingSettlementStore }));

  const app = Fastify({ logger: false, bodyLimit: manifest.guardrails.maxHttpRequestBytes, disableRequestLogging: true });
  const packageVersion = JSON.parse(await (await import('node:fs/promises')).readFile(new URL('../package.json', import.meta.url), 'utf8')).version as string;
  app.get('/healthz', async () => ({
    status: 'ok', envId: config.envId, chainId: manifest.local.chainId, sdk: manifest.x402.version,
    facilitatorNodeVersion: nodeVersion, facilitatorPackageVersion: packageVersion,
    dependencyVersions,
  }));
  app.get('/internal/admin/identity', async (request, reply) => {
    if (!sameSecret(request.headers['x-bef-service-key'], config.serviceKey)) return reply.code(403).send({ error: 'forbidden' });
    try {
      return {
        envId: config.envId, address: account.address, network: manifest.x402.network, manifestSha256,
        facilitatorNodeVersion: nodeVersion, facilitatorPackageVersion: packageVersion,
        dependencyVersions,
        ...(await assertAnvilIdentity(config.rpcUrl, manifest)),
      };
    } catch {
      return reply.code(503).send({ error: 'private_anvil_identity_unavailable' });
    }
  });
  app.post('/internal/admin/sc006/receipt-read-fault/arm', async (request, reply) => {
    if (!sameSecret(request.headers['x-bef-service-key'], config.serviceKey)) return reply.code(403).send({ error: 'forbidden' });
    const parsed = z.object({
      operationId: z.string().uuid(), generationId: z.string().uuid(), ttlMs: z.number().int().min(500).max(15_000),
    }).strict().safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: 'invalid_receipt_fault_request' });
    const current = receiptReadFaults.status(parsed.data.operationId);
    if (current?.armed) return reply.code(409).send({ error: 'receipt_fault_already_armed' });
    const operation = await database.query(
      `SELECT 1 FROM bef_operation WHERE env_id=$1 AND generation_id=$2 AND operation_id=$3
         AND status IN ('awaiting_payment','verifying','settling','settlement_unknown')`,
      [config.envId, parsed.data.generationId, parsed.data.operationId],
    );
    if (!operation.rowCount) return reply.code(404).send({ error: 'receipt_fault_operation_not_found' });
    try {
      return receiptReadFaults.arm({ envId: config.envId, generationId: parsed.data.generationId, operationId: parsed.data.operationId }, parsed.data.ttlMs);
    } catch {
      return reply.code(409).send({ error: 'receipt_fault_already_armed' });
    }
  });
  app.get('/internal/admin/sc006/receipt-read-fault/status/:operationId', async (request, reply) => {
    if (!sameSecret(request.headers['x-bef-service-key'], config.serviceKey)) return reply.code(403).send({ error: 'forbidden' });
    const parsed = z.string().uuid().safeParse((request.params as { operationId?: unknown }).operationId);
    if (!parsed.success) return reply.code(400).send({ error: 'invalid_receipt_fault_operation' });
    const fault = receiptReadFaults.status(parsed.data);
    if (!fault || fault.envId !== config.envId) return reply.code(404).send({ error: 'receipt_fault_not_found' });
    return fault;
  });
  app.post('/internal/admin/sc006/receipt-read-fault/restore', async (request, reply) => {
    if (!sameSecret(request.headers['x-bef-service-key'], config.serviceKey)) return reply.code(403).send({ error: 'forbidden' });
    const parsed = z.object({ operationId: z.string().uuid(), generationId: z.string().uuid() }).strict().safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: 'invalid_receipt_fault_restore_request' });
    const fault = receiptReadFaults.restore(parsed.data.operationId, parsed.data.generationId);
    if (!fault || fault.envId !== config.envId) return reply.code(404).send({ error: 'receipt_fault_not_found' });
    return fault;
  });
  app.post('/internal/admin/recover-after-fork-reset', async (request, reply) => {
    if (!sameSecret(request.headers['x-bef-service-key'], config.serviceKey)) return reply.code(403).send({ error: 'forbidden' });
    const body = request.body as { manifestSha256?: unknown };
    if (body?.manifestSha256 !== manifestSha256) return reply.code(409).send({ error: 'manifest_pin_mismatch' });
    const unresolved = await database.query(
      `SELECT 1 FROM bef_operation WHERE env_id=$1 AND status IN ('settling','settlement_unknown') LIMIT 1`,
      [config.envId],
    );
    if (unresolved.rowCount) return reply.code(409).send({ error: 'unresolved_operation_blocks_reset' });
    try {
      await assertAnvilIdentity(config.rpcUrl, manifest);
      await fundFacilitator();
      const snapshot = pendingSettlementStore.entriesSnapshot();
      for (const key of Object.keys(snapshot)) await pendingSettlementStore.delete(key);
      return { status: 'ready', envId: config.envId, address: account.address, fundedWei: manifest.funding.facilitatorNativeEthWei };
    } catch {
      return reply.code(503).send({ error: 'private_fork_recovery_failed' });
    }
  });
  app.post('/internal/admin/reconcile-original-settlement', async (request, reply) => {
    if (!sameSecret(request.headers['x-bef-service-key'], config.serviceKey)) return reply.code(403).send({ error: 'forbidden' });
    const parsed = z.object({ operationId: z.string().uuid() }).strict().safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: 'invalid_reconciliation_request' });

    const client = await database.connect();
    let inTransaction = false;
    const finish = async (body: Record<string, unknown>, status = 200) => {
      await client.query('COMMIT');
      inTransaction = false;
      return reply.code(status).send(body);
    };
    try {
      await client.query('BEGIN');
      inTransaction = true;
      // Use the same environment key as reset and settlement routes, and keep the
      // lock and guarded durable updates on this transaction's connection.
      await client.query(`SELECT pg_advisory_xact_lock(hashtext('bef-runtime-environment'), hashtext($1))`, [config.envId]);
      type OriginalPaymentRow = {
        operation_id: string;
        generation_id: string;
        request_sha256: string;
        operation_status: string;
        operation_transaction_hash: string | null;
        operation_authorization_sha256: string | null;
        authorization_sha256: string;
        payer_address: string | null;
        generation_payer_address: string | null;
        network: string;
        asset_address: string;
        amount_units: string;
        facilitator_address: string | null;
        payment_transaction_hash: string | null;
      };
      const selected = await client.query<OriginalPaymentRow>(
        `SELECT o.operation_id,o.generation_id,o.request_sha256,o.status AS operation_status,o.transaction_hash AS operation_transaction_hash,
                o.authorization_sha256 AS operation_authorization_sha256,g.payer_address AS generation_payer_address,
                p.authorization_sha256,p.payer_address,p.network,p.asset_address,p.amount_units,
                p.facilitator_address,p.transaction_hash AS payment_transaction_hash
           FROM bef_operation o JOIN bef_payment p
             ON p.operation_id=o.operation_id AND p.env_id=o.env_id AND p.generation_id=o.generation_id
           JOIN bef_generation g ON g.env_id=o.env_id AND g.generation_id=o.generation_id
          WHERE o.env_id=$1 AND o.operation_id=$2
          FOR UPDATE OF o,p`,
        [config.envId, parsed.data.operationId],
      );
      if (!selected.rowCount) return await finish({ accepted: false, reasonCode: 'original_payment_not_found' }, 404);
      const original = selected.rows[0]!;
      const durable = {
        operationId: original.operation_id,
        generationId: original.generation_id,
        operationStatus: original.operation_status,
        operationAuthorizationSha256: original.operation_authorization_sha256,
        authorizationSha256: original.authorization_sha256,
        payerAddress: original.payer_address,
        generationPayerAddress: original.generation_payer_address,
        network: original.network,
        assetAddress: original.asset_address,
        amountUnits: original.amount_units,
        originalPayToAddress: original.facilitator_address,
        operationTransactionHash: original.operation_transaction_hash,
        paymentTransactionHash: original.payment_transaction_hash,
      };
      if (original.operation_status !== 'settlement_unknown' && original.operation_status !== 'settling') {
        return await finish({ accepted: false, reasonCode: 'operation_not_unresolved', deliveryState: 'not_changed', durable });
      }
      const delivery = await client.query('SELECT 1 FROM bef_delivery WHERE operation_id=$1 LIMIT 1', [original.operation_id]);
      if (delivery.rowCount) return await finish({ accepted: false, reasonCode: 'delivery_already_recorded', deliveryState: 'already_recorded', durable }, 409);

      const transactionHashValue = original.operation_transaction_hash;
      const validOriginalBinding = typeof transactionHashValue === 'string' && /^0x[0-9a-f]{64}$/i.test(transactionHashValue) &&
        original.payment_transaction_hash?.toLowerCase() === transactionHashValue.toLowerCase() &&
        original.operation_authorization_sha256?.toLowerCase() === original.authorization_sha256.toLowerCase() &&
        typeof original.payer_address === 'string' && /^0x[0-9a-f]{40}$/i.test(original.payer_address) &&
        original.generation_payer_address?.toLowerCase() === original.payer_address.toLowerCase() &&
        typeof original.facilitator_address === 'string' && /^0x[0-9a-f]{40}$/i.test(original.facilitator_address) &&
        original.network === manifest.x402.network && original.asset_address.toLowerCase() === manifest.x402.asset.toLowerCase() &&
        original.amount_units === manifest.x402.amount && /^[0-9a-f]{64}$/i.test(original.authorization_sha256);
      if (!validOriginalBinding) {
        return await finish({ accepted: false, reasonCode: 'durable_payment_binding_mismatch', deliveryState: 'not_changed', durable });
      }
      const txHash = transactionHashValue as Hex;
      const asset = original.asset_address as Address;
      const payer = original.payer_address as Address;
      // This value is deliberately read from the original payment row. A facilitator
      // process restart can create a different signer; recovery must keep the old payTo.
      const originalPayTo = original.facilitator_address as Address;
      let receipt: TransactionReceipt;
      try {
        await assertAnvilIdentity(config.rpcUrl, manifest);
        receipt = await originalReceiptReadContext.run(
          { envId: config.envId, operationId: original.operation_id, generationId: original.generation_id },
          () => waitForOriginalReceipt(
            () => localObserver.getTransactionReceipt({ hash: txHash }),
            Math.min(manifest.x402.confirmationTimeoutMs, 30_000),
          ),
        );
      } catch {
        return await finish({ accepted: false, reasonCode: 'original_receipt_unavailable', deliveryState: 'not_changed', durable });
      }
      const receiptProof = receiptObservation(receipt, txHash);
      if (receipt.transactionHash.toLowerCase() !== txHash.toLowerCase()) {
        return await finish({ accepted: false, reasonCode: 'original_receipt_hash_mismatch', deliveryState: 'not_changed', durable, observations: { receipt: receiptProof } });
      }
      if (receipt.from.toLowerCase() !== originalPayTo.toLowerCase() || receipt.to?.toLowerCase() !== asset.toLowerCase() ||
          !/^0x[0-9a-f]{64}$/i.test(receipt.blockHash) || receipt.blockNumber < 1n) {
        return await finish({ accepted: false, reasonCode: 'original_receipt_transaction_binding_mismatch', deliveryState: 'not_changed', durable, observations: { receipt: receiptProof } });
      }
      const reconciliationContext: RequestContext = {
        envId: config.envId,
        operationId: original.operation_id,
        generationId: original.generation_id,
        variantId: 'sc006-reconciliation',
        requestSha256: original.request_sha256,
      };
      const costIdentity = facilitatorCostIdentity(
        reconciliationContext, txHash, originalPayTo, manifestSha256, manifest.feePolicy,
      );
      await insertUnknownTransactionCost(client, costIdentity);
      const costObservation = await observeFacilitatorCost(txHash, originalPayTo, receipt);
      if (costObservation) await finalizeTransactionCost(client, costIdentity, costObservation);
      if (receipt.status === 'reverted') {
        const paymentUpdate = await client.query(
          `UPDATE bef_payment SET transaction_hash=$4,receipt_status='reverted',observed_at=clock_timestamp()
            WHERE operation_id=$1 AND env_id=$2 AND generation_id=$3 AND transaction_hash=$4 AND authorization_sha256=$5`,
          [original.operation_id, config.envId, original.generation_id, txHash, original.authorization_sha256],
        );
        const operationUpdate = await client.query(
          `UPDATE bef_operation SET transaction_hash=$4,receipt_status='reverted',status='reverted',completed_at=clock_timestamp()
            WHERE operation_id=$1 AND env_id=$2 AND generation_id=$3 AND transaction_hash=$4 AND status IN ('settling','settlement_unknown')`,
          [original.operation_id, config.envId, original.generation_id, txHash],
        );
        if (paymentUpdate.rowCount !== 1 || operationUpdate.rowCount !== 1) throw new Error('reconciliation_binding_changed');
        return await finish({
          accepted: true,
          reasonCode: 'original_transaction_reverted',
          settlementState: 'reverted',
          deliveryState: 'not_delivered',
          durable,
          observations: { receipt: receiptProof },
        });
      }
      if (receipt.status !== 'success') {
        return await finish({ accepted: false, reasonCode: 'original_receipt_status_unknown', deliveryState: 'not_changed', durable, observations: { receipt: receiptProof } });
      }
      let payerBefore: bigint;
      let payerAfter: bigint;
      let payToBefore: bigint;
      let payToAfter: bigint;
      try {
        const previousBlock = receipt.blockNumber - 1n;
        [payerBefore, payerAfter, payToBefore, payToAfter] = await Promise.all([
          localObserver.readContract({ address: asset, abi: reconciliationTokenAbi, functionName: 'balanceOf', args: [payer], blockNumber: previousBlock }),
          localObserver.readContract({ address: asset, abi: reconciliationTokenAbi, functionName: 'balanceOf', args: [payer], blockNumber: receipt.blockNumber }),
          localObserver.readContract({ address: asset, abi: reconciliationTokenAbi, functionName: 'balanceOf', args: [originalPayTo], blockNumber: previousBlock }),
          localObserver.readContract({ address: asset, abi: reconciliationTokenAbi, functionName: 'balanceOf', args: [originalPayTo], blockNumber: receipt.blockNumber }),
        ]);
      } catch {
        return await finish({ accepted: false, reasonCode: 'historical_balance_observation_unavailable', deliveryState: 'not_changed', durable, observations: { receipt: receiptProof } });
      }
      const amount = BigInt(original.amount_units);
      const payerDelta = payerBefore - payerAfter;
      const payToDelta = payToAfter - payToBefore;
      const observations = {
        receipt: receiptProof,
        payerBefore: tokenBalanceObservation(asset, payer, receipt.blockNumber - 1n, payerBefore),
        payerAfter: tokenBalanceObservation(asset, payer, receipt.blockNumber, payerAfter),
        originalPayToBefore: tokenBalanceObservation(asset, originalPayTo, receipt.blockNumber - 1n, payToBefore),
        originalPayToAfter: tokenBalanceObservation(asset, originalPayTo, receipt.blockNumber, payToAfter),
        effects: { payerDeltaUnits: payerDelta.toString(), originalPayToDeltaUnits: payToDelta.toString(), expectedAmountUnits: amount.toString() },
      };
      if (!isOriginalTransfer(receipt, asset, payer, originalPayTo, amount) || payerDelta !== amount || payToDelta !== amount) {
        return await finish({ accepted: false, reasonCode: 'receipt_effect_mismatch', deliveryState: 'not_changed', durable, observations });
      }
      const paymentUpdate = await client.query(
        `UPDATE bef_payment SET transaction_hash=$4,receipt_status='success',token_delta_units=$5,
             payer_balance_before=$6,payer_balance_after=$7,facilitator_balance_before=$8,facilitator_balance_after=$9,observed_at=clock_timestamp()
          WHERE operation_id=$1 AND env_id=$2 AND generation_id=$3 AND transaction_hash=$4 AND authorization_sha256=$10`,
        [original.operation_id, config.envId, original.generation_id, txHash, amount.toString(), payerBefore.toString(), payerAfter.toString(), payToBefore.toString(), payToAfter.toString(), original.authorization_sha256],
      );
      const operationUpdate = await client.query(
        `UPDATE bef_operation SET transaction_hash=$4,receipt_status='success',status='settled',completed_at=clock_timestamp()
          WHERE operation_id=$1 AND env_id=$2 AND generation_id=$3 AND transaction_hash=$4 AND status IN ('settling','settlement_unknown')`,
        [original.operation_id, config.envId, original.generation_id, txHash],
      );
      if (paymentUpdate.rowCount !== 1 || operationUpdate.rowCount !== 1) throw new Error('reconciliation_binding_changed');
      return await finish({
        accepted: true,
        reasonCode: 'original_settlement_reconciled',
        settlementState: 'settled',
        deliveryState: 'not_delivered',
        durable,
        observations,
      });
    } catch {
      if (inTransaction) await client.query('ROLLBACK').catch(() => undefined);
      inTransaction = false;
      return reply.code(503).send({ accepted: false, reasonCode: 'reconciliation_unavailable' });
    } finally {
      if (inTransaction) await client.query('ROLLBACK').catch(() => undefined);
      client.release();
    }
  });
  app.get('/supported', async (request, reply) => {
    if (!sameSecret(request.headers['x-bef-service-key'], config.serviceKey)) return reply.code(403).send({ error: 'forbidden' });
    try { return await facilitator.getSupported(); } catch { return reply.code(503).send({ error: 'facilitator_capabilities_unavailable' }); }
  });
  const handleProtocolPhase = async (request: FastifyRequest, reply: import('fastify').FastifyReply, phase: 'verify' | 'settle') => {
    const context = await requestContext(request, config, database);
    if (!context) return reply.code(403).send({ error: 'forbidden' });
    const parsed = FacilitatorRequest.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: 'invalid_facilitator_request', reasonCode: 'unsupported_payment_requirements' });
    const selectOperation = () => database.query<{
      request_sha256: string;
      operation_kind: string;
      status: string;
      resource_variant: string;
      selected_offer_id: string | null;
      selected_amount_units: string | null;
      selected_resource_id: string | null;
      selected_resource_sha256: string | null;
      selection_precedes_verification: boolean;
    }>(
      `SELECT o.request_sha256,o.operation_kind,o.status,g.resource_variant,o.selected_offer_id,o.selected_amount_units::text,
              o.selected_resource_id,o.selected_resource_sha256,
              (o.offer_selected_at IS NOT NULL AND o.verification_started_at IS NOT NULL
                AND o.verification_started_at >= o.offer_selected_at) AS selection_precedes_verification
         FROM bef_operation o JOIN bef_generation g USING(env_id,generation_id)
        WHERE o.operation_id=$1 AND o.env_id=$2 AND o.generation_id=$3 AND o.request_sha256=$4
          AND g.status='active' AND g.expires_at>clock_timestamp()`,
      [context.operationId, context.envId, context.generationId, context.requestSha256],
    );
    let selected = await selectOperation();
    const candidate = selected.rows[0];
    if (phase === 'verify' && candidate && (
      parsed.data.paymentRequirements.scheme !== manifest.x402.scheme ||
      parsed.data.paymentRequirements.asset.toLowerCase() !== manifest.x402.asset.toLowerCase()
    )) {
      return reply.code(400).send({
        error: 'unsupported_payment_requirements',
        reasonCode: 'unsupported_asset_scheme',
      });
    }
    if (phase === 'verify' && candidate?.resource_variant === 'verification_without_receipt'
      && candidate.status === 'awaiting_payment') {
      const selectedPinned = selectedPinnedResourceOffer(manifest, {
        resourceId: candidate.selected_resource_id ?? manifest.x402.resourceId,
        offerId: candidate.selected_offer_id,
      });
      if (!selectedPinned || (candidate.selected_resource_sha256 !== null
          && candidate.selected_resource_sha256 !== selectedPinned.resource.resourceSha256)
        || candidate.selected_amount_units !== selectedPinned.offer.amount
        || parsed.data.paymentRequirements.amount !== selectedPinned.offer.amount) {
        return reply.code(409).send({ error: 'offer_choice_mismatch' });
      }
      const requestSupport = supportedRequestChecks(parsed.data, manifest, account.address, selectedPinned.offer.amount);
      if (!requestSupport.supported) return reply.code(400).send({
        error: 'unsupported_payment_requirements',
        reasonCode: parsed.data.paymentRequirements.scheme !== manifest.x402.scheme ||
          parsed.data.paymentRequirements.asset.toLowerCase() !== manifest.x402.asset.toLowerCase()
          ? 'unsupported_asset_scheme'
          : 'unsupported_payment_requirements',
        checks: requestSupport.checks,
      });
      if (!payloadDetails(parsed.data.paymentPayload).signature) return reply.code(400).send({ error: 'payment_signature_required' });
      try {
        const recorded = await recordPrivateVerificationStarted(database, {
          envId: context.envId,
          generationId: context.generationId,
          operationId: context.operationId,
          requestSha256: context.requestSha256,
        }, selectedPinned.offer);
        if (!recorded) return reply.code(409).send({ error: 'offer_choice_mismatch' });
        selected = await selectOperation();
      } catch {
        return reply.code(409).send({ error: 'generation_fenced' });
      }
    }
    const selectedOffer = durableOfferRequirementsMatch(
      manifest, selected.rows[0], context.requestSha256, phase, parsed.data.paymentRequirements,
    );
    if (!selectedOffer) return reply.code(409).send({ error: 'offer_choice_mismatch' });
    const requestSupport = supportedRequestChecks(parsed.data, manifest, account.address, selectedOffer.amount);
    if (!requestSupport.supported) return reply.code(400).send({
      error: 'unsupported_payment_requirements',
      reasonCode: parsed.data.paymentRequirements.scheme !== manifest.x402.scheme ||
        parsed.data.paymentRequirements.asset.toLowerCase() !== manifest.x402.asset.toLowerCase()
        ? 'unsupported_asset_scheme'
        : 'unsupported_payment_requirements',
      checks: requestSupport.checks,
    });
    const body = parsed.data;
    const details = payloadDetails(body.paymentPayload);
    if (!details.signature) return reply.code(400).send({ error: 'payment_signature_required' });
    if (phase === 'verify') {
      type VerifyAttempt = { kind: 'verified'; result: unknown } | { kind: 'fenced' } | { kind: 'failed' };
      let attempt: VerifyAttempt;
      try {
        attempt = await withEnvironmentAdvisoryLock(database, context.envId, async () => {
          const active = await database.query(
            `SELECT 1 FROM bef_generation g JOIN bef_operation o USING(env_id,generation_id)
              WHERE g.env_id=$1 AND g.generation_id=$2 AND g.status='active' AND g.expires_at>clock_timestamp()
                AND o.operation_id=$3 AND o.status IN ('accepted','awaiting_payment','verifying')
              FOR UPDATE OF g,o`,
            [context.envId, context.generationId, context.operationId],
          );
          if (!active.rowCount) return { kind: 'fenced' };
          try {
            const result = await facilitator.verify(body.paymentPayload as never, body.paymentRequirements as never);
            const safeResult = safeProtocolResponse(result);
            const valid = safeResult.isValid === true;
            await recordX402(database, context, 'verify', body, safeResult, valid ? 'success' : 'rejected', null);
            return { kind: 'verified', result: safeResult };
          } catch {
            await recordX402(database, context, 'verify', body, { outcome: 'unknown' }, 'error', null).catch(() => undefined);
            return { kind: 'failed' };
          }
        });
      } catch {
        attempt = { kind: 'failed' };
      }
      if (attempt.kind === 'fenced') return reply.code(409).send({ error: 'generation_fenced' });
      if (attempt.kind === 'failed') return reply.code(502).send({ error: 'facilitator_request_failed' });
      return attempt.result;
    }
    if (phase === 'settle') {
      try {
        await assertAnvilIdentity(config.rpcUrl, manifest);
        await withEnvironmentAdvisoryLock(database, context.envId, () => bindPayment(database, context, body, account.address));
      } catch {
        return reply.code(409).send({ error: 'durable_settlement_binding_failed' });
      }
    }
    const run = async () => {
      activeSettlementRequests.add(context.operationId);
      try {
        await assertAnvilIdentity(config.rpcUrl, manifest);
        const result = await facilitator.settle(body.paymentPayload as never, body.paymentRequirements as never);
        const safeResult = safeProtocolResponse(result);
        const valid = safeResult.success === true;
        const transactionHash = typeof safeResult.transaction === 'string' ? safeResult.transaction : null;
        if (transactionHash) await persistBroadcastHash(
          database, context, transactionHash, account.address, manifestSha256, manifest.feePolicy,
        );
        await recordX402(database, context, 'settle', body, safeResult, valid ? 'success' : 'unknown', transactionHash);
        await database.query(
          RECORD_UNKNOWN_SETTLEMENT_OPERATION_SQL,
          [context.operationId, context.envId, transactionHash, valid && transactionHash ? 'settling' : 'settlement_unknown'],
        );
        await database.query(
          RECORD_UNKNOWN_SETTLEMENT_PAYMENT_SQL,
          [context.operationId, transactionHash],
        );
        if (transactionHash && /^0x[0-9a-f]{64}$/i.test(transactionHash) && context.knownReceipt &&
            context.knownReceipt.transactionHash.toLowerCase() === transactionHash.toLowerCase()) {
          await finalizeFacilitatorCost(context, transactionHash as Hex, account.address, context.knownReceipt);
        }
        return safeResult;
      } catch {
        await recordX402(database, context, 'settle', body, { outcome: 'unknown' }, 'unknown', null).catch(() => undefined);
        await database.query(
          `UPDATE bef_operation SET status='settlement_unknown',receipt_status='unknown' WHERE operation_id=$1 AND env_id=$2 AND generation_id=$3 AND status IN ('settling','settlement_unknown') AND receipt_status <> 'success'`,
          [context.operationId, context.envId, context.generationId],
        ).catch(() => undefined);
        await database.query(
          `UPDATE bef_payment SET receipt_status='unknown' WHERE operation_id=$1 AND env_id=$2 AND generation_id=$3 AND receipt_status <> 'success'`,
          [context.operationId, context.envId, context.generationId],
        ).catch(() => undefined);
        return null;
      } finally {
        activeSettlementRequests.delete(context.operationId);
      }
    };
    const result = await settlementContext.run(context, run);
    if (result === null) return reply.code(502).send({ error: phase === 'settle' ? 'settlement_outcome_unknown' : 'facilitator_request_failed' });
    return result;
  };
  app.post('/verify', async (request, reply) => handleProtocolPhase(request, reply, 'verify'));
  app.post('/settle', async (request, reply) => handleProtocolPhase(request, reply, 'settle'));
  facilitatorStartupPhase = 'server_listen';
  await app.listen({ port: config.port, host: config.bindAddress });
  facilitatorStartupPhase = 'ready';
  const shutdown = async () => { await app.close(); await database.end(); };
  process.once('SIGINT', () => { void shutdown(); });
  process.once('SIGTERM', () => { void shutdown(); });
}

startFacilitator().catch(() => {
  process.stderr.write(`BEF_FACILITATOR_STARTUP_FAILED phase=${facilitatorStartupPhase}\n`);
  process.exitCode = 1;
});
