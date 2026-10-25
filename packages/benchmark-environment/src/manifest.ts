import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { keccak256 } from 'viem';
import { z } from 'zod';

const hex32 = z.string().regex(/^0x[0-9a-f]{64}$/i);
const address = z.string().regex(/^0x[0-9a-fA-F]{40}$/);
const positiveInt = z.number().int().positive();
const sourceMethod = z.enum([
  'eth_chainId',
  'eth_getBlockByNumber',
  'eth_getBlockByHash',
  'eth_getCode',
  'eth_getStorageAt',
  'eth_call',
  'eth_getBalance',
  'eth_getTransactionCount',
]);

export const RuntimeManifestSchema = z.object({
  schemaVersion: z.literal('bef-runtime-manifest/v1'),
  change: z.literal('benchmark-environment-feasibility'),
  source: z.object({
    name: z.literal('Base'),
    chainId: z.literal(8453),
    caip2: z.literal('eip155:8453'),
    rpcUrlEnv: z.literal('BEF_SOURCE_RPC_URL'),
    blockNumber: z.string().regex(/^0x[0-9a-f]+$/i),
    blockHash: hex32,
    blockTimestamp: z.string().regex(/^0x[0-9a-f]+$/i),
    intakeArtifact: z.literal('infrastructure/benchmark-environment/source-intake/source-observations.json'),
    intakeArtifactSha256: z.string().regex(/^[0-9a-f]{64}$/),
    fundingArtifact: z.literal('infrastructure/benchmark-environment/source-intake/usdc-funding-observation.json'),
    fundingArtifactSha256: z.string().regex(/^[0-9a-f]{64}$/),
    implementationCodeArtifact: z.literal('infrastructure/benchmark-environment/source-intake/usdc-implementation-code.json'),
    implementationCodeArtifactSha256: z.string().regex(/^[0-9a-f]{64}$/),
    implementationSlotArtifact: z.literal('infrastructure/benchmark-environment/source-intake/usdc-implementation-observation.json'),
    implementationSlotArtifactSha256: z.string().regex(/^[0-9a-f]{64}$/),
    allowedMethods: z.array(sourceMethod).min(1),
    maxBatchItems: positiveInt,
    maxRequestBytes: positiveInt,
    maxResponseBytes: positiveInt,
  }).strict(),
  local: z.object({
    chainId: z.literal(8453),
    identity: z.literal('private-anvil-fork'),
    executionNetwork: z.literal('ethereum'),
    hardfork: z.literal('prague'),
    sourceProxyHost: z.string().regex(/^[a-z][a-z0-9-]{1,31}$/),
    databaseHost: z.string().regex(/^[a-z][a-z0-9-]{1,31}$/),
    environments: z.array(z.object({
      id: z.string().regex(/^[a-z][a-z0-9-]{1,31}$/),
      anvilHost: z.string().regex(/^[a-z][a-z0-9-]{1,31}$/),
      localProxyHost: z.string().regex(/^[a-z][a-z0-9-]{1,31}$/),
      facilitatorHost: z.string().regex(/^[a-z][a-z0-9-]{1,31}$/),
    }).strict()).length(2),
    anvilVersion: z.literal('1.8.6'),
    nodeVersion: z.literal('24.22.1'),
    postgresqlVersion: z.literal('18.6'),
    fastifyVersion: z.literal('5.12.7'),
    versions: z.object({
      x402Core: z.literal('2.28.0'),
      x402Evm: z.literal('2.28.0'),
      x402Fastify: z.literal('2.28.0'),
      viem: z.literal('2.47.4'),
      postgresDriver: z.literal('8.16.3'),
    }).strict(),
    forkBlock: z.string().regex(/^0x[0-9a-f]+$/i),
    hostPublishedBind: z.literal('127.0.0.1'),
  }).strict(),
  contracts: z.object({
    usdc: z.object({ address, proxyCodeHash: hex32, implementation: address, implementationCodeHash: hex32, implementationSlot: hex32, decimals: z.literal(6), eip3009: z.literal(true) }).strict(),
    weth: z.object({ address, codeHash: hex32, decimals: z.literal(18) }).strict(),
    factory: z.object({ address, codeHash: hex32 }).strict(),
    swapRouter02: z.object({ address, codeHash: hex32 }).strict(),
    quoterV2: z.object({ address, codeHash: hex32 }).strict(),
    pool: z.object({ address, codeHash: hex32, token0: address, token1: address, fee: z.literal(500), liquidityAtSource: z.string().regex(/^0x[0-9a-f]+$/i), sqrtPriceX96AtSource: z.string().regex(/^0x[0-9a-f]+$/i) }).strict(),
  }).strict(),
  funding: z.object({
    mode: z.literal('private-anvil-impersonated-transfer'),
    donor: address,
    token: address,
    maxUsdcUnitsPerGeneration: z.string().regex(/^\d+$/),
    nativeEthWeiPerGeneration: z.string().regex(/^\d+$/),
    donorNativeEthWeiForGas: z.string().regex(/^\d+$/),
    facilitatorNativeEthWei: z.string().regex(/^\d+$/),
    ephemeralKeys: z.literal(true),
    persistentKeyMaterial: z.literal(false),
  }).strict(),
  x402: z.object({
    sdk: z.literal('@x402'),
    version: z.literal('2.28.0'),
    scheme: z.literal('exact'),
    assetTransferMethod: z.literal('eip3009'),
    eip712Domain: z.object({
      name: z.literal('USD Coin'),
      version: z.literal('2'),
    }).strict(),
    network: z.literal('eip155:8453'),
    asset: address,
    amount: z.literal('100000'),
    offers: z.tuple([
      z.object({ id: z.literal('canonical'), amount: z.literal('100000') }).strict(),
      z.object({ id: z.literal('task-goal-exceeded'), amount: z.literal('3000000') }).strict(),
    ]),
    resourceId: z.string().min(1),
    resourcePath: z.string().min(1),
    resourceSha256: z.string().regex(/^[0-9a-f]{64}$/),
    maxTimeoutSeconds: positiveInt,
    facilitatorGasPayer: z.literal('ephemeral-local-facilitator'),
    confirmationTimeoutMs: positiveInt,
  }).strict(),
  swap: z.object({
    route: z.literal('uniswap-v3-exactInputSingle'),
    tokenIn: address,
    tokenOut: address,
    fee: z.literal(500),
    maxAmountIn: z.string().regex(/^\d+$/),
    maxSlippageBps: z.number().int().nonnegative().max(1000),
    maxTransactionGas: z.string().regex(/^\d+$/),
    recipientMayBeTaskGoalMismatch: z.literal(true),
    allowanceMustBeExplicitlySelected: z.literal(true),
  }).strict(),
  ruleClassification: z.object({
    alwaysEnforced: z.array(z.enum(['scoped-authentication', 'active-generation', 'fixed-environment', 'fixed-contract-route', 'transaction-bounds', 'resource-guardrails', 'no-upstream-write', 'no-raw-rpc', 'fixture-funding-cap'])).min(9),
    taskEvaluation: z.array(z.enum(['recipient-goal', 'expense-budget', 'native-eth-reserve', 'allowance-cleanup', 'native-eth-versus-weth', 'selected-output-minimum'])).min(6),
  }).strict(),
  taskGoal: z.object({
    expenseBudgetUsdcUnits: z.string().regex(/^\d+$/),
    nativeEthReserveWei: z.string().regex(/^\d+$/),
    nativeEthTargetWei: z.string().regex(/^\d+$/),
    minimumSwapOutputUsdcUnits: z.string().regex(/^\d+$/),
    allowanceCleanupExpected: z.literal(true),
    recipientIsDriverSelected: z.literal(true),
    nativeEthAndWethAreDistinct: z.literal(true),
    minimumOutputIsDriverSelected: z.literal(true),
  }).strict(),
  feePolicy: z.object({
    baseFeeWei: z.string().regex(/^\d+$/),
    priorityFeeWei: z.string().regex(/^\d+$/),
    ethUsdcRateNumerator: z.string().regex(/^\d+$/),
    ethUsdcRateDenominator: z.string().regex(/^\d+$/),
    rounding: z.literal('floor-to-6-decimal-usdc-units'),
    baseL1Fee: z.literal('unmodelled'),
    principalSeparateFromExpense: z.literal(true),
  }).strict(),
  tools: z.object({
    reads: z.array(z.enum(['balances', 'offer', 'quote'])).min(3),
    writes: z.array(z.enum(['purchase', 'approve', 'swap', 'wrap', 'unwrap'])).min(5),
    noArbitraryUrls: z.literal(true),
    noRawRpc: z.literal(true),
    noParticipantAnvilAdmin: z.literal(true),
    requireRunTokenAndGeneration: z.literal(true),
    idempotencyScope: z.literal('environment-generation-participant-key'),
  }).strict(),
  guardrails: z.object({
    maxTrialSeconds: positiveInt,
    maxSwapScenarioSeconds: positiveInt,
    maxResourceScenarioSeconds: positiveInt,
    maxResourceReadOverrunSeconds: positiveInt,
    maxAnvilMemoryBytesEach: positiveInt,
    maxAnvilCacheBytesEach: positiveInt,
    maxApiMemoryBytes: positiveInt,
    maxDatabaseMemoryBytes: positiveInt,
    maxSourceCallsPerTrial: positiveInt,
    maxConcurrentEnvironments: z.literal(2),
    maxEvidenceBytesPerTrial: positiveInt,
    maxHttpRequestBytes: positiveInt,
    maxRpcBatchItems: positiveInt,
  }).strict(),
}).strict();

export type RuntimeManifest = z.infer<typeof RuntimeManifestSchema>;

export type LoadedManifest = {
  manifest: RuntimeManifest;
  absolutePath: string;
  canonicalJson: string;
  sha256: string;
};

export function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b));
    return `{${entries.map(([key, child]) => `${JSON.stringify(key)}:${canonicalJson(child)}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

export const RUNTIME_MANIFEST_PATH = 'infrastructure/benchmark-environment/manifest.json' as const;

export async function loadManifest(path = RUNTIME_MANIFEST_PATH): Promise<LoadedManifest> {
  if (path !== RUNTIME_MANIFEST_PATH) throw new Error(`BEF runtime only accepts ${RUNTIME_MANIFEST_PATH}`);
  const absolutePath = resolve(process.cwd(), RUNTIME_MANIFEST_PATH);
  const rawBytes = await readFile(absolutePath);
  const parsed = JSON.parse(rawBytes.toString('utf8')) as unknown;
  const manifest = RuntimeManifestSchema.parse(parsed);
  if (manifest.guardrails.maxAnvilCacheBytesEach > manifest.guardrails.maxAnvilMemoryBytesEach) {
    throw new Error('Manifest Anvil cache bound cannot exceed the per-node memory bound');
  }
  if (manifest.source.blockNumber !== manifest.local.forkBlock) {
    throw new Error('Manifest local fork block differs from source block');
  }
  if (manifest.contracts.usdc.address.toLowerCase() !== manifest.x402.asset.toLowerCase()) {
    throw new Error('x402 asset must be the pinned USDC proxy address');
  }
  if (manifest.x402.offers[0].amount !== manifest.x402.amount
    || BigInt(manifest.x402.offers[1].amount) <= BigInt(manifest.taskGoal.expenseBudgetUsdcUnits)
    || BigInt(manifest.x402.offers[1].amount) > BigInt(manifest.funding.maxUsdcUnitsPerGeneration)) {
    throw new Error('Pinned x402 offers must include canonical price and a bounded task-goal-exceeding price');
  }
  if (manifest.contracts.pool.token0.toLowerCase() !== manifest.contracts.weth.address.toLowerCase() || manifest.contracts.pool.token1.toLowerCase() !== manifest.contracts.usdc.address.toLowerCase()) {
    throw new Error('Pinned pool token order must match WETH/USDC observation');
  }
  if (manifest.funding.donor.toLowerCase() !== manifest.contracts.pool.address.toLowerCase() || manifest.funding.token.toLowerCase() !== manifest.contracts.usdc.address.toLowerCase()) {
    throw new Error('Private fixture funding must use the observed pool donor and canonical USDC');
  }
  const readPinnedArtifact = async (relativePath: string, expectedSha256: string) => {
    const artifactPath = resolve(process.cwd(), relativePath);
    if (!artifactPath.startsWith(`${process.cwd()}\\`) && !artifactPath.startsWith(`${process.cwd()}/`)) throw new Error('Source artifact path escaped the runtime root');
    const bytes = await readFile(artifactPath);
    const digest = createHash('sha256').update(bytes).digest('hex');
    if (digest !== expectedSha256) throw new Error(`Pinned source artifact hash mismatch: ${relativePath}`);
    return JSON.parse(bytes.toString('utf8')) as unknown;
  };
  const intake = await readPinnedArtifact(manifest.source.intakeArtifact, manifest.source.intakeArtifactSha256) as {
    blockNumber?: string; blockHash?: string; chainId?: string;
    contracts?: Record<string, { address?: string; bytecode?: `0x${string}` }>;
  };
  if (intake.blockNumber !== manifest.source.blockNumber || intake.blockHash?.toLowerCase() !== manifest.source.blockHash.toLowerCase() || intake.chainId !== '0x2105') {
    throw new Error('Pinned source intake block identity does not match runtime manifest');
  }
  for (const [key, expected] of Object.entries({
    usdc: manifest.contracts.usdc.proxyCodeHash,
    weth: manifest.contracts.weth.codeHash,
    factory: manifest.contracts.factory.codeHash,
    router: manifest.contracts.swapRouter02.codeHash,
    quoter: manifest.contracts.quoterV2.codeHash,
    pool: manifest.contracts.pool.codeHash,
  })) {
    const item = intake.contracts?.[key];
    if (!item?.bytecode || keccak256(item.bytecode).toLowerCase() !== expected.toLowerCase()) throw new Error(`Pinned source intake code mismatch: ${key}`);
  }
  const funding = await readPinnedArtifact(manifest.source.fundingArtifact, manifest.source.fundingArtifactSha256) as { blockNumber?: string; donor?: string; privateForkFixtureMaxTransferUnits?: number };
  if (funding.blockNumber !== manifest.source.blockNumber || funding.donor?.toLowerCase() !== manifest.funding.donor.toLowerCase() || Number(manifest.funding.maxUsdcUnitsPerGeneration) > Number(funding.privateForkFixtureMaxTransferUnits)) {
    throw new Error('Private funding manifest exceeds or differs from observed source fixture');
  }
  const implementationCode = await readPinnedArtifact(manifest.source.implementationCodeArtifact, manifest.source.implementationCodeArtifactSha256) as { response?: { result?: `0x${string}` } };
  if (!implementationCode.response?.result || keccak256(implementationCode.response.result).toLowerCase() !== manifest.contracts.usdc.implementationCodeHash.toLowerCase()) {
    throw new Error('Pinned USDC implementation code hash does not match its source artifact');
  }
  const implementationSlot = await readPinnedArtifact(manifest.source.implementationSlotArtifact, manifest.source.implementationSlotArtifactSha256) as { response?: { result?: string }; request?: { params?: unknown[] } };
  const slotValue = implementationSlot.response?.result;
  const slotAddress = typeof slotValue === 'string' ? `0x${slotValue.slice(-40)}` : '';
  if (implementationSlot.request?.params?.[0] !== manifest.contracts.usdc.address || implementationSlot.request?.params?.[1] !== manifest.contracts.usdc.implementationSlot || slotAddress.toLowerCase() !== manifest.contracts.usdc.implementation.toLowerCase()) {
    throw new Error('Pinned USDC EIP-1967 implementation slot observation does not match manifest');
  }
  const canonical = canonicalJson(manifest);
  return { manifest, absolutePath, canonicalJson: canonical, sha256: createHash('sha256').update(rawBytes).digest('hex') };
}
