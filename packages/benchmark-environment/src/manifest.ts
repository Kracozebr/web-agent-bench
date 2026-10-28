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
    routePool3000Artifact: z.literal('infrastructure/benchmark-environment/source-intake/uniswap-v3-usdc-weth-3000.json').optional(),
    routePool3000ArtifactSha256: z.string().regex(/^[0-9a-f]{64}$/).optional(),
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
    pool3000: z.object({
      address, codeHash: hex32, token0: address, token1: address, fee: z.literal(3000),
      liquidityAtSource: z.string().regex(/^[1-9][0-9]{0,77}$/),
      quote: z.object({ inputAssetId: z.literal('USDC'), outputAssetId: z.literal('WETH'), amountInUnits: z.string().regex(/^[1-9][0-9]{0,77}$/), amountOutUnits: z.string().regex(/^[1-9][0-9]{0,77}$/) }).strict(),
    }).strict().optional(),
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
    catalog: z.array(z.object({
      resourceId: z.string().regex(/^[a-z][a-z0-9-]{2,63}$/),
      resourcePath: z.string().regex(/^infrastructure\/benchmark-environment\/(?:resource\.json|resources\/[a-z0-9-]+\.json)$/),
      resourceSha256: z.string().regex(/^[0-9a-f]{64}$/),
      contentType: z.literal('application/json'),
      schema: z.string().regex(/^[a-z0-9][a-z0-9._/-]{2,95}$/),
      dataType: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/).optional(),
      provenance: z.object({
        classification: z.literal('synthetic-benchmark-fixture'),
        boundary: z.literal('private acceptance environment'),
        source: z.string().min(1).max(160),
      }).strict(),
      offers: z.array(z.object({
        id: z.string().regex(/^[a-z][a-z0-9-]{2,63}$/),
        amount: z.string().regex(/^[1-9][0-9]{0,11}$/),
      }).strict()).min(1).max(8),
    }).strict()).min(2).max(32).optional(),
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
    reads: z.array(z.enum(['balances', 'offer', 'quote', 'catalog', 'retrieve'])).min(3),
    writes: z.array(z.enum(['purchase', 'pay', 'approve', 'swap', 'wrap', 'unwrap', 'transfer'])).min(5),
    participantProtocol: z.enum(['combined_purchase_v1', 'separate_payment_delivery_v2']).optional(),
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
  if (manifest.x402.catalog) {
    const resourceIds = new Set<string>();
    const offerIds = new Set<string>();
    const resourcePaths = new Set<string>();
    for (const resource of manifest.x402.catalog) {
      if (resourceIds.has(resource.resourceId) || resourcePaths.has(resource.resourcePath)) {
        throw new Error('Pinned x402 catalog resource identifiers and paths must be unique');
      }
      resourceIds.add(resource.resourceId);
      resourcePaths.add(resource.resourcePath);
      for (const offer of resource.offers) {
        if (offerIds.has(offer.id)) throw new Error('Pinned x402 catalog offer identifiers must be unique');
        if (BigInt(offer.amount) > BigInt(manifest.funding.maxUsdcUnitsPerGeneration)) {
          throw new Error('Pinned x402 catalog offer exceeds the generation funding bound');
        }
        offerIds.add(offer.id);
      }
    }
    const legacy = manifest.x402.catalog[0];
    if (legacy?.resourceId !== manifest.x402.resourceId || legacy.resourcePath !== manifest.x402.resourcePath
      || legacy.resourceSha256 !== manifest.x402.resourceSha256 || legacy.offers.length !== manifest.x402.offers.length
      || legacy.offers.some((offer, index) => offer.id !== manifest.x402.offers[index]?.id || offer.amount !== manifest.x402.offers[index]?.amount)) {
      throw new Error('The first x402 catalog resource must preserve the legacy pinned resource and offers');
    }
  }
  if (manifest.contracts.pool.token0.toLowerCase() !== manifest.contracts.weth.address.toLowerCase() || manifest.contracts.pool.token1.toLowerCase() !== manifest.contracts.usdc.address.toLowerCase()) {
    throw new Error('Pinned pool token order must match WETH/USDC observation');
  }
  if (Boolean(manifest.contracts.pool3000) !== Boolean(manifest.source.routePool3000Artifact && manifest.source.routePool3000ArtifactSha256)) {
    throw new Error('Pinned fee-3000 pool and its source observation artifact must be declared together');
  }
  if (manifest.contracts.pool3000 && (
    manifest.contracts.pool3000.token0.toLowerCase() !== manifest.contracts.weth.address.toLowerCase() ||
    manifest.contracts.pool3000.token1.toLowerCase() !== manifest.contracts.usdc.address.toLowerCase() ||
    manifest.contracts.pool3000.fee !== 3000 || BigInt(manifest.contracts.pool3000.liquidityAtSource) <= 0n ||
    manifest.contracts.pool3000.address.toLowerCase() === manifest.contracts.pool.address.toLowerCase()
  )) {
    throw new Error('Pinned fee-3000 pool must be a distinct liquid WETH/USDC pool');
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
  if (manifest.contracts.pool3000) {
    const routeObservation = await readPinnedArtifact(
      manifest.source.routePool3000Artifact!,
      manifest.source.routePool3000ArtifactSha256!,
    ) as Record<string, unknown>;
    const source = routeObservation.source as Record<string, unknown> | undefined;
    const observedPool = routeObservation.pool as Record<string, unknown> | undefined;
    if (routeObservation.schemaVersion !== 'bef-uniswap-v3-route-observation/v1' ||
        source?.chainId !== '0x2105' || source.blockNumber !== manifest.source.blockNumber ||
        typeof source.blockHash !== 'string' || source.blockHash.toLowerCase() !== manifest.source.blockHash.toLowerCase() ||
        observedPool?.address !== manifest.contracts.pool3000.address ||
        typeof observedPool.codeHash !== 'string' || observedPool.codeHash.toLowerCase() !== manifest.contracts.pool3000.codeHash.toLowerCase() ||
        observedPool.token0 !== manifest.contracts.pool3000.token0 || observedPool.token1 !== manifest.contracts.pool3000.token1 ||
        observedPool.fee !== 3000 || observedPool.liquidityAtSource !== manifest.contracts.pool3000.liquidityAtSource) {
      throw new Error('Pinned fee-3000 source observation does not match the route manifest');
    }
    const observations = routeObservation.rawRpcObservations;
    const findObservation = (name: string): { request: Record<string, unknown>; response: Record<string, unknown> } | undefined => {
      if (!Array.isArray(observations)) return undefined;
      const candidate = observations.find((item) => item && typeof item === 'object' && !Array.isArray(item) && (item as Record<string, unknown>).name === name) as Record<string, unknown> | undefined;
      if (!candidate || !candidate.request || typeof candidate.request !== 'object' || !candidate.response || typeof candidate.response !== 'object') return undefined;
      return { request: candidate.request as Record<string, unknown>, response: candidate.response as Record<string, unknown> };
    };
    const resultHex = (observation: { request: Record<string, unknown>; response: Record<string, unknown> } | undefined, method: string, target: string, selector?: string): string => {
      if (!observation || observation.request.method !== method || !Array.isArray(observation.request.params) ||
          observation.response.error || typeof observation.response.result !== 'string') throw new Error('Pinned fee-3000 source RPC evidence is incomplete');
      const params = observation.request.params;
      if (method === 'eth_getCode') {
        if (String(params[0]).toLowerCase() !== target.toLowerCase() || params[1] !== manifest.source.blockNumber) throw new Error('Pinned fee-3000 code evidence is not block-bound');
      } else if (method === 'eth_call') {
        const call = params[0] as Record<string, unknown> | undefined;
        if (!call || typeof call !== 'object' || typeof call.to !== 'string' || call.to.toLowerCase() !== target.toLowerCase() ||
            params[1] !== manifest.source.blockNumber || (selector && (typeof call.data !== 'string' || !call.data.toLowerCase().startsWith(selector)))) {
          throw new Error('Pinned fee-3000 call evidence is not contract/block-bound');
        }
      }
      return observation.response.result;
    };
    const code = resultHex(findObservation('pool-fee3000-code'), 'eth_getCode', manifest.contracts.pool3000.address);
    if (keccak256(code as `0x${string}`).toLowerCase() !== manifest.contracts.pool3000.codeHash.toLowerCase()) {
      throw new Error('Pinned fee-3000 source code hash does not match its observation');
    }
    const factoryPool = resultHex(findObservation('factory-fee3000'), 'eth_call', manifest.contracts.factory.address, '0x1698ee82');
    if (`0x${factoryPool.slice(-40)}`.toLowerCase() !== manifest.contracts.pool3000.address.toLowerCase()) {
      throw new Error('Pinned fee-3000 factory observation does not identify the configured pool');
    }
    const views = routeObservation.publicPoolViews as Record<string, unknown> | undefined;
    const readView = (name: string, selector: string): string => resultHex(
      views?.[name] as { request: Record<string, unknown>; response: Record<string, unknown> } | undefined,
      'eth_call', manifest.contracts.pool3000!.address, selector,
    );
    const token0 = readView('token0', '0x0dfe1681');
    const token1 = readView('token1', '0xd21220a7');
    const fee = readView('fee', '0xddca3f43');
    const liquidity = readView('liquidity', '0x1a686502');
    if (`0x${token0.slice(-40)}`.toLowerCase() !== manifest.contracts.pool3000.token0.toLowerCase() ||
        `0x${token1.slice(-40)}`.toLowerCase() !== manifest.contracts.pool3000.token1.toLowerCase() ||
        BigInt(fee).toString() !== '3000' || BigInt(liquidity).toString() !== manifest.contracts.pool3000.liquidityAtSource) {
      throw new Error('Pinned fee-3000 public pool views do not match the configured route');
    }
    const quote = findObservation('quoter-fee3000-0_1-usdc-to-weth');
    const quoteResult = resultHex(quote, 'eth_call', manifest.contracts.quoterV2.address, '0xc6a5026a');
    const quotedOutput = BigInt(`0x${quoteResult.slice(2, 66)}`).toString();
    if (quotedOutput !== manifest.contracts.pool3000.quote.amountOutUnits ||
        manifest.contracts.pool3000.quote.amountInUnits !== '100000' || manifest.contracts.pool3000.quote.inputAssetId !== 'USDC' ||
        manifest.contracts.pool3000.quote.outputAssetId !== 'WETH') {
      throw new Error('Pinned fee-3000 quote evidence does not match the route manifest');
    }
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
