/**
 * Internal owner adapter for one BEF generation preparation.
 *
 * AICODE-NOTE: BEF's PUT reply contains the only copy of the generation run
 * token. Keep it and the ephemeral payer signer in this process only. Public
 * GET/RPC projections are the preparation evidence; never persist or hash the
 * secret PUT reply.
 */
import { createHash, randomUUID } from 'node:crypto';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import type { Network } from '@x402/core/types';
import type { Address, Hex } from 'viem';
import {
  canonicalTaskJson,
  sha256CanonicalTaskJson,
  type TaskCase,
  type TaskReleaseQuerySource,
  type ValidatedTaskReleaseRecord,
} from './task-release.js';
import type {
  ConfirmedTaskEnvironmentFence,
  TaskPreparationAdapter,
  TaskPreparationAdapterOutcome,
  TaskPreparationIntentPins,
  TrustedTaskPreparationResult,
  PreparationUnknownReason,
} from './task-preparation.js';
import type { BefTaskSessionBinding } from './bef-task-executor.js';
import { createEphemeralX402TaskSigner, type EphemeralX402Signer } from './task-action-x402.js';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HASH = /^[0-9a-f]{64}$/i;
const ADDRESS = /^0x[0-9a-f]{40}$/i;
const TX_HASH = /^0x[0-9a-f]{64}$/i;
const RUN_TOKEN = /^[A-Za-z0-9_-]{32,128}$/;
const ENV_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const UINT = /^(?:0|[1-9][0-9]{0,77})$/;
const TRANSFER_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
const APPROVAL_TOPIC = '0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925';
const APPROVE_SELECTOR = '0x095ea7b3';
const BALANCE_OF_SELECTOR = '0x70a08231';
const ALLOWANCE_SELECTOR = '0xdd62ed3e';
const MAX_JSON_BYTES = 4 * 1024 * 1024;
const PREPARATION_BOUNDARY = 'actual_tool_http_x402_local_evm_application_store' as const;

type JsonRecord = Record<string, unknown>;
type RpcRequest = { jsonrpc: '2.0'; id: string; method: string; params: unknown[] };
type RpcResponse = { jsonrpc?: unknown; id?: unknown; result?: unknown; error?: unknown };
type EvidenceReference = { path: string; sha256: string; boundary: typeof PREPARATION_BOUNDARY };

export type SafeTaskPreparationEvidence = {
  schemaVersion: 'owner-bef-task-preparation-evidence/v1';
  kind: 'fixture' | 'baseline' | 'fence';
  preparationId: string;
  environmentId: string;
  publicPinsSha256: string;
  evidence: JsonRecord;
};

export interface TaskPreparationEvidenceSink {
  /** Persist only the already allow-listed, secret-free preparation projection. */
  write(value: SafeTaskPreparationEvidence): Promise<EvidenceReference>;
}

export type BefTaskPreparationAdapterDependencies = {
  /** Trusted service URLs keyed by the release-selected environment id. */
  apiBaseByEnvironment: Readonly<Record<string, string>>;
  /** Read-only local Anvil observer URLs keyed by the release-selected environment id. */
  observerRpcByEnvironment: Readonly<Record<string, string>>;
  /** Read-only source proxy for the pinned source network. */
  sourceRpcUrl: string;
  /** Trusted internal BEF administrator credential; never added to a URL or evidence. */
  adminKey: string;
  /** Selected Anvil engine pins extracted from the trusted environment manifest. */
  anvilManifestPinByEnvironment: Readonly<Record<string, {
    manifestSha256: string;
    executionNetwork: string;
    hardFork: string;
    anvilVersion: string;
  }>>;
  releaseSource: TaskReleaseQuerySource;
  evidenceSink: TaskPreparationEvidenceSink;
  fetch?: typeof fetch;
  requestTimeoutMs?: number;
};

type PinnedCase = { release: ValidatedTaskReleaseRecord; taskCase: TaskCase };
type PublicPreparationStatus = {
  schemaVersion: 'bef-preparation-status/v1';
  envId: string;
  preparationId: string;
  status: 'preparing' | 'ready' | 'unknown' | 'fenced';
  generationId: string | null;
  request: {
    requestSha256: string;
    publicPinsSha256: string | null;
    participantId: string | null;
    payerAddress: string | null;
    resourceVariant: string | null;
    manifestSha256: string | null;
  } | null;
  fixture: {
    state: 'not_started' | 'hash_bound' | 'observed' | 'unknown' | 'reconciled';
    transactionHash: string | null;
    blockHash: string | null;
    fixtureHash: string | null;
    facts: JsonRecord | null;
  };
  baselineReset: {
    identity: JsonRecord;
    completedAt: string | null;
  } | null;
  fenceConfirmedAt: string | null;
};

type CachedGeneration = {
  publicPinsSha256: string;
  requestSha256: string;
  generationId: string;
  participantId: string;
  payerAddress: string;
  runToken: string;
  expiresAt: string;
  resourceVariant: 'canonical';
  x402Signer: EphemeralX402Signer;
  readyResult: TrustedTaskPreparationResult | null;
  s4FixtureAttempted: boolean;
  s4AllowanceFixture: JsonRecord | null;
};

type RpcObservation = { requests: RpcRequest[]; responses: Array<{ id: string; result: unknown }> };

function safeBaselineRpcResult(request: RpcRequest, result: unknown): unknown | null {
  if (request.method === 'eth_getBlockByNumber') {
    const block = object(result);
    const number = hexQuantity(block?.number);
    if (number === null || typeof block?.hash !== 'string' || !TX_HASH.test(block.hash)) return null;
    return { number: `0x${number.toString(16)}`, hash: block.hash.toLowerCase() };
  }
  if (request.method === 'eth_getBalance' || request.method === 'eth_call') {
    if (request.method === 'eth_call') {
      // ERC-20 balanceOf/allowance return ABI-encoded uint256 words, not JSON-RPC quantities.
      // Keep the exact 32-byte public result in evidence; quantity parsing would reject its leading zeroes.
      return hexUint256Data(result) === null ? null : (result as string).toLowerCase();
    }
    const amount = hexQuantity(result);
    return amount === null ? null : `0x${amount.toString(16)}`;
  }
  return null;
}

function object(value: unknown): JsonRecord | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as JsonRecord : null;
}

function validIntent(intent: TaskPreparationIntentPins): boolean {
  return UUID.test(intent.preparationId) && UUID.test(intent.runId) && UUID.test(intent.claimId) && UUID.test(intent.leaseId) &&
    Number.isSafeInteger(intent.taskIndex) && intent.taskIndex >= 0 && intent.taskIndex <= 11 && ENV_ID.test(intent.environmentId) &&
    [intent.manifestHash, intent.caseHash, intent.initialStateSha256, intent.executionIdentityHash,
      intent.environmentManifestSha256, intent.applicationSourceHash].every((value) => HASH.test(value)) &&
    Boolean(intent.releaseIdentity && intent.taskId && intent.caseId && Number.isFinite(Date.parse(intent.createdAt)));
}

/** Hashes exactly the immutable owner intent; participant credentials are separate BEF request pins. */
export function taskPreparationPublicPinsSha256(intent: TaskPreparationIntentPins): string {
  if (!validIntent(intent)) throw new Error('task_preparation_intent_invalid');
  return sha256CanonicalTaskJson({
    preparationId: intent.preparationId,
    runId: intent.runId,
    taskIndex: intent.taskIndex,
    claimId: intent.claimId,
    leaseId: intent.leaseId,
    environmentId: intent.environmentId,
    releaseIdentity: intent.releaseIdentity,
    manifestHash: intent.manifestHash,
    taskId: intent.taskId,
    caseId: intent.caseId,
    caseHash: intent.caseHash,
    initialStateSha256: intent.initialStateSha256,
    executionIdentityHash: intent.executionIdentityHash,
    environmentManifestSha256: intent.environmentManifestSha256,
    applicationSourceHash: intent.applicationSourceHash,
    createdAt: intent.createdAt,
  });
}

function evidenceReference(value: unknown): value is EvidenceReference {
  const item = object(value);
  return Boolean(item && typeof item.path === 'string' && item.path.length <= 512 &&
    /^(?![A-Za-z]:)(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/-]{1,512}$/.test(item.path) &&
    typeof item.sha256 === 'string' && HASH.test(item.sha256) && item.boundary === PREPARATION_BOUNDARY);
}

function decimal(value: unknown): bigint | null {
  return typeof value === 'string' && UINT.test(value) ? BigInt(value) : null;
}

function hexQuantity(value: unknown): bigint | null {
  return typeof value === 'string' && /^0x(?:0|[1-9a-f][0-9a-f]*)$/i.test(value) ? BigInt(value) : null;
}

function hexUint256Data(value: unknown): bigint | null {
  return typeof value === 'string' && /^0x[0-9a-f]{64}$/i.test(value) ? BigInt(value) : null;
}

function hexBytes(value: unknown): boolean {
  return typeof value === 'string' && /^0x(?:[0-9a-f]{2})*$/i.test(value);
}

function normalizedHash32(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const normalized = value.startsWith('0x') || value.startsWith('0X') ? value.slice(2) : value;
  return /^[0-9a-f]{64}$/i.test(normalized) ? normalized.toLowerCase() : null;
}

function hash32Matches(left: unknown, right: unknown): boolean {
  const normalizedLeft = normalizedHash32(left);
  const normalizedRight = normalizedHash32(right);
  return normalizedLeft !== null && normalizedLeft === normalizedRight;
}

function normalizeOrigin(value: string | undefined, errorCode: string): URL {
  let url: URL;
  try { url = new URL(value ?? ''); } catch { throw new Error(errorCode); }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash ||
      (url.pathname !== '' && url.pathname !== '/')) throw new Error(errorCode);
  url.pathname = '/';
  return url;
}

function endpoint(base: URL, path: string): URL {
  return new URL(path, base);
}

function canonicalPreparationRequestHash(input: {
  preparationId: string; envId: string; manifestSha256: string; publicPinsSha256: string;
  participantId: string; payerAddress: string; resourceVariant: 'canonical';
}): string {
  return sha256CanonicalTaskJson([
    input.preparationId,
    input.envId,
    input.manifestSha256.toLowerCase(),
    input.publicPinsSha256.toLowerCase(),
    input.participantId,
    input.payerAddress.toLowerCase(),
    input.resourceVariant,
  ]);
}

function parsePublicPreparationStatus(value: unknown, envId: string, preparationId: string): PublicPreparationStatus | null {
  const body = object(value);
  if (!body || body.schemaVersion !== 'bef-preparation-status/v1' || body.envId !== envId || body.preparationId !== preparationId ||
      !['preparing', 'ready', 'unknown', 'fenced'].includes(String(body.status)) ||
      !(body.generationId === null || (typeof body.generationId === 'string' && UUID.test(body.generationId)))) return null;

  const rawRequest = body.request;
  let request: PublicPreparationStatus['request'] = null;
  if (rawRequest !== null) {
    const row = object(rawRequest);
    if (!row || typeof row.requestSha256 !== 'string' || !HASH.test(row.requestSha256) ||
        !(row.publicPinsSha256 === null || (typeof row.publicPinsSha256 === 'string' && HASH.test(row.publicPinsSha256))) ||
        !(row.participantId === null || (typeof row.participantId === 'string' && row.participantId.length > 0 && row.participantId.length <= 128)) ||
        !(row.payerAddress === null || (typeof row.payerAddress === 'string' && ADDRESS.test(row.payerAddress))) ||
        !(row.resourceVariant === null || ['canonical', 'mismatched_data', 'verification_without_receipt'].includes(String(row.resourceVariant))) ||
        !(row.manifestSha256 === null || (typeof row.manifestSha256 === 'string' && HASH.test(row.manifestSha256)))) return null;
    request = {
      requestSha256: row.requestSha256.toLowerCase(),
      publicPinsSha256: typeof row.publicPinsSha256 === 'string' ? row.publicPinsSha256.toLowerCase() : null,
      participantId: typeof row.participantId === 'string' ? row.participantId : null,
      payerAddress: typeof row.payerAddress === 'string' ? row.payerAddress.toLowerCase() : null,
      resourceVariant: typeof row.resourceVariant === 'string' ? row.resourceVariant : null,
      manifestSha256: typeof row.manifestSha256 === 'string' ? row.manifestSha256.toLowerCase() : null,
    };
  }

  const rawFixture = object(body.fixture);
  if (!rawFixture || !['not_started', 'hash_bound', 'observed', 'unknown', 'reconciled'].includes(String(rawFixture.state)) ||
      !(rawFixture.transactionHash === null || (typeof rawFixture.transactionHash === 'string' && TX_HASH.test(rawFixture.transactionHash))) ||
      !(rawFixture.blockHash === null || (typeof rawFixture.blockHash === 'string' && TX_HASH.test(rawFixture.blockHash))) ||
      !(rawFixture.fixtureHash === null || (typeof rawFixture.fixtureHash === 'string' && HASH.test(rawFixture.fixtureHash))) ||
      !(rawFixture.facts === null || object(rawFixture.facts))) return null;
  const fixture: PublicPreparationStatus['fixture'] = {
    state: rawFixture.state as PublicPreparationStatus['fixture']['state'],
    transactionHash: typeof rawFixture.transactionHash === 'string' ? rawFixture.transactionHash.toLowerCase() : null,
    blockHash: typeof rawFixture.blockHash === 'string' ? rawFixture.blockHash.toLowerCase() : null,
    fixtureHash: typeof rawFixture.fixtureHash === 'string' ? rawFixture.fixtureHash.toLowerCase() : null,
    facts: object(rawFixture.facts),
  };

  let baselineReset: PublicPreparationStatus['baselineReset'] = null;
  if (body.baselineReset !== null) {
    const reset = object(body.baselineReset), identity = object(reset?.identity);
    if (!reset || !identity || !(reset.completedAt === null || typeof reset.completedAt === 'string' && Number.isFinite(Date.parse(reset.completedAt)))) return null;
    baselineReset = { identity: { ...identity }, completedAt: typeof reset.completedAt === 'string' ? reset.completedAt : null };
  }
  if (!(body.fenceConfirmedAt === null || typeof body.fenceConfirmedAt === 'string' && Number.isFinite(Date.parse(body.fenceConfirmedAt)))) return null;
  return {
    schemaVersion: 'bef-preparation-status/v1', envId, preparationId,
    status: body.status as PublicPreparationStatus['status'],
    generationId: typeof body.generationId === 'string' ? body.generationId.toLowerCase() : null,
    request, fixture, baselineReset,
    fenceConfirmedAt: typeof body.fenceConfirmedAt === 'string' ? body.fenceConfirmedAt : null,
  };
}

function safeStatusProjection(status: PublicPreparationStatus): JsonRecord {
  const facts = status.fixture.facts;
  const receiptObservation = object(facts?.receiptObservation);
  const safeReceiptObservation = receiptObservation ? {
    pollCount: receiptObservation.pollCount,
    nullReceiptCount: receiptObservation.nullReceiptCount,
    sourceProxyMethodDeniedCount: receiptObservation.sourceProxyMethodDeniedCount,
    firstUnavailableRpc: object(receiptObservation.firstUnavailableRpc) ? {
      code: (object(receiptObservation.firstUnavailableRpc) as JsonRecord).code,
      name: (object(receiptObservation.firstUnavailableRpc) as JsonRecord).name,
      messageCode: (object(receiptObservation.firstUnavailableRpc) as JsonRecord).messageCode,
    } : null,
  } : null;
  const safeFacts = facts ? {
    amountUnits: facts.amountUnits,
    payerTokenBefore: facts.payerTokenBefore,
    payerTokenAfter: facts.payerTokenAfter,
    donorTokenBefore: facts.donorTokenBefore,
    donorTokenAfter: facts.donorTokenAfter,
    payerNativeBalance: facts.payerNativeBalance,
    receiptObservation: safeReceiptObservation,
  } : null;
  const reset = status.baselineReset?.identity;
  const safeReset = reset ? {
    clientVersion: reset.clientVersion,
    chainId: reset.chainId,
    executionNetwork: reset.executionNetwork,
    hardFork: reset.hardFork,
    forkBlockNumber: reset.forkBlockNumber,
    forkBlockHash: reset.forkBlockHash,
    manifestSha256: reset.manifestSha256,
    facilitatorRecovered: reset.facilitatorRecovered,
  } : null;
  return {
    schemaVersion: status.schemaVersion,
    envId: status.envId,
    preparationId: status.preparationId,
    status: status.status,
    generationId: status.generationId,
    request: status.request,
    fixture: { ...status.fixture, facts: safeFacts },
    baselineReset: safeReset ? { identity: safeReset, completedAt: status.baselineReset?.completedAt ?? null } : null,
    fenceConfirmedAt: status.fenceConfirmedAt,
  };
}

function topicAddress(topic: unknown): string | null {
  return typeof topic === 'string' && /^0x[0-9a-f]{64}$/i.test(topic) ? `0x${topic.slice(-40).toLowerCase()}` : null;
}

type S4AllowanceFixtureSpec = { amountUnits: string; spender: string; tokenAddress: string; routerAddress: string };

function positiveS4FixtureSpec(release: ValidatedTaskReleaseRecord, taskCase: TaskCase): S4AllowanceFixtureSpec | null {
  if (taskCase.taskId !== 'S4' || taskCase.objective.tokenAssetId !== 'USDC' || taskCase.objective.owner !== 'participant') return null;
  const amount = decimal(taskCase.objective.initialAllowanceUnits);
  if (amount === null || amount <= 0n || !ADDRESS.test(taskCase.objective.spender)) return null;
  const identity = release.manifest.executionIdentity;
  const usdc = identity.assets.filter((asset) => asset.assetId === 'USDC' && asset.kind === 'erc20');
  const weth = identity.assets.filter((asset) => asset.assetId === 'WETH' && asset.kind === 'erc20');
  const eth = identity.assets.filter((asset) => asset.assetId === 'ETH' && asset.kind === 'native');
  const routers = identity.contracts.filter((item) => item.contractId === 'swapRouter02');
  const usdcContracts = identity.contracts.filter((item) => item.contractId === 'usdc');
  if (usdc.length !== 1 || !usdc[0]!.address || !ADDRESS.test(usdc[0]!.address) ||
      weth.length !== 1 || !weth[0]!.address || !ADDRESS.test(weth[0]!.address) || eth.length !== 1 ||
      routers.length !== 1 || usdcContracts.length !== 1 ||
      routers[0]!.address.toLowerCase() !== taskCase.objective.spender.toLowerCase() ||
      usdcContracts[0]!.address.toLowerCase() !== usdc[0]!.address.toLowerCase() ||
      usdc.some((asset) => BigInt(asset.chainId) !== BigInt(identity.localChainId)) ||
      weth.some((asset) => BigInt(asset.chainId) !== BigInt(identity.localChainId))) return null;
  const target = taskCase.initialState.allowances.filter((item) => item.owner === 'participant' &&
    item.tokenAssetId === 'USDC' && item.spender.toLowerCase() === routers[0]!.address.toLowerCase());
  const unrelatedWeth = taskCase.initialState.allowances.filter((item) => item.owner === 'participant' &&
    item.tokenAssetId === 'WETH' && item.spender.toLowerCase() === routers[0]!.address.toLowerCase());
  if (target.length !== 1 || target[0]!.amountUnits !== taskCase.objective.initialAllowanceUnits ||
      unrelatedWeth.length !== 1 || decimal(unrelatedWeth[0]!.amountUnits) === null ||
      sha256CanonicalTaskJson({ wethRouterAllowanceUnits: unrelatedWeth[0]!.amountUnits }).toLowerCase() !==
        taskCase.objective.unrelatedAllowanceBaselineSha256.toLowerCase()) return null;
  const participantBalances = taskCase.initialState.balances.filter((item) => item.account === 'participant');
  if (['ETH', 'USDC', 'WETH'].some((assetId) => participantBalances.filter((item) => item.assetId === assetId).length !== 1)) return null;
  return {
    amountUnits: taskCase.objective.initialAllowanceUnits,
    spender: routers[0]!.address.toLowerCase(),
    tokenAddress: usdc[0]!.address.toLowerCase(),
    routerAddress: routers[0]!.address.toLowerCase(),
  };
}

export class BefTaskPreparationAdapter implements TaskPreparationAdapter {
  private readonly fetchImpl: typeof fetch;
  private readonly requestTimeoutMs: number;
  private readonly credentials = new Map<string, CachedGeneration>();
  private readonly attempted = new Set<string>();
  private readonly fencing = new Set<string>();
  private readonly publicPinsByPreparation = new Map<string, string>();
  private readonly inFlight = new Map<string, Promise<TaskPreparationAdapterOutcome>>();

  constructor(private readonly deps: BefTaskPreparationAdapterDependencies) {
    this.fetchImpl = deps.fetch ?? fetch;
    this.requestTimeoutMs = deps.requestTimeoutMs ?? 15_000;
    if (!deps.adminKey || /[\r\n]/.test(deps.adminKey) || !Number.isSafeInteger(this.requestTimeoutMs) ||
        this.requestTimeoutMs < 1_000 || this.requestTimeoutMs > 120_000) {
      throw new Error('bef_task_preparation_configuration_invalid');
    }
  }

  prepare(input: { intent: TaskPreparationIntentPins; dispatchId: string }): Promise<TaskPreparationAdapterOutcome> {
    // dispatchId is deliberately not sent to BEF. preparationId is the single durable identity.
    if (!this.bindPublicPins(input.intent)) return Promise.resolve(this.unknown('preparation_identity_mismatch'));
    return this.singleFlight(input.intent.preparationId, () => this.prepareOnce(input.intent));
  }

  reconcile(input: { intent: TaskPreparationIntentPins; generationId: string }): Promise<TaskPreparationAdapterOutcome> {
    if (!this.bindPublicPins(input.intent)) return Promise.resolve(this.unknown('preparation_identity_mismatch'));
    return this.singleFlight(input.intent.preparationId, () => this.reconcileOnce(input.intent, input.generationId));
  }

  /** Secret-free gate used before debit; it proves the original start session remains in RAM through the task deadline. */
  hasUsableStartSession(intent: TaskPreparationIntentPins, minimumValidUntil: string): boolean {
    const minimum = Date.parse(minimumValidUntil);
    if (!validIntent(intent) || !Number.isFinite(minimum) || this.fencing.has(intent.preparationId.toLowerCase())) return false;
    const cached = this.credentials.get(intent.preparationId.toLowerCase());
    if (!cached || cached.publicPinsSha256 !== taskPreparationPublicPinsSha256(intent)) return false;
    const expires = Date.parse(cached.expiresAt);
    const ready = cached.readyResult;
    return Number.isFinite(expires) && expires > Date.now() && expires > minimum && Boolean(ready) &&
      ready!.environmentId === intent.environmentId && ready!.generationId === cached.generationId &&
      ready!.manifestHash.toLowerCase() === intent.manifestHash.toLowerCase() &&
      ready!.applicationSourceHash.toLowerCase() === intent.applicationSourceHash.toLowerCase() &&
      ready!.environmentManifestSha256.toLowerCase() === intent.environmentManifestSha256.toLowerCase() &&
      ready!.initialStateSha256.toLowerCase() === intent.initialStateSha256.toLowerCase() &&
      cached.participantId === ready!.participantId && cached.payerAddress.toLowerCase() === ready!.payerAddress?.toLowerCase() &&
      cached.runToken.length > 0 && cached.x402Signer.payerAddress.toLowerCase() === cached.payerAddress;
  }

  fence(input: { intent: TaskPreparationIntentPins; generationId: string | null }): Promise<ConfirmedTaskEnvironmentFence> {
    if (!this.bindPublicPins(input.intent)) return Promise.reject(new Error('bef_task_preparation_fence_identity_mismatch'));
    return this.singleFlightFence(input.intent.preparationId, () => this.fenceOnce(input.intent, input.generationId));
  }

  /** Internal handoff for a later start worker; caller must invoke only after the run is running. */
  sessionBindingAfterStart(intent: TaskPreparationIntentPins, minimumValidUntil = new Date().toISOString()): BefTaskSessionBinding | null {
    if (!this.hasUsableStartSession(intent, minimumValidUntil)) return null;
    const key = intent.preparationId.toLowerCase();
    const cached = this.credentials.get(key);
    if (cached && cached.expiresAt <= new Date().toISOString()) {
      this.credentials.delete(key);
      return null;
    }
    if (!cached) return null;
    return {
      runId: intent.runId,
      taskIndex: intent.taskIndex,
      envId: intent.environmentId,
      generationId: cached.generationId,
      manifestHash: intent.environmentManifestSha256.toLowerCase(),
      applicationSourceHash: intent.applicationSourceHash.toLowerCase(),
      runToken: cached.runToken,
      participantId: cached.participantId,
      payerAddress: cached.payerAddress,
      x402Signer: cached.x402Signer,
    };
  }

  /** Drop RAM-only bearer and signing material on shutdown or after a confirmed fence. */
  clearCredentials(preparationId?: string): void {
    if (preparationId) this.credentials.delete(preparationId.toLowerCase());
    else this.credentials.clear();
  }

  private singleFlight(id: string, action: () => Promise<TaskPreparationAdapterOutcome>): Promise<TaskPreparationAdapterOutcome> {
    const key = id.toLowerCase();
    const current = this.inFlight.get(key);
    if (current) return current;
    const next = action();
    this.inFlight.set(key, next);
    void next.finally(() => { if (this.inFlight.get(key) === next) this.inFlight.delete(key); }).catch(() => undefined);
    return next;
  }

  private async singleFlightFence<T>(id: string, action: () => Promise<T>): Promise<T> {
    const key = `fence:${id.toLowerCase()}`;
    const active = this.fenceFlights.get(key) as Promise<T> | undefined;
    if (active) return active;
    const next = action();
    this.fenceFlights.set(key, next);
    void next.finally(() => { if (this.fenceFlights.get(key) === next) this.fenceFlights.delete(key); }).catch(() => undefined);
    return next;
  }

  private readonly fenceFlights = new Map<string, Promise<unknown>>();

  private bindPublicPins(intent: TaskPreparationIntentPins): boolean {
    if (!validIntent(intent)) return false;
    const id = intent.preparationId.toLowerCase();
    const pins = taskPreparationPublicPinsSha256(intent);
    const prior = this.publicPinsByPreparation.get(id);
    if (prior && prior !== pins) return false;
    this.publicPinsByPreparation.set(id, pins);
    return true;
  }

  private async loadPinnedCase(intent: TaskPreparationIntentPins): Promise<PinnedCase | null> {
    const release = await this.deps.releaseSource.getValidatedReleaseRecord(intent.releaseIdentity, intent.manifestHash);
    if (!release || release.releaseIdentity !== intent.releaseIdentity || release.manifestHash.toLowerCase() !== intent.manifestHash.toLowerCase() ||
        release.manifest.executionIdentityHash.toLowerCase() !== intent.executionIdentityHash.toLowerCase() ||
        release.manifest.executionIdentity.environmentManifestSha256.toLowerCase() !== intent.environmentManifestSha256.toLowerCase() ||
        release.manifest.executionIdentity.x402ServiceSha256.toLowerCase() !== intent.applicationSourceHash.toLowerCase()) return null;
    const cases = [...release.manifest.cases.training, ...release.manifest.cases.ranked].filter((item) =>
      item.caseId === intent.caseId && item.caseHash.toLowerCase() === intent.caseHash.toLowerCase() &&
      item.taskId === intent.taskId && item.executionIdentityHash.toLowerCase() === intent.executionIdentityHash.toLowerCase() &&
      item.initialState.stateSha256.toLowerCase() === intent.initialStateSha256.toLowerCase());
    return cases.length === 1 ? { release, taskCase: cases[0]! } : null;
  }

  private async prepareOnce(intent: TaskPreparationIntentPins): Promise<TaskPreparationAdapterOutcome> {
    if (!validIntent(intent)) return this.unknown('preparation_identity_mismatch');
    if (this.fencing.has(intent.preparationId.toLowerCase())) return this.unknown('restart_reconciliation_required');
    const publicPinsSha256 = taskPreparationPublicPinsSha256(intent);
    const cached = this.credentials.get(intent.preparationId.toLowerCase());
    if (cached) {
      if (cached.publicPinsSha256 !== publicPinsSha256) return this.unknown('preparation_identity_mismatch');
      if (cached.expiresAt <= new Date().toISOString()) {
        this.clearCredentials(intent.preparationId);
        return this.unknown('restart_reconciliation_required', cached.generationId);
      }
      return this.reconcileOnce(intent, cached.generationId);
    }
    if (this.attempted.has(intent.preparationId.toLowerCase())) {
      await this.readPublicStatus(intent).catch(() => null);
      return this.unknown('restart_reconciliation_required');
    }

    let pinned: PinnedCase | null;
    try { pinned = await this.loadPinnedCase(intent); } catch { return this.unknown('adapter_call_failed'); }
    if (!pinned) return this.unknown('preparation_identity_mismatch');
    if (pinned.taskCase.taskId === 'S4' && !positiveS4FixtureSpec(pinned.release, pinned.taskCase)) {
      return this.unknown('preparation_identity_mismatch');
    }

    let apiBase: URL;
    let publicPins: string;
    try {
      apiBase = this.apiBase(intent.environmentId);
      publicPins = taskPreparationPublicPinsSha256(intent);
    } catch { return this.unknown('adapter_call_failed'); }

    try {
      const healthy = await this.validateEnvironmentHealth(intent, pinned.release, apiBase, pinned.taskCase);
      if (!healthy) return this.unknown('preparation_identity_mismatch');

      const existing = await this.readPublicStatus(intent, apiBase);
      if (existing.kind !== 'missing') {
        return this.unknown(existing.kind === 'status' && existing.status.request?.publicPinsSha256 === publicPins
          ? 'restart_reconciliation_required' : 'preparation_identity_mismatch');
      }

      const participantId = randomUUID();
      const payerPrivateKey = generatePrivateKey();
      const payerAddress = privateKeyToAccount(payerPrivateKey).address.toLowerCase();
      const manifestSha256 = intent.environmentManifestSha256.toLowerCase();
      const resourceVariant = 'canonical' as const;
      const requestSha256 = canonicalPreparationRequestHash({
        preparationId: intent.preparationId,
        envId: intent.environmentId,
        manifestSha256,
        publicPinsSha256: publicPins,
        participantId,
        payerAddress,
        resourceVariant,
      });
      if (this.fencing.has(intent.preparationId.toLowerCase())) return this.unknown('restart_reconciliation_required');
      this.attempted.add(intent.preparationId.toLowerCase());

      // Exactly one PUT per preparation identity. A lost response is reconciled with GET; it is never resubmitted.
      let putResponse: { status: number; body: unknown };
      try {
        putResponse = await this.adminRequest(apiBase, 'PUT', this.preparationPath(intent), {
          publicPinsSha256: publicPins,
          participantId,
          payerAddress,
          resourceVariant,
          payerPrivateKey,
        });
      } catch {
        await this.readPublicStatus(intent, apiBase).catch(() => null);
        return this.unknown('adapter_outcome_unknown');
      }

      if (putResponse.status !== 201) {
        await this.readPublicStatus(intent, apiBase).catch(() => null);
        return this.unknown('adapter_outcome_unknown');
      }
      const reply = object(putResponse.body);
      const generationId = typeof reply?.generationId === 'string' && UUID.test(reply.generationId) ? reply.generationId.toLowerCase() : null;
      const runToken = typeof reply?.runToken === 'string' && RUN_TOKEN.test(reply.runToken) ? reply.runToken : null;
      const expiresAt = typeof reply?.expiresAt === 'string' ? reply.expiresAt : null;
      const replyMatches = reply?.envId === intent.environmentId && reply?.preparationId === intent.preparationId &&
        generationId !== null && reply?.participantId === participantId && typeof reply?.payerAddress === 'string' &&
        reply.payerAddress.toLowerCase() === payerAddress && expiresAt !== null &&
        Number.isFinite(Date.parse(expiresAt)) && Date.parse(expiresAt) > Date.now();
      if (!replyMatches || !runToken || !generationId || !expiresAt) {
        await this.readPublicStatus(intent, apiBase).catch(() => null);
        return this.unknown('preparation_identity_mismatch', generationId);
      }
      if (this.fencing.has(intent.preparationId.toLowerCase())) return this.unknown('restart_reconciliation_required', generationId);
      const releaseIdentity = pinned.release.manifest.executionIdentity;
      const network = releaseIdentity.localNetwork as Network;
      const cachedGeneration: CachedGeneration = {
        publicPinsSha256: publicPins,
        requestSha256,
        generationId,
        participantId,
        payerAddress,
        runToken,
        expiresAt,
        resourceVariant,
        x402Signer: createEphemeralX402TaskSigner(payerPrivateKey, network),
        readyResult: null,
        s4FixtureAttempted: false,
        s4AllowanceFixture: null,
      };
      this.credentials.set(intent.preparationId.toLowerCase(), cachedGeneration);
      return await this.verifyAndBuildReady(intent, pinned, apiBase, cachedGeneration);
    } catch {
      const cachedAfterError = this.credentials.get(intent.preparationId.toLowerCase());
      return this.unknown('adapter_call_failed', cachedAfterError?.generationId);
    }
  }

  private async reconcileOnce(intent: TaskPreparationIntentPins, generationId: string): Promise<TaskPreparationAdapterOutcome> {
    if (!validIntent(intent) || !UUID.test(generationId)) return this.unknown('preparation_identity_mismatch');
    const expectedGeneration = generationId.toLowerCase();
    const publicPins = taskPreparationPublicPinsSha256(intent);
    const cached = this.credentials.get(intent.preparationId.toLowerCase());
    if (!cached || cached.publicPinsSha256 !== publicPins || cached.generationId !== expectedGeneration ||
        cached.expiresAt <= new Date().toISOString()) {
      if (cached && cached.expiresAt <= new Date().toISOString()) this.clearCredentials(intent.preparationId);
      await this.readPublicStatus(intent).catch(() => null);
      return this.unknown('restart_reconciliation_required', expectedGeneration);
    }
    let pinned: PinnedCase | null;
    let apiBase: URL;
    try {
      pinned = await this.loadPinnedCase(intent);
      apiBase = this.apiBase(intent.environmentId);
    } catch { return this.unknown('adapter_call_failed', expectedGeneration); }
    if (!pinned) return this.unknown('preparation_identity_mismatch', expectedGeneration);
    if (pinned.taskCase.taskId === 'S4' && !positiveS4FixtureSpec(pinned.release, pinned.taskCase)) {
      return this.unknown('preparation_identity_mismatch', expectedGeneration);
    }
    try {
      if (!await this.validateEnvironmentHealth(intent, pinned.release, apiBase, pinned.taskCase)) {
        return this.unknown('preparation_identity_mismatch', expectedGeneration);
      }
      let lookup = await this.readPublicStatus(intent, apiBase);
      if (lookup.kind !== 'status' || !this.statusMatchesRequest(lookup.status, intent, cached)) {
        return this.unknown('preparation_identity_mismatch', expectedGeneration);
      }
      if (lookup.status.generationId !== expectedGeneration) return this.unknown('preparation_identity_mismatch', expectedGeneration);
      if (lookup.status.fixture.state !== 'observed' && lookup.status.fixture.state !== 'reconciled') {
        if (!lookup.status.fixture.transactionHash || !lookup.status.fixture.blockHash || !lookup.status.request?.payerAddress) {
          return this.unknown('adapter_outcome_unknown', expectedGeneration);
        }
        const reconcileResponse = await this.adminRequest(apiBase, 'POST', `${this.preparationPath(intent)}/reconcile`, {});
        if (reconcileResponse.status !== 200 || object(reconcileResponse.body)?.outcome !== 'observed') {
          return this.unknown('adapter_outcome_unknown', expectedGeneration);
        }
        lookup = await this.readPublicStatus(intent, apiBase);
        if (lookup.kind !== 'status' || !this.statusMatchesRequest(lookup.status, intent, cached) ||
            lookup.status.generationId !== expectedGeneration) return this.unknown('preparation_identity_mismatch', expectedGeneration);
      }
      return await this.verifyAndBuildReady(intent, pinned, apiBase, cached, lookup.status);
    } catch {
      return this.unknown('adapter_call_failed', expectedGeneration);
    }
  }

  private async verifyAndBuildReady(
    intent: TaskPreparationIntentPins,
    pinned: PinnedCase,
    apiBase: URL,
    cached: CachedGeneration,
    knownStatus?: PublicPreparationStatus,
  ): Promise<TaskPreparationAdapterOutcome> {
    const lookup = knownStatus ? { kind: 'status' as const, status: knownStatus } : await this.readPublicStatus(intent, apiBase);
    if (lookup.kind !== 'status' || !this.statusMatchesRequest(lookup.status, intent, cached) ||
        lookup.status.status !== 'ready' || lookup.status.generationId !== cached.generationId ||
        !['observed', 'reconciled'].includes(lookup.status.fixture.state) || !lookup.status.baselineReset) {
      return this.unknown('adapter_outcome_unknown', cached.generationId);
    }
    if (!this.resetIdentityMatches(lookup.status, intent, pinned.release)) {
      return this.unknown('preparation_identity_mismatch', cached.generationId);
    }

    const receiptProof = await this.verifyFundingReceipt(intent, pinned.release, lookup.status, cached.payerAddress);
    if (!receiptProof) return this.unknown('adapter_outcome_unknown', cached.generationId);
    let s4FixtureEvidence: EvidenceReference | null = null;
    if (pinned.taskCase.taskId === 'S4') {
      const spec = positiveS4FixtureSpec(pinned.release, pinned.taskCase);
      if (!spec) return this.unknown('preparation_identity_mismatch', cached.generationId);
      const fixture = await this.prepareS4AllowanceFixture(intent, pinned, apiBase, cached, spec);
      if (!fixture) {
        await this.writeEvidence(intent, 'fixture', {
          publicPinsSha256: taskPreparationPublicPinsSha256(intent),
          environmentHealth: this.healthProjection(intent, pinned.release),
          publicStatus: safeStatusProjection(lookup.status),
          fundingReceipt: receiptProof,
          s4AllowanceFixture: cached.s4AllowanceFixture ?? {
            stage: 'pre_task_fixture_setup', outcome: 'unknown', reasonCode: 'adapter_outcome_unknown',
            preparationId: intent.preparationId, generationId: cached.generationId,
          },
        });
        return this.unknown('adapter_outcome_unknown', cached.generationId);
      }
      s4FixtureEvidence = await this.writeEvidence(intent, 'fixture', {
        publicPinsSha256: taskPreparationPublicPinsSha256(intent),
        environmentHealth: this.healthProjection(intent, pinned.release),
        publicStatus: safeStatusProjection(lookup.status),
        fundingReceipt: receiptProof,
        s4AllowanceFixture: fixture,
      });
      if (!s4FixtureEvidence) return this.unknown('adapter_call_failed', cached.generationId);
    }
    const baseline = await this.readCaseBaseline(intent, pinned.release, pinned.taskCase, cached.payerAddress);
    if (!baseline) return this.unknown('adapter_outcome_unknown', cached.generationId);
    const initialStateSha256 = sha256CanonicalTaskJson(baseline.projection);
    const baselineMatches = initialStateSha256.toLowerCase() === intent.initialStateSha256.toLowerCase() &&
      initialStateSha256.toLowerCase() === pinned.taskCase.initialState.stateSha256.toLowerCase();

    const fixtureEvidence = s4FixtureEvidence ?? await this.writeEvidence(intent, 'fixture', {
      publicPinsSha256: taskPreparationPublicPinsSha256(intent),
      environmentHealth: this.healthProjection(intent, pinned.release),
      publicStatus: safeStatusProjection(lookup.status),
      fundingReceipt: receiptProof,
    });
    const baselineEvidence = await this.writeEvidence(intent, 'baseline', {
      publicPinsSha256: taskPreparationPublicPinsSha256(intent),
      publicStatus: safeStatusProjection(lookup.status),
      state: baseline,
      stateSha256: initialStateSha256,
      expectedStateSha256: intent.initialStateSha256.toLowerCase(),
    });
    if (!fixtureEvidence || !baselineEvidence) return this.unknown('adapter_call_failed', cached.generationId);
    if (!baselineMatches) return this.unknown('baseline_state_mismatch', cached.generationId);

    const result: TrustedTaskPreparationResult = {
      environmentId: intent.environmentId,
      generationId: cached.generationId,
      manifestHash: intent.manifestHash.toLowerCase(),
      applicationSourceHash: intent.applicationSourceHash.toLowerCase(),
      environmentManifestSha256: intent.environmentManifestSha256.toLowerCase(),
      initialStateSha256,
      participantId: cached.participantId,
      payerAddress: cached.payerAddress,
      fixtureEvidence,
      baselineEvidence,
    };
    cached.readyResult = result;
    return { status: 'prepared', result };
  }

  /** One owner-only S4 fixture action. An attempted POST is never repeated, even after a lost reply. */
  private async prepareS4AllowanceFixture(
    intent: TaskPreparationIntentPins,
    pinned: PinnedCase,
    apiBase: URL,
    cached: CachedGeneration,
    spec: S4AllowanceFixtureSpec,
  ): Promise<JsonRecord | null> {
    if (cached.s4AllowanceFixture?.outcome === 'observed') return cached.s4AllowanceFixture;
    // Preserve the first attempted operation's safe provenance across reconcile calls. A request
    // that may have reached BEF is never repeated or replaced with a blank attempt projection.
    if (cached.s4FixtureAttempted) return null;
    const action = { kind: 'approve', tokenAssetId: 'USDC', spender: spec.spender,
      amountUnits: spec.amountUnits, gasLimit: '100000' };
    const attempt: JsonRecord = {
      stage: 'pre_task_fixture_setup', outcome: 'unknown', reasonCode: 'adapter_outcome_unknown',
      preparationId: intent.preparationId, generationId: cached.generationId,
      operationId: null, transactionHash: null, responseSha256: null, idempotencyKeySha256: null,
      action: { ...action }, preState: null, transaction: null, receipt: null, block: null,
      gasCostWei: null, postState: null,
    };
    cached.s4AllowanceFixture = attempt;

    try {
      if (!await this.validateEnvironmentHealth(intent, pinned.release, apiBase, pinned.taskCase)) {
        attempt.reasonCode = 'preparation_identity_mismatch';
        return null;
      }
      const preState = await this.readCaseBaseline(intent, pinned.release, pinned.taskCase, cached.payerAddress);
      if (!preState) {
        attempt.reasonCode = 'adapter_outcome_unknown';
        return null;
      }
      attempt.preState = {
        blockNumber: preState.blockNumber, blockHash: preState.blockHash,
        projection: preState.projection, reads: preState.reads,
      };
      if (!this.s4PreStateMatches(pinned.taskCase, preState.projection)) {
        attempt.reasonCode = 'baseline_state_mismatch';
        return null;
      }
      const chainId = hexQuantity(await this.callRpc(this.observerRpc(intent.environmentId), {
        jsonrpc: '2.0', id: 's4-fixture-chain-id', method: 'eth_chainId', params: [],
      }));
      if (chainId === null || chainId !== BigInt(pinned.release.manifest.executionIdentity.localChainId)) {
        attempt.reasonCode = 'preparation_identity_mismatch';
        return null;
      }

      // The key binds only the immutable preparation identity and the exact public request. Credentials
      // remain in the Authorization header and are never hashed into evidence.
      const path = `/tools/${encodeURIComponent(intent.environmentId)}/approve`;
      const idempotencyKey = `owner-s4-${sha256CanonicalTaskJson({
        preparationId: intent.preparationId, generationId: cached.generationId,
        environmentId: intent.environmentId, method: 'POST', path, body: action,
      })}`;
      attempt.idempotencyKeySha256 = createHash('sha256').update(idempotencyKey).digest('hex');
      if (this.fencing.has(intent.preparationId.toLowerCase())) return null;
      cached.s4FixtureAttempted = true;
      let response: Response;
      let responseBytes: Uint8Array;
      try {
        response = await this.fetchImpl(endpoint(apiBase, path), {
          method: 'POST',
          headers: {
            authorization: `Bearer ${cached.runToken}`,
            'x-bef-generation': cached.generationId,
            'idempotency-key': idempotencyKey,
            'content-type': 'application/json',
          },
          body: JSON.stringify({ tokenAssetId: 'USDC', amountUnits: spec.amountUnits, gasLimit: '100000' }),
          cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(this.requestTimeoutMs),
        });
        responseBytes = new Uint8Array(await response.arrayBuffer());
      } catch {
        attempt.reasonCode = 'adapter_outcome_unknown';
        return null;
      }
      attempt.responseSha256 = createHash('sha256').update(responseBytes).digest('hex');
      if (responseBytes.byteLength > MAX_JSON_BYTES) return null;
      let responseBody: JsonRecord | null = null;
      try { responseBody = object(JSON.parse(new TextDecoder().decode(responseBytes)) as unknown); } catch { /* Unknown response: never retry. */ }
      const operationId = typeof responseBody?.operationId === 'string' && UUID.test(responseBody.operationId)
        ? responseBody.operationId.toLowerCase() : null;
      const apiReceipt = object(responseBody?.receipt);
      const apiTransaction = object(responseBody?.transaction);
      const transactionHashValue = apiReceipt?.transactionHash ?? apiTransaction?.hash;
      const transactionHash = typeof transactionHashValue === 'string' && TX_HASH.test(transactionHashValue)
        ? transactionHashValue.toLowerCase() : null;
      attempt.operationId = operationId;
      attempt.transactionHash = transactionHash;
      if (response.status !== 200 || !responseBody || !operationId || !transactionHash || responseBody.outcome !== 'success') return null;

      const selected = object(responseBody.selectedAction);
      const apiGasUsed = decimal(apiReceipt?.gasUsed);
      const apiEffectiveGasPrice = decimal(apiReceipt?.effectiveGasPrice);
      const apiGasCost = decimal(apiReceipt?.gasCostWei);
      const apiTxBlock = decimal(apiTransaction?.blockNumber);
      const apiChainId = typeof apiTransaction?.chainId === 'number' && Number.isSafeInteger(apiTransaction.chainId)
        ? BigInt(apiTransaction.chainId) : decimal(apiTransaction?.chainId);
      const preBlockNumber = hexQuantity(preState.blockNumber);
      const apiPayerBlock = object(responseBody.payerBlock);
      const selectedMatches = selected?.kind === 'approve' && selected.tokenAssetId === 'USDC' &&
        typeof selected.token === 'string' && selected.token.toLowerCase() === spec.tokenAddress &&
        typeof selected.spender === 'string' && selected.spender.toLowerCase() === spec.spender &&
        selected.amountUnits === spec.amountUnits && selected.gasLimit === '100000';
      if (!selectedMatches || apiGasUsed === null || apiGasUsed <= 0n || apiEffectiveGasPrice === null || apiGasCost === null ||
          apiGasUsed * apiEffectiveGasPrice !== apiGasCost || apiReceipt?.status !== 'success' ||
          apiReceipt.transactionHash?.toString().toLowerCase() !== transactionHash ||
          apiReceipt.from?.toString().toLowerCase() !== cached.payerAddress ||
          apiReceipt.to?.toString().toLowerCase() !== spec.tokenAddress ||
          decimal(apiReceipt.blockNumber) !== apiTxBlock ||
          apiTxBlock === null || preBlockNumber === null || apiChainId !== BigInt(pinned.release.manifest.executionIdentity.localChainId) ||
          apiTransaction?.from?.toString().toLowerCase() !== cached.payerAddress ||
          apiTransaction?.to?.toString().toLowerCase() !== spec.tokenAddress ||
          apiTransaction?.type !== 'eip1559' || decimal(apiTransaction?.transactionIndex) !== 0n ||
          decimal(apiTransaction?.nonce) !== 0n || decimal(apiTransaction?.valueWei) !== 0n ||
          decimal(apiTransaction?.gasLimit) !== 100_000n || typeof apiTransaction?.input !== 'string' ||
          apiTransaction.input.toLowerCase() !== `${APPROVE_SELECTOR}${spec.spender.slice(2).padStart(64, '0')}${BigInt(spec.amountUnits).toString(16).padStart(64, '0')}` ||
          apiReceipt?.blockHash?.toString().toLowerCase() !== apiTransaction?.blockHash?.toString().toLowerCase() ||
          !apiPayerBlock || apiPayerBlock.hash?.toString().toLowerCase() !== apiTransaction?.blockHash?.toString().toLowerCase() ||
          decimal(apiPayerBlock.number) !== apiTxBlock || apiPayerBlock.parentHash?.toString().toLowerCase() !== preState.blockHash ||
          apiTxBlock !== preBlockNumber + 1n || !Array.isArray(apiPayerBlock.transactions) ||
          apiPayerBlock.transactions.length !== 1 || object(apiPayerBlock.transactions[0])?.hash?.toString().toLowerCase() !== transactionHash ||
          object(apiPayerBlock.transactions[0])?.from?.toString().toLowerCase() !== cached.payerAddress) return null;

      const rpc = this.observerRpc(intent.environmentId);
      const [rpcReceiptValue, rpcTransactionValue] = await Promise.all([
        this.callRpc(rpc, { jsonrpc: '2.0', id: 's4-fixture-receipt', method: 'eth_getTransactionReceipt', params: [transactionHash] }),
        this.callRpc(rpc, { jsonrpc: '2.0', id: 's4-fixture-transaction', method: 'eth_getTransactionByHash', params: [transactionHash] }),
      ]);
      const rpcReceipt = object(rpcReceiptValue);
      const rpcTransaction = object(rpcTransactionValue);
      const receiptBlockNumber = hexQuantity(rpcReceipt?.blockNumber);
      const txBlockNumber = hexQuantity(rpcTransaction?.blockNumber);
      const gasUsed = hexQuantity(rpcReceipt?.gasUsed);
      const effectiveGasPrice = hexQuantity(rpcReceipt?.effectiveGasPrice);
      const blockTag = receiptBlockNumber === null ? null : `0x${receiptBlockNumber.toString(16)}`;
      const block = blockTag ? object(await this.callRpc(rpc, {
        jsonrpc: '2.0', id: 's4-fixture-block', method: 'eth_getBlockByNumber', params: [blockTag, true],
      })) : null;
      const rpcLogs = Array.isArray(rpcReceipt?.logs) ? rpcReceipt.logs.map(object) : [];
      const log = rpcLogs.length === 1 ? rpcLogs[0] : null;
      const topics = Array.isArray(log?.topics) ? log!.topics : [];
      const expectedInput = `${APPROVE_SELECTOR}${spec.spender.slice(2).padStart(64, '0')}${BigInt(spec.amountUnits).toString(16).padStart(64, '0')}`;
      const apiLogs = Array.isArray(apiReceipt?.logs) ? apiReceipt.logs.map(object) : [];
      const apiLog = apiLogs.length === 1 ? apiLogs[0] : null;
      const expectedAmountWord = `0x${BigInt(spec.amountUnits).toString(16).padStart(64, '0')}`;
      const expectedOwnerTopic = `0x${cached.payerAddress.slice(2).padStart(64, '0')}`;
      const expectedSpenderTopic = `0x${spec.spender.slice(2).padStart(64, '0')}`;
      if (!rpcReceipt || !rpcTransaction || !block || receiptBlockNumber === null || txBlockNumber !== receiptBlockNumber ||
          gasUsed === null || effectiveGasPrice === null || gasUsed <= 0n || receiptBlockNumber !== apiTxBlock ||
          rpcReceipt.transactionHash?.toString().toLowerCase() !== transactionHash || rpcReceipt.status !== '0x1' ||
          rpcReceipt.blockHash?.toString().toLowerCase() !== block.hash?.toString().toLowerCase() ||
          rpcReceipt.from?.toString().toLowerCase() !== cached.payerAddress || rpcReceipt.to?.toString().toLowerCase() !== spec.tokenAddress ||
          rpcTransaction.hash?.toString().toLowerCase() !== transactionHash ||
          rpcTransaction.from?.toString().toLowerCase() !== cached.payerAddress || rpcTransaction.to?.toString().toLowerCase() !== spec.tokenAddress ||
          rpcTransaction.type !== '0x2' ||
          hexQuantity(rpcTransaction.chainId) !== BigInt(pinned.release.manifest.executionIdentity.localChainId) ||
          hexQuantity(rpcTransaction.nonce) !== 0n || hexQuantity(rpcTransaction.value) !== 0n ||
          hexQuantity(rpcTransaction.gas) !== 100_000n || rpcTransaction.input?.toString().toLowerCase() !== expectedInput ||
          rpcTransaction.blockHash?.toString().toLowerCase() !== rpcReceipt.blockHash?.toString().toLowerCase() ||
          hexQuantity(rpcTransaction.transactionIndex) !== 0n || hexQuantity(rpcReceipt.transactionIndex) !== 0n ||
          block.number?.toString().toLowerCase() !== blockTag || block.parentHash?.toString().toLowerCase() !== preState.blockHash ||
          !Array.isArray(block.transactions) || block.transactions.length !== 1 ||
          object(block.transactions[0])?.hash?.toString().toLowerCase() !== transactionHash ||
          object(block.transactions[0])?.from?.toString().toLowerCase() !== cached.payerAddress ||
          topics.length !== 3 || topics[0]?.toString().toLowerCase() !== APPROVAL_TOPIC ||
          topics[1]?.toString().toLowerCase() !== expectedOwnerTopic || topics[2]?.toString().toLowerCase() !== expectedSpenderTopic ||
          log?.address?.toString().toLowerCase() !== spec.tokenAddress || log?.data?.toString().toLowerCase() !== expectedAmountWord ||
          apiLog?.address?.toString().toLowerCase() !== spec.tokenAddress ||
          !Array.isArray(apiLog?.topics) || apiLog!.topics!.length !== 3 ||
          (apiLog!.topics as unknown[])[0]?.toString().toLowerCase() !== APPROVAL_TOPIC ||
          (apiLog!.topics as unknown[])[1]?.toString().toLowerCase() !== expectedOwnerTopic ||
          (apiLog!.topics as unknown[])[2]?.toString().toLowerCase() !== expectedSpenderTopic ||
          apiLog?.data?.toString().toLowerCase() !== expectedAmountWord || apiLog?.removed === true ||
          gasUsed !== apiGasUsed || effectiveGasPrice !== apiEffectiveGasPrice || gasUsed * effectiveGasPrice !== apiGasCost ||
          log?.transactionHash?.toString().toLowerCase() !== transactionHash ||
          log?.blockHash?.toString().toLowerCase() !== rpcReceipt.blockHash?.toString().toLowerCase() ||
          hexQuantity(log?.blockNumber) !== receiptBlockNumber || hexQuantity(log?.transactionIndex) !== 0n || log?.removed === true) {
        attempt.reasonCode = 'adapter_outcome_unknown';
        return null;
      }

      const receiptProjection = {
        transactionHash, status: 'success', from: cached.payerAddress, to: spec.tokenAddress,
        blockNumber: `0x${receiptBlockNumber.toString(16)}`, blockHash: block.hash!.toString().toLowerCase(),
        transactionIndex: '0x0', gasUsed: gasUsed.toString(), effectiveGasPrice: effectiveGasPrice.toString(),
        logs: [{ address: spec.tokenAddress, owner: cached.payerAddress, spender: spec.spender,
          amountUnits: spec.amountUnits, logIndex: hexQuantity(log!.logIndex)?.toString() ?? null }],
      };
      const transactionProjection = {
        hash: transactionHash, from: cached.payerAddress, to: spec.tokenAddress,
        chainId: BigInt(pinned.release.manifest.executionIdentity.localChainId).toString(),
        nonce: '0', input: expectedInput, valueWei: '0', gasLimit: '100000',
        blockNumber: `0x${receiptBlockNumber.toString(16)}`, blockHash: block.hash!.toString().toLowerCase(), transactionIndex: '0x0',
      };
      const safeBlock = { number: `0x${receiptBlockNumber.toString(16)}`,
        hash: block.hash!.toString().toLowerCase(), parentHash: preState.blockHash, transactionCount: 1 };
      attempt.transaction = transactionProjection;
      attempt.receipt = receiptProjection;
      attempt.block = safeBlock;
      attempt.gasCostWei = (gasUsed * effectiveGasPrice).toString();

      const postState = await this.readCaseBaseline(intent, pinned.release, pinned.taskCase, cached.payerAddress, receiptBlockNumber);
      if (!postState) {
        attempt.reasonCode = 'adapter_outcome_unknown';
        return null;
      }
      const postHash = sha256CanonicalTaskJson(postState.projection).toLowerCase();
      attempt.postState = { blockNumber: postState.blockNumber, blockHash: postState.blockHash,
        projection: postState.projection, reads: postState.reads, baselineSha256: postHash };
      if (postHash !== intent.initialStateSha256.toLowerCase() ||
          postHash !== pinned.taskCase.initialState.stateSha256.toLowerCase() ||
          !this.s4TransitionMatches(preState.projection, postState.projection, spec, gasUsed * effectiveGasPrice)) {
        attempt.reasonCode = 'baseline_state_mismatch';
        return null;
      }
      const proof: JsonRecord = {
        stage: 'pre_task_fixture_setup', outcome: 'observed', reasonCode: null,
        preparationId: intent.preparationId, generationId: cached.generationId,
        operationId, transactionHash, responseSha256: attempt.responseSha256,
        idempotencyKeySha256: attempt.idempotencyKeySha256,
        action: { ...action }, preState: attempt.preState,
        transaction: transactionProjection, receipt: receiptProjection,
        block: { number: `0x${receiptBlockNumber.toString(16)}`, hash: block.hash!.toString().toLowerCase(),
          parentHash: preState.blockHash, transactionCount: 1 },
        gasCostWei: (gasUsed * effectiveGasPrice).toString(),
        postState: { blockNumber: postState.blockNumber, blockHash: postState.blockHash,
          projection: postState.projection, reads: postState.reads, baselineSha256: postHash },
      };
      cached.s4AllowanceFixture = proof;
      return proof;
    } catch {
      attempt.reasonCode = 'adapter_outcome_unknown';
      return null;
    }
  }

  private s4PreStateMatches(taskCase: TaskCase, observedValue: unknown): boolean {
    if (taskCase.taskId !== 'S4') return false;
    const observed = object(observedValue);
    if (!observed || !Array.isArray(observed.balances) || !Array.isArray(observed.allowances)) return false;
    const targetKey = `${taskCase.objective.owner}|${taskCase.objective.tokenAssetId}|${taskCase.objective.spender.toLowerCase()}`;
    const expectedBalances = taskCase.initialState.balances;
    const expectedAllowances = taskCase.initialState.allowances;
    if (observed.balances.length !== expectedBalances.length || observed.allowances.length !== expectedAllowances.length) return false;
    const seenBalances = new Set<string>();
    for (const expected of expectedBalances) {
      const key = `${expected.account.toLowerCase()}|${expected.assetId}`;
      const actual = (observed.balances as unknown[]).map(object).find((item) => item && `${String(item.account).toLowerCase()}|${String(item.assetId)}` === key);
      if (!actual || seenBalances.has(key) || decimal(actual.amountUnits) === null) return false;
      seenBalances.add(key);
      const expectedAmount = decimal(expected.amountUnits)!;
      if (expected.account === 'participant' && expected.assetId === 'ETH') {
        if (BigInt(actual.amountUnits as string) <= expectedAmount) return false;
      } else if (BigInt(actual.amountUnits as string) !== expectedAmount) return false;
    }
    const seenAllowances = new Set<string>();
    for (const expected of expectedAllowances) {
      const key = `${expected.owner.toLowerCase()}|${expected.tokenAssetId}|${expected.spender.toLowerCase()}`;
      const actual = (observed.allowances as unknown[]).map(object).find((item) => item &&
        `${String(item.owner).toLowerCase()}|${String(item.tokenAssetId)}|${String(item.spender).toLowerCase()}` === key);
      if (!actual || seenAllowances.has(key) || decimal(actual.amountUnits) === null) return false;
      seenAllowances.add(key);
      const target = key === targetKey;
      if (target ? BigInt(actual.amountUnits as string) !== 0n : BigInt(actual.amountUnits as string) !== BigInt(expected.amountUnits)) return false;
    }
    return true;
  }

  private s4TransitionMatches(beforeValue: unknown, afterValue: unknown, spec: S4AllowanceFixtureSpec, gasCost: bigint): boolean {
    const before = object(beforeValue), after = object(afterValue);
    if (!before || !after || !Array.isArray(before.balances) || !Array.isArray(after.balances) ||
        !Array.isArray(before.allowances) || !Array.isArray(after.allowances) ||
        before.balances.length !== after.balances.length || before.allowances.length !== after.allowances.length) return false;
    const balanceMap = (value: unknown[]): Map<string, bigint | null> => new Map<string, bigint | null>(value.map(object).filter((item): item is JsonRecord => item !== null)
      .map((item) => [`${String(item.account).toLowerCase()}|${String(item.assetId)}`, decimal(item.amountUnits)] as const));
    const allowanceMap = (value: unknown[]): Map<string, bigint | null> => new Map<string, bigint | null>(value.map(object).filter((item): item is JsonRecord => item !== null)
      .map((item) => [`${String(item.owner).toLowerCase()}|${String(item.tokenAssetId)}|${String(item.spender).toLowerCase()}`, decimal(item.amountUnits)] as const));
    const beforeBalances = balanceMap(before.balances), afterBalances = balanceMap(after.balances);
    const beforeAllowances = allowanceMap(before.allowances), afterAllowances = allowanceMap(after.allowances);
    if (beforeBalances.size !== before.balances.length || afterBalances.size !== after.balances.length ||
        beforeAllowances.size !== before.allowances.length || afterAllowances.size !== after.allowances.length ||
        beforeBalances.size !== afterBalances.size || beforeAllowances.size !== afterAllowances.size) return false;
    const nativeKey = [...beforeBalances.keys()].find((key) => key === 'participant|ETH');
    if (!nativeKey) return false;
    for (const [key, amount] of beforeBalances) {
      const next = afterBalances.get(key);
      if (amount === null || next === null || next === undefined) return false;
      if (key === nativeKey ? amount - next !== gasCost : amount !== next) return false;
    }
    const targetKey: string = `participant|USDC|${spec.spender}`;
    for (const [key, amount] of beforeAllowances) {
      const next = afterAllowances.get(key);
      if (amount === null || next === null || next === undefined) return false;
      if (key === targetKey ? amount !== 0n || next !== BigInt(spec.amountUnits) : amount !== next) return false;
    }
    return beforeAllowances.has(targetKey);
  }

  private async verifyFundingReceipt(
    intent: TaskPreparationIntentPins,
    release: ValidatedTaskReleaseRecord,
    status: PublicPreparationStatus,
    payerAddress: string,
  ): Promise<JsonRecord | null> {
    const fixture = status.fixture;
    const facts = fixture.facts;
    if (!fixture.transactionHash || !fixture.blockHash || !fixture.fixtureHash || !facts || !status.request ||
        status.request.payerAddress?.toLowerCase() !== payerAddress.toLowerCase()) return null;
    const amount = decimal(facts.amountUnits);
    const payerBefore = decimal(facts.payerTokenBefore);
    const payerAfter = decimal(facts.payerTokenAfter);
    const donorBefore = decimal(facts.donorTokenBefore);
    const donorAfter = decimal(facts.donorTokenAfter);
    const nativeBalance = decimal(facts.payerNativeBalance);
    if (amount === null || amount <= 0n || payerBefore === null || payerAfter === null || donorBefore === null ||
        donorAfter === null || nativeBalance === null || payerAfter - payerBefore !== amount || donorBefore - donorAfter !== amount) return null;
    const usdc = release.manifest.executionIdentity.assets.filter((asset) => asset.assetId === 'USDC' && asset.kind === 'erc20');
    if (usdc.length !== 1 || !usdc[0]!.address) return null;
    const rpc = await this.callRpc(this.observerRpc(intent.environmentId), {
      jsonrpc: '2.0', id: 'fixture-receipt', method: 'eth_getTransactionReceipt', params: [fixture.transactionHash],
    });
    const receipt = object(rpc);
    const receiptBlockNumber = hexQuantity(receipt?.blockNumber);
    if (!receipt || typeof receipt.transactionHash !== 'string' || receipt.transactionHash.toLowerCase() !== fixture.transactionHash ||
        typeof receipt.blockHash !== 'string' || receipt.blockHash.toLowerCase() !== fixture.blockHash || receipt.status !== '0x1' ||
        receiptBlockNumber === null ||
        typeof receipt.from !== 'string' || !ADDRESS.test(receipt.from) || typeof receipt.to !== 'string' ||
        receipt.to.toLowerCase() !== usdc[0]!.address!.toLowerCase() ||
        !Array.isArray(receipt.logs)) return null;
    const matching = receipt.logs.filter((value) => {
      const log = object(value);
      const topics = log?.topics;
      if (!log || typeof log.address !== 'string' || log.address.toLowerCase() !== usdc[0]!.address!.toLowerCase() ||
          !Array.isArray(topics) || topics.length !== 3 || typeof topics[0] !== 'string' || topics[0].toLowerCase() !== TRANSFER_TOPIC ||
          topicAddress(topics[2]) !== payerAddress.toLowerCase() || !hexBytes(log.data)) return false;
      try { return BigInt(log.data as string) === amount; } catch { return false; }
    });
    if (matching.length !== 1) return null;
    const log = object(matching[0]);
    const transferFrom = topicAddress((log?.topics as unknown[])[1]);
    if (!transferFrom || transferFrom !== receipt.from.toLowerCase()) return null;
    const transaction = object(await this.callRpc(this.observerRpc(intent.environmentId), {
      jsonrpc: '2.0', id: 'fixture-transaction', method: 'eth_getTransactionByHash', params: [fixture.transactionHash],
    }));
    const expectedTransferInput = `0xa9059cbb${payerAddress.slice(2).toLowerCase().padStart(64, '0')}${amount.toString(16).padStart(64, '0')}`;
    if (!transaction || typeof transaction.hash !== 'string' || transaction.hash.toLowerCase() !== fixture.transactionHash ||
        typeof transaction.from !== 'string' || transaction.from.toLowerCase() !== transferFrom ||
        typeof transaction.to !== 'string' || transaction.to.toLowerCase() !== usdc[0]!.address!.toLowerCase() ||
        typeof transaction.input !== 'string' || transaction.input.toLowerCase() !== expectedTransferInput ||
        typeof transaction.blockHash !== 'string' || transaction.blockHash.toLowerCase() !== fixture.blockHash ||
        transaction.blockHash.toLowerCase() !== receipt.blockHash.toLowerCase() ||
        hexQuantity(transaction.blockNumber) !== receiptBlockNumber) return null;
    return {
      transactionHash: fixture.transactionHash,
      blockHash: fixture.blockHash,
      fixtureHash: fixture.fixtureHash,
      amountUnits: amount.toString(),
      payerAddress: payerAddress.toLowerCase(),
      tokenAddress: usdc[0]!.address.toLowerCase(),
      transferLog: {
        address: usdc[0]!.address.toLowerCase(),
        from: transferFrom,
        to: payerAddress.toLowerCase(),
        amountUnits: amount.toString(),
        logIndex: typeof log?.logIndex === 'string' ? log.logIndex : null,
      },
      receiptStatus: 'success',
      receiptBlockNumber: `0x${receiptBlockNumber.toString(16)}`,
      readOnlyObserver: true,
    };
  }

  private async readCaseBaseline(
    intent: TaskPreparationIntentPins,
    release: ValidatedTaskReleaseRecord,
    taskCase: TaskCase,
    payerAddress: string,
    atBlockNumber?: bigint,
  ): Promise<JsonRecord | null> {
    const initial = taskCase.initialState;
    if (initial.deliveredComponentIds.length || initial.fulfilledObligationIds.length) return null;
    const identity = release.manifest.executionIdentity;
    const assets = new Map<string, typeof identity.assets[number]>();
    for (const asset of identity.assets) {
      if (assets.has(asset.assetId)) return null;
      assets.set(asset.assetId, asset);
    }
    const addresses = new Set(identity.contracts.map((item) => item.address.toLowerCase()));
    const blockNumberResponse = atBlockNumber === undefined ? await this.callRpc(this.observerRpc(intent.environmentId), {
      jsonrpc: '2.0', id: 'baseline-head', method: 'eth_blockNumber', params: [],
    }) : `0x${atBlockNumber.toString(16)}`;
    const head = hexQuantity(blockNumberResponse);
    if (head === null) return null;
    const blockTag = `0x${head.toString(16)}`;
    const requests: RpcRequest[] = [{ jsonrpc: '2.0', id: 'baseline-block', method: 'eth_getBlockByNumber', params: [blockTag, false] }];
    const reads: Array<{ index: number; field: 'balance' | 'allowance'; account: string; assetId: string; owner?: string; spender?: string }> = [];
    for (let index = 0; index < initial.balances.length; index += 1) {
      const item = initial.balances[index]!;
      const asset = assets.get(item.assetId);
      const account = item.account === 'participant' ? payerAddress : item.account.toLowerCase();
      if (!asset || !(item.account === 'participant' || ADDRESS.test(item.account)) || BigInt(asset.chainId) !== BigInt(identity.localChainId)) return null;
      const id = `balance-${index}`;
      if (asset.kind === 'native') {
        if (asset.address !== null) return null;
        requests.push({ jsonrpc: '2.0', id, method: 'eth_getBalance', params: [account, blockTag] });
      } else {
        if (!asset.address || !ADDRESS.test(asset.address)) return null;
        requests.push({ jsonrpc: '2.0', id, method: 'eth_call', params: [
          { to: asset.address, data: `${BALANCE_OF_SELECTOR}${account.slice(2).toLowerCase().padStart(64, '0')}` }, blockTag,
        ] });
      }
      reads.push({ index, field: 'balance', account: item.account, assetId: item.assetId });
    }
    for (let index = 0; index < initial.allowances.length; index += 1) {
      const item = initial.allowances[index]!;
      const asset = assets.get(item.tokenAssetId);
      const owner = item.owner === 'participant' ? payerAddress : item.owner.toLowerCase();
      const spender = item.spender.toLowerCase();
      if (!asset || asset.kind !== 'erc20' || !asset.address || !(item.owner === 'participant' || ADDRESS.test(item.owner)) ||
          !addresses.has(spender) || BigInt(asset.chainId) !== BigInt(identity.localChainId)) return null;
      requests.push({ jsonrpc: '2.0', id: `allowance-${index}`, method: 'eth_call', params: [
        { to: asset.address, data: `${ALLOWANCE_SELECTOR}${owner.slice(2).toLowerCase().padStart(64, '0')}${spender.slice(2).padStart(64, '0')}` }, blockTag,
      ] });
      reads.push({ index, field: 'allowance', account: item.owner, assetId: item.tokenAssetId, owner: item.owner, spender: item.spender });
    }
    const batchResult = await this.callRpcBatch(this.observerRpc(intent.environmentId), requests);
    if (!batchResult) return null;
    const responses = new Map(batchResult.responses.map((item) => [item.id, item.result]));
    const block = object(responses.get('baseline-block'));
    if (!block || block.number?.toString().toLowerCase() !== blockTag.toLowerCase() || typeof block.hash !== 'string' || !TX_HASH.test(block.hash)) return null;

    const balances = initial.balances.map((item, index) => {
      const result = responses.get(`balance-${index}`);
      const asset = assets.get(item.assetId);
      const amount = asset?.kind === 'native' ? hexQuantity(result) : hexUint256Data(result);
      if (amount === null) throw new Error('baseline_balance_unobserved');
      return { account: item.account, assetId: item.assetId, amountUnits: amount.toString() };
    });
    const allowances = initial.allowances.map((item, index) => {
      const amount = hexUint256Data(responses.get(`allowance-${index}`));
      if (amount === null) throw new Error('baseline_allowance_unobserved');
      return { owner: item.owner, tokenAssetId: item.tokenAssetId, spender: item.spender, amountUnits: amount.toString() };
    });
    const balanceKey = (item: typeof balances[number]) => `${item.account.toLowerCase()}|${item.assetId}`;
    const allowanceKey = (item: typeof allowances[number]) => `${item.owner.toLowerCase()}|${item.tokenAssetId}|${item.spender.toLowerCase()}`;
    const compareStable = (left: string, right: string) => left < right ? -1 : left > right ? 1 : 0;
    balances.sort((left, right) => compareStable(balanceKey(left), balanceKey(right)));
    allowances.sort((left, right) => compareStable(allowanceKey(left), allowanceKey(right)));
    const projection = {
      balances,
      allowances,
      deliveredComponentIds: [],
      fulfilledObligationIds: [],
    };
    const safeReads: JsonRecord[] = [];
    for (const request of batchResult.requests) {
      const response = batchResult.responses.find((item) => item.id === request.id);
      if (!response) return null;
      const result = safeBaselineRpcResult(request, response.result);
      if (result === null) return null;
      safeReads.push({ method: request.method, params: request.params, result });
    }
    return {
      blockNumber: blockTag,
      blockHash: block.hash.toLowerCase(),
      projection,
      reads: safeReads,
      sameBlock: true,
      queriedKeyCount: reads.length,
    };
  }

  private async validateEnvironmentHealth(
    intent: TaskPreparationIntentPins,
    release: ValidatedTaskReleaseRecord,
    apiBase: URL,
    taskCase: TaskCase,
  ): Promise<boolean> {
    const identity = release.manifest.executionIdentity;
    const anvilPin = this.deps.anvilManifestPinByEnvironment[intent.environmentId];
    if (!anvilPin || !HASH.test(anvilPin.manifestSha256) ||
        anvilPin.manifestSha256.toLowerCase() !== intent.environmentManifestSha256.toLowerCase() ||
        !anvilPin.executionNetwork || !anvilPin.hardFork || !/^\d+\.\d+\.\d+$/.test(anvilPin.anvilVersion) ||
        identity.sourceNetwork.toLowerCase() !== `eip155:${identity.sourceChainId}` ||
        identity.localNetwork.toLowerCase() !== `eip155:${identity.localChainId}`) return false;
    const healthResult = await this.httpJson(endpoint(apiBase, '/healthz'), { method: 'GET', cache: 'no-store', redirect: 'error' });
    const health = object(healthResult.body);
    if (healthResult.status !== 200 || !health || health.status !== 'ready' || health.boundary !== 'benchmark-environment-api' ||
        typeof health.manifestSha256 !== 'string' || health.manifestSha256.toLowerCase() !== intent.environmentManifestSha256.toLowerCase() ||
        typeof health.applicationSourceSha256 !== 'string' || health.applicationSourceSha256.toLowerCase() !== intent.applicationSourceHash.toLowerCase() ||
        !Array.isArray(health.environments)) return false;
    const environments = health.environments.map(object).filter((item): item is JsonRecord => item !== null && item.envId === intent.environmentId);
    if (environments.length !== 1) return false;
    // AICODE-NOTE: Equal fork baselines do not make a different environment's
    // facilitator compatible with a case's immutable public payment tuple.
    let requiredRecipient: string | null = null;
    switch (taskCase.taskId) {
      case 'M1': requiredRecipient = taskCase.objective.paymentRequirements.recipient; break;
      case 'S2': requiredRecipient = taskCase.objective.completePaymentRequirements.recipient; break;
      case 'S3': case 'M2': requiredRecipient = taskCase.objective.required.recipient; break;
    }
    if (requiredRecipient !== null) {
      const facilitator = object(environments[0]!.facilitator);
      if (!ADDRESS.test(requiredRecipient) || typeof facilitator?.address !== 'string'
        || !ADDRESS.test(facilitator.address)
        || facilitator.address.toLowerCase() !== requiredRecipient.toLowerCase()) return false;
    }
    const rawAnvil = object(environments[0]!.anvil);
    if (!rawAnvil || typeof rawAnvil.clientVersion !== 'string' || typeof rawAnvil.chainId !== 'string' ||
        typeof rawAnvil.executionNetwork !== 'string' || typeof rawAnvil.hardFork !== 'string' ||
        typeof rawAnvil.forkBlockNumber !== 'string' || typeof rawAnvil.forkBlockHash !== 'string' ||
        !rawAnvil.clientVersion.toLowerCase().includes(`anvil/v${anvilPin.anvilVersion}`.toLowerCase()) ||
        BigInt(rawAnvil.chainId) !== BigInt(identity.localChainId) ||
        // CAIP-2 localNetwork and Anvil's engine executionNetwork are separate pins.
        rawAnvil.executionNetwork.toLowerCase() !== anvilPin.executionNetwork.toLowerCase() ||
        rawAnvil.hardFork.toLowerCase() !== anvilPin.hardFork.toLowerCase() ||
        BigInt(rawAnvil.forkBlockNumber) !== BigInt(identity.localForkBlockNumber) ||
        !hash32Matches(rawAnvil.forkBlockHash, identity.sourceBlockHash)) return false;

    const sourceBase = normalizeOrigin(this.deps.sourceRpcUrl, 'bef_task_preparation_source_rpc_unconfigured');
    const sourceHealthResult = await this.httpJson(endpoint(sourceBase, '/healthz'), { method: 'GET', cache: 'no-store', redirect: 'error' });
    const sourceHealth = object(sourceHealthResult.body);
    if (sourceHealthResult.status !== 200 || !sourceHealth || sourceHealth.status !== 'ok' ||
        sourceHealth.boundary !== 'source-readonly-proxy' || sourceHealth.manifestSha256 !== intent.environmentManifestSha256.toLowerCase()) return false;

    const sourceBlockTag = `0x${BigInt(identity.sourceBlockNumber).toString(16)}`;
    const sourceRpc = await this.callRpcBatch(sourceBase, [
      { jsonrpc: '2.0', id: 'source-chain-id', method: 'eth_chainId', params: [] },
      { jsonrpc: '2.0', id: 'source-pinned-block', method: 'eth_getBlockByNumber', params: [sourceBlockTag, false] },
    ]);
    if (!sourceRpc) return false;
    const sourceResults = new Map(sourceRpc.responses.map((item) => [item.id, item.result]));
    const sourceBlock = object(sourceResults.get('source-pinned-block'));
    const sourceChainId = hexQuantity(sourceResults.get('source-chain-id'));
    if (!sourceBlock || sourceChainId !== BigInt(identity.sourceChainId) ||
        sourceBlock.number?.toString().toLowerCase() !== sourceBlockTag || typeof sourceBlock.hash !== 'string' ||
        !hash32Matches(sourceBlock.hash, identity.sourceBlockHash)) return false;

    const localRpc = await this.callRpcBatch(this.observerRpc(intent.environmentId), [
      { jsonrpc: '2.0', id: 'local-chain-id', method: 'eth_chainId', params: [] },
      { jsonrpc: '2.0', id: 'local-pinned-block', method: 'eth_getBlockByNumber',
        params: [`0x${BigInt(identity.localForkBlockNumber).toString(16)}`, false] },
    ]);
    if (!localRpc) return false;
    const localResults = new Map(localRpc.responses.map((item) => [item.id, item.result]));
    const localBlock = object(localResults.get('local-pinned-block'));
    const localChainId = hexQuantity(localResults.get('local-chain-id'));
    const localBlockTag = `0x${BigInt(identity.localForkBlockNumber).toString(16)}`;
    return Boolean(localBlock && localChainId === BigInt(identity.localChainId) &&
      localBlock.number?.toString().toLowerCase() === localBlockTag && typeof localBlock.hash === 'string' &&
      hash32Matches(localBlock.hash, identity.sourceBlockHash));
  }

  private healthProjection(intent: TaskPreparationIntentPins, release: ValidatedTaskReleaseRecord): JsonRecord {
    const identity = release.manifest.executionIdentity;
    return {
      boundary: 'benchmark-environment-api',
      environmentId: intent.environmentId,
      environmentManifestSha256: intent.environmentManifestSha256.toLowerCase(),
      applicationSourceSha256: intent.applicationSourceHash.toLowerCase(),
      sourceNetwork: identity.sourceNetwork,
      sourceChainId: identity.sourceChainId,
      sourceBlockNumber: identity.sourceBlockNumber,
      sourceBlockHash: identity.sourceBlockHash.toLowerCase(),
      localNetwork: identity.localNetwork,
      localChainId: identity.localChainId,
      localForkBlockNumber: identity.localForkBlockNumber,
    };
  }

  private resetIdentityMatches(status: PublicPreparationStatus, intent: TaskPreparationIntentPins, release: ValidatedTaskReleaseRecord): boolean {
    const identity = status.baselineReset?.identity;
    const pinned = release.manifest.executionIdentity;
    const anvilPin = this.deps.anvilManifestPinByEnvironment[intent.environmentId];
    if (!identity || !anvilPin || anvilPin.manifestSha256.toLowerCase() !== intent.environmentManifestSha256.toLowerCase() ||
        identity.manifestSha256 !== intent.environmentManifestSha256.toLowerCase() || identity.facilitatorRecovered !== true ||
        typeof identity.clientVersion !== 'string' || typeof identity.hardFork !== 'string' ||
        typeof identity.chainId !== 'string' || typeof identity.executionNetwork !== 'string' ||
        typeof identity.forkBlockNumber !== 'string') return false;
    try {
      return identity.clientVersion.toLowerCase().includes(`anvil/v${anvilPin.anvilVersion}`.toLowerCase()) &&
        identity.hardFork.toLowerCase() === anvilPin.hardFork.toLowerCase() &&
        BigInt(identity.chainId) === BigInt(pinned.localChainId) &&
        BigInt(identity.forkBlockNumber) === BigInt(pinned.localForkBlockNumber) &&
        identity.executionNetwork.toLowerCase() === anvilPin.executionNetwork.toLowerCase() &&
        hash32Matches(identity.forkBlockHash, pinned.sourceBlockHash);
    } catch { return false; }
  }

  private statusMatchesRequest(status: PublicPreparationStatus, intent: TaskPreparationIntentPins, cached: CachedGeneration): boolean {
    const request = status.request;
    return status.envId === intent.environmentId && status.preparationId === intent.preparationId && request !== null &&
      request.publicPinsSha256?.toLowerCase() === cached.publicPinsSha256 &&
      request.requestSha256.toLowerCase() === cached.requestSha256 && request.participantId === cached.participantId &&
      request.payerAddress?.toLowerCase() === cached.payerAddress && request.resourceVariant === cached.resourceVariant &&
      request.manifestSha256?.toLowerCase() === intent.environmentManifestSha256.toLowerCase();
  }

  private async fenceOnce(intent: TaskPreparationIntentPins, requestedGenerationId: string | null): Promise<ConfirmedTaskEnvironmentFence> {
    if (!validIntent(intent) || (requestedGenerationId !== null && !UUID.test(requestedGenerationId))) {
      throw new Error('bef_task_preparation_fence_identity_invalid');
    }
    this.fencing.add(intent.preparationId.toLowerCase());
    this.attempted.add(intent.preparationId.toLowerCase());
    const publicPins = taskPreparationPublicPinsSha256(intent);
    const apiBase = this.apiBase(intent.environmentId);
    // Fence by durable preparation ID even if status is missing or contradictory; the post-fence
    // public identity/generation checks decide whether this caller may release its owner lease.
    const before = await this.readPublicStatus(intent, apiBase);
    const path = `${this.preparationPath(intent)}/fence`;
    let fenceReply: JsonRecord | null = null;
    try {
      const response = await this.adminRequest(apiBase, 'POST', path, {});
      fenceReply = object(response.body);
    } catch { /* A secret-free GET below can confirm a lost fence reply. */ }
    const after = await this.readPublicStatus(intent, apiBase);
    if (after.kind !== 'status' || after.status.status !== 'fenced' || !after.status.fenceConfirmedAt ||
        after.status.envId !== intent.environmentId || after.status.preparationId !== intent.preparationId) {
      throw new Error('bef_task_preparation_fence_unconfirmed');
    }
    if (after.status.request && after.status.request.publicPinsSha256?.toLowerCase() !== publicPins) {
      throw new Error('bef_task_preparation_fence_identity_mismatch');
    }
    if (requestedGenerationId !== null && after.status.generationId !== requestedGenerationId.toLowerCase()) {
      throw new Error('bef_task_preparation_fence_generation_mismatch');
    }
    if (fenceReply && (fenceReply.fenceConfirmed !== true || fenceReply.signerErased !== true || fenceReply.chainState !== 'not_touched')) {
      throw new Error('bef_task_preparation_fence_response_invalid');
    }
    const evidence = await this.writeEvidence(intent, 'fence', {
      publicPinsSha256: publicPins,
      expectedOwnerGenerationId: requestedGenerationId?.toLowerCase() ?? null,
      actualBefGenerationId: after.status.generationId,
      before: before.kind === 'status' ? safeStatusProjection(before.status) : null,
      after: safeStatusProjection(after.status),
      fenceConfirmed: true,
      chainState: fenceReply?.chainState === 'not_touched' ? 'not_touched' : 'fence_state_confirmed_by_public_get',
    });
    if (!evidence) throw new Error('bef_task_preparation_fence_evidence_unavailable');
    this.clearCredentials(intent.preparationId);
    return {
      confirmed: true,
      preparationId: intent.preparationId,
      leaseId: intent.leaseId,
      environmentId: intent.environmentId,
      // Null remains null when owner never received the original PUT generation response.
      generationId: requestedGenerationId?.toLowerCase() ?? null,
      evidence,
    };
  }

  private async readPublicStatus(intent: TaskPreparationIntentPins, base?: URL): Promise<
    { kind: 'missing' } | { kind: 'status'; status: PublicPreparationStatus } | { kind: 'invalid' }
  > {
    const apiBase = base ?? this.apiBase(intent.environmentId);
    const response = await this.httpJson(endpoint(apiBase, this.preparationPath(intent)), {
      method: 'GET', headers: { 'x-bef-admin-key': this.deps.adminKey }, cache: 'no-store', redirect: 'error',
    });
    const body = object(response.body);
    if (response.status === 404 && body?.error === 'preparation_not_found') return { kind: 'missing' };
    if (response.status !== 200) return { kind: 'invalid' };
    const status = parsePublicPreparationStatus(response.body, intent.environmentId, intent.preparationId);
    return status ? { kind: 'status', status } : { kind: 'invalid' };
  }

  private async writeEvidence(intent: TaskPreparationIntentPins, kind: SafeTaskPreparationEvidence['kind'], evidence: JsonRecord): Promise<EvidenceReference | null> {
    try {
      const reference = await this.deps.evidenceSink.write({
        schemaVersion: 'owner-bef-task-preparation-evidence/v1', kind,
        preparationId: intent.preparationId, environmentId: intent.environmentId,
        publicPinsSha256: taskPreparationPublicPinsSha256(intent), evidence,
      });
      if (!evidenceReference(reference)) return null;
      return { path: reference.path, sha256: reference.sha256.toLowerCase(), boundary: PREPARATION_BOUNDARY };
    } catch { return null; }
  }

  private async adminRequest(base: URL, method: 'PUT' | 'POST', path: string, body: JsonRecord): Promise<{ status: number; body: unknown }> {
    return this.httpJson(endpoint(base, path), {
      method,
      headers: { 'x-bef-admin-key': this.deps.adminKey, 'content-type': 'application/json' },
      body: JSON.stringify(body), cache: 'no-store', redirect: 'error',
    });
  }

  private async httpJson(url: URL, init: RequestInit): Promise<{ status: number; body: unknown }> {
    const response = await this.fetchImpl(url, { ...init, signal: AbortSignal.timeout(this.requestTimeoutMs) });
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes.byteLength > MAX_JSON_BYTES) return { status: response.status, body: null };
    try { return { status: response.status, body: JSON.parse(new TextDecoder().decode(bytes)) as unknown }; }
    catch { return { status: response.status, body: null }; }
  }

  private async callRpc(url: URL, request: RpcRequest): Promise<unknown> {
    const response = await this.httpJson(url, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(request), cache: 'no-store', redirect: 'error',
    });
    const body = object(response.body) as RpcResponse | null;
    if (response.status !== 200 || !body || body.jsonrpc !== '2.0' || body.id !== request.id || Object.hasOwn(body, 'error') || !Object.hasOwn(body, 'result')) {
      throw new Error('bef_task_preparation_rpc_unavailable');
    }
    return body.result;
  }

  private async callRpcBatch(url: URL, requests: RpcRequest[]): Promise<RpcObservation | null> {
    if (!requests.length || requests.length > 256) return null;
    const response = await this.httpJson(url, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(requests), cache: 'no-store', redirect: 'error',
    });
    if (response.status !== 200 || !Array.isArray(response.body) || response.body.length !== requests.length) return null;
    const expected = new Map(requests.map((request) => [request.id, request]));
    const responses: Array<{ id: string; result: unknown }> = [];
    for (const raw of response.body) {
      const item = object(raw) as RpcResponse | null;
      if (!item || item.jsonrpc !== '2.0' || typeof item.id !== 'string' || !expected.has(item.id) ||
          Object.hasOwn(item, 'error') || !Object.hasOwn(item, 'result')) return null;
      responses.push({ id: item.id, result: item.result });
    }
    if (new Set(responses.map((item) => item.id)).size !== requests.length) return null;
    return { requests, responses };
  }

  private apiBase(envId: string): URL {
    return normalizeOrigin(this.deps.apiBaseByEnvironment[envId], 'bef_task_preparation_api_unconfigured');
  }

  private observerRpc(envId: string): URL {
    return normalizeOrigin(this.deps.observerRpcByEnvironment[envId], 'bef_task_preparation_observer_unconfigured');
  }

  private preparationPath(intent: TaskPreparationIntentPins): string {
    return `/internal/admin/environments/${encodeURIComponent(intent.environmentId)}/preparations/${encodeURIComponent(intent.preparationId)}`;
  }

  private unknown(reasonCode: PreparationUnknownReason, generationId?: string | null): TaskPreparationAdapterOutcome {
    return { status: 'unknown', reasonCode, ...(generationId ? { generationId: generationId.toLowerCase() } : {}) };
  }
}

