/**
 * Durable bridge from admitted task actions to the selected BEF participant
 * tools. This module is an internal executor boundary; it does not create or
 * activate runs and exposes no owner-facing or agent-facing route.
 *
 * AICODE-NOTE: the only server-side release pin BEF currently publishes for
 * its whole API source tree is healthz.applicationSourceSha256. BTS pins that
 * same digest as executionIdentity.x402ServiceSha256 for the selected BEF
 * application build. The immutable manifest digest is checked separately.
 */
import { createHash, randomUUID } from 'node:crypto';
import type { PaymentRequired, PaymentRequirements } from '@x402/core/types';
import { sql } from 'drizzle-orm';
import { z } from 'zod';
import type { OwnerDatabase } from './db.js';
import { HttpError } from './http-error.js';
import { recordTaskActionReceipt, TaskActionCommandSchema, type TaskActionCommand } from './task-action-service.js';
import {
  assertTaskExecutionBinding,
  ensureTaskExecutionBinding,
  getTaskExecutionBinding,
  getTaskExecutionContext,
  type PublicTaskExecutionBindingInput,
} from './task-execution-binding.js';
import { canonicalTaskJson, type TaskReleaseQuerySource, type TaskReleaseTransaction } from './task-release.js';
import {
  assertTaskPaymentProtocol,
  resolveTaskPaymentReference,
  type TaskPaymentReference,
} from './task-payment-references.js';
import {
  findPinnedResourceOffer,
  hasPaymentChallengeHeader,
  hashPaymentChallengeHeaders,
  paymentRequirementMatchesPins,
  pinnedOfferResponseMatches,
  OWNER_X402_SIGNER_SDK_VERSIONS,
  type EphemeralX402Signer,
  type PinnedX402Offer,
  type PinnedX402Policy,
  type PinnedX402Resource,
} from './task-action-x402.js';
export type { EphemeralX402Signer, PinnedX402Offer, PinnedX402Policy, PinnedX402Resource } from './task-action-x402.js';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HASH = /^[0-9a-f]{64}$/i;
const TOKEN = /^[A-Za-z0-9_-]{32,128}$/;
const TX_HASH = /^0x[0-9a-f]{64}$/i;
const ENV_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const MAX_RESPONSE_BYTES = 1024 * 1024;

type Transaction = Parameters<Parameters<OwnerDatabase['transaction']>[0]>[0];

export interface BefTaskSessionBinding {
  runId: string;
  taskIndex: number;
  envId: string;
  generationId: string;
  manifestHash: string;
  applicationSourceHash: string;
  /** Participant run token. It is held in RAM and is never written to DB or evidence. */
  runToken: string;
  /** Public generation identities are RAM-only bindings used for payment scope checks. */
  participantId?: string;
  payerAddress?: string;
  x402Signer?: EphemeralX402Signer;
}

export interface SafeTaskActionEvidence {
  schema: 'bef-task-action-observation-v1';
  actionId: string;
  runId: string;
  taskIndex: number;
  actionSequence: string;
  ownerOperationId: string;
  actionKind: TaskActionCommand['kind'];
  commandSha256: string;
  environmentId: string;
  generationId: string | null;
  manifestSha256: string | null;
  applicationSourceSha256: string | null;
  idempotencyKey: string;
  status: 'observed' | 'rejected_before_execution' | 'unknown';
  reasonCode?: string;
  requestStartedAt?: string;
  requestFinishedAt?: string;
  httpStatus?: number;
  befOperationId?: string;
  transactionHash?: string;
  outcome?: 'success' | 'reverted';
  receiptStatus?: 'success' | 'reverted';
  rawResponseSha256?: string;
  participantToolResponse?: Record<string, unknown>;
  receiptGasUsed?: string;
  receiptEffectiveGasPriceWei?: string;
  /** Payment challenge and settlement metadata with no authorization bytes/signature. */
  paymentProtocol?: Record<string, unknown>;
  environmentHealth?: {
    boundary: 'benchmark-environment-api';
    manifestSha256: string;
    applicationSourceSha256: string;
    envId: string;
  };
}

export interface TaskActionEvidenceSink {
  /** Persist this allow-listed projection and return its durable raw path/hash. */
  write(evidence: SafeTaskActionEvidence): Promise<{ path: string; sha256: string }>;
}

export interface BefTaskExecutorDependencies {
  db: OwnerDatabase;
  taskReleaseSource: TaskReleaseQuerySource;
  /** Trusted server configuration keyed by the immutable run environment ID. */
  participantApiByEnvironment: Readonly<Record<string, string>>;
  /** Exact x402 policy projection keyed by env; hash must equal the health/release manifest pin. */
  pinnedX402PolicyByEnvironment?: Readonly<Record<string, PinnedX402Policy>>;
  evidenceSink: TaskActionEvidenceSink;
  fetch?: typeof fetch;
  requestTimeoutMs?: number;
  staleDeliveryMs?: number;
}

export type ExecuteTaskActionResult =
  | { status: 'idle' }
  | { status: 'in_progress'; actionId: string }
  | {
    status: 'recorded'; actionId: string; receiptStatus: 'observed' | 'rejected_before_execution' | 'unknown';
    evidenceHash: string; evidencePath: string | null; transactionHash?: string; befOperationId?: string;
  };

interface ActionCandidate {
  id: string;
  run_id: string;
  task_index: number;
  task_id: string;
  action_sequence: string;
  operation_id: string;
  payload_hash: string;
  action_kind: TaskActionCommand['kind'];
  command_json: unknown;
  environment_id: string;
  owner_id: string;
  agent_id: string;
  access_generation: number;
  grant_id: string;
  environment_manifest_hash: string | null;
  application_source_hash: string | null;
  outbox_status: 'pending' | 'delivered';
  delivered_at: Date | string | null;
  receipt_status: 'pending' | 'observed' | 'rejected_before_execution' | 'unknown';
}

interface RunAuthorizationRow {
  id: string;
  owner_id: string;
  agent_id: string;
  access_generation: number;
  agent_policy_revision: number;
  mode: 'training' | 'ranked';
  task_ids: string[];
  status: string;
  environment_id: string | null;
  release_identity: string;
  manifest_hash: string;
}

interface TaskAuthorizationRow {
  run_id: string;
  task_index: number;
  task_id: string;
  status: string;
  accepted_action_sequence: string;
  action_cutoff_sequence: string | null;
  closure_status: 'open' | 'closing' | 'closed' | 'unknown';
}

interface LockedContext {
  candidate: ActionCandidate;
  run: RunAuthorizationRow;
  task: TaskAuthorizationRow;
  command: TaskActionCommand;
  ownerAdmissionStatus: string;
  agentAccessGeneration: number;
  agentAccessRevoked: boolean;
}

interface HealthIdentity {
  boundary: 'benchmark-environment-api';
  manifestSha256: string;
  applicationSourceSha256: string;
  envId: string;
  facilitatorAddress?: string;
  anvil?: {
    clientVersion: string;
    chainId: string;
    executionNetwork: string;
    hardFork: string;
    forkBlockNumber: string;
    forkBlockHash: string;
  };
  sdkVersions?: { core: string; evm: string; viem: string };
}

interface DispatchObservation {
  status: SafeTaskActionEvidence['status'];
  reasonCode?: string;
  requestStartedAt?: string;
  requestFinishedAt?: string;
  httpStatus?: number;
  befOperationId?: string;
  transactionHash?: string;
  outcome?: 'success' | 'reverted';
  receiptStatus?: 'success' | 'reverted';
  rawResponseSha256?: string;
  participantToolResponse?: Record<string, unknown>;
  receiptGasUsed?: string;
  receiptEffectiveGasPriceWei?: string;
  paymentProtocol?: Record<string, unknown>;
  environmentHealth?: HealthIdentity;
}

function record<T>(value: unknown): T[] {
  if (!Array.isArray(value)) throw new Error('task_action_executor_database_result_invalid');
  return value as T[];
}

async function query<T>(tx: Transaction, statement: ReturnType<typeof sql>): Promise<T[]> {
  return record<T>(await tx.execute(statement));
}

function digest(value: unknown): string {
  return createHash('sha256').update(canonicalTaskJson(value)).digest('hex');
}

function iso(value: Date | string): string {
  const parsed = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(parsed.getTime())) throw new Error('task_action_executor_timestamp_invalid');
  return parsed.toISOString();
}

function sessionKey(runId: string, taskIndex: number): string {
  return `${runId}:${taskIndex}`;
}

function publicBindingInput(binding: BefTaskSessionBinding): PublicTaskExecutionBindingInput {
  return {
    runId: binding.runId, taskIndex: binding.taskIndex, envId: binding.envId,
    generationId: binding.generationId, manifestHash: binding.manifestHash,
    applicationSourceHash: binding.applicationSourceHash,
    ...(binding.participantId ? { participantId: binding.participantId } : {}),
    ...(binding.payerAddress ? { payerAddress: binding.payerAddress } : {}),
  };
}

function validateBinding(input: BefTaskSessionBinding): void {
  if (!UUID.test(input.runId) || !Number.isSafeInteger(input.taskIndex) || input.taskIndex < 0 || input.taskIndex > 11 ||
      !ENV_ID.test(input.envId) || !UUID.test(input.generationId) || !HASH.test(input.manifestHash) ||
      !HASH.test(input.applicationSourceHash) || !TOKEN.test(input.runToken) ||
      (input.participantId !== undefined && !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(input.participantId)) ||
      (input.payerAddress !== undefined && !/^0x[0-9a-f]{40}$/i.test(input.payerAddress))) {
    throw new Error('task_action_executor_session_binding_invalid');
  }
  if (input.x402Signer && (!input.payerAddress || input.x402Signer.payerAddress.toLowerCase() !== input.payerAddress.toLowerCase())) {
    throw new Error('task_action_executor_payment_signer_identity_mismatch');
  }
}

function configuredBaseUrl(value: string | undefined): URL {
  let url: URL;
  try { url = new URL(value ?? ''); } catch { throw new Error('task_action_executor_api_unconfigured'); }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash ||
      (url.pathname !== '' && url.pathname !== '/')) {
    throw new Error('task_action_executor_api_origin_invalid');
  }
  return url;
}

function configuredLocalForkBaseUrl(value: string | undefined): URL {
  const url = configuredBaseUrl(value);
  const hostname = url.hostname.toLowerCase();
  const allowedHosts = new Set([
    'localhost', '127.0.0.1', '[::1]', '::1', 'host.docker.internal',
    'api', 'bef-api', 'benchmark-environment-api',
  ]);
  if (url.protocol !== 'http:' || !allowedHosts.has(hostname)) {
    throw new Error('task_action_executor_purchase_requires_local_bef');
  }
  return url;
}

function commandFrom(value: unknown): TaskActionCommand {
  const parsed = TaskActionCommandSchema.safeParse(value);
  if (!parsed.success) throw new Error('task_action_executor_persisted_command_invalid');
  return parsed.data;
}

async function readBounded(response: Response, limit = MAX_RESPONSE_BYTES): Promise<Uint8Array> {
  const declared = response.headers.get('content-length');
  if (declared && /^\d+$/.test(declared) && Number(declared) > limit) throw new Error('response_too_large');
  if (!response.body) return new Uint8Array();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      size += next.value.byteLength;
      if (size > limit) {
        await reader.cancel().catch(() => undefined);
        throw new Error('response_too_large');
      }
      chunks.push(next.value);
    }
  } finally {
    reader.releaseLock();
  }
  const output = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { output.set(chunk, offset); offset += chunk.byteLength; }
  return output;
}

function parseJson(bytes: Uint8Array): Record<string, unknown> | null {
  try {
    const value: unknown = JSON.parse(new TextDecoder().decode(bytes));
    return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null;
  } catch { return null; }
}

function healthIdentity(value: unknown, binding: BefTaskSessionBinding): HealthIdentity | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const body = value as Record<string, unknown>;
  if (body.status !== 'ready' || body.boundary !== 'benchmark-environment-api' ||
      typeof body.manifestSha256 !== 'string' || body.manifestSha256.toLowerCase() !== binding.manifestHash.toLowerCase() ||
      typeof body.applicationSourceSha256 !== 'string' || body.applicationSourceSha256.toLowerCase() !== binding.applicationSourceHash.toLowerCase() ||
      !Array.isArray(body.environments)) return null;
  const found = body.environments.find((item) => item && typeof item === 'object' && !Array.isArray(item) &&
    (item as Record<string, unknown>).envId === binding.envId);
  if (!found) return null;
  const facilitator = (found as Record<string, unknown>).facilitator;
  const facilitatorAddress = facilitator && typeof facilitator === 'object' && !Array.isArray(facilitator)
    ? (facilitator as Record<string, unknown>).address : undefined;
  const rawAnvil = (found as Record<string, unknown>).anvil;
  const anvil = rawAnvil && typeof rawAnvil === 'object' && !Array.isArray(rawAnvil)
    ? rawAnvil as Record<string, unknown> : null;
  const anvilFields = anvil && ['clientVersion', 'chainId', 'executionNetwork', 'hardFork', 'forkBlockNumber', 'forkBlockHash']
    .every((key) => typeof anvil[key] === 'string') ? {
      clientVersion: anvil.clientVersion as string,
      chainId: anvil.chainId as string,
      executionNetwork: anvil.executionNetwork as string,
      hardFork: anvil.hardFork as string,
      forkBlockNumber: anvil.forkBlockNumber as string,
      forkBlockHash: anvil.forkBlockHash as string,
    } : undefined;
  const rawVersions = body.dependencyVersions;
  const versions = rawVersions && typeof rawVersions === 'object' && !Array.isArray(rawVersions)
    ? rawVersions as Record<string, unknown> : null;
  const sdkVersions = versions && typeof versions['@x402/core'] === 'string' &&
    typeof versions['@x402/evm'] === 'string' && typeof versions.viem === 'string'
    ? { core: versions['@x402/core'], evm: versions['@x402/evm'], viem: versions.viem } : undefined;
  return {
    boundary: 'benchmark-environment-api', manifestSha256: body.manifestSha256,
    applicationSourceSha256: body.applicationSourceSha256, envId: binding.envId,
    ...(typeof facilitatorAddress === 'string' && /^0x[0-9a-f]{40}$/i.test(facilitatorAddress) ? { facilitatorAddress } : {}),
    ...(anvilFields ? { anvil: anvilFields } : {}),
    ...(sdkVersions ? { sdkVersions } : {}),
  };
}

export function privateAnvilHealthMatches(health: HealthIdentity, policy: PinnedX402Policy): boolean {
  const anvil = health.anvil;
  const versions = health.sdkVersions;
  if (!anvil || !versions || !health.facilitatorAddress) return false;
  const expectedClient = `anvil/v${policy.localAnvil.anvilVersion}`.toLowerCase();
  let chainId: bigint;
  let forkBlock: bigint;
  try {
    chainId = BigInt(anvil.chainId);
    forkBlock = BigInt(anvil.forkBlockNumber);
  } catch { return false; }
  let expectedForkBlock: bigint;
  try { expectedForkBlock = BigInt(policy.localAnvil.forkBlockNumber); } catch { return false; }
  return anvil.clientVersion.toLowerCase().includes(expectedClient) &&
    chainId === BigInt(policy.localAnvil.chainId) &&
    anvil.executionNetwork.toLowerCase() === policy.localAnvil.executionNetwork.toLowerCase() &&
    anvil.hardFork.toLowerCase() === policy.localAnvil.hardFork.toLowerCase() &&
    forkBlock === expectedForkBlock &&
    anvil.forkBlockHash.toLowerCase() === policy.localAnvil.forkBlockHash.toLowerCase() &&
    versions.core === policy.sdkVersions.core && versions.evm === policy.sdkVersions.evm &&
    versions.viem === policy.sdkVersions.viem;
}

function paymentHeaders(response: Response): Record<string, string> {
  const result: Record<string, string> = {};
  response.headers.forEach((value, name) => { result[name.toLowerCase()] = value; });
  return result;
}

function hashSettlementHeaders(headers: Readonly<Record<string, string>>): string | undefined {
  const value = headers['payment-response'] ?? headers['x-payment-response'];
  return value ? createHash('sha256').update(value, 'utf8').digest('hex') : undefined;
}

export function pinnedPurchaseDeliveryMatches(input: {
  body: Record<string, unknown> | null;
  resourceId: string;
  resourceSha256: string;
  contentType: string;
  operationId: string;
}): boolean {
  const { body, resourceId, resourceSha256, contentType, operationId } = input;
  if (!body || body.operationId !== operationId || body.resourceId !== resourceId ||
      body.contentHash !== resourceSha256 || body.contentType !== contentType ||
      typeof body.contentBytes !== 'string' || body.contentBytes.length < 4 || body.contentBytes.length > MAX_RESPONSE_BYTES * 2) return false;
  try {
    const bytes = Buffer.from(body.contentBytes, 'base64');
    if (bytes.toString('base64') !== body.contentBytes || createHash('sha256').update(bytes).digest('hex') !== resourceSha256) return false;
    const decoded: unknown = JSON.parse(bytes.toString('utf8'));
    return canonicalTaskJson(decoded) === canonicalTaskJson(body.content);
  } catch { return false; }
}

function responseErrorCode(body: Record<string, unknown> | null): string | null {
  const value = body?.error;
  return typeof value === 'string' && /^[a-z0-9_]{1,80}$/.test(value) ? value : null;
}

type ParticipantToolRequest = { method: 'GET'; path: string } | { method: 'POST'; path: string };

export function isReadOnlyCommand(command: TaskActionCommand): boolean {
  return command.kind === 'inspect_catalog' || command.kind === 'inspect_offer';
}

export function participantToolRequest(command: TaskActionCommand, paymentReference?: TaskPaymentReference): ParticipantToolRequest | null {
  if (command.kind === 'purchase') return null;
  if (command.kind === 'pay') return paymentReference?.kind === 'pay' ? { method: 'POST', path: '/pay' } : null;
  if (command.kind === 'retrieve') return paymentReference?.kind === 'retrieve'
    ? { method: 'GET', path: `/retrieve?operationId=${encodeURIComponent(paymentReference.operationId)}` }
    : null;
  if (command.kind === 'inspect_catalog') return { method: 'GET', path: '/catalog' };
  if (command.kind === 'inspect_offer') return {
    method: 'GET', path: `/offer?resourceId=${encodeURIComponent(command.resourceId)}`,
  };
  return { method: 'POST', path: `/${command.kind}` };
}

function validPaymentQuote(value: unknown): boolean {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const payment = value as Record<string, unknown>;
  return typeof payment.scheme === 'string' && payment.scheme.length > 0 && payment.scheme.length <= 80 &&
    typeof payment.network === 'string' && payment.network.length > 0 && payment.network.length <= 80 &&
    typeof payment.asset === 'string' && payment.asset.length > 0 && payment.asset.length <= 128 &&
    typeof payment.amount === 'string' && /^(?:0|[1-9][0-9]{0,77})$/.test(payment.amount) &&
    typeof payment.payTo === 'string' && /^0x[0-9a-f]{40}$/i.test(payment.payTo) &&
    typeof payment.transferMethod === 'string' && payment.transferMethod.length > 0 && payment.transferMethod.length <= 80;
}

function validOfferList(value: unknown): value is Array<Record<string, unknown>> {
  if (!Array.isArray(value) || value.length < 1 || value.length > 256) return false;
  const ids = new Set<string>();
  return value.every((item) => {
    if (!item || typeof item !== 'object' || Array.isArray(item)) return false;
    const offer = item as Record<string, unknown>;
    if (typeof offer.id !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(offer.id) || ids.has(offer.id) ||
        !validPaymentQuote(offer.payment)) return false;
    ids.add(offer.id);
    return true;
  });
}

export function readOnlyToolResponseMatches(command: Extract<TaskActionCommand, { kind: 'inspect_catalog' | 'inspect_offer' }>, value: unknown): boolean {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const body = value as Record<string, unknown>;
  if (body.freeInspection !== true || body.deliveryState !== 'not_delivered') return false;
  const bodyOperationId = typeof body.operationId === 'string' && UUID.test(body.operationId) ? body.operationId : null;
  const readHandle = body.readHandle;
  if (readHandle !== undefined) {
    if (!readHandle || typeof readHandle !== 'object' || Array.isArray(readHandle)) return false;
    const handle = readHandle as Record<string, unknown>;
    const expectedKind = command.kind === 'inspect_catalog' ? 'catalog' : 'offer';
    if (Object.keys(handle).sort().join(',') !== 'kind,operationId' || handle.kind !== expectedKind ||
        typeof handle.operationId !== 'string' || !UUID.test(handle.operationId) || bodyOperationId !== handle.operationId) return false;
  }
  if (command.kind === 'inspect_catalog') {
    if (!Array.isArray(body.catalog) || body.catalog.length < 1 || body.catalog.length > 128) return false;
    const resourceIds = new Set<string>();
    return body.catalog.every((item) => {
      if (!item || typeof item !== 'object' || Array.isArray(item)) return false;
      const resource = item as Record<string, unknown>;
      if (typeof resource.resourceId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(resource.resourceId) ||
          resourceIds.has(resource.resourceId) || typeof resource.resourceSha256 !== 'string' || !HASH.test(resource.resourceSha256) ||
          typeof resource.contentType !== 'string' || resource.contentType.length < 1 || resource.contentType.length > 128 ||
          (resource.dataType !== undefined && (typeof resource.dataType !== 'string' || resource.dataType.length < 1 || resource.dataType.length > 128)) ||
          !validOfferList(resource.offers)) return false;
      resourceIds.add(resource.resourceId);
      return true;
    });
  }
  if (body.resourceId !== command.resourceId || typeof body.resourceSha256 !== 'string' || !HASH.test(body.resourceSha256) ||
      typeof body.contentType !== 'string' || body.contentType.length < 1 || body.contentType.length > 128 ||
      (body.dataType !== undefined && (typeof body.dataType !== 'string' || body.dataType.length < 1 || body.dataType.length > 128)) ||
      !validPaymentQuote(body.payment) || !validOfferList(body.offers) || bodyOperationId === null) return false;
  const firstOffer = body.offers[0] as Record<string, unknown>;
  const rootPayment = body.payment as Record<string, unknown>;
  const firstPayment = firstOffer.payment as Record<string, unknown>;
  if (rootPayment.scheme !== firstPayment.scheme || rootPayment.network !== firstPayment.network ||
      rootPayment.amount !== firstPayment.amount || rootPayment.transferMethod !== firstPayment.transferMethod ||
      String(rootPayment.asset).toLowerCase() !== String(firstPayment.asset).toLowerCase() ||
      String(rootPayment.payTo).toLowerCase() !== String(firstPayment.payTo).toLowerCase()) return false;
  if (command.offerId !== undefined && !body.offers.some((item) => item.id === command.offerId)) return false;
  return typeof body.operationId === 'string' && UUID.test(body.operationId);
}

export function classifyReadOnlyBefTaskActionResponse(input: {
  command: Extract<TaskActionCommand, { kind: 'inspect_catalog' | 'inspect_offer' }>;
  status: number;
  headerOperationId: string | null;
  body: Record<string, unknown> | null;
  rawResponseSha256: string;
  participantToolResponse?: Record<string, unknown>;
}): DispatchObservation {
  const { command, status, headerOperationId, body, rawResponseSha256, participantToolResponse } = input;
  const bodyOperationId = typeof body?.operationId === 'string' ? body.operationId : null;
  const readHandle = body && body.readHandle && typeof body.readHandle === 'object' && !Array.isArray(body.readHandle)
    ? body.readHandle as Record<string, unknown> : null;
  const expectedKind = command.kind === 'inspect_catalog' ? 'catalog' : 'offer';
  const handleMatches = readHandle === null || (readHandle.kind === expectedKind &&
    typeof readHandle.operationId === 'string' && UUID.test(readHandle.operationId) && readHandle.operationId === bodyOperationId);
  const operationBindingMatches = command.kind === 'inspect_catalog'
    ? (bodyOperationId === null && headerOperationId === null && readHandle === null) ||
      (bodyOperationId !== null && UUID.test(bodyOperationId) && handleMatches &&
        (headerOperationId === null || headerOperationId === bodyOperationId))
    : bodyOperationId !== null && UUID.test(bodyOperationId) && handleMatches &&
      (headerOperationId === null || headerOperationId === bodyOperationId);
  if (status === 200 && body && participantToolResponse && operationBindingMatches && readOnlyToolResponseMatches(command, body)) {
    return {
      status: 'observed', rawResponseSha256, participantToolResponse,
      ...(bodyOperationId ? { befOperationId: bodyOperationId } : {}),
    };
  }
  return { status: 'unknown', reasonCode: 'participant_read_observation_ambiguous', httpStatus: status,
    ...(bodyOperationId && UUID.test(bodyOperationId) ? { befOperationId: bodyOperationId } : {}), rawResponseSha256,
    ...(participantToolResponse ? { participantToolResponse } : {}) };
}

export function selectedActionMatches(command: Exclude<TaskActionCommand, { kind: 'purchase' }>, value: unknown): boolean {
  if (command.kind === 'inspect_catalog' || command.kind === 'inspect_offer' || command.kind === 'pay' || command.kind === 'retrieve') return false;
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const selected = value as Record<string, unknown>;
  if (selected.kind !== command.kind) return false;
  switch (command.kind) {
    case 'approve':
      return selected.tokenAssetId === (command.tokenAssetId ?? 'WETH') && selected.amountUnits === command.amountUnits && selected.gasLimit === command.gasLimit;
    case 'transfer':
      return selected.amountUnits === command.amountUnits && typeof selected.recipient === 'string' &&
        selected.recipient.toLowerCase() === command.recipient.toLowerCase() && selected.gasLimit === command.gasLimit;
    case 'wrap':
    case 'unwrap':
      return selected.amountWei === command.amountWei && selected.gasLimit === command.gasLimit;
    case 'swap':
      return selected.inputAssetId === command.inputAssetId && selected.outputAssetId === command.outputAssetId &&
        selected.fee === (command.feeTier ?? 500) && selected.amountInUnits === command.amountInUnits &&
        selected.amountOutMinimumUnits === command.amountOutMinimumUnits && typeof selected.recipient === 'string' &&
        selected.recipient.toLowerCase() === command.recipient.toLowerCase() && selected.gasLimit === command.gasLimit;
  }
}

export function classifyBefTaskActionResponse(input: {
  status: number; headerOperationId: string | null; body: Record<string, unknown> | null; rawResponseSha256: string;
  participantToolResponse?: Record<string, unknown>;
}): DispatchObservation {
  const { status, headerOperationId, body, rawResponseSha256, participantToolResponse } = input;
  const bodyOperationId = typeof body?.operationId === 'string' ? body.operationId : undefined;
  const operationId = bodyOperationId ?? undefined;
  const receipt = body?.receipt && typeof body.receipt === 'object' && !Array.isArray(body.receipt)
    ? body.receipt as Record<string, unknown> : null;
  const transaction = body?.transaction && typeof body.transaction === 'object' && !Array.isArray(body.transaction)
    ? body.transaction as Record<string, unknown> : null;
  const transactionHash = typeof receipt?.transactionHash === 'string' && TX_HASH.test(receipt.transactionHash)
    ? receipt.transactionHash.toLowerCase()
    : typeof body?.transactionHash === 'string' && TX_HASH.test(body.transactionHash) ? body.transactionHash.toLowerCase() : undefined;
  const code = responseErrorCode(body);
  // The selected-execution API binds operation identity in its response body.
  // Some deployments omit the optional response header, so compare it when
  // present but do not require it to classify a fully bound measurement.
  if (status === 200 && body && operationId &&
      (headerOperationId === null || headerOperationId === operationId) &&
      (body.outcome === 'success' || body.outcome === 'reverted') && receipt && transaction && transactionHash &&
      participantToolResponse !== undefined &&
      typeof receipt.transactionHash === 'string' && receipt.transactionHash.toLowerCase() === transactionHash.toLowerCase() &&
      typeof transaction.hash === 'string' && transaction.hash.toLowerCase() === transactionHash.toLowerCase() &&
      (receipt.status === 'success' || receipt.status === 'reverted') &&
      receipt.status === body.outcome && typeof receipt.gasUsed === 'string' && /^\d+$/.test(receipt.gasUsed) &&
      typeof receipt.effectiveGasPrice === 'string' && /^\d+$/.test(receipt.effectiveGasPrice)) {
    return {
      status: 'observed', befOperationId: operationId, transactionHash, outcome: body.outcome,
      receiptStatus: receipt.status, rawResponseSha256, receiptGasUsed: receipt.gasUsed,
      receiptEffectiveGasPriceWei: receipt.effectiveGasPrice,
      participantToolResponse,
    };
  }
  // These replies are emitted before a transaction can be broadcast. Other
  // errors, including generic 4xx/5xx, remain unknown because they may follow
  // an earlier idempotent operation or a lost receipt observation.
  if (status === 400 && ['invalid_selected_action', 'selected_action_outside_hard_bounds'].includes(code ?? '') ||
      status === 409 && code === 'generation_signer_unavailable' ||
      (status === 401 || status === 403) && ['scoped_authentication_required', 'generation_scope_denied'].includes(code ?? '')) {
    return { status: 'rejected_before_execution', reasonCode: code ?? 'participant_tool_rejected', httpStatus: status,
      ...(operationId ? { befOperationId: operationId } : {}), rawResponseSha256,
      ...(participantToolResponse ? { participantToolResponse } : {}) };
  }
  return { status: 'unknown', reasonCode: code ?? 'participant_tool_observation_ambiguous', httpStatus: status,
    ...(operationId ? { befOperationId: operationId } : {}), ...(transactionHash ? { transactionHash } : {}), rawResponseSha256,
    ...(participantToolResponse ? { participantToolResponse } : {}) };
}

type SplitSettlement = { success: boolean; transaction: string; network: string; payer?: string; amount?: string };

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  return Object.keys(value).sort().join(',') === [...expected].sort().join(',');
}

export function classifySplitPayBefTaskActionResponse(input: {
  status: number;
  headerOperationId: string | null;
  body: Record<string, unknown> | null;
  rawResponseSha256: string;
  expectedOperationId: string;
  settlement: SplitSettlement | null;
  payerAddress: string;
  network: string;
  asset: string;
  amount: string;
  payTo: string;
  participantToolResponse?: Record<string, unknown>;
}): DispatchObservation {
  const { body, expectedOperationId } = input;
  const payment = body && body.payment && typeof body.payment === 'object' && !Array.isArray(body.payment)
    ? body.payment as Record<string, unknown> : null;
  const settlement = input.settlement;
  const txHash = typeof payment?.transactionHash === 'string' && TX_HASH.test(payment.transactionHash)
    ? payment.transactionHash.toLowerCase() : null;
  const shapeMatches = Boolean(body && exactKeys(body, ['operationId', 'status', 'payment', 'deliveryHandle']) &&
    payment && exactKeys(payment, ['transactionHash', 'receiptStatus', 'amount', 'asset', 'network', 'payTo']));
  const operationMatches = body?.operationId === expectedOperationId && body?.status === 'payment_confirmed' &&
    body?.deliveryHandle === expectedOperationId &&
    (input.headerOperationId === null || input.headerOperationId === expectedOperationId);
  const paymentMatches = payment?.receiptStatus === 'success' && payment.amount === input.amount &&
    typeof payment.asset === 'string' && payment.asset.toLowerCase() === input.asset.toLowerCase() &&
    payment.network === input.network && typeof payment.payTo === 'string' && payment.payTo.toLowerCase() === input.payTo.toLowerCase();
  const settlementMatches = Boolean(settlement?.success && txHash && TX_HASH.test(settlement.transaction) &&
    settlement.transaction.toLowerCase() === txHash && settlement.network === input.network &&
    settlement.payer?.toLowerCase() === input.payerAddress.toLowerCase() &&
    (settlement.amount === undefined || settlement.amount === input.amount));
  if (input.status === 200 && shapeMatches && operationMatches && paymentMatches && settlementMatches &&
      input.participantToolResponse) {
    return {
      status: 'observed', befOperationId: expectedOperationId, transactionHash: txHash!,
      outcome: 'success', receiptStatus: 'success', rawResponseSha256: input.rawResponseSha256,
      participantToolResponse: input.participantToolResponse,
    };
  }
  const bodyOperationId = typeof body?.operationId === 'string' && UUID.test(body.operationId) ? body.operationId : undefined;
  return {
    status: 'unknown', reasonCode: 'task_split_pay_settlement_or_response_unverified', httpStatus: input.status,
    ...(bodyOperationId ? { befOperationId: bodyOperationId } : {}), ...(txHash ? { transactionHash: txHash } : {}),
    rawResponseSha256: input.rawResponseSha256,
    ...(input.participantToolResponse ? { participantToolResponse: input.participantToolResponse } : {}),
  };
}

function acceptedTermsMatchPins(reference: Extract<TaskPaymentReference, { kind: 'pay' }>, input: {
  policy: PinnedX402Policy;
  resourceId: string;
  offerId: string;
  amount: string;
  payTo: string;
}): boolean {
  const terms = reference.acceptedTerms;
  const handle = reference.readHandle;
  return UUID.test(handle.operationId) && (handle.kind === 'offer' || handle.kind === 'catalog') &&
    terms.scheme === input.policy.scheme && terms.network === input.policy.network &&
    terms.asset.toLowerCase() === input.policy.asset.toLowerCase() && terms.amount === input.amount &&
    terms.payTo.toLowerCase() === input.payTo.toLowerCase() && terms.transferMethod === input.policy.assetTransferMethod &&
    /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(input.resourceId) && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(input.offerId);
}

/** One-shot split payment using only the already observed read handle and terms. */
export async function dispatchSplitPaymentRequest(input: {
  fetch: typeof fetch;
  timeoutMs: number;
  apiBase: URL;
  binding: BefTaskSessionBinding;
  command: Extract<TaskActionCommand, { kind: 'pay' }>;
  reference: Extract<TaskPaymentReference, { kind: 'pay' }>;
  policy: PinnedX402Policy;
  selected: { resource: PinnedX402Resource; offer: PinnedX402Offer };
  health: HealthIdentity;
  idempotencyKey: string;
}): Promise<DispatchObservation> {
  const { fetch: fetchImpl, timeoutMs, apiBase, binding, command, reference, policy, selected, health, idempotencyKey } = input;
  const startedAt = new Date().toISOString();
  const signer = binding.x402Signer;
  const payPath = `/tools/${binding.envId}/pay`;
  const termsMatch = acceptedTermsMatchPins(reference, {
    policy, resourceId: command.resourceId, offerId: command.offerId, amount: selected.offer.amount,
    payTo: health.facilitatorAddress ?? '',
  });
  const baseProtocol = {
    schema: 'bef-x402-split-payment-observation-v1',
    resourceId: command.resourceId,
    offerId: command.offerId,
    resourceSha256: selected.resource.resourceSha256,
    amountUnits: selected.offer.amount,
    network: policy.network,
    asset: policy.asset,
    readHandle: reference.readHandle,
    acceptedTerms: reference.acceptedTerms,
    befServerSdkVersions: policy.sdkVersions,
    ownerSignerSdkVersions: OWNER_X402_SIGNER_SDK_VERSIONS,
  };
  if (policy.manifestSha256.toLowerCase() !== binding.manifestHash.toLowerCase() ||
      !privateAnvilHealthMatches(health, policy) || !health.facilitatorAddress || !termsMatch ||
      !binding.payerAddress || !signer || signer.payerAddress.toLowerCase() !== binding.payerAddress.toLowerCase()) {
    return { status: 'rejected_before_execution', reasonCode: 'task_split_pay_pinned_context_unavailable',
      requestStartedAt: startedAt, requestFinishedAt: new Date().toISOString(), environmentHealth: health,
      paymentProtocol: baseProtocol };
  }
  const requestBody = canonicalTaskJson(participantToolBody(command, reference));
  const headers: Record<string, string> = {
    authorization: `Bearer ${binding.runToken}`,
    'x-bef-generation': binding.generationId,
    'idempotency-key': idempotencyKey,
    accept: 'application/json',
    'content-type': 'application/json',
  };
  let challengeResponse: Response;
  let challengeBytes: Uint8Array;
  try {
    challengeResponse = await fetchImpl(new URL(payPath, apiBase), {
      method: 'POST', redirect: 'error', headers, body: requestBody,
      signal: AbortSignal.timeout(timeoutMs),
    });
    challengeBytes = await readBounded(challengeResponse);
  } catch {
    return { status: 'rejected_before_execution', reasonCode: 'task_split_pay_challenge_unavailable',
      requestStartedAt: startedAt, requestFinishedAt: new Date().toISOString(), environmentHealth: health,
      paymentProtocol: baseProtocol };
  }
  const challengeRawHash = createHash('sha256').update(challengeBytes).digest('hex');
  const challengeBody = parseJson(challengeBytes);
  const challengeHeaderId = challengeResponse.headers.get('x-bef-operation-id');
  const challengeHeaders = paymentHeaders(challengeResponse);
  if (challengeResponse.status !== 402 || !challengeHeaderId || !UUID.test(challengeHeaderId) ||
      (challengeBody?.operationId !== undefined && challengeBody.operationId !== challengeHeaderId) ||
      !hasPaymentChallengeHeader(challengeHeaders)) {
    return { status: 'rejected_before_execution', reasonCode: 'task_split_pay_challenge_invalid',
      httpStatus: challengeResponse.status, rawResponseSha256: challengeRawHash,
      requestStartedAt: startedAt, requestFinishedAt: new Date().toISOString(), environmentHealth: health,
      paymentProtocol: { ...baseProtocol, challengeResponseSha256: challengeRawHash } };
  }
  const challengeSha256 = hashPaymentChallengeHeaders(challengeHeaders);
  let declaration: PaymentRequired;
  let requirements: PaymentRequirements | null;
  let authorization: Record<string, string>;
  try {
    declaration = signer.parsePaymentRequired(challengeHeaders, challengeBody);
    requirements = paymentRequirementMatchesPins({
      declaration, expectedResourceId: command.resourceId, expectedOffer: selected.offer, policy,
      facilitatorAddress: health.facilitatorAddress, expectedPath: payPath,
    });
    if (!requirements || requirements.scheme !== reference.acceptedTerms.scheme ||
        requirements.network !== reference.acceptedTerms.network ||
        requirements.asset.toLowerCase() !== reference.acceptedTerms.asset.toLowerCase() ||
        requirements.amount !== reference.acceptedTerms.amount ||
        requirements.payTo.toLowerCase() !== reference.acceptedTerms.payTo.toLowerCase()) {
      throw new Error('task_split_pay_challenge_terms_mismatch');
    }
    authorization = await signer.createAuthorization(declaration, requirements);
  } catch {
    return { status: 'rejected_before_execution', reasonCode: 'task_split_pay_challenge_scope_mismatch',
      httpStatus: challengeResponse.status, rawResponseSha256: challengeRawHash,
      requestStartedAt: startedAt, requestFinishedAt: new Date().toISOString(), befOperationId: challengeHeaderId,
      environmentHealth: health,
      paymentProtocol: { ...baseProtocol, challengeResponseSha256: challengeRawHash, challengeHeaderSha256: challengeSha256 } };
  }
  const authorizationEntries = Object.entries(authorization);
  if (authorizationEntries.length !== 1 || !['payment-signature', 'x-payment'].includes(authorizationEntries[0]![0].toLowerCase()) ||
      authorizationEntries[0]![1].length < 16 || authorizationEntries[0]![1].length > 65_536) {
    return { status: 'rejected_before_execution', reasonCode: 'task_split_pay_authorization_invalid',
      requestStartedAt: startedAt, requestFinishedAt: new Date().toISOString(), befOperationId: challengeHeaderId,
      environmentHealth: health,
      paymentProtocol: { ...baseProtocol, challengeResponseSha256: challengeRawHash, challengeHeaderSha256: challengeSha256 } };
  }
  let paidResponse: Response;
  let paidBytes: Uint8Array;
  try {
    paidResponse = await fetchImpl(new URL(payPath, apiBase), {
      method: 'POST', redirect: 'error', headers: { ...headers, ...authorization }, body: requestBody,
      signal: AbortSignal.timeout(timeoutMs),
    });
    paidBytes = await readBounded(paidResponse);
  } catch {
    return { status: 'unknown', reasonCode: 'task_split_pay_response_lost',
      requestStartedAt: startedAt, requestFinishedAt: new Date().toISOString(), befOperationId: challengeHeaderId,
      environmentHealth: health,
      paymentProtocol: { ...baseProtocol, challengeResponseSha256: challengeRawHash,
        challengeHeaderSha256: challengeSha256, settlementObserved: false } };
  }
  const rawResponseSha256 = createHash('sha256').update(paidBytes).digest('hex');
  const body = parseJson(paidBytes);
  const paidHeaders = paymentHeaders(paidResponse);
  const headerOperationId = paidResponse.headers.get('x-bef-operation-id');
  let settlement: SplitSettlement | null = null;
  try {
    const parsed = signer.parseSettlement(paidHeaders);
    if (parsed) settlement = {
      success: parsed.success, transaction: parsed.transaction, network: parsed.network,
      ...(parsed.payer ? { payer: parsed.payer } : {}), ...(parsed.amount ? { amount: parsed.amount } : {}),
    };
  } catch { /* a malformed settlement remains unknown */ }
  const bodyPayment = body?.payment && typeof body.payment === 'object' && !Array.isArray(body.payment)
    ? body.payment as Record<string, unknown> : null;
  let participantToolResponse: Record<string, unknown> | undefined;
  try { participantToolResponse = safeMeasurementProjection(body, binding.runToken); }
  catch { /* persist hashes and settlement metadata without trusting malformed projection fields */ }
  const classified = classifySplitPayBefTaskActionResponse({
    status: paidResponse.status, headerOperationId, body, rawResponseSha256, expectedOperationId: challengeHeaderId,
    settlement, payerAddress: binding.payerAddress, network: policy.network, asset: policy.asset,
    amount: selected.offer.amount, payTo: health.facilitatorAddress,
    ...(participantToolResponse ? { participantToolResponse } : {}),
  });
  const transactionHash = typeof bodyPayment?.transactionHash === 'string' && TX_HASH.test(bodyPayment.transactionHash)
    ? bodyPayment.transactionHash.toLowerCase() : undefined;
  const settlementHeaderSha256 = hashSettlementHeaders(paidHeaders);
  return {
    ...classified,
    ...(classified.status === 'observed' && transactionHash ? { transactionHash } : {}),
    requestStartedAt: startedAt,
    requestFinishedAt: new Date().toISOString(),
    httpStatus: paidResponse.status,
    environmentHealth: health,
    paymentProtocol: {
      ...baseProtocol,
      facilitatorAddress: health.facilitatorAddress,
      payerAddress: binding.payerAddress,
      challengeResponseSha256: challengeRawHash,
      challengeHeaderSha256: challengeSha256,
      befOperationId: challengeHeaderId,
      settlementObserved: settlement !== null,
      settlementMatchesPins: classified.status === 'observed',
      ...(transactionHash ? { transactionHash } : {}),
      ...(settlementHeaderSha256 ? { settlementHeaderSha256 } : {}),
    },
  };
}

/** Retrieve only bytes from the already paid original operation; no signer is used. */
export async function dispatchSplitRetrieveRequest(input: {
  fetch: typeof fetch;
  timeoutMs: number;
  apiBase: URL;
  binding: BefTaskSessionBinding;
  operationId: string;
  resource: PinnedX402Resource;
  policy: PinnedX402Policy;
  idempotencyKey: string;
  health: HealthIdentity;
}): Promise<DispatchObservation> {
  const { fetch: fetchImpl, timeoutMs, apiBase, binding, operationId, resource, policy, idempotencyKey, health } = input;
  const startedAt = new Date().toISOString();
  if (!UUID.test(operationId) || !HASH.test(resource.resourceSha256) || !resource.resourceId || !resource.contentType ||
      policy.manifestSha256.toLowerCase() !== binding.manifestHash.toLowerCase() ||
      !privateAnvilHealthMatches(health, policy)) {
    return { status: 'rejected_before_execution', reasonCode: 'task_split_retrieve_pinned_resource_invalid', environmentHealth: health };
  }
  const path = `/tools/${binding.envId}/retrieve?operationId=${encodeURIComponent(operationId)}`;
  let response: Response;
  let bytes: Uint8Array;
  try {
    response = await fetchImpl(new URL(path, apiBase), {
      method: 'GET', redirect: 'error', headers: {
        authorization: `Bearer ${binding.runToken}`,
        'x-bef-generation': binding.generationId,
        'idempotency-key': idempotencyKey,
        accept: 'application/json',
      },
      signal: AbortSignal.timeout(timeoutMs),
    });
    bytes = await readBounded(response);
  } catch {
    return { status: 'unknown', reasonCode: 'task_split_retrieve_response_lost',
      requestStartedAt: startedAt, requestFinishedAt: new Date().toISOString(), environmentHealth: health,
      paymentProtocol: { schema: 'bef-x402-retrieve-observation-v1', payOperationId: operationId,
        resourceId: resource.resourceId, resourceSha256: resource.resourceSha256 } };
  }
  const rawResponseSha256 = createHash('sha256').update(bytes).digest('hex');
  const body = parseJson(bytes);
  const headerOperationId = response.headers.get('x-bef-operation-id');
  const expectedKeys = ['operationId', 'resourceId', 'contentType', 'contentHash', 'contentBytes', 'content'];
  const exactShape = Boolean(body && exactKeys(body, expectedKeys));
  const operationMatches = body?.operationId === operationId && (headerOperationId === null || headerOperationId === operationId);
  const deliveryMatches = response.status === 200 && exactShape && operationMatches && pinnedPurchaseDeliveryMatches({
    body, resourceId: resource.resourceId, resourceSha256: resource.resourceSha256,
    contentType: resource.contentType, operationId,
  });
  let participantToolResponse: Record<string, unknown> | undefined;
  try { participantToolResponse = safeMeasurementProjection(body, binding.runToken, deliveryMatches); }
  catch { /* malformed content is never projected as verified delivery */ }
  const deliveryEvidenceRetained = deliveryMatches && participantToolResponse !== undefined;
  return {
    status: deliveryEvidenceRetained ? 'observed' : 'unknown',
    ...(!deliveryMatches ? { reasonCode: 'task_split_retrieve_delivery_pin_mismatch' }
      : !deliveryEvidenceRetained ? { reasonCode: 'task_split_retrieve_evidence_projection_invalid' } : {}),
    httpStatus: response.status,
    requestStartedAt: startedAt,
    requestFinishedAt: new Date().toISOString(),
    befOperationId: operationId,
    rawResponseSha256,
    ...(participantToolResponse ? { participantToolResponse } : {}),
    environmentHealth: health,
    paymentProtocol: {
      schema: 'bef-x402-retrieve-observation-v1', payOperationId: operationId,
      resourceId: resource.resourceId, resourceSha256: resource.resourceSha256,
      contentSha256: deliveryMatches ? resource.resourceSha256 : undefined,
      deliveryMatchesPinnedResource: deliveryMatches,
    },
  };
}

export function participantToolBody(
  command: Exclude<TaskActionCommand, { kind: 'purchase' }>,
  paymentReference?: TaskPaymentReference,
): Record<string, unknown> {
  if (command.kind === 'pay') {
    if (paymentReference?.kind !== 'pay') throw new Error('task_action_executor_payment_reference_required');
    return {
      resourceId: command.resourceId,
      offerId: command.offerId,
      readHandle: paymentReference.readHandle,
      acceptedTerms: paymentReference.acceptedTerms,
    };
  }
  if (command.kind === 'retrieve') throw new Error('task_action_executor_retrieve_has_no_body');
  const { kind: _kind, ...body } = command;
  return body;
}

const RESPONSE_FIELDS = [
  'outcome', 'operationId', 'receipt', 'transaction', 'payerBlock', 'selectedAction',
  'before', 'after', 'effects', 'quote', 'fee', 'taskEvaluationInputs',
  'catalog', 'resourceId', 'resourceSha256', 'contentType', 'dataType', 'schema', 'provenance',
  'contentHash',
  'payment', 'offers', 'freeInspection', 'deliveryState',
  'readHandle', 'status', 'deliveryHandle',
] as const;
const SECRET_FIELD = /^(?:authorization|bearer|privateKey|secret|seed|mnemonic|signature|runToken)$/i;

export function safeMeasurementProjection(
  body: Record<string, unknown> | null, runToken?: string, includeVerifiedPurchasedContent = false,
): Record<string, unknown> | undefined {
  if (!body) return undefined;
  const copy = (value: unknown, depth: number): unknown => {
    if (depth > 12) throw new Error('participant_measurement_depth_exceeded');
    if (value === null || typeof value === 'boolean') return value;
    if (typeof value === 'number') {
      if (!Number.isFinite(value)) throw new Error('participant_measurement_number_invalid');
      return value;
    }
    if (typeof value === 'string') {
      if (value.length > MAX_RESPONSE_BYTES) throw new Error('participant_measurement_string_too_large');
      return runToken ? value.replaceAll(runToken, '[redacted]') : value;
    }
    if (Array.isArray(value)) {
      if (value.length > 4096) throw new Error('participant_measurement_array_too_large');
      return value.map((item) => copy(item, depth + 1));
    }
    if (value && typeof value === 'object') {
      const output: Record<string, unknown> = {};
      for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
        if (key.length > 128) throw new Error('participant_measurement_key_too_large');
        if (!SECRET_FIELD.test(key)) output[key] = copy(item, depth + 1);
      }
      return output;
    }
    throw new Error('participant_measurement_value_invalid');
  };
  const projected: Record<string, unknown> = {};
  const payment = body.payment && typeof body.payment === 'object' && !Array.isArray(body.payment)
    ? body.payment as Record<string, unknown> : null;
  const paymentReplyValid = exactKeys(body, ['operationId', 'status', 'payment', 'deliveryHandle']) &&
    typeof body.operationId === 'string' && UUID.test(body.operationId) && body.status === 'payment_confirmed' &&
    body.deliveryHandle === body.operationId && payment !== null &&
    exactKeys(payment, ['transactionHash', 'receiptStatus', 'amount', 'asset', 'network', 'payTo']) &&
    typeof payment.transactionHash === 'string' && TX_HASH.test(payment.transactionHash) &&
    payment.receiptStatus === 'success' && typeof payment.amount === 'string' && /^[1-9][0-9]{0,77}$/.test(payment.amount) &&
    typeof payment.asset === 'string' && /^0x[0-9a-f]{40}$/i.test(payment.asset) &&
    typeof payment.network === 'string' && payment.network.length > 0 && payment.network.length <= 128 &&
    typeof payment.payTo === 'string' && /^0x[0-9a-f]{40}$/i.test(payment.payTo);
  const rawReadHandle = body.readHandle && typeof body.readHandle === 'object' && !Array.isArray(body.readHandle)
    ? body.readHandle as Record<string, unknown> : null;
  const readHandleValid = rawReadHandle !== null && exactKeys(rawReadHandle, ['kind', 'operationId']) &&
    (rawReadHandle.kind === 'offer' || rawReadHandle.kind === 'catalog') &&
    typeof rawReadHandle.operationId === 'string' && UUID.test(rawReadHandle.operationId) &&
    body.operationId === rawReadHandle.operationId && body.freeInspection === true && body.deliveryState === 'not_delivered';
  for (const key of RESPONSE_FIELDS) {
    if (!(key in body)) continue;
    if (key === 'readHandle' && !readHandleValid) continue;
    if ((key === 'status' || key === 'deliveryHandle') && !paymentReplyValid) continue;
    projected[key] = copy(body[key], 0);
  }
  if (includeVerifiedPurchasedContent) {
    for (const key of ['contentBytes', 'content'] as const) if (key in body) projected[key] = copy(body[key], 0);
  }
  return Object.keys(projected).length ? projected : undefined;
}

async function lockOwner(tx: Transaction, ownerId: string): Promise<string> {
  const found = await query<{ id: string; admission_status: string }>(tx, sql`SELECT id,admission_status FROM oid_owner WHERE id=${ownerId} FOR NO KEY UPDATE`);
  if (!found.length) throw new Error('task_action_executor_owner_missing');
  return found[0]!.admission_status;
}

async function appendEvent(tx: Transaction, context: LockedContext, eventType: string, extra: Record<string, unknown> = {}): Promise<void> {
  const sequenceRows = await query<{ sequence: number }>(tx, sql`SELECT COALESCE(MAX(sequence),0)+1 AS sequence
    FROM oid_run_event WHERE run_id=${context.candidate.run_id}`);
  const payload = {
    actionId: context.candidate.id, taskIndex: context.candidate.task_index, taskId: context.candidate.task_id,
    actionSequence: context.candidate.action_sequence, ownerOperationId: context.candidate.operation_id,
    actionKind: context.candidate.action_kind, payloadHash: context.candidate.payload_hash, ...extra,
  };
  await tx.execute(sql`INSERT INTO oid_run_event(id,run_id,sequence,source,event_type,payload_hash,payload_json)
    VALUES (${randomUUID()},${context.candidate.run_id},${sequenceRows[0]?.sequence ?? 1},'executor',${eventType},
      ${digest(payload)},${canonicalTaskJson(payload)}::jsonb)`);
}

async function originalPayCommand(tx: Transaction, context: LockedContext, payActionId: string): Promise<Extract<TaskActionCommand, { kind: 'pay' }> | null> {
  const rows = await query<{ command_json: unknown }>(tx, sql`SELECT command_json FROM oid_run_task_action
    WHERE id=${payActionId} AND action_kind='pay' AND run_id=${context.candidate.run_id}
      AND task_index=${context.candidate.task_index} AND environment_id=${context.candidate.environment_id}
      AND owner_id=${context.candidate.owner_id} AND agent_id=${context.candidate.agent_id}
      AND access_generation=${context.candidate.access_generation} FOR KEY SHARE`);
  if (!rows[0]) return null;
  const command = commandFrom(rows[0].command_json);
  return command.kind === 'pay' ? command : null;
}

/**
 * Owns only the in-memory binding and dispatcher. It must be wired by a trusted
 * server lifecycle component after the run environment has been provisioned.
 */
export class BefTaskExecutor {
  private readonly sessions = new Map<string, BefTaskSessionBinding>();
  private readonly fetchImpl: typeof fetch;
  private readonly requestTimeoutMs: number;
  private readonly staleDeliveryMs: number;

  constructor(private readonly deps: BefTaskExecutorDependencies) {
    this.fetchImpl = deps.fetch ?? fetch;
    this.requestTimeoutMs = deps.requestTimeoutMs ?? 45_000;
    this.staleDeliveryMs = deps.staleDeliveryMs ?? this.requestTimeoutMs + 30_000;
    if (!Number.isSafeInteger(this.requestTimeoutMs) || this.requestTimeoutMs < 1_000 || this.requestTimeoutMs > 120_000 ||
        !Number.isSafeInteger(this.staleDeliveryMs) || this.staleDeliveryMs <= this.requestTimeoutMs) {
      throw new Error('task_action_executor_timeout_policy_invalid');
    }
  }

  private sessionMatches(existing: BefTaskSessionBinding, input: BefTaskSessionBinding): boolean {
    return existing.envId === input.envId && existing.generationId === input.generationId &&
      existing.manifestHash === input.manifestHash && existing.applicationSourceHash === input.applicationSourceHash &&
      existing.runToken === input.runToken && existing.participantId === input.participantId &&
      existing.payerAddress?.toLowerCase() === input.payerAddress?.toLowerCase() && existing.x402Signer === input.x402Signer;
  }

  private rememberSession(input: BefTaskSessionBinding): void {
    this.sessions.set(sessionKey(input.runId, input.taskIndex), {
      runId: input.runId, taskIndex: input.taskIndex, envId: input.envId,
      generationId: input.generationId, manifestHash: input.manifestHash.toLowerCase(),
      applicationSourceHash: input.applicationSourceHash.toLowerCase(), runToken: input.runToken,
      ...(input.participantId ? { participantId: input.participantId } : {}),
      ...(input.payerAddress ? { payerAddress: input.payerAddress.toLowerCase() } : {}),
      ...(input.x402Signer ? { x402Signer: input.x402Signer } : {}),
    });
  }

  private async assertStartedIdentity(input: BefTaskSessionBinding): Promise<void> {
    const execution = await getTaskExecutionContext(this.deps.db, { runId: input.runId, taskIndex: input.taskIndex },
      { requireActive: true });
    if (!execution || execution.envId !== input.envId || execution.generationId !== input.generationId ||
        execution.environmentManifestSha256.toLowerCase() !== input.manifestHash.toLowerCase() ||
        execution.applicationSourceHash.toLowerCase() !== input.applicationSourceHash.toLowerCase() ||
        execution.participantId !== (input.participantId ?? null) ||
        execution.payerAddress !== (input.payerAddress?.toLowerCase() ?? null)) {
      throw new Error('task_action_executor_run_environment_mismatch');
    }
    const release = await this.deps.taskReleaseSource.getValidatedReleaseRecord(execution.releaseIdentity, execution.releaseManifestHash);
    const identity = release?.manifest.executionIdentity;
    const taskCase = release?.manifest.cases[execution.mode].find((entry) => entry.taskId === execution.taskId);
    if (!release || release.releaseIdentity !== execution.releaseIdentity || release.manifestHash !== execution.releaseManifestHash ||
        !identity || !taskCase || taskCase.caseId !== execution.caseId || taskCase.caseHash !== execution.caseHash ||
        taskCase.executionIdentityHash !== execution.executionIdentityHash ||
        taskCase.initialState.stateSha256 !== execution.initialStateSha256 ||
        identity.environmentManifestSha256.toLowerCase() !== input.manifestHash.toLowerCase() ||
        identity.x402ServiceSha256.toLowerCase() !== input.applicationSourceHash.toLowerCase()) {
      throw new Error('task_action_executor_release_identity_mismatch');
    }
    const health = await this.readHealth(input);
    if (!health) throw new Error('task_action_executor_bef_identity_mismatch');
  }

  /** Bind the exact validated release and healthy BEF build in process memory. */
  async bindSession(input: BefTaskSessionBinding): Promise<void> {
    validateBinding(input);
    const key = sessionKey(input.runId, input.taskIndex);
    const existing = this.sessions.get(key);
    if (existing) {
      if (this.sessionMatches(existing, input)) return;
      throw new Error('task_action_executor_session_rebind_denied');
    }
    await this.assertStartedIdentity(input);
    const durableBinding = await ensureTaskExecutionBinding(this.deps.db, publicBindingInput(input));
    if (durableBinding.replayed) {
      throw new Error('task_action_executor_session_rebind_denied_after_restart');
    }
    this.rememberSession(input);
  }

  /** Attach RAM-only credentials to an already committed atomic start binding. */
  async attachStartedSession(input: BefTaskSessionBinding): Promise<void> {
    validateBinding(input);
    const key = sessionKey(input.runId, input.taskIndex);
    const existing = this.sessions.get(key);
    if (existing) {
      if (this.sessionMatches(existing, input)) return;
      throw new Error('task_action_executor_session_rebind_denied');
    }
    await this.assertStartedIdentity(input);
    await assertTaskExecutionBinding(this.deps.db, publicBindingInput(input));
    this.rememberSession(input);
  }

  /** Remove only the local token reference; this does not fence BEF itself. */
  unbindSession(runId: string, taskIndex: number): void {
    this.sessions.delete(sessionKey(runId, taskIndex));
  }

  /** Claim or reconcile one action. A delivered request is never sent again. */
  async executeNext(runId: string, taskIndex: number): Promise<ExecuteTaskActionResult> {
    if (!UUID.test(runId) || !Number.isSafeInteger(taskIndex) || taskIndex < 0 || taskIndex > 11) {
      throw new Error('task_action_executor_target_invalid');
    }
    const candidateRows = record<ActionCandidate>(await this.deps.db.execute(sql`SELECT a.id,a.run_id,a.task_index,a.task_id,
        a.action_sequence::text AS action_sequence,a.operation_id,a.payload_hash,a.action_kind,a.command_json,a.environment_id,
        a.owner_id,a.agent_id,a.access_generation,a.grant_id,
        tr.sealed_manifest->'executionIdentity'->>'environmentManifestSha256' AS environment_manifest_hash,
        tr.sealed_manifest->'executionIdentity'->>'x402ServiceSha256' AS application_source_hash,
        o.status AS outbox_status,o.delivered_at,r.receipt_status
      FROM oid_run_task_action a JOIN oid_run_task_action_outbox o ON o.action_id=a.id
      JOIN oid_run_task_action_receipt r ON r.action_id=a.id
      JOIN oid_benchmark_run br ON br.id=a.run_id
      LEFT JOIN oid_task_release tr ON tr.release_identity=br.release_identity AND tr.manifest_hash=br.manifest_hash
      WHERE a.run_id=${runId} AND a.task_index=${taskIndex} AND r.receipt_status IN ('pending','unknown')
      ORDER BY a.action_sequence LIMIT 1`));
    const candidate = candidateRows[0];
    if (!candidate) return { status: 'idle' };
    if (candidate.receipt_status !== 'pending') return { status: 'idle' };

    const binding = this.sessions.get(sessionKey(runId, taskIndex));
    if (candidate.outbox_status === 'delivered') {
      const deliveredAt = candidate.delivered_at ? new Date(candidate.delivered_at).getTime() : 0;
      if (!Number.isFinite(deliveredAt) || Date.now() - deliveredAt < this.staleDeliveryMs) return { status: 'in_progress', actionId: candidate.id };
      return await this.recordSafe(candidate, {
        status: 'unknown', reasonCode: binding ? 'executor_delivery_stale' : 'executor_session_missing_after_dispatch',
      });
    }

    if (!binding) {
      const durableBinding = await getTaskExecutionBinding(this.deps.db, { runId, taskIndex });
      if (durableBinding) {
        // Atomic prepared starts persist this pin before post-commit RAM
        // handoff. After a crash/restart, leave pending work untouched so the
        // coordinator can cancel and fence instead of consuming it.
        return { status: 'idle' };
      }
      // Pending is the durable pre-dispatch state. With no process-local
      // generation binding, fail closed rather than reconstructing a session.
      const claimed = await this.claim(candidate);
      if (!claimed) return { status: 'idle' };
      return await this.recordSafe(candidate, { status: 'rejected_before_execution', reasonCode: 'executor_session_not_bound' });
    }
    if (candidate.action_kind === 'purchase') {
      const claimed = await this.claim(candidate, binding);
      if (!claimed) return { status: 'idle' };
      return await this.executeClaimed(candidate, binding);
    }
    const claimed = await this.claim(candidate, binding);
    if (!claimed) return { status: 'idle' };
    return await this.executeClaimed(candidate, binding);
  }

  private async claim(candidate: ActionCandidate, binding?: BefTaskSessionBinding): Promise<boolean> {
    return this.deps.db.transaction(async (tx) => {
      const context = await this.lockContext(tx, candidate.id);
      if (!context || context.candidate.outbox_status !== 'pending' || context.candidate.receipt_status !== 'pending') return false;
      const publicBinding = binding
        ? await assertTaskExecutionBinding(tx, publicBindingInput(binding))
        : await getTaskExecutionBinding(tx, { runId: context.candidate.run_id, taskIndex: context.candidate.task_index });
      await tx.execute(sql`UPDATE oid_run_task_action_outbox SET status='delivered',delivered_at=clock_timestamp()
        WHERE action_id=${candidate.id} AND status='pending'`);
      await appendEvent(tx, context, 'task.action.dispatch_claimed', {
        idempotencyKey: `task-action-${candidate.id}`,
        ...(publicBinding ? {
          environmentId: publicBinding.envId, generationId: publicBinding.generationId,
          manifestSha256: publicBinding.manifestHash, applicationSourceSha256: publicBinding.applicationSourceHash,
          ...(publicBinding.participantId ? { participantId: publicBinding.participantId } : {}),
          ...(publicBinding.payerAddress ? { payerAddress: publicBinding.payerAddress } : {}),
        } : {}),
      });
      return true;
    });
  }

  private async lockContext(tx: Transaction, actionId: string): Promise<LockedContext | null> {
    const hints = record<{ owner_id: string }>(await tx.execute(sql`SELECT owner_id FROM oid_run_task_action WHERE id=${actionId}`));
    const hint = hints[0];
    if (!hint) return null;
    const ownerAdmissionStatus = await lockOwner(tx, hint.owner_id);
    const agentRows = await query<{
      id: string; owner_id: string; access_generation: number; access_revoked_at: unknown; admission_status: string;
    }>(tx, sql`SELECT a.id,a.owner_id,a.access_generation,a.access_revoked_at,o.admission_status
      FROM oid_agent a JOIN oid_owner o ON o.id=a.owner_id
      WHERE a.id=(SELECT agent_id FROM oid_run_task_action WHERE id=${actionId}) AND a.owner_id=${hint.owner_id}
      FOR NO KEY UPDATE OF a`);
    const agent = agentRows[0];
    if (!agent) return null;
    const runRows = await query<RunAuthorizationRow>(tx, sql`SELECT id,owner_id,agent_id,access_generation,agent_policy_revision,
        mode,task_ids,status,environment_id,release_identity,manifest_hash
      FROM oid_benchmark_run WHERE id=(SELECT run_id FROM oid_run_task_action WHERE id=${actionId})
        AND owner_id=${hint.owner_id} FOR UPDATE`);
    const run = runRows[0];
    if (!run) return null;
    const taskRows = await query<TaskAuthorizationRow>(tx, sql`SELECT run_id,task_index,task_id,status,
        accepted_action_sequence::text AS accepted_action_sequence,action_cutoff_sequence::text AS action_cutoff_sequence,closure_status
      FROM oid_run_task WHERE run_id=${run.id}
        AND task_index=(SELECT task_index FROM oid_run_task_action WHERE id=${actionId}) FOR UPDATE`);
    const task = taskRows[0];
    const actionRows = await query<ActionCandidate>(tx, sql`SELECT a.id,a.run_id,a.task_index,a.task_id,
        a.action_sequence::text AS action_sequence,a.operation_id,a.payload_hash,a.action_kind,a.command_json,a.environment_id,
        a.owner_id,a.agent_id,a.access_generation,a.grant_id,
        NULL::text AS environment_manifest_hash,NULL::text AS application_source_hash,
        o.status AS outbox_status,o.delivered_at,r.receipt_status
      FROM oid_run_task_action a JOIN oid_run_task_action_outbox o ON o.action_id=a.id
      JOIN oid_run_task_action_receipt r ON r.action_id=a.id WHERE a.id=${actionId} FOR UPDATE OF a,o,r`);
    const action = actionRows[0];
    if (!task || !action) return null;
    const command = commandFrom(action.command_json);
    if (action.owner_id !== hint.owner_id || action.agent_id !== run.agent_id || action.agent_id !== agent.id ||
        action.access_generation !== run.access_generation || task.task_id !== action.task_id ||
        run.task_ids[action.task_index] !== action.task_id) throw new Error('task_action_executor_scope_fenced');
    return {
      candidate: action, run, task, command, ownerAdmissionStatus,
      agentAccessGeneration: agent.access_generation, agentAccessRevoked: agent.access_revoked_at !== null,
    };
  }

  private async authorizeDispatch(tx: Transaction, context: LockedContext, binding: BefTaskSessionBinding): Promise<string | null> {
    const { candidate: action, run, task, command } = context;
    if (context.ownerAdmissionStatus !== 'admitted') return 'owner_admission_fenced';
    if (context.agentAccessRevoked || context.agentAccessGeneration !== action.access_generation) return 'agent_access_generation_changed';
    if (binding.runId !== run.id || binding.taskIndex !== action.task_index || run.status !== 'running') return 'run_or_environment_fenced';
    if (run.access_generation !== action.access_generation) return 'agent_access_generation_changed';
    const grant = await query<{ id: string }>(tx, sql`SELECT id FROM oid_agent_access_grant
      WHERE id=${action.grant_id} AND owner_id=${action.owner_id} AND agent_id=${action.agent_id} AND role='agent'
        AND access_generation=${action.access_generation} AND revoked_at IS NULL AND expires_at>clock_timestamp()`);
    if (!grant.length) return 'agent_grant_revoked';
    const policyRows = await query<{ training: boolean; ranked: boolean }>(tx, sql`SELECT training,ranked
      FROM oid_agent_policy WHERE agent_id=${action.agent_id}`);
    const policy = policyRows[0];
    if (!policy || !(run.mode === 'training' ? policy.training : policy.ranked)) return 'run_mode_permission_revoked';
    const fences = await query<{ fenced: boolean }>(tx, sql`SELECT EXISTS(
      SELECT 1 FROM oid_run_mode_cancellation_outbox WHERE owner_id=${action.owner_id} AND agent_id=${action.agent_id}
        AND mode=${run.mode} AND policy_revision>${run.agent_policy_revision}
    ) AS fenced`);
    if (fences[0]?.fenced) return 'run_mode_fenced';
    const sequence = BigInt(action.action_sequence);
    if (sequence > BigInt(task.accepted_action_sequence)) return 'action_sequence_invalid';
    if (task.closure_status === 'closing') {
      if (task.action_cutoff_sequence === null || sequence > BigInt(task.action_cutoff_sequence)) return 'task_cutoff_fenced';
    } else if (task.closure_status !== 'open') return 'task_closed';
    if (task.status !== 'active') return 'task_not_active';
    const execution = await getTaskExecutionContext(tx, { runId: run.id, taskIndex: action.task_index }, { requireActive: true });
    if (!execution || execution.envId !== binding.envId || execution.envId !== action.environment_id ||
        execution.generationId !== binding.generationId || execution.environmentManifestSha256 !== binding.manifestHash ||
        execution.applicationSourceHash !== binding.applicationSourceHash ||
        execution.releaseIdentity !== run.release_identity || execution.releaseManifestHash !== run.manifest_hash) {
      return 'task_execution_binding_unavailable';
    }
    const release = await this.deps.taskReleaseSource.getValidatedReleaseRecord(
      run.release_identity, run.manifest_hash, tx as unknown as TaskReleaseTransaction,
    );
    const identity = release?.manifest.executionIdentity;
    const taskCase = release?.manifest.cases[run.mode].find((entry) => entry.taskId === task.task_id);
    if (!identity || identity.environmentManifestSha256.toLowerCase() !== binding.manifestHash.toLowerCase() ||
        identity.x402ServiceSha256.toLowerCase() !== binding.applicationSourceHash.toLowerCase() ||
        !taskCase || taskCase.caseId !== execution.caseId || taskCase.caseHash !== execution.caseHash ||
        taskCase.executionIdentityHash !== execution.executionIdentityHash ||
        taskCase.initialState.stateSha256 !== execution.initialStateSha256) return 'release_identity_changed';
    if (command.kind === 'purchase') {
      const policy = this.deps.pinnedX402PolicyByEnvironment?.[binding.envId];
      if (!policy || policy.manifestSha256.toLowerCase() !== binding.manifestHash.toLowerCase()) return 'task_x402_manifest_policy_unavailable';
      if (!findPinnedResourceOffer(policy, command.resourceId, command.offerId)) return 'task_x402_resource_offer_unpinned';
      if (!binding.x402Signer || !binding.payerAddress ||
          binding.x402Signer.payerAddress.toLowerCase() !== binding.payerAddress.toLowerCase()) return 'task_x402_generation_signer_unavailable';
    }
    return null;
  }

  private async readHealth(binding: BefTaskSessionBinding): Promise<HealthIdentity | null> {
    const base = configuredBaseUrl(this.deps.participantApiByEnvironment[binding.envId]);
    try {
      const response = await this.fetchImpl(new URL('/healthz', base), {
        method: 'GET', redirect: 'error', signal: AbortSignal.timeout(this.requestTimeoutMs),
      });
      const bytes = await readBounded(response, 256 * 1024);
      if (!response.ok) return null;
      return healthIdentity(parseJson(bytes), binding);
    } catch { return null; }
  }

  private async executeClaimed(
    candidate: ActionCandidate,
    binding: BefTaskSessionBinding,
    forcedReason?: string,
  ): Promise<ExecuteTaskActionResult> {
    const observation = await this.deps.db.transaction(async (tx): Promise<DispatchObservation> => {
      const context = await this.lockContext(tx, candidate.id);
      if (!context || context.candidate.outbox_status !== 'delivered' || context.candidate.receipt_status !== 'pending') {
        return { status: 'unknown', reasonCode: 'claimed_action_state_unavailable' };
      }
      if (forcedReason) return { status: 'unknown', reasonCode: forcedReason };
      await assertTaskExecutionBinding(tx, publicBindingInput(binding));
      const denied = await this.authorizeDispatch(tx, context, binding);
      if (denied) return { status: 'rejected_before_execution', reasonCode: denied };
      let paymentReference: TaskPaymentReference | undefined;
      let retrievalPayCommand: Extract<TaskActionCommand, { kind: 'pay' }> | undefined;
      try {
        await assertTaskPaymentProtocol(tx, context.run.id, context.command);
        if (context.command.kind === 'pay' || context.command.kind === 'retrieve') {
          paymentReference = await resolveTaskPaymentReference(tx, {
            runId: context.run.id,
            taskIndex: context.candidate.task_index,
            environmentId: context.candidate.environment_id,
            command: context.command,
          });
        }
        if (context.command.kind === 'retrieve') {
          retrievalPayCommand = await originalPayCommand(tx, context, context.command.payActionId) ?? undefined;
          if (!retrievalPayCommand) throw new HttpError(409, 'TASK_PAYMENT_REFERENCE_INVALID', 'Retrieval must name this task’s pay action');
        }
      } catch (error) {
        return {
          status: 'rejected_before_execution',
          reasonCode: error instanceof HttpError ? error.code.toLowerCase() : 'task_payment_reference_unavailable',
        };
      }
      const requiresLocalFork = ['purchase', 'pay', 'retrieve'].includes(context.command.kind);
      let apiBase: URL;
      let healthBytes: Uint8Array;
      try {
        apiBase = requiresLocalFork
          ? configuredLocalForkBaseUrl(this.deps.participantApiByEnvironment[binding.envId])
          : configuredBaseUrl(this.deps.participantApiByEnvironment[binding.envId]);
        healthBytes = await this.fetchHealthBytes(apiBase);
      } catch {
        return { status: 'rejected_before_execution', reasonCode: requiresLocalFork
          ? 'task_x402_local_bef_unavailable' : 'bef_environment_health_unavailable' };
      }
      const health = healthIdentity(parseJson(healthBytes), binding);
      if (!health) return { status: 'rejected_before_execution', reasonCode: 'bef_environment_identity_mismatch' };
      if (context.command.kind === 'purchase') return await this.executePurchase(context, binding, apiBase, health);
      if (context.command.kind === 'pay') {
        const policy = this.deps.pinnedX402PolicyByEnvironment?.[binding.envId];
        const selected = policy ? findPinnedResourceOffer(policy, context.command.resourceId, context.command.offerId) : null;
        if (!policy || !selected || paymentReference?.kind !== 'pay' ||
            policy.manifestSha256.toLowerCase() !== binding.manifestHash.toLowerCase()) {
          return { status: 'rejected_before_execution', reasonCode: 'task_split_pay_pinned_context_unavailable', environmentHealth: health };
        }
        return await dispatchSplitPaymentRequest({
          fetch: this.fetchImpl, timeoutMs: this.requestTimeoutMs, apiBase, binding,
          command: context.command, reference: paymentReference, policy, selected, health,
          idempotencyKey: `task-action-${context.candidate.id}`,
        });
      }
      if (context.command.kind === 'retrieve') {
        const policy = this.deps.pinnedX402PolicyByEnvironment?.[binding.envId];
        const selected = policy && retrievalPayCommand
          ? findPinnedResourceOffer(policy, retrievalPayCommand.resourceId, retrievalPayCommand.offerId) : null;
        if (!policy || !selected || paymentReference?.kind !== 'retrieve' ||
            policy.manifestSha256.toLowerCase() !== binding.manifestHash.toLowerCase()) {
          return { status: 'rejected_before_execution', reasonCode: 'task_split_retrieve_pinned_context_unavailable', environmentHealth: health };
        }
        return await dispatchSplitRetrieveRequest({
          fetch: this.fetchImpl, timeoutMs: this.requestTimeoutMs, apiBase, binding,
          operationId: paymentReference.operationId, resource: selected.resource, policy, health,
          idempotencyKey: `task-action-${context.candidate.id}`,
        });
      }
      const participantRequest = participantToolRequest(context.command, paymentReference);
      if (!participantRequest) return { status: 'unknown', reasonCode: 'task_purchase_path_unsupported', environmentHealth: health };
      const started = new Date().toISOString();
      let response: Response;
      let bytes: Uint8Array;
      try {
        const headers: Record<string, string> = {
          authorization: `Bearer ${binding.runToken}`,
          'x-bef-generation': binding.generationId,
          'idempotency-key': `task-action-${context.candidate.id}`,
          accept: 'application/json',
        };
        const isReadOnly = participantRequest.method === 'GET';
        if (!isReadOnly) headers['content-type'] = 'application/json';
        response = await this.fetchImpl(new URL(`/tools/${binding.envId}${participantRequest.path}`, apiBase), {
          method: participantRequest.method,
          redirect: 'error',
          headers,
          ...(isReadOnly ? {} : { body: canonicalTaskJson(participantToolBody(context.command as Exclude<TaskActionCommand, { kind: 'purchase' | 'pay' | 'retrieve' | 'inspect_catalog' | 'inspect_offer' }>)) }),
          signal: AbortSignal.timeout(this.requestTimeoutMs),
        });
        bytes = await readBounded(response);
      } catch {
        return {
          status: 'unknown', reasonCode: 'participant_tool_response_lost', requestStartedAt: started,
          requestFinishedAt: new Date().toISOString(), environmentHealth: health,
        };
      }
      const rawResponseSha256 = createHash('sha256').update(bytes).digest('hex');
      const body = parseJson(bytes);
      const headerOperationId = response.headers.get('x-bef-operation-id');
      let participantToolResponse: Record<string, unknown> | undefined;
      try { participantToolResponse = safeMeasurementProjection(body, binding.runToken); }
      catch {
        if (isReadOnlyCommand(context.command)) return {
          status: 'unknown', reasonCode: 'participant_read_projection_invalid', requestStartedAt: started,
          requestFinishedAt: new Date().toISOString(), httpStatus: response.status,
          rawResponseSha256, environmentHealth: health,
        };
        const partial = classifyBefTaskActionResponse({ status: response.status, headerOperationId, body, rawResponseSha256 });
        return {
          ...partial, status: 'unknown', reasonCode: 'participant_measurement_projection_invalid',
          requestStartedAt: started, requestFinishedAt: new Date().toISOString(),
          httpStatus: response.status, environmentHealth: health,
        };
      }
      const classified = isReadOnlyCommand(context.command)
        ? classifyReadOnlyBefTaskActionResponse({
          command: context.command as Extract<TaskActionCommand, { kind: 'inspect_catalog' | 'inspect_offer' }>,
          status: response.status, headerOperationId, body, rawResponseSha256,
          ...(participantToolResponse ? { participantToolResponse } : {}),
        })
        : classifyBefTaskActionResponse({
          status: response.status, headerOperationId, body, rawResponseSha256,
          ...(participantToolResponse ? { participantToolResponse } : {}),
        });
      if (classified.status === 'observed' && !isReadOnlyCommand(context.command) &&
          !selectedActionMatches(context.command as Exclude<TaskActionCommand, { kind: 'purchase' }>, body?.selectedAction)) {
        return { ...classified, status: 'unknown', reasonCode: 'participant_tool_action_binding_mismatch' };
      }
      return {
        ...classified, requestStartedAt: started, requestFinishedAt: new Date().toISOString(),
        httpStatus: response.status, environmentHealth: health,
      };
    });
    const result = await this.recordSafe(candidate, observation);
    return result;
  }

  /**
   * One-shot x402 purchase through the public participant endpoint. The local
   * fork, exact manifest offer, generation payer, challenge, settlement and
   * returned bytes are all checked before a result is called observed. Once a
   * signed request starts, every ambiguous response stays unknown; this method
   * never retries it or creates a replacement operation.
   */
  private async executePurchase(
    context: LockedContext,
    binding: BefTaskSessionBinding,
    apiBase: URL,
    health: HealthIdentity,
  ): Promise<DispatchObservation> {
    if (context.command.kind !== 'purchase') return { status: 'unknown', reasonCode: 'task_x402_command_invalid' };
    const command = context.command;
    const policy = this.deps.pinnedX402PolicyByEnvironment?.[binding.envId];
    const signer = binding.x402Signer;
    const selected = policy ? findPinnedResourceOffer(policy, command.resourceId, command.offerId) : null;
    const baseObservation = {
      environmentHealth: health,
      paymentProtocol: {
        schema: 'bef-x402-purchase-observation-v1',
        resourceId: command.resourceId,
        offerId: command.offerId,
        ...(policy ? { befServerSdkVersions: policy.sdkVersions } : {}),
        ownerSignerSdkVersions: OWNER_X402_SIGNER_SDK_VERSIONS,
        ...(selected ? { resourceSha256: selected.resource.resourceSha256, amountUnits: selected.offer.amount } : {}),
        ...(policy ? { network: policy.network, asset: policy.asset } : {}),
      },
    } satisfies Pick<DispatchObservation, 'environmentHealth' | 'paymentProtocol'>;
    if (!policy || !selected || policy.manifestSha256.toLowerCase() !== binding.manifestHash.toLowerCase()) {
      return { ...baseObservation, status: 'rejected_before_execution', reasonCode: 'task_x402_manifest_policy_unavailable' };
    }
    if (!privateAnvilHealthMatches(health, policy)) {
      return { ...baseObservation, status: 'rejected_before_execution', reasonCode: 'task_x402_private_fork_identity_mismatch' };
    }
    if (!signer || !binding.payerAddress || signer.payerAddress.toLowerCase() !== binding.payerAddress.toLowerCase()) {
      return { ...baseObservation, status: 'rejected_before_execution', reasonCode: 'task_x402_generation_signer_unavailable' };
    }

    const startedAt = new Date().toISOString();
    const idempotencyKey = `task-action-${context.candidate.id}`;
    const offerHeaders: Record<string, string> = {
      authorization: `Bearer ${binding.runToken}`,
      'x-bef-generation': binding.generationId,
      'idempotency-key': `${idempotencyKey}-offer`,
      accept: 'application/json',
    };
    let offerResponse: Response;
    let offerBytes: Uint8Array;
    try {
      offerResponse = await this.fetchImpl(new URL(
        `/tools/${binding.envId}/offer?resourceId=${encodeURIComponent(command.resourceId)}`, apiBase,
      ), { method: 'GET', redirect: 'error', headers: offerHeaders, signal: AbortSignal.timeout(this.requestTimeoutMs) });
      offerBytes = await readBounded(offerResponse);
    } catch {
      return { ...baseObservation, status: 'rejected_before_execution', reasonCode: 'task_x402_offer_unavailable',
        requestStartedAt: startedAt, requestFinishedAt: new Date().toISOString() };
    }
    const offerHash = createHash('sha256').update(offerBytes).digest('hex');
    const offerBody = parseJson(offerBytes);
    const offerOperationId = typeof offerBody?.operationId === 'string' && UUID.test(offerBody.operationId)
      ? offerBody.operationId : null;
    if (offerResponse.status !== 200 || !offerOperationId || !health.facilitatorAddress || !pinnedOfferResponseMatches({
      body: offerBody, command, pinnedResource: selected.resource, pinnedOffer: selected.offer,
      policy, facilitatorAddress: health.facilitatorAddress,
    })) {
      return { ...baseObservation, status: 'rejected_before_execution', reasonCode: 'task_x402_offer_pin_mismatch',
        httpStatus: offerResponse.status, rawResponseSha256: offerHash,
        requestStartedAt: startedAt, requestFinishedAt: new Date().toISOString(),
        paymentProtocol: { ...baseObservation.paymentProtocol, offerResponseSha256: offerHash } };
    }

    const purchasePath = `/tools/${binding.envId}/purchase`;
    const requestBody = canonicalTaskJson({ resourceId: command.resourceId, offerId: command.offerId });
    let challengeResponse: Response;
    let challengeBytes: Uint8Array;
    try {
      challengeResponse = await this.fetchImpl(new URL(purchasePath, apiBase), {
        method: 'POST', redirect: 'error', headers: {
          authorization: `Bearer ${binding.runToken}`, 'x-bef-generation': binding.generationId,
          'idempotency-key': idempotencyKey, accept: 'application/json', 'content-type': 'application/json',
        },
        body: requestBody, signal: AbortSignal.timeout(this.requestTimeoutMs),
      });
      challengeBytes = await readBounded(challengeResponse);
    } catch {
      return { ...baseObservation, status: 'rejected_before_execution', reasonCode: 'task_x402_challenge_unavailable',
        requestStartedAt: startedAt, requestFinishedAt: new Date().toISOString(),
        paymentProtocol: { ...baseObservation.paymentProtocol, offerResponseSha256: offerHash } };
    }
    const challengeRawHash = createHash('sha256').update(challengeBytes).digest('hex');
    const challengeBody = parseJson(challengeBytes);
    const challengeHeaderId = challengeResponse.headers.get('x-bef-operation-id');
    const challengeHeaders = paymentHeaders(challengeResponse);
    if (challengeResponse.status !== 402 || !challengeHeaderId || !UUID.test(challengeHeaderId) ||
        !hasPaymentChallengeHeader(challengeHeaders)) {
      return { ...baseObservation, status: 'rejected_before_execution', reasonCode: 'task_x402_payment_challenge_invalid',
        httpStatus: challengeResponse.status, rawResponseSha256: challengeRawHash,
        requestStartedAt: startedAt, requestFinishedAt: new Date().toISOString(),
        ...(challengeHeaderId && UUID.test(challengeHeaderId) ? { befOperationId: challengeHeaderId } : {}),
        paymentProtocol: { ...baseObservation.paymentProtocol, offerResponseSha256: offerHash,
          challengeResponseSha256: challengeRawHash } };
    }

    const challengeSha256 = hashPaymentChallengeHeaders(challengeHeaders);
    let declaration: PaymentRequired;
    let requirements: PaymentRequirements | null;
    let authorization: Record<string, string>;
    try {
      declaration = signer.parsePaymentRequired(challengeHeaders, challengeBody);
      requirements = paymentRequirementMatchesPins({
        declaration, expectedResourceId: command.resourceId, expectedOffer: selected.offer, policy,
        facilitatorAddress: health.facilitatorAddress, expectedPath: purchasePath,
      });
      if (!requirements) throw new Error('task_x402_challenge_scope_mismatch');
      authorization = await signer.createAuthorization(declaration, requirements);
    } catch {
      return { ...baseObservation, status: 'rejected_before_execution', reasonCode: 'task_x402_challenge_scope_mismatch',
        httpStatus: challengeResponse.status, rawResponseSha256: challengeRawHash,
        requestStartedAt: startedAt, requestFinishedAt: new Date().toISOString(), befOperationId: challengeHeaderId,
        paymentProtocol: { ...baseObservation.paymentProtocol, offerResponseSha256: offerHash,
          challengeResponseSha256: challengeRawHash, challengeHeaderSha256: challengeSha256 } };
    }
    const authorizationEntries = Object.entries(authorization);
    if (authorizationEntries.length !== 1 || !['payment-signature', 'x-payment'].includes(authorizationEntries[0]![0].toLowerCase()) ||
        authorizationEntries[0]![1].length < 16 || authorizationEntries[0]![1].length > 65_536) {
      return { ...baseObservation, status: 'rejected_before_execution', reasonCode: 'task_x402_authorization_invalid',
        requestStartedAt: startedAt, requestFinishedAt: new Date().toISOString(), befOperationId: challengeHeaderId,
        paymentProtocol: { ...baseObservation.paymentProtocol, offerResponseSha256: offerHash,
          challengeResponseSha256: challengeRawHash, challengeHeaderSha256: challengeSha256 } };
    }

    let paidResponse: Response;
    let paidBytes: Uint8Array;
    try {
      paidResponse = await this.fetchImpl(new URL(purchasePath, apiBase), {
        method: 'POST', redirect: 'error',
        headers: {
          authorization: `Bearer ${binding.runToken}`, 'x-bef-generation': binding.generationId,
          'idempotency-key': idempotencyKey, accept: 'application/json', 'content-type': 'application/json', ...authorization,
        },
        body: requestBody, signal: AbortSignal.timeout(this.requestTimeoutMs),
      });
      paidBytes = await readBounded(paidResponse);
    } catch {
      return { ...baseObservation, status: 'unknown', reasonCode: 'task_x402_paid_response_lost',
        requestStartedAt: startedAt, requestFinishedAt: new Date().toISOString(), befOperationId: challengeHeaderId,
        paymentProtocol: { ...baseObservation.paymentProtocol, offerResponseSha256: offerHash,
          challengeHeaderSha256: challengeSha256, settlementObserved: false } };
    }
    const paidHash = createHash('sha256').update(paidBytes).digest('hex');
    const paidBody = parseJson(paidBytes);
    const paidHeaders = paymentHeaders(paidResponse);
    const paidHeaderId = paidResponse.headers.get('x-bef-operation-id');
    let settlement: ReturnType<EphemeralX402Signer['parseSettlement']> = null;
    try { settlement = signer.parseSettlement(paidHeaders); } catch { /* malformed settlement is unknown */ }
    const transactionHash = settlement && TX_HASH.test(settlement.transaction) ? settlement.transaction.toLowerCase() : undefined;
    const settlementMatches = Boolean(settlement?.success && transactionHash && settlement.network === policy.network &&
      settlement.payer?.toLowerCase() === signer.payerAddress.toLowerCase() &&
      (settlement.amount === undefined || settlement.amount === selected.offer.amount));
    const operationMatches = paidBody?.operationId === challengeHeaderId &&
      (paidHeaderId === null || paidHeaderId === challengeHeaderId);
    const deliveryMatches = pinnedPurchaseDeliveryMatches({
      body: paidBody, resourceId: selected.resource.resourceId, resourceSha256: selected.resource.resourceSha256,
      contentType: selected.resource.contentType, operationId: challengeHeaderId,
    });
    const settlementHeaderSha256 = hashSettlementHeaders(paidHeaders);
    let participantToolResponse: Record<string, unknown> | undefined;
    try { participantToolResponse = safeMeasurementProjection(paidBody, binding.runToken, settlementMatches && deliveryMatches); }
    catch { /* The raw hash and independently parsed settlement remain evidence. */ }
    const observed = paidResponse.status === 200 &&
      (paidResponse.headers.get('content-type') ?? '').split(';', 1)[0]!.trim().toLowerCase() === selected.resource.contentType.toLowerCase() &&
      settlementMatches && operationMatches && deliveryMatches;
    return {
      status: observed ? 'observed' : 'unknown',
      ...(!observed ? { reasonCode: settlementMatches && operationMatches
        ? 'task_x402_delivery_pin_mismatch' : 'task_x402_settlement_or_operation_unverified' } : {}),
      requestStartedAt: startedAt, requestFinishedAt: new Date().toISOString(), httpStatus: paidResponse.status,
      befOperationId: challengeHeaderId,
      ...(transactionHash ? { transactionHash } : {}),
      ...(settlementMatches ? { outcome: 'success' as const, receiptStatus: 'success' as const } : {}),
      rawResponseSha256: paidHash,
      ...(participantToolResponse ? { participantToolResponse } : {}),
      paymentProtocol: {
        schema: 'bef-x402-purchase-observation-v1', resourceId: command.resourceId, offerId: command.offerId,
        befServerSdkVersions: policy.sdkVersions,
        ownerSignerSdkVersions: OWNER_X402_SIGNER_SDK_VERSIONS,
        resourceSha256: selected.resource.resourceSha256, amountUnits: selected.offer.amount,
        network: policy.network, asset: policy.asset, facilitatorAddress: health.facilitatorAddress,
        payerAddress: signer.payerAddress, offerResponseSha256: offerHash,
        challengeResponseSha256: challengeRawHash, challengeHeaderSha256: challengeSha256,
        befOperationId: challengeHeaderId, settlementObserved: settlement !== null,
        settlementMatchesPins: settlementMatches, ...(transactionHash ? { transactionHash } : {}),
        ...(settlementHeaderSha256 ? { settlementHeaderSha256 } : {}),
        deliveryMatchesPinnedResource: deliveryMatches,
        ...(typeof paidBody?.contentHash === 'string' && HASH.test(paidBody.contentHash)
          ? { deliveredContentSha256: paidBody.contentHash.toLowerCase() } : {}),
      },
      environmentHealth: health,
    };
  }

  private async fetchHealthBytes(base: URL): Promise<Uint8Array> {
    const response = await this.fetchImpl(new URL('/healthz', base), {
      method: 'GET', redirect: 'error', signal: AbortSignal.timeout(this.requestTimeoutMs),
    });
    if (!response.ok) throw new Error('bef_health_unavailable');
    return await readBounded(response, 256 * 1024);
  }

  private async recordSafe(candidate: ActionCandidate, observation: DispatchObservation): Promise<ExecuteTaskActionResult> {
    const data: SafeTaskActionEvidence = {
      schema: 'bef-task-action-observation-v1', actionId: candidate.id, runId: candidate.run_id,
      taskIndex: candidate.task_index, actionSequence: String(candidate.action_sequence), ownerOperationId: candidate.operation_id,
      actionKind: candidate.action_kind, commandSha256: candidate.payload_hash, environmentId: candidate.environment_id,
      generationId: this.sessions.get(sessionKey(candidate.run_id, candidate.task_index))?.generationId ?? null,
      manifestSha256: this.sessions.get(sessionKey(candidate.run_id, candidate.task_index))?.manifestHash ??
        (candidate.environment_manifest_hash && HASH.test(candidate.environment_manifest_hash) ? candidate.environment_manifest_hash.toLowerCase() : null),
      applicationSourceSha256: this.sessions.get(sessionKey(candidate.run_id, candidate.task_index))?.applicationSourceHash ??
        (candidate.application_source_hash && HASH.test(candidate.application_source_hash) ? candidate.application_source_hash.toLowerCase() : null),
      idempotencyKey: `task-action-${candidate.id}`, status: observation.status,
      ...(observation.reasonCode ? { reasonCode: observation.reasonCode } : {}),
      ...(observation.requestStartedAt ? { requestStartedAt: observation.requestStartedAt } : {}),
      ...(observation.requestFinishedAt ? { requestFinishedAt: observation.requestFinishedAt } : {}),
      ...(observation.httpStatus !== undefined ? { httpStatus: observation.httpStatus } : {}),
      ...(observation.befOperationId ? { befOperationId: observation.befOperationId } : {}),
      ...(observation.transactionHash ? { transactionHash: observation.transactionHash } : {}),
      ...(observation.outcome ? { outcome: observation.outcome } : {}),
      ...(observation.receiptStatus ? { receiptStatus: observation.receiptStatus } : {}),
      ...(observation.rawResponseSha256 ? { rawResponseSha256: observation.rawResponseSha256 } : {}),
      ...(observation.participantToolResponse ? { participantToolResponse: observation.participantToolResponse } : {}),
      ...(observation.paymentProtocol ? { paymentProtocol: observation.paymentProtocol } : {}),
      ...(observation.receiptGasUsed ? { receiptGasUsed: observation.receiptGasUsed } : {}),
      ...(observation.receiptEffectiveGasPriceWei ? { receiptEffectiveGasPriceWei: observation.receiptEffectiveGasPriceWei } : {}),
      ...(observation.environmentHealth ? { environmentHealth: observation.environmentHealth } : {}),
    };
    let evidenceHash = digest(data);
    let evidencePath: string | null = null;
    let finalStatus = observation.status;
    try {
      const written = await this.deps.evidenceSink.write(data);
      if (!HASH.test(written.sha256) || !/^(?![A-Za-z]:)(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/-]{1,512}$/.test(written.path)) {
        throw new Error('task_action_executor_evidence_reference_invalid');
      }
      evidenceHash = written.sha256.toLowerCase();
      evidencePath = written.path;
    } catch {
      // A chain receipt without durable observer evidence remains unknown.
      finalStatus = 'unknown';
      evidenceHash = digest({ ...data, status: 'unknown', reasonCode: 'evidence_sink_unavailable' });
    }
    await recordTaskActionReceipt({ db: this.deps.db }, {
      actionId: candidate.id, status: finalStatus, evidenceHash,
      ...(evidencePath ? { evidencePath } : {}),
      ...(observation.transactionHash ? { transactionHash: observation.transactionHash } : {}),
      ...(observation.participantToolResponse ? { toolResponse: observation.participantToolResponse } : {}),
    });
    return {
      status: 'recorded', actionId: candidate.id, receiptStatus: finalStatus, evidenceHash, evidencePath,
      ...(observation.transactionHash ? { transactionHash: observation.transactionHash } : {}),
      ...(observation.befOperationId ? { befOperationId: observation.befOperationId } : {}),
    };
  }
}
