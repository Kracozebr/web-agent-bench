import { createHash } from 'node:crypto';
import { x402Client, x402HTTPClient } from '@x402/core/client';
import type { Network, PaymentPayload, PaymentRequired, PaymentRequirements, SettleResponse } from '@x402/core/types';
import { registerExactEvmScheme } from '@x402/evm/exact/client';
import { privateKeyToAccount } from 'viem/accounts';
import type { Address, Hex } from 'viem';

/** Exact owner-side signer packages; distinct from BEF's manifest-pinned server dependencies. */
export const OWNER_X402_SIGNER_SDK_VERSIONS = {
  core: '2.28.0',
  evm: '2.28.0',
  viem: '2.56.9',
} as const;

const HASH = /^[0-9a-f]{64}$/i;
const ADDRESS = /^0x[0-9a-f]{40}$/i;
const TRANSACTION_HASH = /^0x[0-9a-f]{64}$/i;
const RESOURCE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const OFFER_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

export interface PinnedX402Offer {
  id: string;
  amount: string;
}

export interface PinnedX402Resource {
  resourceId: string;
  resourceSha256: string;
  contentType: string;
  dataType?: string;
  schema?: string;
  provenance?: { classification: string; boundary: string; source: string };
  offers: readonly PinnedX402Offer[];
}

/** Small immutable projection of the exact BEF manifest pinned by its SHA-256. */
export interface PinnedX402Policy {
  manifestSha256: string;
  scheme: string;
  network: string;
  asset: string;
  assetTransferMethod: string;
  eip712Domain: { name: string; version: string };
  maxTimeoutSeconds: number;
  sdkVersions: { core: string; evm: string; viem: string };
  localAnvil: {
    identity: 'private-anvil-fork';
    chainId: 8453;
    anvilVersion: string;
    executionNetwork: string;
    hardFork: string;
    forkBlockNumber: string;
    forkBlockHash: string;
  };
  resources: readonly PinnedX402Resource[];
}

export interface EphemeralX402Signer {
  /** Public payer identity from the same generation whose RAM key signs payments. */
  readonly payerAddress: string;
  parsePaymentRequired(headers: Readonly<Record<string, string>>, body: unknown): PaymentRequired;
  /** Returns transient payment headers only; never return payload/signature to a journal. */
  createAuthorization(declaration: PaymentRequired, requirements: PaymentRequirements): Promise<Record<string, string>>;
  parseSettlement(headers: Readonly<Record<string, string>>): SettleResponse | null;
}

export function findPinnedResourceOffer(
  policy: PinnedX402Policy,
  resourceId: string,
  offerId: string,
): { resource: PinnedX402Resource; offer: PinnedX402Offer } | null {
  if (!HASH.test(policy.manifestSha256) || !policy.scheme || !policy.network || !ADDRESS.test(policy.asset) ||
      !policy.assetTransferMethod || !policy.eip712Domain?.name || !policy.eip712Domain?.version ||
      !Number.isSafeInteger(policy.maxTimeoutSeconds) || policy.maxTimeoutSeconds < 1 ||
      policy.scheme !== 'exact' || policy.network !== 'eip155:8453' || policy.assetTransferMethod !== 'eip3009' ||
      policy.sdkVersions?.core !== '2.28.0' || policy.sdkVersions?.evm !== '2.28.0' ||
      !/^\d+\.\d+\.\d+$/.test(policy.sdkVersions?.viem ?? '') ||
      policy.localAnvil?.identity !== 'private-anvil-fork' || policy.localAnvil.chainId !== 8453 ||
      !/^\d+\.\d+\.\d+$/.test(policy.localAnvil.anvilVersion) || !policy.localAnvil.executionNetwork ||
      !policy.localAnvil.hardFork || !/^0x[0-9a-f]+$/i.test(policy.localAnvil.forkBlockNumber) ||
      !TRANSACTION_HASH.test(policy.localAnvil.forkBlockHash) || policy.network !== `eip155:${policy.localAnvil.chainId}` ||
      !RESOURCE_ID.test(resourceId) || !OFFER_ID.test(offerId)) return null;
  const resources = policy.resources.filter((item) => item.resourceId === resourceId);
  if (resources.length !== 1) return null;
  const resource = resources[0]!;
  if (!HASH.test(resource.resourceSha256) || typeof resource.contentType !== 'string' || !resource.contentType ||
      !Array.isArray(resource.offers)) return null;
  const offers = resource.offers.filter((item) => item.id === offerId);
  if (offers.length !== 1 || !/^[1-9][0-9]{0,77}$/.test(offers[0]!.amount)) return null;
  return { resource, offer: offers[0]! };
}

export function paymentRequirementMatchesPins(input: {
  declaration: PaymentRequired;
  expectedResourceId: string;
  expectedOffer: PinnedX402Offer;
  policy: PinnedX402Policy;
  facilitatorAddress: string;
  expectedPath: string;
}): PaymentRequirements | null {
  const { declaration, expectedOffer, policy, facilitatorAddress, expectedPath } = input;
  if (declaration.x402Version !== 2 || !Array.isArray(declaration.accepts) || declaration.accepts.length !== 1 ||
      !declaration.resource || typeof declaration.resource.url !== 'string' || !ADDRESS.test(facilitatorAddress)) return null;
  let challengePath: string;
  try {
    const resourceUrl = new URL(declaration.resource.url);
    if (!['http:', 'https:'].includes(resourceUrl.protocol) || resourceUrl.username || resourceUrl.password ||
        resourceUrl.search || resourceUrl.hash || resourceUrl.origin !== 'http://localhost') return null;
    challengePath = resourceUrl.pathname;
  } catch { return null; }
  if (challengePath !== expectedPath) return null;
  if (declaration.resource.mimeType !== undefined && declaration.resource.mimeType !== 'application/json') return null;
  const requirements = declaration.accepts[0] as PaymentRequirements;
  const extra = requirements.extra;
  if (requirements.scheme !== policy.scheme || requirements.network !== policy.network ||
      !ADDRESS.test(requirements.asset) || requirements.asset.toLowerCase() !== policy.asset.toLowerCase() ||
      requirements.amount !== expectedOffer.amount || !ADDRESS.test(requirements.payTo) ||
      requirements.payTo.toLowerCase() !== facilitatorAddress.toLowerCase() ||
      !Number.isSafeInteger(requirements.maxTimeoutSeconds) || requirements.maxTimeoutSeconds < 1 ||
      requirements.maxTimeoutSeconds > policy.maxTimeoutSeconds || !extra ||
      extra.assetTransferMethod !== policy.assetTransferMethod || extra.paymentFlow !== 'authorization' ||
      extra.name !== policy.eip712Domain.name || extra.version !== policy.eip712Domain.version) return null;
  if (Object.keys(extra).sort().join(',') !== 'assetTransferMethod,name,paymentFlow,version') return null;
  return requirements;
}

export function pinnedOfferResponseMatches(input: {
  body: Record<string, unknown> | null;
  command: { resourceId: string; offerId: string };
  pinnedResource: PinnedX402Resource;
  pinnedOffer: PinnedX402Offer;
  policy: PinnedX402Policy;
  facilitatorAddress: string;
}): boolean {
  const { body, command, pinnedResource, pinnedOffer, policy, facilitatorAddress } = input;
  if (!body || body.resourceId !== command.resourceId || body.resourceSha256 !== pinnedResource.resourceSha256 ||
      body.contentType !== pinnedResource.contentType || body.freeInspection !== true || body.deliveryState !== 'not_delivered' ||
      !Array.isArray(body.offers) || !ADDRESS.test(facilitatorAddress)) return false;
  if ((pinnedResource.dataType !== undefined && body.dataType !== pinnedResource.dataType) ||
      (pinnedResource.schema !== undefined && body.schema !== pinnedResource.schema)) return false;
  if (pinnedResource.provenance !== undefined) {
    const actual = body.provenance;
    if (!actual || typeof actual !== 'object' || Array.isArray(actual)) return false;
    const provenance = actual as Record<string, unknown>;
    if (Object.keys(provenance).sort().join(',') !== 'boundary,classification,source' ||
        provenance.classification !== pinnedResource.provenance.classification ||
        provenance.boundary !== pinnedResource.provenance.boundary || provenance.source !== pinnedResource.provenance.source) return false;
  }
  const payment = body.payment;
  if (!payment || typeof payment !== 'object' || Array.isArray(payment)) return false;
  const basePayment = payment as Record<string, unknown>;
  if (basePayment.scheme !== policy.scheme || basePayment.network !== policy.network ||
      typeof basePayment.asset !== 'string' || basePayment.asset.toLowerCase() !== policy.asset.toLowerCase() ||
      basePayment.amount !== pinnedResource.offers[0]?.amount ||
      typeof basePayment.payTo !== 'string' || basePayment.payTo.toLowerCase() !== facilitatorAddress.toLowerCase() ||
      basePayment.transferMethod !== policy.assetTransferMethod) return false;
  const actualOffers = body.offers as unknown[];
  if (actualOffers.length !== pinnedResource.offers.length) return false;
  const selected = actualOffers.filter((item) => item && typeof item === 'object' && !Array.isArray(item) &&
    (item as Record<string, unknown>).id === command.offerId);
  if (selected.length !== 1) return false;
  return pinnedResource.offers.every((expected) => {
    const rows = actualOffers.filter((item) => item && typeof item === 'object' && !Array.isArray(item) &&
      (item as Record<string, unknown>).id === expected.id) as Array<Record<string, unknown>>;
    if (rows.length !== 1) return false;
    const rowPayment = rows[0]!.payment;
    if (!rowPayment || typeof rowPayment !== 'object' || Array.isArray(rowPayment)) return false;
    const candidate = rowPayment as Record<string, unknown>;
    return candidate.scheme === policy.scheme && candidate.network === policy.network &&
      typeof candidate.asset === 'string' && candidate.asset.toLowerCase() === policy.asset.toLowerCase() &&
      candidate.amount === expected.amount && typeof candidate.payTo === 'string' &&
      candidate.payTo.toLowerCase() === facilitatorAddress.toLowerCase() &&
      candidate.transferMethod === policy.assetTransferMethod;
  }) && ((selected[0] as Record<string, unknown>).payment as Record<string, unknown> | undefined)?.amount === pinnedOffer.amount;
}

/**
 * Creates a RAM-only x402 client for one already-funded BEF generation.
 * Spend controls are reset to exactly one selected pinned offer before signing.
 */
export function createEphemeralX402TaskSigner(privateKey: Hex, network: Network): EphemeralX402Signer {
  const account = privateKeyToAccount(privateKey);
  const client = new x402Client();
  registerExactEvmScheme(client, { signer: account, networks: [network] });
  const httpClient = new x402HTTPClient(client);
  return {
    payerAddress: account.address,
    parsePaymentRequired(headers, body) {
      const normalized = normalizeHeaders(headers);
      return httpClient.getPaymentRequiredResponse((name) => normalized[name.toLowerCase()], body);
    },
    async createAuthorization(declaration, requirements) {
      const amount = requirements.amount;
      if (requirements.network !== network || !ADDRESS.test(requirements.asset) || !/^[1-9][0-9]{0,77}$/.test(amount)) {
        throw new Error('task_x402_signer_scope_invalid');
      }
      client.setSpendControls({ allowedAssets: [{
        network: requirements.network,
        asset: requirements.asset as Address,
        maxAmountPerPayment: amount,
      }] });
      const payload: PaymentPayload = await httpClient.createPaymentPayload({ ...declaration, accepts: [requirements] });
      const headers = httpClient.encodePaymentSignatureHeader(payload);
      const output: Record<string, string> = {};
      for (const [name, value] of Object.entries(headers)) {
        const key = name.toLowerCase();
        if (!['payment-signature', 'x-payment'].includes(key) || typeof value !== 'string' || value.length < 16 || value.length > 65536) {
          throw new Error('task_x402_signer_header_invalid');
        }
        output[key] = value;
      }
      if (Object.keys(output).length !== 1) throw new Error('task_x402_signer_header_invalid');
      return output;
    },
    parseSettlement(headers) {
      const normalized = normalizeHeaders(headers);
      if (!normalized['payment-response'] && !normalized['x-payment-response']) return null;
      return httpClient.getPaymentSettleResponse((name) => normalized[name.toLowerCase()]);
    },
  };
}

export function hasPaymentChallengeHeader(headers: Readonly<Record<string, string>>): boolean {
  const normalized = normalizeHeaders(headers);
  const value = normalized['payment-required'] ?? normalized['x-payment-required'];
  return typeof value === 'string' && value.length > 0 && value.length <= 65536;
}

export function hashPaymentChallengeHeaders(headers: Readonly<Record<string, string>>): string {
  const normalized = normalizeHeaders(headers);
  const required = normalized['payment-required'] ?? normalized['x-payment-required'] ?? '';
  return createHash('sha256').update(required, 'utf8').digest('hex');
}

function normalizeHeaders(headers: Readonly<Record<string, string>>): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers)) result[name.toLowerCase()] = value;
  return result;
}

