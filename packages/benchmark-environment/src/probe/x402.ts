import { x402Client, x402HTTPClient } from '@x402/core/client';
import type { PaymentPayload, PaymentRequired, PaymentRequirements } from '@x402/core/types';
import { registerExactEvmScheme } from '@x402/evm/exact/client';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import type { Address } from 'viem';
import type { RuntimeManifest } from '../manifest.js';
import type { ProbeHeaders } from './fetch-types.js';

export type EphemeralSigner = {
  privateKey: `0x${string}`;
  payerAddress: Address;
  httpClient: x402HTTPClient;
};

export function createEphemeralSigner(): EphemeralSigner {
  const privateKey = generatePrivateKey();
  const account = privateKeyToAccount(privateKey);
  const client = new x402Client();
  registerExactEvmScheme(client, { signer: account, networks: ['eip155:8453'] });
  return { privateKey, payerAddress: account.address, httpClient: new x402HTTPClient(client) };
}

export function readPaymentRequired(
  signer: EphemeralSigner,
  responseHeaders: ProbeHeaders,
  responseBody: unknown,
  manifest: RuntimeManifest,
  offerId = 'canonical',
): { declaration: PaymentRequired; requirements: PaymentRequirements } {
  const declaration = signer.httpClient.getPaymentRequiredResponse(
    (name) => responseHeaders.get(name),
    responseBody,
  );
  const offer = manifest.x402.offers.find((candidate) => candidate.id === offerId);
  if (!offer) throw new Error('probe_x402_offer_not_pinned');
  const requirements = declaration.accepts.find((entry) =>
    entry.scheme === 'exact'
    && entry.network === manifest.x402.network
    && entry.asset.toLowerCase() === manifest.x402.asset.toLowerCase()
    && entry.amount === offer.amount,
  );
  if (!requirements) throw new Error('probe_x402_requirements_mismatch');
  return { declaration, requirements };
}

export async function createSignedPayload(
  signer: EphemeralSigner,
  declaration: PaymentRequired,
  requirements?: PaymentRequirements,
): Promise<{ payload: PaymentPayload; headers: Record<string, string> }> {
  try {
    const paymentRequired = requirements
      ? { ...declaration, accepts: [requirements] }
      : declaration;
    const payload = await signer.httpClient.createPaymentPayload(paymentRequired);
    const headers = signer.httpClient.encodePaymentSignatureHeader(payload);
    return { payload, headers };
  } catch (error) {
    const message = error instanceof Error ? error.message : '';
    const category = /EIP-712 domain parameters \(name, version\) are required/i.test(message)
      ? 'probe_x402_signing_domain_metadata_missing'
      : /All payment requirements were rejected by spendControls/i.test(message)
        ? 'probe_x402_spend_controls_rejected_requirements'
        : 'probe_x402_signing_failed';
    throw new Error(category);
  }
}

/**
 * Sign only the manifest-pinned SC002 above-budget offer, with an exact per-asset SDK cap.
 * The ordinary client and its default spend controls remain unchanged.
 */
export async function createPinnedSelectedOfferPayload(
  signer: EphemeralSigner,
  declaration: PaymentRequired,
  requirements: PaymentRequirements,
  manifest: RuntimeManifest,
  offerId: string,
): Promise<{ payload: PaymentPayload; headers: Record<string, string> }> {
  const offers = manifest.x402.offers.filter((offer) => offer.id === offerId);
  const offer = offers.length === 1 ? offers[0] : undefined;
  const maxUnits = manifest.funding.maxUsdcUnitsPerGeneration;
  if (offerId !== 'task-goal-exceeded' || !offer
    || !/^[1-9][0-9]*$/.test(offer.amount) || !/^[1-9][0-9]*$/.test(maxUnits)
    || BigInt(offer.amount) > BigInt(maxUnits)
    || requirements.scheme !== manifest.x402.scheme
    || requirements.network !== manifest.x402.network
    || requirements.asset.toLowerCase() !== manifest.x402.asset.toLowerCase()
    || requirements.amount !== offer.amount
    || declaration.x402Version !== 2) {
    throw new Error('probe_x402_selected_offer_out_of_scope');
  }

  const client = new x402Client();
  registerExactEvmScheme(client, {
    signer: privateKeyToAccount(signer.privateKey),
    networks: [requirements.network],
  });
  client.setSpendControls({
    allowedAssets: [{
      network: requirements.network,
      asset: requirements.asset,
      maxAmountPerPayment: offer.amount,
    }],
  });
  const httpClient = new x402HTTPClient(client);
  try {
    const payload = await httpClient.createPaymentPayload({ ...declaration, accepts: [requirements] });
    return { payload, headers: httpClient.encodePaymentSignatureHeader(payload) };
  } catch (error) {
    const message = error instanceof Error ? error.message : '';
    const category = /EIP-712 domain parameters \(name, version\) are required/i.test(message)
      ? 'probe_x402_signing_domain_metadata_missing'
      : /spendControls/i.test(message)
        ? 'probe_x402_spend_controls_rejected_requirements'
        : 'probe_x402_signing_failed';
    throw new Error(category);
  }
}

export async function createNegativeRequirementPayload(
  signer: EphemeralSigner,
  declaration: PaymentRequired,
  requirements: PaymentRequirements,
  variant: 'wrong_domain' | 'amount_mismatch',
): Promise<{ payload: PaymentPayload; headers: Record<string, string> }> {
  if (requirements.scheme !== 'exact' || requirements.network !== 'eip155:8453'
    || !/^0x[0-9a-f]{40}$/i.test(requirements.asset) || !/^\d+$/.test(requirements.amount)) {
    throw new Error('probe_x402_negative_requirement_out_of_scope');
  }
  const wrongAmount = variant === 'amount_mismatch'
    ? (BigInt(requirements.amount) + 1n).toString()
    : requirements.amount;
  const wrongRequirements: PaymentRequirements = variant === 'amount_mismatch'
    ? { ...requirements, amount: wrongAmount }
    : {
      ...requirements,
      extra: {
        ...(requirements.extra ?? {}),
        name: `${requirements.extra?.name ?? 'USDC'} BEF Wrong Domain`,
      },
    };
  const client = new x402Client();
  registerExactEvmScheme(client, {
    signer: privateKeyToAccount(signer.privateKey),
    networks: [requirements.network],
  });
  client.setSpendControls({
    allowedAssets: [{
      network: requirements.network,
      asset: requirements.asset as Address,
      maxAmountPerPayment: wrongAmount,
    }],
  });
  const httpClient = new x402HTTPClient(client);
  try {
    const payload = await httpClient.createPaymentPayload({ ...declaration, accepts: [wrongRequirements] });
    return { payload, headers: httpClient.encodePaymentSignatureHeader(payload) };
  } catch {
    throw new Error(variant === 'wrong_domain'
      ? 'probe_x402_wrong_domain_signing_failed'
      : 'probe_x402_amount_mismatch_signing_failed');
  }
}

/** Create a real authorization for one deliberately unsupported token.
 *
 * The SDK's default spend controls reject unknown assets. This negative-only
 * client opts in to exactly the selected fake asset, network, and amount; the
 * ordinary participant client retains its default controls. The signature is
 * therefore bound to the wrong token instead of mutating signed metadata.
 */
export async function createWrongTokenPayload(
  signer: EphemeralSigner,
  declaration: PaymentRequired,
  requirements: PaymentRequirements,
): Promise<{ payload: PaymentPayload; headers: Record<string, string> }> {
  const pinnedAsset = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
  const unsupportedAsset = '0x0000000000000000000000000000000000000001' as Address;
  if (requirements.scheme !== 'exact'
    || requirements.network !== 'eip155:8453'
    || requirements.amount !== '100000'
    || requirements.asset.toLowerCase() !== pinnedAsset.toLowerCase()
    || requirements.asset.toLowerCase() === unsupportedAsset.toLowerCase()) {
    throw new Error('probe_x402_wrong_token_candidate_out_of_scope');
  }

  const client = new x402Client();
  registerExactEvmScheme(client, {
    signer: privateKeyToAccount(signer.privateKey),
    networks: [requirements.network],
  });
  client.setSpendControls({
    allowedAssets: [{
      network: requirements.network,
      asset: unsupportedAsset,
      maxAmountPerPayment: requirements.amount,
    }],
  });
  const httpClient = new x402HTTPClient(client);
  const wrongRequirements: PaymentRequirements = { ...requirements, asset: unsupportedAsset };
  try {
    const payload = await httpClient.createPaymentPayload({
      ...declaration,
      accepts: [wrongRequirements],
    });
    const headers = httpClient.encodePaymentSignatureHeader(payload);
    return { payload, headers };
  } catch (error) {
    const message = error instanceof Error ? error.message : '';
    const category = /EIP-712 domain parameters \(name, version\) are required/i.test(message)
      ? 'probe_x402_signing_domain_metadata_missing'
      : /spendControls/i.test(message)
        ? 'probe_x402_spend_controls_rejected_requirements'
        : 'probe_x402_signing_failed';
    throw new Error(category);
  }
}

export function readSettlementHeader(httpClient: x402HTTPClient, responseHeaders: ProbeHeaders): ReturnType<x402HTTPClient['getPaymentSettleResponse']> | null {
  if (!responseHeaders.has('payment-response') && !responseHeaders.has('x-payment-response')) return null;
  return httpClient.getPaymentSettleResponse((name) => responseHeaders.get(name));
}
