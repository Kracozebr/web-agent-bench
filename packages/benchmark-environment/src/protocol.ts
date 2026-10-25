import { AsyncLocalStorage } from 'node:async_hooks';
import { HTTPFacilitatorClient, x402HTTPResourceServer, x402ResourceServer } from '@x402/core/server';
import { ExactEvmScheme } from '@x402/evm/exact/server';
import type { RuntimeEnvironment } from './runtime.js';
import type { RuntimeManifest } from './manifest.js';
import { selectedPinnedOffer } from './offers.js';

export type FacilitatorRequestScope = {
  operationId: string;
  generationId: string;
  requestSha256: string;
  variantId: string;
};

export const facilitatorRequestScope = new AsyncLocalStorage<FacilitatorRequestScope>();

export type PaymentProtocol = {
  http: x402HTTPResourceServer;
};

export async function createPaymentProtocol(
  environment: RuntimeEnvironment,
  manifest: RuntimeManifest,
  serviceKey: string,
): Promise<PaymentProtocol> {
  const facilitator = new HTTPFacilitatorClient({
    url: environment.facilitatorUrl,
    timeoutMs: manifest.x402.confirmationTimeoutMs,
    createAuthHeaders: async () => {
      const baseHeaders = { 'X-BEF-Service-Key': serviceKey };
      const scope = facilitatorRequestScope.getStore();
      const scopedHeaders = scope ? {
        ...baseHeaders,
        'X-BEF-Operation-Id': scope.operationId,
        'X-BEF-Generation': scope.generationId,
        'X-BEF-Request-SHA256': scope.requestSha256,
        'X-BEF-Variant-Id': scope.variantId,
      } : baseHeaders;
      return {
        supported: baseHeaders,
        verify: scopedHeaders,
        settle: scopedHeaders,
      };
    },
  });
  const server = new x402ResourceServer(facilitator)
    .register(manifest.x402.network, new ExactEvmScheme());
  const route = `POST /tools/${environment.id}/purchase`;
  const http = new x402HTTPResourceServer(server, {
    [route]: {
      accepts: {
        scheme: manifest.x402.scheme,
        network: manifest.x402.network,
        payTo: environment.facilitatorAddress,
        price: (context) => {
          const body = context.adapter.getBody?.();
          const offer = selectedPinnedOffer(manifest, body);
          if (!offer) throw new Error('unlisted_offer');
          return { asset: manifest.x402.asset, amount: offer.amount };
        },
        maxTimeoutSeconds: manifest.x402.maxTimeoutSeconds,
        extra: {
          assetTransferMethod: manifest.x402.assetTransferMethod,
          paymentFlow: 'authorization',
          name: manifest.x402.eip712Domain.name,
          version: manifest.x402.eip712Domain.version,
        },
      },
      resource: `http://localhost/tools/${environment.id}/purchase`,
      description: 'Pinned local benchmark resource',
      mimeType: 'application/json',
      serviceName: 'web-agent-bench-bef-local',
      unpaidResponseBody: async () => ({ contentType: 'application/json', body: { error: 'payment_required' } }),
    },
  });
  await http.initialize();
  return { http };
}
