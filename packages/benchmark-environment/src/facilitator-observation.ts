import { createHash } from 'node:crypto';

function recordOf(value: unknown): Record<string, unknown> | undefined {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function sha256(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

/** Build the public x402 request projection stored with facilitator observations. */
export function buildSafeRequest(bodyValue: unknown, operationRequestSha256: string): Record<string, unknown> {
  const body = recordOf(bodyValue) ?? {};
  const paymentPayload = recordOf(body.paymentPayload) ?? {};
  const payload = recordOf(paymentPayload.payload) ?? {};
  const transfer = recordOf(payload.authorization) ?? payload;
  const paymentRequirements = recordOf(body.paymentRequirements) ?? {};
  const signature = typeof payload.signature === 'string'
    ? payload.signature
    : typeof paymentPayload.signature === 'string' ? paymentPayload.signature : '';
  return {
    operationRequestSha256,
    x402Version: body.x402Version,
    paymentPayload: {
      x402Version: paymentPayload.x402Version,
      resource: paymentPayload.resource,
      accepted: paymentPayload.accepted,
      transfer: {
        from: transfer.from,
        to: transfer.to,
        value: transfer.value,
      },
      proofSha256: sha256(signature),
    },
    paymentRequirements: {
      scheme: paymentRequirements.scheme,
      network: paymentRequirements.network,
      asset: paymentRequirements.asset,
      amount: paymentRequirements.amount,
      payTo: paymentRequirements.payTo,
      maxTimeoutSeconds: paymentRequirements.maxTimeoutSeconds,
      extra: paymentRequirements.extra ?? {},
    },
  };
}
