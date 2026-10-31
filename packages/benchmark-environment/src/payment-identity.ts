import type { RuntimeManifest } from './manifest.js';

// AICODE-NOTE: Public merchant metadata and actual authorization extras must derive
// from the same provider policy, never a task rubric or an agent-supplied answer.
export function pinnedPaymentIdentity(manifest: RuntimeManifest) {
  return { paymentFlow: 'authorization' as const,
    name: manifest.x402.eip712Domain.name,
    version: manifest.x402.eip712Domain.version };
}
