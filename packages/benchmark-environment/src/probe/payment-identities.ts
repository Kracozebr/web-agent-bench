import type { ProbeContext } from './runner.js';
export function settlementSignerAddress(ctx: ProbeContext): string {
  const services = ctx.capability.services as Record<string, unknown>;
  const facilitator = services.facilitator as Record<string, unknown>;
  const value = facilitator.address;
  if (typeof value !== 'string' || !/^0x[0-9a-f]{40}$/i.test(value)) throw new Error('probe_settlement_signer_invalid');
  return value.toLowerCase();
}
