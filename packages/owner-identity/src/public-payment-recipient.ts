const ADDRESS = /^0x[0-9a-f]{40}$/i;
/** Public recipient is independent of the ephemeral gas signer; malformed presence never falls back. */
export function readPublicPaymentRecipient(facilitator: Record<string, unknown> | null): string | null {
  if (!facilitator) return null;
  if (typeof facilitator.address !== 'string' || !ADDRESS.test(facilitator.address) || /^0x0{40}$/i.test(facilitator.address)) return null;
  const value = Object.hasOwn(facilitator, 'paymentRecipient') ? facilitator.paymentRecipient : facilitator.address;
  return typeof value === 'string' && ADDRESS.test(value) && !/^0x0{40}$/i.test(value) ? value.toLowerCase() : null;
}
