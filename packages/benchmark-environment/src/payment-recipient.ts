import type { Address } from 'viem';

/** Public payee identity is independent of the short-lived transaction signer. */
export function parsePaymentRecipient(value: string | undefined): Address | undefined {
  if (value === undefined || value === '') return undefined;
  if (!/^0x[0-9a-f]{40}$/i.test(value) || /^0x0{40}$/i.test(value)) throw new Error('BEF_PAYMENT_RECIPIENT must be a nonzero public EVM address');
  return value.toLowerCase() as Address;
}
export function paymentRecipient(environment: { paymentRecipient?: Address | undefined; facilitatorAddress: Address }): Address {
  return environment.paymentRecipient ?? environment.facilitatorAddress;
}
export function verifyPaymentRecipient(configured: Address | undefined, identity: Record<string, unknown>): Address {
  const present = Object.hasOwn(identity, 'paymentRecipient');
  if (present && (typeof identity.paymentRecipient !== 'string' || !identity.paymentRecipient)) throw new Error('Private facilitator public payee is malformed');
  const advertised = present ? parsePaymentRecipient(identity.paymentRecipient as string) : undefined;
  if (configured && advertised !== configured) throw new Error('Private facilitator payment recipient does not match configured public payee');
  if (!configured && advertised) throw new Error('API public payment recipient is not configured');
  const signer = typeof identity.address === 'string' ? parsePaymentRecipient(identity.address) : undefined;
  if (!signer) throw new Error('Private facilitator signer address is malformed');
  return configured ?? signer;
}

/** Delivery must use the original observed payee, never the current gas signer. */
export function durablePaymentRecipient(row: { facilitator_address: unknown; payment_recipient?: unknown; original_requirements_pay_to: unknown }): Address | null {
  try {
    const signer = typeof row.facilitator_address === 'string' ? parsePaymentRecipient(row.facilitator_address) : undefined;
    const raw = row.payment_recipient === null || !Object.hasOwn(row, 'payment_recipient') ? row.facilitator_address : row.payment_recipient;
    const payee = typeof raw === 'string' ? parsePaymentRecipient(raw) : undefined;
    const observed = typeof row.original_requirements_pay_to === 'string' ? parsePaymentRecipient(row.original_requirements_pay_to) : undefined;
    return signer && payee && observed && payee === observed ? payee : null;
  } catch { return null; }
}

/** Retained recovery separates the original transaction sender from its payee. */
export function retainedPaymentActors(row: {facilitator_address: unknown;payment_recipient?: unknown}): {signer:Address;payee:Address}|null {
  try {
    const rawPayee = !Object.hasOwn(row,'payment_recipient') || row.payment_recipient === null ? row.facilitator_address : row.payment_recipient;
    const signer = typeof row.facilitator_address === 'string' ? parsePaymentRecipient(row.facilitator_address) : undefined;
    const payee = typeof rawPayee === 'string' ? parsePaymentRecipient(rawPayee) : undefined;
    return signer && payee ? {signer,payee} : null;
  } catch {return null;}
}
