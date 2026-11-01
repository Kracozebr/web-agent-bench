const ADDRESS = /^0x[0-9a-f]{40}$/i;
type Row = Record<string, unknown>;
// AICODE-NOTE: Absence/null DB values decode old captures without changing them.
// A present protocol field is never a fallback hint: both new identities must match.
export function capturePaymentRecipient(protocol: Row, payment: Row): string {
  const modern = Object.hasOwn(protocol, 'paymentRecipient');
  const stored = payment.payment_recipient;
  const signer = !modern && !Object.hasOwn(protocol,'facilitatorAddress') ? payment.facilitator_address : protocol.facilitatorAddress;
  if (typeof signer !== 'string' || !ADDRESS.test(signer) ||
      typeof payment.facilitator_address !== 'string' || !ADDRESS.test(payment.facilitator_address) ||
      signer.toLowerCase() !== payment.facilitator_address.toLowerCase()) throw new Error('capture_payment_identity_invalid');
  if (modern) {
    if (/^0x0{40}$/i.test(signer) || /^0x0{40}$/i.test(String(stored)) || /^0x0{40}$/i.test(String(protocol.paymentRecipient))) throw new Error('capture_payment_identity_invalid');
    if (typeof protocol.paymentRecipient !== 'string' || !ADDRESS.test(protocol.paymentRecipient) ||
        typeof stored !== 'string' || !ADDRESS.test(stored) || stored.toLowerCase() !== protocol.paymentRecipient.toLowerCase()) throw new Error('capture_payment_identity_invalid');
    return stored;
  }
  if (stored !== null && stored !== undefined) throw new Error('capture_payment_identity_mode_mismatch');
  return signer;
}
