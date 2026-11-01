const ADDRESS = /^0x[0-9a-f]{40}$/i;
const ZERO = /^0x0{40}$/i;
function address(value: unknown): string | null {
  return typeof value === 'string' && ADDRESS.test(value) && !ZERO.test(value) ? value.toLowerCase() : null;
}
/** Raw DB payee metadata distinguishes the modern profile; old packets retain signer-as-payee semantics. */
export function referencePaymentIdentityMatches(row: Record<string, unknown>, expectedRecipient: unknown, receiptFrom: unknown,
  declaration: Record<string, unknown> = {}): boolean {
  const recipient = address(expectedRecipient), signer = address(row.facilitator_address), sender = address(receiptFrom);
  if (!recipient || !signer || !sender || sender !== signer) return false;
  const modern = Object.hasOwn(row, 'payment_recipient') && row.payment_recipient !== null;
  if ((modern ? address(row.payment_recipient) : signer) !== recipient) return false;
  if (Object.hasOwn(declaration, 'settlementSignerAddress') && address(declaration.settlementSignerAddress) !== signer) return false;
  return true;
}
