/** Keep the historical raw-row shape when the optional additive column is NULL. */
export function capturePaymentMetadata(row: Record<string, unknown>): Record<string, unknown> {
  if (!Object.hasOwn(row, 'payment_recipient') || row.payment_recipient !== null) return row;
  const result={...row};delete result.payment_recipient;return result;
}
