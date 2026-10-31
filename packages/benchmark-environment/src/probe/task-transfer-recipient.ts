/** Public fixture target pin only; receiving an ERC20 transfer needs no recipient key. */
export function referenceRecipientOption(taskId: string, mode: string, value?: string): string | undefined {
  if (value === undefined) return undefined;
  if (taskId !== 'S1' || !['ranked', 'training'].includes(mode)) throw new Error('task_transfer_recipient_scope_invalid');
  return validateTransferRecipient(value);
}

export function validateTransferRecipient(value: string, fixedAddresses: readonly string[] = [], payer?: string): `0x${string}` {
  if (!/^0x[0-9a-f]{40}$/i.test(value) || /^0x0{40}$/i.test(value)) throw new Error('task_transfer_recipient_invalid');
  const address = value.toLowerCase();
  if (fixedAddresses.some(fixed => fixed.toLowerCase() === address)) throw new Error('task_transfer_recipient_collides_with_contract');
  if (payer?.toLowerCase() === address) throw new Error('task_transfer_recipient_collides_with_payer');
  return address as `0x${string}`;
}
