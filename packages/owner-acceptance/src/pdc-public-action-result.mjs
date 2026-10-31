/** Preserve the observed MCP receipt and submitted command for the existing public reference actor. */
export function publicActorResultFromMcpReceipt(receipt, command, expectsTransaction) {
  if (receipt?.status !== 'observed' || typeof receipt.actionId !== 'string' || !command || typeof command.kind !== 'string') {
    throw Object.assign(new Error('pdc_public_action_not_observed'), { code: 'pdc_public_action_not_observed' });
  }
  if (expectsTransaction === true && !/^0x[0-9a-f]{64}$/i.test(receipt.transactionHash ?? '') ||
      expectsTransaction === false && receipt.transactionHash !== null) {
    throw Object.assign(new Error('pdc_public_action_transaction_mismatch'), { code: 'pdc_public_action_transaction_mismatch' });
  }
  return { apiPayload: receipt, action: { ...receipt, receiptStatus: receipt.status,
    kind: command.kind, command: structuredClone(command) } };
}

/** Describe only fields absent from the actual public S2 inspection, without filling them. */
export function s2PublicDisclosureGap(task, receipt, publicResponseReference) {
  const body = receipt?.toolResponse;
  if (task?.taskId !== 'S2' || receipt?.status !== 'observed' || body?.resourceId !== task.conditions?.resourceId ||
      body?.freeInspection !== true || !Array.isArray(task.conditions.requiredAnswerFields)) return null;
  const offer = body.offers?.find((item) => item.id === task.conditions.offerId), payment = offer?.payment;
  if (!payment) return null;
  const asset = task.execution.assets.find((item) => typeof item.address === 'string' && typeof payment.asset === 'string' &&
    item.address.toLowerCase() === payment.asset.toLowerCase() && payment.network === 'eip155:' + item.chainId);
  const values = { amountUnits: payment.amount, network: payment.network, assetId: asset?.assetId,
    recipient: payment.payTo, scheme: payment.scheme, resourceId: body.resourceId, offerId: offer.id,
    version: payment.version ?? body.version, assetTransferMethod: payment.transferMethod,
    paymentFlow: payment.paymentFlow, name: payment.name ?? offer.assetName ?? body.assetName };
  const requiredFields = [...task.conditions.requiredAnswerFields];
  const missingFields = requiredFields.filter((field) => typeof values[field] !== 'string');
  if (!missingFields.length) return null;
  return { kind: 'S2_REQUIRED_IDENTITY_FIELDS_UNDISCLOSED', status: 'open', betaReady: false, requiredFields, missingFields,
    publicInspectionActionId: receipt.actionId, publicResponseReference };
}

export function isKnownS2DisclosureGap(grade, gap) {
  return grade?.result_status === 'known' && grade.task_id === 'S2' && grade.outcome === 'partial' &&
    grade.credit?.numerator === '7' && grade.credit.denominator === '10' &&
    JSON.stringify(gap?.missingFields?.slice().sort()) === JSON.stringify(['name','paymentFlow','version']) &&
    Array.isArray(gap.requiredFields) && gap.requiredFields.length === 11 && new Set(gap.requiredFields).size === 11 &&
    ['amountUnits','network','assetId','recipient','scheme','resourceId','offerId','version','assetTransferMethod','paymentFlow','name']
      .every((field) => gap.requiredFields.includes(field));
}
