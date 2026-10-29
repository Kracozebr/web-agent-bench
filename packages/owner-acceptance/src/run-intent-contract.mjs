function assert(condition, message) {
  if (!condition) throw new Error(message);
}

export function validateCreatedRunIntent({ responseStatus, body, request, agentId, expectedQuote, expectedTaskIds }) {
  const intent = body?.intent;
  assert(responseStatus === 201 && typeof intent?.id === "string"
    && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(intent.id),
  "Owner run-intent response did not include a created intent UUID");
  assert(intent.agentId === agentId && intent.mode === "training"
    && intent.quote?.price === expectedQuote && intent.quote?.precision === 6 && intent.quote?.token === "USDC"
    && Array.isArray(intent.taskIds) && JSON.stringify(intent.taskIds) === JSON.stringify(expectedTaskIds)
    && request.expectedQuotePrice === expectedQuote
    && JSON.stringify(request.taskIds) === JSON.stringify(expectedTaskIds)
    && typeof request.operationId === "string" && /^[A-Za-z0-9_-]{12,128}$/.test(request.operationId),
  "Owner run-intent response did not match the requested task selection and quote");
  return { status: responseStatus, operationId: request.operationId, intentId: intent.id,
    agentId, mode: intent.mode, taskIds: intent.taskIds, quotePrice: intent.quote.price };
}
