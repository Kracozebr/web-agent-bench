const OPERATION_ID = /^[A-Za-z0-9_-]{12,128}$/;

export function captureRows(value) {
  const rows = value?.capture ?? value;
  if (!rows || !Array.isArray(rows.requests)) {
    throw new TypeError("Expected browser capture rows or an attachSafeBrowserCapture wrapper");
  }
  return rows;
}

export function browserCaptureApi(value) {
  if (!value || typeof value.action !== "function" || !value.capture || !Array.isArray(value.capture.requests)) {
    throw new TypeError("Browser actions require the attachSafeBrowserCapture wrapper");
  }
  return { rows: value.capture, action: value.action.bind(value) };
}

export function capturedOperation(value, path, method = "POST", after = 0) {
  const row = captureRows(value).requests.slice(after)
    .filter((item) => item.path === path && item.method === method).at(-1);
  return typeof row?.operationId === "string" && OPERATION_ID.test(row.operationId) ? row.operationId : null;
}

export function sameRedemptionReceipt(original, retry) {
  return retry?.status === 200
    && typeof original?.redemptionId === "string"
    && original.redemptionId === retry.redemptionId
    && typeof original?.grantId === "string"
    && original.grantId === retry.grantId;
}

export function hasCodeError(outcome, status, errorCode) {
  return outcome?.status === status && outcome.errorCode === errorCode;
}
