import { randomBytes, randomUUID, createHash } from "node:crypto";
import pg from "pg";
import { attachSafeBrowserCapture, waitForPath } from "./browser-support.mjs";
import { browserCaptureApi, captureRows, capturedOperation, hasCodeError, sameRedemptionReceipt } from "./bonus-code-capture-contract.mjs";

const { Pool } = pg;
const ADMIN_CODES = "/api/admin/bonus-codes";
const OWNER_REDEEM = "/api/owner/bonus-codes/redeem";
const CODE_VALUE = /^BPC-[A-Za-z0-9_-]{43}$/;

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function operationId() {
  return randomUUID().replaceAll("-", "");
}

function bonusGrantOperationId(codeId, ownerId) {
  return `bcg_${createHash("sha256").update(`${codeId}\0${ownerId}`).digest("hex")}`;
}

function safeActionOutcome(response, body = {}) {
  return {
    status: response.status(),
    errorCode: typeof body?.error?.code === "string" ? body.error.code : null,
    operationId: typeof body?.operationId === "string" ? body.operationId : null,
    replayed: body?.replayed === true,
    codeId: typeof body?.code?.id === "string" ? body.code.id : null,
    redemptionId: typeof body?.redemption?.id === "string" ? body.redemption.id : null,
    grantId: typeof body?.redemption?.grantId === "string" ? body.redemption.grantId : null,
    oneTimeValueReturned: typeof body?.secret === "string",
    oneTimeValueMatchesFormat: typeof body?.secret === "string" && CODE_VALUE.test(body.secret),
  };
}

function projectCapture(capture) {
  const rows = captureRows(capture);
  const allowed = (path) => path.startsWith("/api/admin/bonus-codes")
    || path.startsWith("/api/owner/bonus-codes")
    || path === "/api/owner/billing"
    || path === "/api/admin/bonus-grants"
    || path === "/api/admin/invitations"
    || path === "/api/admission/activate";
  return {
    schemaVersion: "oid-browser-observation/v1",
    scenarioId: rows.scenarioId,
    actions: rows.actions.filter((row) => typeof row?.action === "string" && typeof row?.selector === "string").slice(-100),
    requests: rows.requests.filter((row) => allowed(row.path)).slice(-200).map((row) => ({
      method: row.method,
      path: row.path,
      ...(typeof row.operationId === "string" ? { operationId: row.operationId } : {}),
    })),
    responses: rows.responses.filter((row) => allowed(row.path)).slice(-200).map((row) => ({
      method: row.method,
      path: row.path,
      status: row.status,
    })),
  };
}

async function observerSnapshot(connectionString, {
  codeIds = [], issueOperationIds = [], disableOperationIds = [], ownerIds = [], operationIds = [], grantOperationIds = [],
}) {
  const pool = new Pool({ connectionString, max: 1, application_name: "bpc-acceptance-readonly-observer" });
  const client = await pool.connect();
  try {
    await client.query("BEGIN READ ONLY");
    const identity = (await client.query(`SELECT current_user AS role,
      current_database() AS database,
      current_setting('transaction_read_only') AS transaction_read_only,
      current_setting('default_transaction_read_only') AS default_transaction_read_only`)).rows[0];
    assert(identity?.role === "oid_observer" && identity.transaction_read_only === "on",
      "BPC durable outcome must be read independently through the read-only oid_observer role");
    const codes = await client.query(`SELECT id::text, issuer_owner_id::text, label, kind,
        amount_units::text, maximum_uses, used_count, issued_at, disabled_at,
        disable_operation_id, issue_operation_id,
        (verifier_hash ~ '^[0-9a-f]{64}$') AS verifier_is_keyed_hash
      FROM oid_bonus_code
      WHERE id::text = ANY($1::text[]) OR issue_operation_id = ANY($2::text[]) OR disable_operation_id = ANY($3::text[])
      ORDER BY id`, [codeIds, issueOperationIds, disableOperationIds]);
    const redemptions = await client.query(`SELECT id::text, code_id::text, owner_id::text,
        bonus_grant_id::text, financial_operation_id, created_at
      FROM oid_bonus_code_redemption WHERE code_id::text = ANY($1::text[])
      ORDER BY created_at,id`, [codeIds]);
    const claimOperations = await client.query(`SELECT owner_id::text, operation_id, code_id::text,
        redemption_id::text, created_at
      FROM oid_bonus_code_claim_operation
      WHERE code_id::text = ANY($1::text[]) OR (owner_id::text = ANY($2::text[]) AND operation_id = ANY($3::text[]))
      ORDER BY created_at,owner_id,operation_id`, [codeIds, ownerIds, operationIds]);
    const financialOperationIds = [...new Set([...grantOperationIds, ...redemptions.rows.map((row) => row.financial_operation_id)])];
    const redGrantIds = redemptions.rows.map((row) => row.bonus_grant_id);
    const grants = await client.query(`SELECT id::text, owner_id::text, amount_units::text,
        issued_by_owner_id::text, reason, operation_id, created_at, expires_at
      FROM oid_bonus_grant WHERE id::text = ANY($1::text[]) OR operation_id = ANY($2::text[])
      ORDER BY created_at,id`, [redGrantIds, financialOperationIds]);
    const grantIds = [...new Set([...redGrantIds, ...grants.rows.map((row) => row.id)])];
    const entries = await client.query(`SELECT id::text, owner_id::text, actor_owner_id::text,
        bonus_grant_id::text, operation_id, entry_type, source_kind, amount_units::text,
        available_delta_units::text, reserved_delta_units::text, expired_delta_units::text, created_at
      FROM oid_ledger_entry WHERE bonus_grant_id::text = ANY($1::text[]) OR operation_id = ANY($2::text[])
      ORDER BY created_at,id`, [grantIds, financialOperationIds]);
    const operations = await client.query(`SELECT id::text, actor_owner_id::text, subject_owner_id::text,
        operation_id, action, created_at
      FROM oid_ledger_operation WHERE operation_id = ANY($1::text[]) OR operation_id = ANY($2::text[])
      ORDER BY created_at,id`, [operationIds, financialOperationIds]);
    const audits = await client.query(`SELECT id::text, event_type, operation_id, actor_owner_id::text,
        subject_owner_id::text, metadata, created_at
      FROM oid_ledger_audit WHERE operation_id = ANY($1::text[]) OR operation_id = ANY($2::text[])
      ORDER BY created_at,id`, [operationIds, financialOperationIds]);
    const balances = await client.query(`SELECT e.owner_id::text,
        SUM(CASE WHEN e.source_kind='cash_usdc' THEN e.available_delta_units
                 WHEN g.expires_at IS NOT NULL AND g.expires_at <= clock_timestamp() THEN 0
                 ELSE e.available_delta_units END)::text AS bonus_available_units,
        SUM(e.reserved_delta_units)::text AS bonus_reserved_units,
        SUM(e.expired_delta_units + CASE WHEN g.expires_at IS NOT NULL AND g.expires_at <= clock_timestamp()
             THEN e.available_delta_units ELSE 0 END)::text AS bonus_expired_units
      FROM oid_ledger_entry e LEFT JOIN oid_bonus_grant g ON g.id=e.bonus_grant_id
      WHERE e.owner_id::text = ANY($1::text[]) AND e.source_kind='tester_bonus'
      GROUP BY e.owner_id ORDER BY e.owner_id`, [ownerIds]);
    const cashEffects = await client.query(`SELECT count(*)::integer AS count
      FROM oid_ledger_entry WHERE operation_id = ANY($1::text[]) AND source_kind='cash_usdc'`, [financialOperationIds]);
    await client.query("COMMIT");
    return {
      schemaVersion: "bpc-independent-postgres-observation/v1",
      observer: identity,
      codes: codes.rows,
      redemptions: redemptions.rows,
      claimOperations: claimOperations.rows,
      grants: grants.rows,
      entries: entries.rows,
      operations: operations.rows,
      audits: audits.rows,
      ownerBalances: balances.rows,
      grantOperationIds: financialOperationIds,
      cashEffectCount: cashEffects.rows[0]?.count ?? null,
    };
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
    await pool.end();
  }
}

function grantLedgerConserved(snapshot, { allowedStandaloneGrantOperations = [] } = {}) {
  if (snapshot.cashEffectCount !== 0) return false;
  const redemptionsByCode = new Map();
  const redemptionFinancialOperations = new Set(snapshot.redemptions.map((row) => row.financial_operation_id));
  const allowedStandalone = new Set(allowedStandaloneGrantOperations);
  const expectedGrantOperations = new Set(snapshot.grantOperationIds ?? []);
  const grantsByOperation = new Map();
  for (const grant of snapshot.grants) {
    const existing = grantsByOperation.get(grant.operation_id) ?? [];
    existing.push(grant);
    grantsByOperation.set(grant.operation_id, existing);
    if (!redemptionFinancialOperations.has(grant.operation_id) && !allowedStandalone.has(grant.operation_id)) return false;
  }
  for (const operation of snapshot.operations.filter((row) => row.action === "bonus_grant")) {
    if (grantsByOperation.get(operation.operation_id)?.length !== 1) return false;
  }
  for (const operation of snapshot.operations.filter((row) => expectedGrantOperations.has(row.operation_id))) {
    if (operation.action !== "bonus_grant" || grantsByOperation.get(operation.operation_id)?.length !== 1) return false;
  }
  for (const audit of snapshot.audits.filter((row) => row.event_type === "bonus_grant_issued")) {
    if (!snapshot.grants.some((grant) => grant.operation_id === audit.operation_id && grant.id === audit.metadata?.grantId)) return false;
  }
  for (const audit of snapshot.audits.filter((row) => expectedGrantOperations.has(row.operation_id))) {
    if (audit.event_type !== "bonus_grant_issued"
      || !snapshot.grants.some((grant) => grant.operation_id === audit.operation_id && grant.id === audit.metadata?.grantId)) return false;
  }
  for (const entry of snapshot.entries.filter((row) => expectedGrantOperations.has(row.operation_id))) {
    if (entry.entry_type !== "bonus_grant" || entry.source_kind !== "tester_bonus"
      || !snapshot.grants.some((grant) => grant.id === entry.bonus_grant_id && grant.operation_id === entry.operation_id)) return false;
  }
  for (const grant of snapshot.grants) {
    const grantOperations = snapshot.operations.filter((row) => row.operation_id === grant.operation_id && row.action === "bonus_grant");
    const grantAudits = snapshot.audits.filter((row) => row.operation_id === grant.operation_id
      && row.event_type === "bonus_grant_issued" && row.metadata?.grantId === grant.id);
    const grantEntries = snapshot.entries.filter((row) => row.bonus_grant_id === grant.id);
    if (grantOperations.length !== 1 || grantAudits.length !== 1 || grantEntries.length !== 1
      || grantOperations[0].actor_owner_id !== grant.issued_by_owner_id || grantOperations[0].subject_owner_id !== grant.owner_id
      || grantAudits[0].actor_owner_id !== grant.issued_by_owner_id || grantAudits[0].subject_owner_id !== grant.owner_id
      || grantEntries[0].owner_id !== grant.owner_id || grantEntries[0].actor_owner_id !== grant.issued_by_owner_id
      || grantEntries[0].operation_id !== grant.operation_id || grantEntries[0].entry_type !== "bonus_grant"
      || grantEntries[0].source_kind !== "tester_bonus" || grantEntries[0].amount_units !== grant.amount_units
      || grantEntries[0].available_delta_units !== grant.amount_units || grantEntries[0].reserved_delta_units !== "0"
      || grantEntries[0].expired_delta_units !== "0") return false;
  }
  for (const entry of snapshot.entries.filter((row) => row.entry_type === "bonus_grant" && row.source_kind === "tester_bonus")) {
    if (!snapshot.grants.some((grant) => grant.id === entry.bonus_grant_id && grant.operation_id === entry.operation_id)) return false;
  }
  for (const redemption of snapshot.redemptions) {
    const existing = redemptionsByCode.get(redemption.code_id) ?? [];
    existing.push(redemption);
    redemptionsByCode.set(redemption.code_id, existing);
    const code = snapshot.codes.find((row) => row.id === redemption.code_id);
    if (!code) return false;
    const grants = snapshot.grants.filter((row) => row.id === redemption.bonus_grant_id);
    if (grants.length !== 1) return false;
    const grant = grants[0];
    const entries = snapshot.entries.filter((row) => row.bonus_grant_id === grant.id);
    const grantOperations = snapshot.operations.filter((row) => row.operation_id === redemption.financial_operation_id
      && row.action === "bonus_grant");
    const grantAudits = snapshot.audits.filter((row) => row.operation_id === redemption.financial_operation_id
      && row.event_type === "bonus_grant_issued" && row.metadata?.grantId === grant.id);
    const claimOperations = snapshot.claimOperations.filter((row) => row.redemption_id === redemption.id);
    const redemptionAudits = snapshot.audits.filter((row) => row.event_type === "bonus_code_redeemed"
      && row.metadata?.receiptId === redemption.id && row.metadata?.grantId === grant.id
      && row.metadata?.codeId === redemption.code_id);
    if (grant.owner_id !== redemption.owner_id || grant.issued_by_owner_id !== code.issuer_owner_id
      || grant.amount_units !== code.amount_units || grant.operation_id !== redemption.financial_operation_id
      || grant.reason !== "Bonus code redemption" || grant.expires_at !== null
      || entries.length !== 1 || entries[0].owner_id !== redemption.owner_id
      || entries[0].actor_owner_id !== code.issuer_owner_id || entries[0].operation_id !== redemption.financial_operation_id
      || entries[0].entry_type !== "bonus_grant" || entries[0].source_kind !== "tester_bonus"
      || entries[0].amount_units !== grant.amount_units || entries[0].available_delta_units !== grant.amount_units
      || entries[0].reserved_delta_units !== "0" || entries[0].expired_delta_units !== "0"
      || grantOperations.length !== 1 || grantOperations[0].actor_owner_id !== code.issuer_owner_id
      || grantOperations[0].subject_owner_id !== redemption.owner_id || grantAudits.length !== 1
      || claimOperations.length < 1 || claimOperations.some((row) => row.owner_id !== redemption.owner_id || row.code_id !== redemption.code_id)
      || redemptionAudits.length !== 1 || redemptionAudits[0].actor_owner_id !== redemption.owner_id
      || !claimOperations.some((row) => row.operation_id === redemptionAudits[0].operation_id)) return false;
  }
  return snapshot.codes.every((code) => code.used_count === (redemptionsByCode.get(code.id)?.length ?? 0));
}

async function issueThroughUi(page, capture, { label, kind = "group", amount = "0.250001", maximumUses = 3 }) {
  const captureApi = browserCaptureApi(capture);
  const browserCapture = captureApi.rows;
  const form = page.getByTestId("bonus-code-issue-form");
  await form.waitFor({ state: "visible" });
  await form.getByTestId("bonus-code-label").fill(label);
  await form.getByTestId("bonus-code-kind").selectOption(kind);
  await form.getByTestId("bonus-code-amount").fill(amount);
  if (kind === "group") await form.getByTestId("bonus-code-maximum").fill(String(maximumUses));
  const before = browserCapture.requests.length;
  const responsePromise = page.waitForResponse((response) => new URL(response.url()).pathname === ADMIN_CODES
    && response.request().method() === "POST", { timeout: 15000 });
  captureApi.action("click", "bonus-code-issue-submit");
  await form.getByTestId("bonus-code-issue-submit").click();
  const response = await responsePromise;
  const body = await response.json().catch(() => ({}));
  const operation = capturedOperation(browserCapture, ADMIN_CODES, "POST", before);
  assert(response.status() === 201 && typeof body?.code?.id === "string" && typeof body?.secret === "string",
    "Administrator UI did not issue a bonus code with a one-time plaintext value");
  assert(CODE_VALUE.test(body.secret), "Issued bonus code did not meet the high-entropy plaintext format");
  return {
    code: { id: body.code.id, label: body.code.label, kind: body.code.kind, amount: body.code.amount,
      maximumUses: body.code.maximumUses, usedCount: body.code.usedCount, issuedAt: body.code.issuedAt },
    secret: body.secret,
    outcome: safeActionOutcome(response, body),
    operationId: operation,
  };
}

async function redeemThroughUi(page, capture, code) {
  const captureApi = browserCaptureApi(capture);
  const browserCapture = captureApi.rows;
  await page.getByTestId("owner-bonus-codes").waitFor({ state: "visible" });
  const before = browserCapture.requests.length;
  await page.getByTestId("bonus-code-input").fill(code);
  const responsePromise = page.waitForResponse((response) => new URL(response.url()).pathname === OWNER_REDEEM
    && response.request().method() === "POST", { timeout: 15000 });
  captureApi.action("click", "bonus-code-redeem-submit");
  await page.getByTestId("bonus-code-redeem-submit").click();
  const response = await responsePromise;
  const body = await response.json().catch(() => ({}));
  const operation = capturedOperation(browserCapture, OWNER_REDEEM, "POST", before);
  return { outcome: safeActionOutcome(response, body), operationId: operation };
}

async function adminRequest(page, method, path, data) {
  return sameOriginApiRequest(page, method, path, data);
}

async function sameOriginApiRequest(page, method, path, data) {
  const result = await page.evaluate(async ({ requestMethod, requestPath, requestData }) => {
    const response = await fetch(requestPath, {
      method: requestMethod.toUpperCase(),
      credentials: "same-origin",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(requestData),
    });
    let body = {};
    try { body = await response.json(); } catch {}
    return { status: response.status, body };
  }, { requestMethod: method, requestPath: path, requestData: data });
  const response = { status: () => result.status };
  return { response, body: result.body, outcome: safeActionOutcome(response, result.body) };
}

async function disableThroughUi(page, capture, codeId) {
  const button = page.getByTestId(`bonus-code-disable-${codeId}`);
  await button.waitFor({ state: "visible" });
  const responsePromise = page.waitForResponse((response) => new URL(response.url()).pathname === `${ADMIN_CODES}/${codeId}/disable`
    && response.request().method() === "POST", { timeout: 15000 });
  browserCaptureApi(capture).action("click", `bonus-code-disable-${codeId}`);
  await button.click();
  const response = await responsePromise;
  const body = await response.json().catch(() => ({}));
  return { response, body, outcome: safeActionOutcome(response, body) };
}

async function readOwner(page) {
  const response = await page.request.get("/api/owner");
  const body = await response.json().catch(() => ({}));
  assert(response.status() === 200 && typeof body?.owner?.id === "string", "Authenticated owner identity is missing");
  return { id: body.owner.id, isAdmin: body.owner.isAdmin === true, admissionStatus: body.owner.admissionStatus };
}

async function readBilling(page, expectedBonus = null) {
  await page.getByTestId("billing-balances").waitFor({ state: "visible" });
  if (expectedBonus !== null) {
    await page.waitForFunction((expected) => {
      const value = document.querySelector('[data-testid="billing-bonus-available"]')?.textContent?.trim();
      return value === `${expected} USDC`;
    }, expectedBonus, { timeout: 15000 });
  }
  const readAmount = async (testId) => {
    const text = (await page.getByTestId(testId).innerText()).trim();
    const match = /^(0|[1-9][0-9]*)(?:\.([0-9]{6}))? USDC$/.exec(text);
    assert(match, `Owner billing UI value ${testId} was not an exact decimal USDC amount`);
    return `${match[1]}.${match[2] ?? "000000"}`;
  };
  return {
    cash: { available: await readAmount("billing-cash-available") },
    bonus: { available: await readAmount("billing-bonus-available") },
  };
}

function formatMicroUnits(value) {
  return `${value / 1_000_000n}.${(value % 1_000_000n).toString().padStart(6, "0")}`;
}

async function createAdmittedOwner({ adminPage, newContext, login, subject }) {
  const context = await newContext();
  const signedIn = await login(context, subject);
  assert(signedIn.owner.status === 200 && signedIn.owner.owner?.admissionStatus === "pending",
    "Fixture owner was not created as pending before admin admission");
  const invitationResponsePromise = adminPage.waitForResponse((response) => new URL(response.url()).pathname === "/api/admin/invitations"
    && response.request().method() === "POST", { timeout: 15000 });
  await adminPage.getByTestId("invite-create").click();
  const invitationResponse = await invitationResponsePromise;
  assert(invitationResponse.status() === 201, "Administrator could not issue the disposable admission invitation");
  let invitationValue = (await adminPage.getByTestId("invite-secret-once").locator("code").first().innerText()).trim();
  const activationResponsePromise = signedIn.page.waitForResponse((response) => new URL(response.url()).pathname === "/api/admission/activate"
    && response.request().method() === "POST", { timeout: 15000 });
  await signedIn.page.getByTestId("invitation-code").fill(invitationValue);
  signedIn.captureApi.action("click", "activate-owner");
  await signedIn.page.getByTestId("activate-owner").click();
  const activation = await activationResponsePromise;
  invitationValue = "";
  assert(activation.status() === 200, "Fixture owner could not activate through the real invitation form");
  await waitForPath(signedIn.page, ["/account"], 15000);
  const owner = await readOwner(signedIn.page);
  assert(owner.admissionStatus === "admitted", "Fixture owner did not reach admitted state");
  return { context, page: signedIn.page, owner, capture: signedIn.capture, captureApi: signedIn.captureApi };
}

function scenarioData(scenarioId, localObservations, negativeVariants, browserData, databaseData, blocker = null) {
  const values = [...Object.values(localObservations), ...Object.values(negativeVariants)];
  const localStatus = values.some((value) => value === false)
    ? "failed"
    : values.length > 0 && values.every((value) => value === true) ? "complete" : "partial";
  return {
    scenarioId,
    localStatus,
    localObservations,
    negativeVariants,
    browserData,
    databaseData,
    ...(blocker ? { blocker } : {}),
  };
}

export async function runBonusCodeCases({ adminPage, ownerPage, ownerId, newContext, publicOrigin,
  login, observerDatabaseUrl, databaseUrl, restartApi, rerunMigrations }) {
  const adminBrowser = attachSafeBrowserCapture(adminPage, "BPC-SC-003");
  await adminPage.goto(new URL("/admin/bonus-codes", publicOrigin).toString(), { waitUntil: "domcontentloaded" });
  await adminPage.getByTestId("bonus-code-issue-form").waitFor({ state: "visible", timeout: 15000 });
  await ownerPage.goto(new URL("/billing", publicOrigin).toString(), { waitUntil: "domcontentloaded" });
  await ownerPage.getByTestId("owner-bonus-codes").waitFor({ state: "visible", timeout: 15000 });
  const sc003OwnerBrowser = attachSafeBrowserCapture(ownerPage, "BPC-SC-003");
  const primaryOwner = await readOwner(ownerPage);
  assert(primaryOwner.id === ownerId && primaryOwner.admissionStatus === "admitted", "Bonus-code runner owner changed identity or admission state");

  await adminPage.goto(new URL("/admin", publicOrigin).toString(), { waitUntil: "domcontentloaded" });
  await adminPage.getByTestId("invite-create").waitFor({ state: "visible", timeout: 15000 });
  const invited = await createAdmittedOwner({
    adminPage, newContext, login: (context, subject) => login(context, "BPC-SC-006", subject),
    subject: `oid-bpc-owner-${randomUUID()}`,
  });
  await adminPage.goto(new URL("/admin/bonus-codes", publicOrigin).toString(), { waitUntil: "domcontentloaded" });
  await adminPage.getByTestId("bonus-code-issue-form").waitFor({ state: "visible", timeout: 15000 });
  const secondOwnerPage = invited.page;
  await secondOwnerPage.goto(new URL("/billing", publicOrigin).toString(), { waitUntil: "domcontentloaded" });
  await secondOwnerPage.getByTestId("owner-bonus-codes").waitFor({ state: "visible", timeout: 15000 });

  const sc003Start = adminBrowser.capture.requests.length;
  const groupIssue = await issueThroughUi(adminPage, adminBrowser, {
    label: "BPC local group offer", kind: "group", amount: "1.250001", maximumUses: 3,
  });
  const groupIssueAudit = capturedOperation(adminBrowser.capture, ADMIN_CODES, "POST", sc003Start);
  const firstListResponse = await adminPage.request.get(ADMIN_CODES);
  const firstList = await firstListResponse.json();
  const listHidesSecret = firstListResponse.status() === 200 && !JSON.stringify(firstList).includes(groupIssue.secret);
  const groupId = groupIssue.code.id;

  const invalidAmountBefore = adminBrowser.capture.requests.length;
  await adminPage.getByTestId("bonus-code-label").fill("BPC invalid precision");
  await adminPage.getByTestId("bonus-code-kind").selectOption("group");
  await adminPage.getByTestId("bonus-code-amount").fill("1.0000001");
  const invalidAmountResponsePromise = adminPage.waitForResponse((response) => new URL(response.url()).pathname === ADMIN_CODES
    && response.request().method() === "POST", { timeout: 15000 });
  adminBrowser.action("click", "bonus-code-issue-submit-invalid-precision");
  await adminPage.getByTestId("bonus-code-issue-submit").click();
  const invalidAmountResponse = await invalidAmountResponsePromise;
  const invalidAmountBody = await invalidAmountResponse.json().catch(() => ({}));
  const invalidAmountOperation = capturedOperation(adminBrowser.capture, ADMIN_CODES, "POST", invalidAmountBefore);

  const invalidMaximumOperation = operationId();
  const invalidMaximum = await adminRequest(adminPage, "post", ADMIN_CODES, {
    operationId: invalidMaximumOperation, label: "BPC invalid maximum", kind: "group", amount: "1.000000", maximumUses: 0,
  });
  const invalidKindOperation = operationId();
  const invalidKind = await adminRequest(adminPage, "post", ADMIN_CODES, {
    operationId: invalidKindOperation, label: "BPC invalid kind", kind: "unexpected", amount: "1.000000", maximumUses: 1,
  });
  const conflictIssueOperation = groupIssue.operationId;
  const conflictingIssue = await adminRequest(adminPage, "post", ADMIN_CODES, {
    operationId: conflictIssueOperation, label: "BPC local group offer", kind: "group", amount: "9.000000", maximumUses: 3,
  });
  const attemptedTermsEdit = await adminRequest(adminPage, "put", `${ADMIN_CODES}/${groupId}`, {
    label: "changed offer", kind: "group", amount: "9.000000", maximumUses: 9,
  });
  const unauthorizedIssueOperation = operationId();
  const unauthorizedIssue = await sameOriginApiRequest(ownerPage, "post", ADMIN_CODES, {
    operationId: unauthorizedIssueOperation, label: "BPC unauthorized", kind: "single_use", amount: "1.000000", maximumUses: 1,
  });

  await adminPage.getByTestId("bonus-code-amount").fill("0.500001");
  await adminPage.getByTestId("bonus-code-kind").selectOption("group");
  await adminPage.getByTestId("bonus-code-maximum").fill("2");
  await adminPage.getByTestId("bonus-code-label").fill("BPC lost issue response");
  const issuePath = `**${ADMIN_CODES}`;
  let lostIssueResponse = false;
  const lostIssueOutcomePromise = adminPage.waitForResponse((response) => new URL(response.url()).pathname === ADMIN_CODES
    && response.request().method() === "POST", { timeout: 15000 }).catch(() => null);
  await adminPage.route(issuePath, async (route) => {
    if (route.request().method() !== "POST" || lostIssueResponse) return route.continue();
    lostIssueResponse = true;
    await route.fetch();
    await route.abort("failed");
  });
  const lostIssueCaptureStart = adminBrowser.capture.requests.length;
  adminBrowser.action("click", "bonus-code-issue-submit-lost-response");
  await adminPage.getByTestId("bonus-code-issue-submit").click();
  const lostIssueUpstream = await lostIssueOutcomePromise;
  await adminPage.getByTestId("bonus-code-admin-status").filter({ hasText: "not confirmed" }).waitFor({ timeout: 15000 });
  const lostIssueOperation = capturedOperation(adminBrowser.capture, ADMIN_CODES, "POST", lostIssueCaptureStart);
  assert(lostIssueResponse && lostIssueOperation && lostIssueUpstream === null,
    "First issuance response was not lost after a committed browser request");
  await adminPage.unroute(issuePath);
  const issueApiRestarted = await restartApi();
  const retryIssueResponsePromise = adminPage.waitForResponse((response) => new URL(response.url()).pathname === ADMIN_CODES
    && response.request().method() === "POST", { timeout: 15000 });
  await adminPage.getByTestId("bonus-code-issue-retry").click();
  const retryIssueResponse = await retryIssueResponsePromise;
  const retryIssueBody = await retryIssueResponse.json().catch(() => ({}));
  await adminPage.getByTestId("bonus-code-admin-status").filter({ hasText: "plaintext was already delivered or lost" }).waitFor({ timeout: 15000 });
  const noSecretOnRetry = retryIssueResponse.status() === 200 && retryIssueBody?.replayed === true && retryIssueBody?.secret === null;
  const lostIssueId = retryIssueBody?.code?.id;
  const lostIssueListResponse = await adminPage.request.get(ADMIN_CODES);
  const lostIssueList = await lostIssueListResponse.json();
  const lostIssueListNoSecret = lostIssueResponse && !JSON.stringify(lostIssueList).includes("secret");
  const sc003Snapshot = await observerSnapshot(observerDatabaseUrl, {
    codeIds: [groupId, lostIssueId].filter(Boolean), ownerIds: [ownerId],
    issueOperationIds: [groupIssue.operationId, invalidAmountOperation, invalidMaximumOperation, invalidKindOperation,
      conflictIssueOperation, lostIssueOperation, unauthorizedIssueOperation],
    operationIds: [groupIssue.operationId, invalidAmountOperation, invalidMaximumOperation, invalidKindOperation,
      conflictIssueOperation, lostIssueOperation, unauthorizedIssueOperation],
  });
  const sc003Rows = sc003Snapshot.codes;
  const sc003OneCodePerOperation = sc003Rows.filter((row) => row.issue_operation_id === groupIssue.operationId).length === 1
    && groupIssue.operationId === groupIssueAudit
    && sc003Rows.filter((row) => row.issue_operation_id === lostIssueOperation).length === 1
    && sc003Rows.length === 2
    && [invalidAmountOperation, invalidMaximumOperation, invalidKindOperation, unauthorizedIssueOperation]
      .every((operation) => !sc003Rows.some((row) => row.issue_operation_id === operation));
  const sc003TermsExact = sc003Rows.find((row) => row.id === groupId)?.amount_units === "1250001"
    && sc003Rows.find((row) => row.id === groupId)?.maximum_uses === 3
    && sc003Rows.find((row) => row.id === groupId)?.kind === "group"
    && sc003Rows.find((row) => row.id === groupId)?.verifier_is_keyed_hash === true
    && sc003Rows.find((row) => row.id === lostIssueId)?.amount_units === "500001"
    && sc003Rows.find((row) => row.id === lostIssueId)?.maximum_uses === 2;
  const sc003Data = scenarioData("BPC-SC-003", {
    one_code_per_operation: sc003OneCodePerOperation,
    exact_immutable_terms: sc003TermsExact,
    one_time_secret: groupIssue.outcome.oneTimeValueReturned && groupIssue.outcome.oneTimeValueMatchesFormat
      && listHidesSecret && noSecretOnRetry && lostIssueListNoSecret,
    safe_issue_retry: noSecretOnRetry && lostIssueOperation === capturedOperation(adminBrowser.capture, ADMIN_CODES, "POST", lostIssueCaptureStart),
  }, {
    invalid_amount_precision: invalidAmountResponse.status() === 400 && invalidAmountBody?.error?.code === "INVALID_AMOUNT",
    invalid_maximum: invalidMaximum.response.status() === 400 && invalidMaximum.body?.error?.code === "INVALID_MAXIMUM",
    invalid_kind: invalidKind.response.status() === 400 && invalidKind.body?.error?.code === "INVALID_KIND",
    conflicting_retry: conflictingIssue.response.status() === 409 && conflictingIssue.body?.error?.code === "IDEMPOTENCY_CONFLICT",
    attempted_terms_edit: attemptedTermsEdit.response.status() === 409 && attemptedTermsEdit.body?.error?.code === "BONUS_CODE_TERMS_IMMUTABLE",
    unauthorized_issue: unauthorizedIssue.response.status() === 403,
    lost_first_response: lostIssueResponse && lostIssueOperation !== null && lostIssueUpstream === null && retryIssueResponse.status() === 200,
    restart: issueApiRestarted === true,
  }, {
    admin: projectCapture(adminBrowser.capture),
    owner: projectCapture(sc003OwnerBrowser.capture),
    outcomes: {
      groupIssue: { ...groupIssue.outcome, operationId: groupIssue.operationId },
      invalidAmount: { ...safeActionOutcome(invalidAmountResponse, invalidAmountBody), operationId: invalidAmountOperation },
      invalidMaximum: invalidMaximum.outcome,
      invalidKind: invalidKind.outcome,
      conflictingIssue: conflictingIssue.outcome,
      termsEdit: attemptedTermsEdit.outcome,
      unauthorizedIssue: unauthorizedIssue.outcome,
      firstResponseLost: lostIssueResponse && lostIssueUpstream === null,
      retryIssue: { ...safeActionOutcome(retryIssueResponse, retryIssueBody), operationId: lostIssueOperation },
      listExcludesFirstPlaintext: listHidesSecret,
      listExcludesLostPlaintext: lostIssueListNoSecret,
    },
  }, sc003Snapshot);

  const sc005AdminBrowser = attachSafeBrowserCapture(adminPage, "BPC-SC-005");
  const sc005Group = await issueThroughUi(adminPage, sc005AdminBrowser, {
    label: "BPC SC005 group training credit", kind: "group", amount: "2.125001", maximumUses: 5,
  });
  const sc005Single = await issueThroughUi(adminPage, sc005AdminBrowser, {
    label: "BPC SC005 single-owner credit", kind: "single_use", amount: "3.000007", maximumUses: 1,
  });
  const sc005OwnerBrowser = attachSafeBrowserCapture(ownerPage, "BPC-SC-005");
  const sc005SecondOwnerBrowser = attachSafeBrowserCapture(secondOwnerPage, "BPC-SC-005");
  const ownerBefore = await readBilling(ownerPage);
  const secondBefore = await readBilling(secondOwnerPage);
  const groupClaim = await redeemThroughUi(ownerPage, sc005OwnerBrowser, sc005Group.secret);
  const ownerReceipt = ownerPage.getByTestId("bonus-code-redemption-receipt");
  await ownerReceipt.waitFor({ state: "visible" });
  const ownerReceiptText = await ownerReceipt.innerText();
  const ownerReceiptExact = ownerReceiptText.includes("2.125001 bonus USDC")
    && ownerReceiptText.includes("BPC SC005 group training credit");
  const singleClaim = await redeemThroughUi(secondOwnerPage, sc005SecondOwnerBrowser, sc005Single.secret);
  const secondOwnerReceipt = secondOwnerPage.getByTestId("bonus-code-redemption-receipt");
  await secondOwnerReceipt.waitFor({ state: "visible" });
  const secondOwnerReceiptText = await secondOwnerReceipt.innerText();
  const secondOwnerReceiptExact = secondOwnerReceiptText.includes("3.000007 bonus USDC")
    && secondOwnerReceiptText.includes("BPC SC005 single-owner credit");
  const invalidCodeClaim = await redeemThroughUi(ownerPage, sc005OwnerBrowser, `BPC-${randomBytes(32).toString("base64url")}`);
  const exhaustedCodeClaim = await redeemThroughUi(ownerPage, sc005OwnerBrowser, sc005Single.secret);
  const sc005DisabledCode = await issueThroughUi(adminPage, sc005AdminBrowser, {
    label: "BPC SC005 disabled claim", kind: "single_use", amount: "0.200001", maximumUses: 1,
  });
  const sc005DisableResponsePromise = adminPage.waitForResponse((response) =>
    new URL(response.url()).pathname === `${ADMIN_CODES}/${sc005DisabledCode.code.id}/disable`
      && response.request().method() === "POST", { timeout: 15000 });
  sc005AdminBrowser.action("click", `bonus-code-disable-${sc005DisabledCode.code.id}`);
  await adminPage.getByTestId(`bonus-code-disable-${sc005DisabledCode.code.id}`).click();
  const sc005DisableResponse = await sc005DisableResponsePromise;
  const disabledCodeClaim = await redeemThroughUi(ownerPage, sc005OwnerBrowser, sc005DisabledCode.secret);
  const ownerExpectedBonusAfter = formatMicroUnits(BigInt(ownerBefore.bonus.available.replace(".", "")) + 2_125_001n);
  const secondExpectedBonusAfter = formatMicroUnits(BigInt(secondBefore.bonus.available.replace(".", "")) + 3_000_007n);
  const ownerAfter = await readBilling(ownerPage, ownerExpectedBonusAfter);
  const secondAfter = await readBilling(secondOwnerPage, secondExpectedBonusAfter);
  const sc005InitialSnapshot = await observerSnapshot(observerDatabaseUrl, {
    codeIds: [sc005Group.code.id, sc005Single.code.id, sc005DisabledCode.code.id], ownerIds: [ownerId, invited.owner.id],
    operationIds: [sc005Group.operationId, sc005Single.operationId, sc005DisabledCode.operationId,
      groupClaim.operationId, singleClaim.operationId, invalidCodeClaim.operationId,
      exhaustedCodeClaim.operationId, disabledCodeClaim.operationId].filter(Boolean),
  });
  const groupRedemption = sc005InitialSnapshot.redemptions.find((row) => row.code_id === sc005Group.code.id);
  const singleRedemption = sc005InitialSnapshot.redemptions.find((row) => row.code_id === sc005Single.code.id);
  const sc005GroupAndSingleExact = Boolean(groupRedemption && singleRedemption
    && groupRedemption.owner_id === ownerId && singleRedemption.owner_id === invited.owner.id
    && groupRedemption.bonus_grant_id !== singleRedemption.bonus_grant_id
    && sc005InitialSnapshot.grants.find((row) => row.id === groupRedemption.bonus_grant_id)?.amount_units === "2125001"
    && sc005InitialSnapshot.grants.find((row) => row.id === singleRedemption.bonus_grant_id)?.amount_units === "3000007"
    && sc005InitialSnapshot.grants.find((row) => row.id === groupRedemption.bonus_grant_id)?.expires_at === null
    && sc005InitialSnapshot.grants.find((row) => row.id === singleRedemption.bonus_grant_id)?.expires_at === null);
  const balanceRow = (id) => sc005InitialSnapshot.ownerBalances.find((row) => row.owner_id === id);
  const dbOwnerBonus = balanceRow(ownerId);
  const dbSecondBonus = balanceRow(invited.owner.id);
  const independentBalanceMatch = Boolean(dbOwnerBonus && dbSecondBonus
    && BigInt(dbOwnerBonus.bonus_available_units) === BigInt(ownerAfter.bonus.available.replace(".", ""))
    && BigInt(dbSecondBonus.bonus_available_units) === BigInt(secondAfter.bonus.available.replace(".", "")));
  const sc005Data = scenarioData("BPC-SC-005", {
    group_and_single_claim_exact: sc005GroupAndSingleExact && groupClaim.outcome.status === 200 && singleClaim.outcome.status === 200
      && ownerReceiptExact && secondOwnerReceiptExact && grantLedgerConserved(sc005InitialSnapshot),
    independent_bonus_balance_matches_ledger: independentBalanceMatch,
    code_lot_funds_training_and_full12: null,
    independent_balance_and_debit: null,
    no_cash_fallback: ownerBefore.cash.available === ownerAfter.cash.available
      && secondBefore.cash.available === secondAfter.cash.available && sc005InitialSnapshot.cashEffectCount === 0,
  }, {
    invalid_code: invalidCodeClaim.outcome.status === 404 && invalidCodeClaim.outcome.errorCode === "BONUS_CODE_INVALID",
    disabled_code: sc005DisableResponse.status() === 200 && disabledCodeClaim.outcome.status === 409
      && disabledCodeClaim.outcome.errorCode === "BONUS_CODE_DISABLED",
    exhausted_code: exhaustedCodeClaim.outcome.status === 409 && exhaustedCodeClaim.outcome.errorCode === "BONUS_CODE_EXHAUSTED",
    insufficient_bonus: null,
    missing_mode_permission: null,
    nominal_cap_exceeded: null,
    anonymous_or_agent_claim: null,
  }, {
    admin: projectCapture(sc005AdminBrowser.capture),
    owner: projectCapture(sc005OwnerBrowser.capture),
    secondOwner: projectCapture(sc005SecondOwnerBrowser.capture),
    owners: [{ id: ownerId, admissionStatus: primaryOwner.admissionStatus }, { id: invited.owner.id, admissionStatus: invited.owner.admissionStatus }],
    outcomes: {
      groupIssue: { ...sc005Group.outcome, operationId: sc005Group.operationId },
      singleIssue: { ...sc005Single.outcome, operationId: sc005Single.operationId },
      groupClaim: { ...groupClaim.outcome, operationId: groupClaim.operationId },
      singleClaim: { ...singleClaim.outcome, operationId: singleClaim.operationId },
      ownerReceiptExact,
      secondOwnerReceiptExact,
      invalidCode: invalidCodeClaim.outcome,
      disabledCode: disabledCodeClaim.outcome,
      exhaustedCode: exhaustedCodeClaim.outcome,
      ownerBalanceBefore: { cash: ownerBefore.cash, bonus: ownerBefore.bonus },
      ownerBalanceAfter: { cash: ownerAfter.cash, bonus: ownerAfter.bonus },
      secondBalanceBefore: { cash: secondBefore.cash, bonus: secondBefore.bonus },
      secondBalanceAfter: { cash: secondAfter.cash, bonus: secondAfter.bonus },
      independentBonusBalanceMatch: independentBalanceMatch,
      bonusSpendBoundary: { status: "not_run", reasonCode: "local_run_executor_not_configured_for_bpc_capture" },
    },
  }, sc005InitialSnapshot, "The local capture does not have an authorized training/full12 worker boundary.");

  const adminSc004 = attachSafeBrowserCapture(adminPage, "BPC-SC-004");
  const ownerSc004 = attachSafeBrowserCapture(ownerPage, "BPC-SC-004");
  const secondOwnerSc004 = attachSafeBrowserCapture(secondOwnerPage, "BPC-SC-004");
  const disableFirstCode = await issueThroughUi(adminPage, adminSc004, {
    label: "BPC disable before claim", kind: "single_use", amount: "0.100001", maximumUses: 1,
  });
  const disableFirstButton = adminPage.getByTestId(`bonus-code-disable-${disableFirstCode.code.id}`);
  const disableFirstResponsePromise = adminPage.waitForResponse((response) => new URL(response.url()).pathname === `${ADMIN_CODES}/${disableFirstCode.code.id}/disable`
    && response.request().method() === "POST", { timeout: 15000 });
  adminSc004.action("click", `bonus-code-disable-${disableFirstCode.code.id}`);
  await disableFirstButton.click();
  const disableFirstResponse = await disableFirstResponsePromise;
  const disableFirstBody = await disableFirstResponse.json().catch(() => ({}));
  const disableFirstClaim = await redeemThroughUi(ownerPage, ownerSc004, disableFirstCode.secret);
  const secondForeignDisable = await sameOriginApiRequest(ownerPage, "post", `${ADMIN_CODES}/${disableFirstCode.code.id}/disable`, { operationId: operationId() });

  const claimFirstCode = await issueThroughUi(adminPage, adminSc004, {
    label: "BPC claim before disable", kind: "single_use", amount: "0.100002", maximumUses: 1,
  });
  const claimFirst = await redeemThroughUi(ownerPage, ownerSc004, claimFirstCode.secret);
  const claimFirstDisable = await disableThroughUi(adminPage, adminSc004, claimFirstCode.code.id);
  const claimFirstReplay = claimFirst.operationId ? await sameOriginApiRequest(ownerPage, "post", OWNER_REDEEM, {
    operationId: claimFirst.operationId, code: claimFirstCode.secret,
  }) : null;
  const claimFirstReplayOutcome = claimFirstReplay?.outcome ?? null;
  const claimAfterDisableNewKey = await redeemThroughUi(ownerPage, ownerSc004, claimFirstCode.secret);
  const claimAfterDisableSameReceipt = sameRedemptionReceipt(claimFirst.outcome, claimAfterDisableNewKey.outcome);
  const newOwnerDisabledClaim = await redeemThroughUi(secondOwnerPage, secondOwnerSc004, claimFirstCode.secret);

  const raceCode = await issueThroughUi(adminPage, adminSc004, {
    label: "BPC disable redemption serialization", kind: "single_use", amount: "0.100003", maximumUses: 1,
  });
  await ownerPage.getByTestId("bonus-code-input").fill(raceCode.secret);
  const raceDisableResponsePromise = adminPage.waitForResponse((response) => new URL(response.url()).pathname === `${ADMIN_CODES}/${raceCode.code.id}/disable`
    && response.request().method() === "POST", { timeout: 15000 });
  const raceClaimResponsePromise = ownerPage.waitForResponse((response) => new URL(response.url()).pathname === OWNER_REDEEM
    && response.request().method() === "POST", { timeout: 15000 });
  adminSc004.action("click", `bonus-code-disable-${raceCode.code.id}`);
  ownerSc004.action("click", "bonus-code-redeem-submit-racing-disable");
  const [raceDisableResponse, raceClaimResponse] = await Promise.all([
    adminPage.getByTestId(`bonus-code-disable-${raceCode.code.id}`).click().then(() => raceDisableResponsePromise),
    ownerPage.getByTestId("bonus-code-redeem-submit").click().then(() => raceClaimResponsePromise),
  ]);
  const raceDisableBody = await raceDisableResponse.json().catch(() => ({}));
  const raceClaimBody = await raceClaimResponse.json().catch(() => ({}));
  const raceClaimOutcome = safeActionOutcome(raceClaimResponse, raceClaimBody);

  const retryDisableCode = await issueThroughUi(adminPage, adminSc004, {
    label: "BPC disable lost response", kind: "single_use", amount: "0.100004", maximumUses: 1,
  });
  const disablePath = `**${ADMIN_CODES}/${retryDisableCode.code.id}/disable`;
  let lostDisableResponse = false;
  await adminPage.route(disablePath, async (route) => {
    if (route.request().method() !== "POST" || lostDisableResponse) return route.continue();
    lostDisableResponse = true;
    await route.fetch();
    await route.abort("failed");
  });
  const lostDisableResponsePromise = adminPage.waitForResponse((response) => new URL(response.url()).pathname === `${ADMIN_CODES}/${retryDisableCode.code.id}/disable`
    && response.request().method() === "POST", { timeout: 15000 }).catch(() => null);
  const disableRetryButton = adminPage.getByTestId(`bonus-code-disable-${retryDisableCode.code.id}`);
  adminSc004.action("click", `bonus-code-disable-${retryDisableCode.code.id}`);
  await disableRetryButton.click();
  const lostDisableBrowserResponse = await lostDisableResponsePromise;
  await adminPage.getByTestId("bonus-code-admin-status").filter({ hasText: "not confirmed" }).waitFor({ timeout: 15000 });
  const lostDisableOperation = capturedOperation(adminSc004.capture, `${ADMIN_CODES}/${retryDisableCode.code.id}/disable`);
  assert(lostDisableResponse && lostDisableOperation && lostDisableBrowserResponse === null,
    "Disable response was not lost after a committed browser request");
  await adminPage.unroute(disablePath);
  const disableApiRestarted = await restartApi();
  const retriedDisableResponsePromise = adminPage.waitForResponse((response) => new URL(response.url()).pathname === `${ADMIN_CODES}/${retryDisableCode.code.id}/disable`
    && response.request().method() === "POST", { timeout: 15000 });
  await adminPage.getByTestId(`bonus-code-disable-${retryDisableCode.code.id}`).click();
  const retriedDisableResponse = await retriedDisableResponsePromise;
  const retriedDisableBody = await retriedDisableResponse.json().catch(() => ({}));
  const sameDisableOperationRetried = capturedOperation(adminSc004.capture, `${ADMIN_CODES}/${retryDisableCode.code.id}/disable`, "POST") === lostDisableOperation;

  const sc004CodeIds = [disableFirstCode.code.id, claimFirstCode.code.id, raceCode.code.id, retryDisableCode.code.id];
  const sc004OperationIds = [disableFirstCode.operationId, disableFirstClaim.operationId, claimFirstCode.operationId,
    claimFirst.operationId, claimFirstDisable.outcome.operationId, claimAfterDisableNewKey.operationId,
    newOwnerDisabledClaim.operationId, lostDisableOperation].filter(Boolean);
  const sc004Snapshot = await observerSnapshot(observerDatabaseUrl, { codeIds: sc004CodeIds, ownerIds: [ownerId], operationIds: sc004OperationIds });
  const raceRedemption = sc004Snapshot.redemptions.find((row) => row.code_id === raceCode.code.id);
  const raceCodeRow = sc004Snapshot.codes.find((row) => row.id === raceCode.code.id);
  const raceSerialized = Boolean(raceCodeRow && raceCodeRow.disabled_at
    && raceCodeRow.used_count === (raceRedemption ? 1 : 0)
    && (raceRedemption ? new Date(raceRedemption.created_at) < new Date(raceCodeRow.disabled_at) : raceClaimOutcome.status === 409));
  const usageExact = sc004Snapshot.codes.every((row) => row.used_count === sc004Snapshot.redemptions.filter((redemption) => redemption.code_id === row.id).length);
  const sc004OldGrantsPreserved = [claimFirstCode.code.id, raceCode.code.id].every((id) => {
    const redemptions = sc004Snapshot.redemptions.filter((row) => row.code_id === id);
    return redemptions.every((redemption) => sc004Snapshot.grants.some((grant) => grant.id === redemption.bonus_grant_id));
  });
  const claimFirstRedemptions = sc004Snapshot.redemptions.filter((row) => row.code_id === claimFirstCode.code.id);
  const claimFirstOperations = sc004Snapshot.claimOperations.filter((row) => row.code_id === claimFirstCode.code.id
    && row.owner_id === ownerId);
  const noExtraEffectsAfterDisable = claimFirstRedemptions.length === 1
    && claimFirstOperations.length === 2
    && claimFirstOperations.every((row) => row.redemption_id === claimFirstRedemptions[0].id)
    && new Set(claimFirstOperations.map((row) => row.operation_id)).size === 2;
  const sc004Data = scenarioData("BPC-SC-004", {
    disable_claim_order_serialized: raceSerialized,
    usage_exact: usageExact && [disableFirstCode.code.id, claimFirstCode.code.id, raceCode.code.id, retryDisableCode.code.id].every((id) => sc004Snapshot.codes.some((row) => row.id === id)),
    old_grants_preserved: sc004OldGrantsPreserved && noExtraEffectsAfterDisable,
    unauthorized_disable_denied: secondForeignDisable.response.status() === 403,
  }, {
    disable_before_claim: disableFirstResponse.status() === 200
      && hasCodeError(disableFirstClaim.outcome, 409, "BONUS_CODE_DISABLED")
      && hasCodeError(newOwnerDisabledClaim.outcome, 409, "BONUS_CODE_DISABLED"),
    claim_before_disable: claimFirst.outcome.status === 200 && claimFirstDisable.response.status() === 200
      && sameRedemptionReceipt(claimFirst.outcome, claimFirstReplayOutcome)
      && claimAfterDisableNewKey.operationId !== claimFirst.operationId
      && claimAfterDisableSameReceipt,
    concurrent_disable_retry: lostDisableResponse && retriedDisableResponse.status() === 200
      && disableApiRestarted === true && lostDisableBrowserResponse === null
      && retriedDisableBody?.replayed === true && sameDisableOperationRetried,
    foreign_disable: secondForeignDisable.response.status() === 403,
  }, {
    admin: projectCapture(adminSc004.capture),
    owner: projectCapture(ownerSc004.capture),
    secondOwner: projectCapture(secondOwnerSc004.capture),
    outcomes: {
      disableBeforeClaim: safeActionOutcome(disableFirstResponse, disableFirstBody),
      claimAfterDisable: disableFirstClaim.outcome,
      claimBeforeDisable: claimFirst.outcome,
      disableAfterClaim: claimFirstDisable.outcome,
      claimReplay: claimFirstReplayOutcome,
      sameOwnerNewKeyAfterDisable: claimAfterDisableNewKey.outcome,
      sameOwnerNewKeySameReceipt: claimAfterDisableSameReceipt,
      newOwnerClaimAfterDisable: newOwnerDisabledClaim.outcome,
      noExtraEffectsAfterDisable,
      concurrentRace: {
        disable: safeActionOutcome(raceDisableResponse, raceDisableBody),
        claim: raceClaimOutcome,
      },
      foreignDisable: secondForeignDisable.outcome,
      lostDisable: { intercepted: lostDisableResponse, retry: safeActionOutcome(retriedDisableResponse, retriedDisableBody), operationId: lostDisableOperation },
    },
  }, sc004Snapshot);

  const sc006OwnerBrowser = attachSafeBrowserCapture(ownerPage, "BPC-SC-006");
  const sc006SecondOwnerBrowser = attachSafeBrowserCapture(secondOwnerPage, "BPC-SC-006");
  const sc006AdminBrowser = attachSafeBrowserCapture(adminPage, "BPC-SC-006");
  const lastUseCode = await issueThroughUi(adminPage, sc006AdminBrowser, {
    label: "BPC last-use owner race", kind: "single_use", amount: "0.300001", maximumUses: 1,
  });
  const lastUseOutcomes = await Promise.all([
    redeemThroughUi(ownerPage, sc006OwnerBrowser, lastUseCode.secret),
    redeemThroughUi(secondOwnerPage, sc006SecondOwnerBrowser, lastUseCode.secret),
  ]);

  const groupAliasCode = await issueThroughUi(adminPage, sc006AdminBrowser, {
    label: "BPC same-owner alias", kind: "group", amount: "0.300002", maximumUses: 4,
  });
  const aliasPage = await ownerPage.context().newPage();
  const aliasBrowser = attachSafeBrowserCapture(aliasPage, "BPC-SC-006");
  await aliasPage.goto(new URL("/billing", publicOrigin).toString(), { waitUntil: "domcontentloaded" });
  await aliasPage.getByTestId("owner-bonus-codes").waitFor({ state: "visible", timeout: 15000 });
  await ownerPage.getByTestId("bonus-code-input").fill(groupAliasCode.secret);
  await aliasPage.getByTestId("bonus-code-input").fill(groupAliasCode.secret);
  const aliasAResponsePromise = ownerPage.waitForResponse((response) => new URL(response.url()).pathname === OWNER_REDEEM && response.request().method() === "POST", { timeout: 15000 });
  const aliasBResponsePromise = aliasPage.waitForResponse((response) => new URL(response.url()).pathname === OWNER_REDEEM && response.request().method() === "POST", { timeout: 15000 });
  const [aliasAResponse, aliasBResponse] = await Promise.all([
    ownerPage.getByTestId("bonus-code-redeem-submit").click().then(() => aliasAResponsePromise),
    aliasPage.getByTestId("bonus-code-redeem-submit").click().then(() => aliasBResponsePromise),
  ]);
  const aliasABody = await aliasAResponse.json().catch(() => ({}));
  const aliasBBody = await aliasBResponse.json().catch(() => ({}));
  const aliasAOperation = capturedOperation(sc006OwnerBrowser.capture, OWNER_REDEEM);
  const aliasBOperation = capturedOperation(aliasBrowser.capture, OWNER_REDEEM);

  const crossCodeA = await issueThroughUi(adminPage, sc006AdminBrowser, {
    label: "BPC cross-code operation A", kind: "group", amount: "0.300003", maximumUses: 4,
  });
  const crossCodeB = await issueThroughUi(adminPage, sc006AdminBrowser, {
    label: "BPC cross-code operation B", kind: "group", amount: "0.300004", maximumUses: 4,
  });
  const crossCodeKey = operationId();
  const crossCodeResults = await ownerPage.evaluate(async ({ path, operationIdValue, codeA, codeB }) => {
    const submit = async (code) => {
      const response = await fetch(path, { method: "POST", credentials: "same-origin",
        headers: { "content-type": "application/json" }, body: JSON.stringify({ operationId: operationIdValue, code }) });
      let body = {};
      try { body = await response.json(); } catch {}
      return { status: response.status, errorCode: body?.error?.code ?? null, replayed: body?.replayed === true };
    };
    return Promise.all([submit(codeA), submit(codeB)]);
  }, { path: OWNER_REDEEM, operationIdValue: crossCodeKey, codeA: crossCodeA.secret, codeB: crossCodeB.secret });

  const rollbackCode = await issueThroughUi(adminPage, sc006AdminBrowser, {
    label: "BPC atomic rollback", kind: "group", amount: "0.300005", maximumUses: 3,
  });
  const triggerFunction = "bpc_acceptance_fail_redemption";
  const triggerName = "bpc_acceptance_fail_redemption_trg";
  const rollbackGrantOperation = bonusGrantOperationId(rollbackCode.code.id, ownerId);
  let rollbackDurableBeforeRetry = false;
  let rollbackClaimOperation = null;
  const dbClient = new pg.Client({ connectionString: databaseUrl, application_name: "bpc-acceptance-test-failpoint" });
  await dbClient.connect();
  try {
    await dbClient.query(`CREATE OR REPLACE FUNCTION ${triggerFunction}() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN RAISE EXCEPTION 'test-owned bonus redemption rollback probe' USING ERRCODE='P0001'; END $$`);
    await dbClient.query(`CREATE TRIGGER ${triggerName} BEFORE INSERT ON oid_bonus_code_redemption FOR EACH ROW EXECUTE FUNCTION ${triggerFunction}()`);
    const failedClaim = await redeemThroughUi(ownerPage, sc006OwnerBrowser, rollbackCode.secret);
    assert(failedClaim.outcome.status >= 500, "Test-owned database failpoint did not fail the redemption transaction");
    const rollbackOperation = failedClaim.operationId;
    rollbackClaimOperation = rollbackOperation;
    await ownerPage.getByTestId("bonus-code-redemption-status").filter({ hasText: "not confirmed" }).waitFor({ timeout: 15000 });
    const failedSnapshot = await observerSnapshot(observerDatabaseUrl, {
      codeIds: [rollbackCode.code.id], ownerIds: [ownerId], operationIds: [rollbackOperation].filter(Boolean),
      grantOperationIds: [rollbackGrantOperation],
    });
    const rollbackDurable = failedSnapshot.codes.find((row) => row.id === rollbackCode.code.id)?.used_count === 0
      && failedSnapshot.redemptions.length === 0 && failedSnapshot.grants.length === 0
      && failedSnapshot.entries.length === 0 && failedSnapshot.claimOperations.length === 0
      && !failedSnapshot.operations.some((row) => row.operation_id === rollbackGrantOperation)
      && !failedSnapshot.audits.some((row) => row.operation_id === rollbackGrantOperation
        || row.event_type === "bonus_code_redeemed")
      && failedSnapshot.cashEffectCount === 0;
    rollbackDurableBeforeRetry = rollbackDurable;
    await dbClient.query(`DROP TRIGGER ${triggerName} ON oid_bonus_code_redemption`);
    await dbClient.query(`DROP FUNCTION ${triggerFunction}()`);
    const retryRollbackResponsePromise = ownerPage.waitForResponse((response) => new URL(response.url()).pathname === OWNER_REDEEM
      && response.request().method() === "POST", { timeout: 15000 });
    await ownerPage.getByTestId("bonus-code-redeem-retry").click();
    const retryRollbackResponse = await retryRollbackResponsePromise;
    const retryRollbackBody = await retryRollbackResponse.json().catch(() => ({}));
    assert(rollbackDurable && retryRollbackResponse.status() === 200 && failedClaim.operationId === capturedOperation(sc006OwnerBrowser.capture, OWNER_REDEEM),
      "Failed redemption did not roll back all ledger effects or same-key retry did not recover");
  } finally {
    await dbClient.query(`DROP TRIGGER IF EXISTS ${triggerName} ON oid_bonus_code_redemption`).catch(() => undefined);
    await dbClient.query(`DROP FUNCTION IF EXISTS ${triggerFunction}()`).catch(() => undefined);
    await dbClient.end();
  }

  const lostClaimCode = await issueThroughUi(adminPage, sc006AdminBrowser, {
    label: "BPC lost claim response", kind: "group", amount: "0.300006", maximumUses: 3,
  });
  const claimPath = `**${OWNER_REDEEM}`;
  let lostClaimResponse = false;
  await ownerPage.route(claimPath, async (route) => {
    if (route.request().method() !== "POST" || lostClaimResponse) return route.continue();
    lostClaimResponse = true;
    await route.fetch();
    await route.abort("failed");
  });
  const lostClaimResponsePromise = ownerPage.waitForResponse((response) => new URL(response.url()).pathname === OWNER_REDEEM
    && response.request().method() === "POST", { timeout: 15000 }).catch(() => null);
  await ownerPage.getByTestId("bonus-code-input").fill(lostClaimCode.secret);
  await ownerPage.getByTestId("bonus-code-redeem-submit").click();
  await ownerPage.getByTestId("bonus-code-redemption-status").filter({ hasText: "not confirmed" }).waitFor({ timeout: 15000 });
  const lostClaimOperation = capturedOperation(sc006OwnerBrowser.capture, OWNER_REDEEM);
  const lostClaimBrowserResponse = await lostClaimResponsePromise;
  assert(lostClaimResponse && lostClaimOperation && lostClaimBrowserResponse === null,
    "Redemption response was not lost after a committed browser request");
  await ownerPage.unroute(claimPath);
  const claimApiRestarted = await restartApi();
  const retryLostClaimResponsePromise = ownerPage.waitForResponse((response) => new URL(response.url()).pathname === OWNER_REDEEM
    && response.request().method() === "POST", { timeout: 15000 });
  await ownerPage.getByTestId("bonus-code-redeem-retry").click();
  const retryLostClaimResponse = await retryLostClaimResponsePromise;
  const retryLostClaimBody = await retryLostClaimResponse.json().catch(() => ({}));
  const conflictingPayload = await sameOriginApiRequest(ownerPage, "post", OWNER_REDEEM, {
    operationId: lostClaimOperation, code: crossCodeA.secret,
  });
  const conflictingPayloadBody = conflictingPayload.body;

  const collisionCode = await issueThroughUi(adminPage, sc006AdminBrowser, {
    label: "BPC deterministic operation namespace collision", kind: "group", amount: "0.300007", maximumUses: 2,
  });
  const collisionOperation = bonusGrantOperationId(collisionCode.code.id, ownerId);
  const collisionGrant = await adminRequest(adminPage, "post", "/api/admin/bonus-grants", {
    operationId: collisionOperation, ownerId, amount: collisionCode.code.amount, reason: "Bonus code redemption",
  });
  const collisionClaim = await redeemThroughUi(ownerPage, sc006OwnerBrowser, collisionCode.secret);

  const exhaustedCode = await issueThroughUi(adminPage, sc006AdminBrowser, {
    label: "BPC exhausted single use", kind: "single_use", amount: "0.300008", maximumUses: 1,
  });
  const exhaustedFirst = await redeemThroughUi(secondOwnerPage, sc006SecondOwnerBrowser, exhaustedCode.secret);
  const exhaustedSecond = await redeemThroughUi(ownerPage, sc006OwnerBrowser, exhaustedCode.secret);
  const exhaustedWinnerReplay = await redeemThroughUi(secondOwnerPage, sc006SecondOwnerBrowser, exhaustedCode.secret);
  const exhaustedWinnerSameReceipt = sameRedemptionReceipt(exhaustedFirst.outcome, exhaustedWinnerReplay.outcome);

  const sc006CodeIds = [lastUseCode.code.id, groupAliasCode.code.id, crossCodeA.code.id, crossCodeB.code.id,
    rollbackCode.code.id, lostClaimCode.code.id, collisionCode.code.id, exhaustedCode.code.id];
  const crossGrantKeyA = bonusGrantOperationId(crossCodeA.code.id, ownerId);
  const crossGrantKeyB = bonusGrantOperationId(crossCodeB.code.id, ownerId);
  const sc006GrantOperationIds = [...new Set([
    bonusGrantOperationId(lastUseCode.code.id, ownerId), bonusGrantOperationId(lastUseCode.code.id, invited.owner.id),
    bonusGrantOperationId(groupAliasCode.code.id, ownerId), crossGrantKeyA, crossGrantKeyB,
    rollbackGrantOperation, bonusGrantOperationId(lostClaimCode.code.id, ownerId),
    collisionOperation, bonusGrantOperationId(exhaustedCode.code.id, ownerId),
    bonusGrantOperationId(exhaustedCode.code.id, invited.owner.id),
  ])];
  const sc006OperationIds = [lastUseOutcomes[0].operationId, lastUseOutcomes[1].operationId, aliasAOperation, aliasBOperation,
    crossCodeKey, rollbackClaimOperation, lostClaimOperation, collisionOperation, exhaustedFirst.operationId,
    exhaustedSecond.operationId, exhaustedWinnerReplay.operationId].filter(Boolean);
  const sc006Snapshot = await observerSnapshot(observerDatabaseUrl, {
    codeIds: sc006CodeIds, ownerIds: [ownerId, invited.owner.id], operationIds: sc006OperationIds,
    grantOperationIds: sc006GrantOperationIds,
  });
  const lastUseRows = sc006Snapshot.redemptions.filter((row) => row.code_id === lastUseCode.code.id);
  const lastUseCountsExact = sc006Snapshot.codes.find((row) => row.id === lastUseCode.code.id)?.used_count === 1
    && lastUseRows.length === 1 && lastUseRows[0].owner_id === [ownerId, invited.owner.id].find((id) => id === lastUseRows[0].owner_id)
    && lastUseOutcomes.filter((row) => row.outcome.status === 200).length === 1;
  const aliasRows = sc006Snapshot.redemptions.filter((row) => row.code_id === groupAliasCode.code.id);
  const aliasOperations = sc006Snapshot.claimOperations.filter((row) => row.code_id === groupAliasCode.code.id && row.owner_id === ownerId);
  const oneClaimPerOwner = aliasRows.length === 1 && aliasOperations.length === 2
    && aliasOperations[0]?.redemption_id === aliasOperations[1]?.redemption_id;
  const exhaustedRedemptions = sc006Snapshot.redemptions.filter((row) => row.code_id === exhaustedCode.code.id);
  const exhaustedClaimOperations = sc006Snapshot.claimOperations.filter((row) => row.code_id === exhaustedCode.code.id
    && row.owner_id === invited.owner.id);
  const exhaustedReplayNoExtraEffects = exhaustedRedemptions.length === 1 && exhaustedClaimOperations.length === 2
    && exhaustedClaimOperations.every((row) => row.redemption_id === exhaustedRedemptions[0].id)
    && new Set(exhaustedClaimOperations.map((row) => row.operation_id)).size === 2;
  const crossCodeConflict = crossCodeResults.filter((row) => row.status === 409 && row.errorCode === "IDEMPOTENCY_CONFLICT").length === 1
    && crossCodeResults.filter((row) => row.status === 200).length === 1;
  const rollbackFinal = sc006Snapshot.codes.find((row) => row.id === rollbackCode.code.id)?.used_count === 1
    && sc006Snapshot.redemptions.filter((row) => row.code_id === rollbackCode.code.id).length === 1
    && sc006Snapshot.grants.filter((row) => row.operation_id === bonusGrantOperationId(rollbackCode.code.id, ownerId)).length === 1;
  const lostOriginalReceipt = retryLostClaimResponse.status() === 200 && retryLostClaimBody?.replayed === true
    && retryLostClaimBody?.redemption?.id === sc006Snapshot.redemptions.find((row) => row.code_id === lostClaimCode.code.id)?.id;
  const collisionNoCapacity = collisionGrant.response.status() === 200 && collisionClaim.outcome.status === 409
    && collisionClaim.outcome.errorCode === "BONUS_CODE_GRANT_OPERATION_COLLISION"
    && sc006Snapshot.codes.find((row) => row.id === collisionCode.code.id)?.used_count === 0
    && !sc006Snapshot.redemptions.some((row) => row.code_id === collisionCode.code.id);
  const sc006Data = scenarioData("BPC-SC-006", {
    last_use_one_winner: lastUseCountsExact,
    one_claim_per_owner: oneClaimPerOwner,
    counter_grant_atomic: rollbackFinal && grantLedgerConserved(sc006Snapshot, { allowedStandaloneGrantOperations: [collisionOperation] }),
    original_receipt_recovered: lostOriginalReceipt && Boolean(lostClaimOperation),
  }, {
    different_owner_last_use: lastUseOutcomes.filter((row) => row.outcome.status === 409 && ["BONUS_CODE_EXHAUSTED", "BONUS_CODE_DISABLED"].includes(row.outcome.errorCode)).length === 1,
    same_owner_different_keys: oneClaimPerOwner && exhaustedWinnerSameReceipt
      && exhaustedWinnerReplay.operationId !== exhaustedFirst.operationId && exhaustedReplayNoExtraEffects,
    transaction_failure: rollbackDurableBeforeRetry && rollbackClaimOperation !== null && rollbackFinal,
    response_lost_after_commit: lostClaimResponse && lostClaimOperation !== null
      && lostClaimBrowserResponse === null && lostOriginalReceipt,
    restart: claimApiRestarted === true,
    conflicting_payload: conflictingPayload.response.status() === 409 && conflictingPayloadBody?.error?.code === "IDEMPOTENCY_CONFLICT",
  }, {
    admin: projectCapture(sc006AdminBrowser.capture),
    owner: projectCapture(sc006OwnerBrowser.capture),
    secondOwner: projectCapture(sc006SecondOwnerBrowser.capture),
    sameOwnerSecondTab: projectCapture(aliasBrowser.capture),
    outcomes: {
      differentOwnerLastUse: lastUseOutcomes.map((row) => row.outcome),
      sameOwnerDifferentKeys: [safeActionOutcome(aliasAResponse, aliasABody), safeActionOutcome(aliasBResponse, aliasBBody)],
      sameOwnerOperationIds: [aliasAOperation, aliasBOperation],
      crossCodeSameOperation: crossCodeResults,
      failpoint: { transactionFailed: true, durableRollbackVerifiedBeforeRetry: true, sameOperationRetryStatus: 200 },
      lostClaim: { responseIntercepted: lostClaimResponse, browserResponseLost: lostClaimBrowserResponse === null,
        retry: safeActionOutcome(retryLostClaimResponse, retryLostClaimBody), operationId: lostClaimOperation },
      conflictingPayload: conflictingPayload.outcome,
      grantOperationCollision: { grantIssued: collisionGrant.response.status() === 200, claim: collisionClaim.outcome },
      exhaustedUse: { first: exhaustedFirst.outcome, secondOwnerNewClaim: exhaustedSecond.outcome,
        sameOwnerNewKeyReplay: exhaustedWinnerReplay.outcome, sameOwnerSameReceipt: exhaustedWinnerSameReceipt },
    },
  }, sc006Snapshot);

  sc005Data.browserData.outcomes.disabledAndExhausted = {
    disabledClaim: disabledCodeClaim.outcome,
    exhaustedClaim: exhaustedCodeClaim.outcome,
  };
  const sc005Snapshot = await observerSnapshot(observerDatabaseUrl, {
    codeIds: [sc005Group.code.id, sc005Single.code.id, sc005DisabledCode.code.id],
    ownerIds: [ownerId, invited.owner.id],
    operationIds: [sc005Group.operationId, sc005Single.operationId, groupClaim.operationId, singleClaim.operationId,
      sc005DisabledCode.operationId, invalidCodeClaim.operationId, exhaustedCodeClaim.operationId,
      disabledCodeClaim.operationId].filter(Boolean),
  });
  sc005Data.databaseData = sc005Snapshot;

  const preservationSnapshots = [sc003Snapshot, sc004Snapshot, sc005Snapshot, sc006Snapshot];
  const migrationRefs = {
    codeIds: [...new Set(preservationSnapshots.flatMap((snapshot) => snapshot.codes.map((row) => row.id)))],
    ownerIds: [ownerId, invited.owner.id],
    operationIds: [...new Set(preservationSnapshots.flatMap((snapshot) => [
      ...snapshot.codes.flatMap((row) => [row.issue_operation_id, row.disable_operation_id].filter(Boolean)),
      ...snapshot.claimOperations.map((row) => row.operation_id),
    ]))],
    grantOperationIds: [...new Set([
      ...preservationSnapshots.flatMap((snapshot) => snapshot.redemptions.map((row) => row.financial_operation_id)),
      collisionOperation,
    ])],
  };
  let migrationPreservation = { status: "not_run", reasonCode: "migration_replay_callback_unavailable" };
  if (typeof rerunMigrations === "function") {
    const before = await observerSnapshot(observerDatabaseUrl, migrationRefs);
    await rerunMigrations();
    const after = await observerSnapshot(observerDatabaseUrl, migrationRefs);
    const preserved = JSON.stringify(before) === JSON.stringify(after);
    migrationPreservation = {
      status: preserved ? "observed" : "failed",
      operation: "additive_migration_rerun_after_existing_ledger_rows",
      before,
      after,
    };
  }

  const actualLocalBoundary = {
    profile: "local_docker_google_oauth_fixture",
    publicOrigin,
    externalGoogleUsed: false,
    externalTargetHost: false,
    browser: "Playwright Chromium through owner web UI and same-origin Fastify API",
    durableObserverRole: sc006Snapshot.observer.role,
    durableObserverReadOnly: sc006Snapshot.observer.transaction_read_only === "on",
  };
  const result = {
    scenarioData: { "BPC-SC-003": sc003Data, "BPC-SC-004": sc004Data, "BPC-SC-005": sc005Data, "BPC-SC-006": sc006Data },
    localBoundary: actualLocalBoundary,
    migrationPreservation,
    sourceSecretNotReturnedOnReplay: noSecretOnRetry,
  };
  await aliasPage.close();
  await invited.context.close();
  return result;
}

/** Issue and redeem one worker-funding code through the real admin and owner pages. */
export async function issueAndRedeemBonusCodeForWorker({ adminPage, ownerPage, adminCapture, ownerCapture,
  ownerId, observerDatabaseUrl, label, amount, amountUnits }) {
  assert(typeof amount === "string" && typeof amountUnits === "string" && /^\d+$/.test(amountUnits),
    "Worker bonus-code funding amount is invalid");
  await adminPage.goto("/admin/bonus-codes", { waitUntil: "domcontentloaded" });
  const issued = await issueThroughUi(adminPage, adminCapture, {
    label, kind: "single_use", amount, maximumUses: 1,
  });
  await ownerPage.goto("/billing", { waitUntil: "domcontentloaded" });
  const claimed = await redeemThroughUi(ownerPage, ownerCapture, issued.secret);
  issued.secret = "";
  const grantOperation = bonusGrantOperationId(issued.code.id, ownerId);
  const snapshot = await observerSnapshot(observerDatabaseUrl, {
    codeIds: [issued.code.id],
    issueOperationIds: [issued.operationId],
    ownerIds: [ownerId],
    operationIds: [claimed.operationId].filter(Boolean),
    grantOperationIds: [grantOperation],
  });
  const code = snapshot.codes.find((row) => row.id === issued.code.id);
  const redemption = snapshot.redemptions.find((row) => row.code_id === issued.code.id && row.owner_id === ownerId);
  const grant = snapshot.grants.find((row) => row.operation_id === grantOperation);
  const grantEntry = grant && snapshot.entries.find((row) => row.bonus_grant_id === grant.id);
  const ownerBalance = snapshot.ownerBalances.find((row) => row.owner_id === ownerId);
  const balanceField = Object.keys(ownerBalance ?? {}).find((key) => /bonus.*available|available.*bonus/i.test(key));
  const cashBalanceField = Object.keys(ownerBalance ?? {}).find((key) => /cash.*available|available.*cash/i.test(key));
  const exactStartingBalance = Boolean(ownerBalance && balanceField
    && BigInt(ownerBalance[balanceField]) === BigInt(amountUnits));
  const exactLocalLot = snapshot.observer.role === "oid_observer"
    && snapshot.observer.transaction_read_only === "on"
    && code?.kind === "single_use" && code.maximum_uses === 1 && code.used_count === 1
    && code.verifier_is_keyed_hash === true
    && redemption?.id === claimed.outcome.redemptionId && redemption.bonus_grant_id === claimed.outcome.grantId
    && redemption.financial_operation_id === grantOperation
    && grant?.owner_id === ownerId && grant.issued_by_owner_id === code.issuer_owner_id
    && grant.amount_units === amountUnits && grant.reason === "Bonus code redemption" && grant.expires_at === null
    && grantEntry?.source_kind === "tester_bonus" && grantEntry.available_delta_units === amountUnits
    && exactStartingBalance && grantLedgerConserved(snapshot);
  assert(issued.outcome.status === 201 && issued.outcome.oneTimeValueReturned && issued.outcome.oneTimeValueMatchesFormat
    && claimed.outcome.status === 200 && claimed.outcome.grantId && exactLocalLot,
  "Worker funding code was not issued/redeemed through the browser and independently conserved in PostgreSQL");
  return {
    issue: { status: issued.outcome.status, operationId: issued.operationId,
      codeId: issued.code.id, kind: issued.code.kind, maximumUses: issued.code.maximumUses,
      oneTimeValueReturned: issued.outcome.oneTimeValueReturned },
    redemption: { ...claimed.outcome, operationId: claimed.operationId },
    grantId: grant.id,
    grantOperationId: grantOperation,
    amountUnits,
    database: {
      observer: snapshot.observer,
      code,
      redemption,
      grant,
      grantEntry,
      ownerBalance,
      exactStartingBalance,
      cashAvailableUnits: cashBalanceField ? ownerBalance[cashBalanceField] : null,
      ledgerConserved: true,
      cashEffectCount: snapshot.cashEffectCount,
      ownerBalances: snapshot.ownerBalances,
    },
  };
}
