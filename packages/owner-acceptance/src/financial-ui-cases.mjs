import { randomUUID } from "node:crypto";
import pg from "pg";
import { assertSecretFree } from "./evidence.mjs";
import { attachSafeBrowserCapture } from "./browser-support.mjs";
import { createCard } from "./credential-cases.mjs";

const { Pool } = pg;
const CATEGORY_LIMITS = {
  benchmark: "3.250001",
  forum: "1.000007",
};
const UPDATED_POLICY = {
  allowCashShortfall: true,
  operationLimit: "2.125000",
  utcDayLimit: "9.500000",
  categoryLimits: CATEGORY_LIMITS,
};

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function decimalUnits(value) {
  if (typeof value !== "string") throw new Error("Expected an exact decimal string");
  const match = /^(0|[1-9][0-9]*)(?:\.([0-9]{1,6}))?$/.exec(value);
  if (!match) throw new Error("Expected a nonnegative decimal with at most six fractional digits");
  return BigInt(match[1]) * 1_000_000n + BigInt((match[2] ?? "").padEnd(6, "0") || "0");
}

function formatTimestamp(value) {
  if (!value) return "No expiry";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return `${new Intl.DateTimeFormat("en", {
    dateStyle: "medium",
    timeStyle: "medium",
    timeZone: "UTC",
  }).format(date)} UTC`;
}

function displayLabel(value) {
  return value.replace(/[_-]+/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function amountFromDisplay(value) {
  const match = /^\s*([0-9]+(?:\.[0-9]+)?)\s+USDC\s*$/.exec(value);
  if (!match) throw new Error("Owner billing UI did not render an exact USDC amount");
  return match[1];
}

async function compareMoney(page, testId, expected) {
  const displayed = amountFromDisplay(await page.getByTestId(testId).innerText());
  assert(decimalUnits(displayed) === decimalUnits(expected), `Visible ${testId} does not match the prior owner billing projection`);
  return displayed;
}

async function visibleGrantRows(page, expectedGrants) {
  if (!expectedGrants.length) {
    assert(await page.getByTestId("billing-grants-empty").isVisible(), "The empty grant state is not visible");
    return [];
  }

  const table = page.getByTestId("billing-grants");
  await table.waitFor({ state: "visible" });
  const rows = await page.locator('tr[data-testid^="billing-grant-"]').all();
  assert(rows.length === expectedGrants.length, "The owner billing page did not show every grant from the prior owner projection");
  const expectedById = new Map(expectedGrants.map((grant) => [grant.id, grant]));
  const actual = [];

  for (const row of rows) {
    const cells = (await row.locator("td").allInnerTexts()).map((value) => value.trim());
    assert(cells.length === 9, "The owner billing grant row has an unexpected shape");
    const [id, createdAt, amountText, availableText, reservedText, expiredText, expiresAt, status, reason] = cells;
    const expected = expectedById.get(id);
    assert(expected, "The owner billing page showed a grant absent from the prior owner projection");
    const observed = {
      id,
      createdAt,
      amount: amountFromDisplay(amountText),
      available: amountFromDisplay(availableText),
      reserved: amountFromDisplay(reservedText),
      expired: amountFromDisplay(expiredText),
      expiresAt,
      status,
      reason,
    };
    assert(decimalUnits(observed.amount) === decimalUnits(expected.amount), `Grant ${id} amount differs from the owner projection`);
    assert(decimalUnits(observed.available) === decimalUnits(expected.available), `Grant ${id} available units differ from the owner projection`);
    assert(decimalUnits(observed.reserved) === decimalUnits(expected.reserved), `Grant ${id} reserved units differ from the owner projection`);
    assert(decimalUnits(observed.expired) === decimalUnits(expected.expired), `Grant ${id} expired units differ from the owner projection`);
    assert(observed.createdAt === formatTimestamp(expected.createdAt), `Grant ${id} creation time differs from the owner projection`);
    assert(observed.expiresAt === formatTimestamp(expected.expiresAt), `Grant ${id} expiry differs from the owner projection`);
    assert(observed.status === displayLabel(expected.status), `Grant ${id} status differs from the owner projection`);
    assert(observed.reason === expected.reason, `Grant ${id} reason differs from the owner projection`);
    actual.push(observed);
  }
  return actual;
}

async function readPolicyUi(page, agentId) {
  const form = page.getByTestId(`financial-policy-form-${agentId}`);
  await form.waitFor({ state: "visible" });
  const cap = async (name) => ({
    amount: await page.getByTestId(`financial-policy-${name}-limit-${agentId}`).inputValue(),
    unlimited: await page.getByTestId(`financial-policy-${name}-unlimited-${agentId}`).isChecked(),
  });
  return {
    allowCashShortfall: await page.getByTestId(`financial-policy-cash-${agentId}`).isChecked(),
    operationLimit: await cap("operation"),
    utcDayLimit: await cap("utc-day"),
    benchmarkLimit: await cap("benchmark"),
    forumLimit: await cap("forum"),
  };
}

function assertDefaultPolicy(policy) {
  assert(policy.allowCashShortfall === false, "A new agent's cash shortfall permission is not off by default");
  for (const name of ["operationLimit", "utcDayLimit", "benchmarkLimit", "forumLimit"]) {
    assert(policy[name].amount === "0.000000" && policy[name].unlimited === false,
      `A new agent's ${name} is not a zero cap by default`);
  }
}

function assertUpdatedUiPolicy(policy) {
  assert(policy.allowCashShortfall === UPDATED_POLICY.allowCashShortfall, "The saved cash shortfall switch did not persist in the UI");
  const expected = {
    operationLimit: UPDATED_POLICY.operationLimit,
    utcDayLimit: UPDATED_POLICY.utcDayLimit,
    benchmarkLimit: UPDATED_POLICY.categoryLimits.benchmark,
    forumLimit: UPDATED_POLICY.categoryLimits.forum,
  };
  for (const [name, amount] of Object.entries(expected)) {
    assert(policy[name].amount === amount && policy[name].unlimited === false,
      `The saved ${name} did not persist in the UI`);
  }
}

async function readFinancialPolicyEvidence(observerDatabaseUrl, ownerId, agentId, operationId) {
  const pool = new Pool({
    connectionString: observerDatabaseUrl,
    max: 1,
    application_name: "tbb-financial-policy-readonly-observer",
  });
  const client = await pool.connect();
  try {
    await client.query("BEGIN READ ONLY");
    const identity = await client.query(
      "SELECT current_user AS role, current_setting('transaction_read_only') AS transaction_read_only",
    );
    const observer = identity.rows[0];
    assert(observer?.role === "oid_observer" && observer.transaction_read_only === "on",
      "Financial policy inspection did not use independent read-only oid_observer access");

    const policyResult = await client.query(
      `SELECT owner_id::text, agent_id::text, revision, allow_cash_shortfall,
              operation_limit_units::text, utc_day_limit_units::text, category_limits, updated_at
       FROM oid_agent_financial_policy
       WHERE owner_id=$1::uuid AND agent_id=$2::uuid`, [ownerId, agentId],
    );
    const operationResult = await client.query(
      `SELECT id::text, actor_owner_id::text, subject_owner_id::text, operation_id,
              action, payload_hash, response_json, created_at
       FROM oid_ledger_operation
       WHERE actor_owner_id=$1::uuid AND operation_id=$2
       ORDER BY created_at,id`, [ownerId, operationId],
    );
    const auditResult = await client.query(
      `SELECT id::text, event_type, operation_id, actor_owner_id::text,
              subject_owner_id::text, metadata, created_at
       FROM oid_ledger_audit
       WHERE actor_owner_id=$1::uuid AND operation_id=$2
         AND event_type='agent_financial_policy_updated'
       ORDER BY created_at,id`, [ownerId, operationId],
    );
    await client.query("COMMIT");

    assert(policyResult.rows.length === 1, "The independent observer did not find exactly one persisted agent financial policy");
    assert(operationResult.rows.length === 1, "The independent observer did not find exactly one correlated policy operation receipt");
    assert(auditResult.rows.length === 1, "The independent observer did not find exactly one correlated financial policy audit");
    const policy = policyResult.rows[0];
    const operation = operationResult.rows[0];
    const audit = auditResult.rows[0];
    const response = typeof operation.response_json === "string"
      ? JSON.parse(operation.response_json)
      : operation.response_json;
    const categoryLimits = policy.category_limits;
    assert(policy.owner_id === ownerId && policy.agent_id === agentId, "Persisted policy ownership does not match the browser action");
    assert(policy.revision === 1 && policy.allow_cash_shortfall === true, "Persisted policy revision or cash permission is incorrect");
    assert(BigInt(policy.operation_limit_units) === decimalUnits(UPDATED_POLICY.operationLimit), "Persisted operation cap differs from the exact six-decimal request");
    assert(BigInt(policy.utc_day_limit_units) === decimalUnits(UPDATED_POLICY.utcDayLimit), "Persisted UTC-day cap differs from the exact six-decimal request");
    assert(isObject(categoryLimits)
      && decimalUnits(categoryLimits.benchmark) === decimalUnits(UPDATED_POLICY.categoryLimits.benchmark)
      && decimalUnits(categoryLimits.forum) === decimalUnits(UPDATED_POLICY.categoryLimits.forum),
    "Persisted category caps differ from the exact six-decimal request");
    assert(operation.action === "agent_financial_policy_update"
      && operation.actor_owner_id === ownerId && operation.subject_owner_id === ownerId
      && operation.operation_id === operationId && /^[0-9a-f]{64}$/.test(operation.payload_hash),
    "Correlated policy operation receipt has an unexpected identity or action");
    assert(isObject(response) && response.revision === 1 && response.allowCashShortfall === true
      && decimalUnits(response.operationLimit) === decimalUnits(UPDATED_POLICY.operationLimit)
      && decimalUnits(response.utcDayLimit) === decimalUnits(UPDATED_POLICY.utcDayLimit)
      && decimalUnits(response.categoryLimits?.benchmark) === decimalUnits(UPDATED_POLICY.categoryLimits.benchmark)
      && decimalUnits(response.categoryLimits?.forum) === decimalUnits(UPDATED_POLICY.categoryLimits.forum),
    "Stored operation receipt does not preserve the saved policy response");
    assert(audit.event_type === "agent_financial_policy_updated"
      && audit.actor_owner_id === ownerId && audit.subject_owner_id === ownerId
      && audit.operation_id === operationId && audit.metadata?.agentId === agentId
      && audit.metadata?.revision === 1 && audit.metadata?.allowCashShortfall === true,
    "Correlated policy audit does not identify the saved owner, agent and revision");
    assert(decimalUnits(audit.metadata?.operationLimit) === decimalUnits(UPDATED_POLICY.operationLimit)
      && decimalUnits(audit.metadata?.utcDayLimit) === decimalUnits(UPDATED_POLICY.utcDayLimit)
      && decimalUnits(audit.metadata?.categoryLimits?.benchmark) === decimalUnits(UPDATED_POLICY.categoryLimits.benchmark)
      && decimalUnits(audit.metadata?.categoryLimits?.forum) === decimalUnits(UPDATED_POLICY.categoryLimits.forum),
    "Correlated policy audit does not preserve the exact six-decimal limits");

    return {
      observer: { role: observer.role, transactionReadOnly: observer.transaction_read_only },
      policy,
      operationReceipt: operation,
      audit,
      correlatedRows: true,
    };
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
    await pool.end();
  }
}

export async function runFinancialUiCases({ page, ownerId, observerDatabaseUrl, billingData }) {
  assert(page && typeof ownerId === "string" && ownerId.length > 0 && observerDatabaseUrl,
    "Financial UI acceptance requires an authenticated owner page, owner ID and read-only observer URL");
  const ownerView = billingData?.browserData?.["TBB-SC-001"]?.ownerView;
  assert(isObject(ownerView) && isObject(ownerView.cash) && isObject(ownerView.bonus) && Array.isArray(ownerView.grants),
    "Financial UI acceptance requires the TBB-SC-001 owner billing projection");

  const ownerResponse = await page.request.get("/api/owner");
  const ownerBody = await ownerResponse.json().catch(() => ({}));
  assert(ownerResponse.status() === 200 && ownerBody?.owner?.id === ownerId
    && ownerBody.owner.admissionStatus === "admitted",
  "Financial UI browser session does not match the declared admitted owner");

  const capture = attachSafeBrowserCapture(page, "TBB-SC-013");
  capture.action("navigate", "/billing");
  await page.goto("/billing", { waitUntil: "domcontentloaded" });
  await page.getByTestId("billing-balances").waitFor({ state: "visible" });
  const balances = {
    cashAvailable: await compareMoney(page, "billing-cash-available", ownerView.cash.available),
    cashReserved: await compareMoney(page, "billing-cash-reserved", ownerView.cash.reserved),
    bonusAvailable: await compareMoney(page, "billing-bonus-available", ownerView.bonus.available),
    bonusReserved: await compareMoney(page, "billing-bonus-reserved", ownerView.bonus.reserved),
    bonusExpired: await compareMoney(page, "billing-bonus-expired", ownerView.bonus.expired),
  };
  const grants = await visibleGrantRows(page, ownerView.grants);

  capture.action("navigate", "/agents");
  await page.goto("/agents", { waitUntil: "domcontentloaded" });
  await page.getByTestId("agent-create-form").waitFor({ state: "visible" });
  const agent = await createCard(page, `Financial UI acceptance ${randomUUID().slice(0, 8)}`, capture);
  const endpoint = `/api/owner/agents/${encodeURIComponent(agent.id)}/financial-policy`;
  const initialPolicyUi = await readPolicyUi(page, agent.id);
  assertDefaultPolicy(initialPolicyUi);

  await page.getByTestId(`financial-policy-cash-${agent.id}`).check();
  await page.getByTestId(`financial-policy-operation-limit-${agent.id}`).fill(UPDATED_POLICY.operationLimit);
  await page.getByTestId(`financial-policy-utc-day-limit-${agent.id}`).fill(UPDATED_POLICY.utcDayLimit);
  await page.getByTestId(`financial-policy-benchmark-limit-${agent.id}`).fill(UPDATED_POLICY.categoryLimits.benchmark);
  await page.getByTestId(`financial-policy-forum-limit-${agent.id}`).fill(UPDATED_POLICY.categoryLimits.forum);
  const saveResponsePromise = page.waitForResponse((response) =>
    new URL(response.url()).pathname === endpoint && response.request().method() === "PUT", { timeout: 15000 },
  );
  capture.action("click", `financial-policy-save-${agent.id}`);
  await page.getByTestId(`financial-policy-save-${agent.id}`).click();
  const saveResponse = await saveResponsePromise;
  const request = saveResponse.request().postDataJSON();
  const response = await saveResponse.json().catch(() => ({}));
  assert(saveResponse.status() === 200 && request?.expectedRevision === 0
    && typeof request.operationId === "string" && /^[A-Za-z0-9_-]{12,128}$/.test(request.operationId),
  "Owner UI did not save the financial policy with a valid revision and operation identity");
  assert(request.allowCashShortfall === UPDATED_POLICY.allowCashShortfall
    && decimalUnits(request.operationLimit) === decimalUnits(UPDATED_POLICY.operationLimit)
    && decimalUnits(request.utcDayLimit) === decimalUnits(UPDATED_POLICY.utcDayLimit)
    && decimalUnits(request.categoryLimits?.benchmark) === decimalUnits(UPDATED_POLICY.categoryLimits.benchmark)
    && decimalUnits(request.categoryLimits?.forum) === decimalUnits(UPDATED_POLICY.categoryLimits.forum),
  "Owner UI submitted different financial policy values than the reviewed controls");
  assert(response?.revision === 1 && response.allowCashShortfall === true,
    "Owner UI did not receive the committed financial policy response");
  await page.waitForFunction((agentId) => {
    const status = document.querySelector(`[data-testid="financial-policy-status-${agentId}"]`);
    const text = status?.textContent ?? "";
    return text.includes("saved") && text.includes("revision 1");
  }, agent.id, { timeout: 15000 });
  const saveStatus = await page.getByTestId(`financial-policy-status-${agent.id}`).innerText();
  assert(saveStatus.includes("saved") && saveStatus.includes("revision 1"), "Owner UI did not confirm the saved policy revision");

  capture.action("reload", "/agents");
  await page.reload({ waitUntil: "domcontentloaded" });
  await page.getByTestId(`agent-card-${agent.id}`).waitFor({ state: "visible" });
  const persistedPolicyUi = await readPolicyUi(page, agent.id);
  assertUpdatedUiPolicy(persistedPolicyUi);

  const databaseData = await readFinancialPolicyEvidence(observerDatabaseUrl, ownerId, agent.id, request.operationId);
  const browserData = {
    scope: "partial TBB-SC-013 owner billing display and financial policy persistence only",
    ownerId,
    billing: {
      route: "/billing",
      sourceProjection: "TBB-SC-001 ownerView",
      balances,
      visibleGrantCount: grants.length,
      visibleGrantRows: grants,
      comparedAllGrantRows: grants.length === ownerView.grants.length,
    },
    financialPolicy: {
      agentId: agent.id,
      cardCreationOperationId: agent.operationId,
      initialPolicyUi,
      save: {
        status: saveResponse.status(),
        operationId: request.operationId,
        expectedRevision: request.expectedRevision,
        submittedPolicy: UPDATED_POLICY,
        responseRevision: response.revision,
        confirmationText: saveStatus,
      },
      reloadedPolicyUi: persistedPolicyUi,
    },
    browserCapture: capture.capture,
  };
  assertSecretFree(browserData, "TBB-SC-013 partial financial browser observation");
  assertSecretFree(databaseData, "TBB-SC-013 partial financial database observation");
  return { browserData, databaseData };
}
