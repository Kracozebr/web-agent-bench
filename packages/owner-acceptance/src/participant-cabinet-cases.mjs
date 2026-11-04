import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { relative, resolve, isAbsolute } from "node:path";
import pg from "pg";
import { waitForHistoryRefreshRender } from "./participant-history-render.mjs";
import { assertSecretFree } from "./evidence.mjs";

const hash = (value) => createHash("sha256").update(typeof value === "string" || Buffer.isBuffer(value) ? value : JSON.stringify(value)).digest("hex");
const resources = {
  runs: { path: "/api/owner/runs", section: "owner-runs", item: "owner-run-", older: "owner-runs-older" },
  intents: { path: "/api/owner/runs/intents", section: "run-intents", item: "run-intent-", older: "run-intents-older" },
  grants: { path: "/api/owner/billing/grants", section: "billing-grants", item: "billing-grant-", older: "billing-grants-older" },
  history: { path: "/api/owner/billing/history", section: "billing-history", item: "billing-history-entry-", older: "billing-history-older" },
};

async function responseRecord(response) {
  const body = await response.json().catch(() => null);
  return { status: response.status(), requestId: response.headers()["x-request-id"] ?? null,
    cacheControl: response.headers()["cache-control"] ?? null, body };
}

/** Independent observer. No query in this module has business-write authority. */
async function snapshot(pool, ownerId) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ, READ ONLY");
    const observer = (await client.query("SELECT current_user AS role,current_database() AS database,current_setting('transaction_read_only') AS read_only")).rows[0];
    assert.equal(observer.role, "oid_observer"); assert.equal(observer.read_only, "on");
    assert.match(observer.database, /^oid_acceptance_[a-f0-9]{32}$/);
    const queries = {
      runs: "SELECT id::text,owner_id::text,agent_id::text,intent_id::text,mode,task_ids,status,quote_price_units::text,queued_at FROM oid_benchmark_run WHERE owner_id=$1 ORDER BY queued_at DESC,id DESC",
      intents: "SELECT id::text,owner_id::text,agent_id::text,run_id::text,mode,task_ids,status,quote_price_units::text,cash_ceiling_units::text,created_at FROM oid_run_launch_intent WHERE owner_id=$1 ORDER BY created_at DESC,id DESC",
      grants: "SELECT id::text,owner_id::text,amount_units::text,created_at FROM oid_bonus_grant WHERE owner_id=$1 ORDER BY created_at DESC,id DESC",
      history: "SELECT id::text,owner_id::text,bonus_grant_id::text,entry_type,source_kind,amount_units::text,available_delta_units::text,reserved_delta_units::text,expired_delta_units::text,created_at FROM oid_ledger_entry WHERE owner_id=$1 ORDER BY created_at DESC,id DESC",
      reports: "SELECT id::text,owner_id::text,operation_id,run_id::text,task_id,action_id::text,client_version,safe_context,status,revision FROM oid_support_report WHERE owner_id=$1 ORDER BY created_at,id",
      reportAudits: "SELECT a.id::text,r.owner_id::text,a.report_id::text,a.event_type,a.previous_status,a.next_status,a.revision FROM oid_support_report_audit a JOIN oid_support_report r ON r.id=a.report_id WHERE r.owner_id=$1 ORDER BY a.created_at,a.id",
      images: "SELECT id::text,owner_id::text,report_id::text,status,expected_sha256,expected_input_bytes,input_mime,output_sha256,output_mime,output_bytes,width,height FROM oid_support_image_upload WHERE owner_id=$1 ORDER BY created_at,id",
    };
    const result = { observer };
    for (const [name, query] of Object.entries(queries)) result[name] = (await client.query(query, [ownerId])).rows;
    await client.query("COMMIT");
    return JSON.parse(JSON.stringify(result));
  } catch (failure) { await client.query("ROLLBACK").catch(() => {}); throw failure; }
  finally { client.release(); }
}

async function trainingRows(pool, runId, ownerId) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN READ ONLY");
    const run = (await client.query("SELECT id::text,owner_id::text,mode,status FROM oid_benchmark_run WHERE id=$1 AND owner_id=$2", [runId, ownerId])).rows;
    const evaluations = (await client.query("SELECT task_index,task_id,input_hash,result_hash,result_json FROM oid_run_task_evaluation WHERE run_id=$1 ORDER BY task_index", [runId])).rows;
    const tasks = (await client.query("SELECT task_index,task_id,status,closure_status FROM oid_run_task WHERE run_id=$1 ORDER BY task_index", [runId])).rows;
    const actions = (await client.query("SELECT a.id::text,a.task_index,a.action_sequence::text,a.action_kind,r.receipt_status,r.evidence_hash FROM oid_run_task_action a JOIN oid_run_task_action_receipt r ON r.action_id=a.id WHERE a.run_id=$1 AND a.owner_id=$2 ORDER BY a.task_index,a.action_sequence", [runId, ownerId])).rows;
    await client.query("COMMIT"); return JSON.parse(JSON.stringify({ run, tasks, evaluations, actions }));
  } catch (failure) { await client.query("ROLLBACK").catch(() => {}); throw failure; }
  finally { client.release(); }
}

async function browserHistory(page, kind, onFirstPage) {
  const resource = resources[kind];
  const pages = [];
  const collect = async (response) => {
    if (response.request().method() === "GET" && new URL(response.url()).pathname === resource.path && response.ok()) {
      const record = await responseRecord(response);
      pages.push({ status: record.status, query: Object.fromEntries(new URL(response.url()).searchParams), records: record.body[kind], nextCursor: record.body.nextCursor });
    }
  };
  const pending = new Set();
  const listener = (response) => { const promise = collect(response); pending.add(promise); void promise.finally(() => pending.delete(promise)); };
  page.on("response", listener);
  try {
    await page.goto(kind === "runs" || kind === "intents" ? "/runs" : "/billing", { waitUntil: "networkidle" });
    await page.locator(`[data-testid="${resource.section}"], [data-testid="${resource.section}-empty"]`).first().waitFor();
    await Promise.all([...pending]);
    const initial = await page.getByTestId(resource.section).locator(kind === "runs" || kind === "intents" ? ":scope > article" : "tbody > tr").count();
    if (onFirstPage) await onFirstPage(kind);
    let clicks = 0;
    while (await page.getByTestId(resource.older).count()) {
      assert.ok(clicks++ < 100, "Bounded PCU history traversal exceeded 100 pages");
      const response = page.waitForResponse((row) => new URL(row.url()).pathname === resource.path && row.request().method() === "GET");
      await page.getByTestId(resource.older).click(); await response; await page.waitForLoadState("networkidle"); await Promise.all([...pending]);
    }
    const renderedIds = await page.getByTestId(resource.section).locator(kind === "runs" || kind === "intents" ? ":scope > article" : "tbody > tr").evaluateAll((items, prefix) => items.map((item) => item.getAttribute("data-testid")?.slice(prefix.length)), resource.item);
    const expansion = kind === "runs" ? page.locator('[data-testid^="owner-run-details-"]').first() : kind === "intents" ? page.locator('[data-testid^="run-intent-details-"]').first() : page.getByTestId(resource.section).locator("details").first();
    let expanded = false;
    if (await expansion.count()) { await expansion.locator("summary").click(); expanded = await expansion.getAttribute("open") !== null; }
    const traversedPages = pages.slice();
    let refreshedFirstIds = null;
    if (onFirstPage) {
      const response = page.waitForResponse((row) => new URL(row.url()).pathname === resource.path && row.request().method() === "GET");
      await page.getByTestId(kind === "runs" || kind === "intents" ? "run-intents-refresh" : "billing-refresh").click();
      const refreshed = await responseRecord(await response);
      assert.equal(refreshed.status, 200, "History refresh failed");
      // AICODE-NOTE: HTTP arrival and document networkidle do not prove a React commit after the shared refresh Promise.all.
      refreshedFirstIds = await waitForHistoryRefreshRender(page, resource, kind, refreshed.body[kind]);
      await Promise.all([...pending]);
    }
    return { initial, clicks, pages: traversedPages, renderedIds, expanded, refreshedFirstIds };
  } finally { page.off("response", listener); await Promise.all([...pending]); }
}

async function deny(page, path, options = {}) {
  return responseRecord(await page.request.get(path, options));
}

/** Real controls initiate business actions. Setup and adversarial HTTP calls remain labelled. */
export async function runParticipantCabinetCases(input) {
  const { ownerPage: page, adminPage, foreignOwnerPage = adminPage, ownerId, observerDatabaseUrl, repoRoot,
    training, ranked, nativeConnectionCaptureRef = null, supplementalEvidenceRefs = {} } = input;
  assert.ok(page && adminPage && training?.runId && training?.agentId && observerDatabaseUrl);
  const captureRoot = resolve(input.captureRoot ?? repoRoot, input.captureRoot ? "." : `artifacts/pcu/${input.captureId ?? randomUUID()}`);
  const relativeRoot = relative(repoRoot, captureRoot);
  assert.ok(!isAbsolute(relativeRoot) && !relativeRoot.startsWith(".."), "PCU capture root must be repository-scoped");
  await mkdir(captureRoot, { recursive: true });
  const pool = new pg.Pool({ connectionString: observerDatabaseUrl, max: 1, application_name: "pcu-independent-readonly-observer" });
  const capture = { schemaVersion: "pcu-browser-boundary-capture/v1", ownerId, trainingSource: training.sourceCaptureRef ?? null,
    trainingHistory: training.historyRef ?? null,
    provenance: input.provenance ?? null, nativeConnectionCaptureRef, supplementalEvidenceRefs, cases: {}, startedAt: new Date().toISOString() };
  try {
    capture.phase = "history";
    capture.before = await snapshot(pool, ownerId);
    const histories = {};
    for (const kind of Object.keys(resources)) {
      const expected = (await snapshot(pool, ownerId))[kind];
      let concurrent = null;
      const onFirstPage = input.onHistoryFirstPage ? async (resource) => {
        await input.onHistoryFirstPage(resource); concurrent = (await snapshot(pool, ownerId))[resource];
      } : null;
      histories[kind] = { ...await browserHistory(page, kind, onFirstPage), expected, concurrent };
    }
    const cursorDenials = {};
    for (const [kind, resource] of Object.entries(resources)) {
      const cursor = histories[kind].pages[0]?.nextCursor;
      if (cursor) cursorDenials[kind] = await deny(foreignOwnerPage, `${resource.path}?limit=5&cursor=${encodeURIComponent(cursor)}`);
    }
    let emptyHistory = null;
    if (input.emptyOwnerPage) {
      const emptyOwner = await responseRecord(await input.emptyOwnerPage.request.get("/api/owner"));
      const expected = await snapshot(pool, emptyOwner.body.owner.id);
      const observed = {};
      for (const kind of Object.keys(resources)) observed[kind] = await browserHistory(input.emptyOwnerPage, kind);
      emptyHistory = { database: expected, histories: observed };
    }
    capture.cases["PCU-SC-003"] = { histories, cursorDenials, emptyHistory };

    capture.phase = "money";
    const moneyBefore = await snapshot(pool, ownerId);
    await page.goto("/billing", { waitUntil: "networkidle" });
    for (const kind of ["grants", "history"]) {
      let count = 0;
      while (await page.getByTestId(resources[kind].older).count()) {
        assert.ok(count++ < 100, "Bounded PCU exact-money traversal exceeded 100 pages");
        const response = page.waitForResponse((row) => new URL(row.url()).pathname === resources[kind].path);
        await page.getByTestId(resources[kind].older).click(); await response; await page.waitForLoadState("networkidle");
      }
    }
    const money = [];
    for (const amount of await page.locator(".money").all()) {
      const summary = await amount.locator(":scope > span").first().innerText();
      await amount.getByRole("button", { name: "Exact amount" }).click();
      const ledger = await amount.evaluate((element) => { const row = element.closest("tr[data-ledger-type]"); return row ? { rowId: row.getAttribute("data-testid"), type: row.getAttribute("data-ledger-type"), rawAmount: row.getAttribute("data-ledger-amount") } : null; });
      let rawDisclosure = null;
      if (ledger) { const details = page.getByTestId(ledger.rowId).locator("details.ledger-detail"); await details.locator("summary").click(); rawDisclosure = await details.innerText(); }
      money.push({ summary, exact: await amount.locator(".money-detail").innerText(), ledger, rawDisclosure });
    }
    capture.cases["PCU-SC-002"] = { money, before: moneyBefore, after: await snapshot(pool, ownerId) };

    capture.phase = "launch";
    await page.goto("/runs", { waitUntil: "networkidle" });
    const launch = { priceText: await page.getByTestId("run-price-summary").innerText(), cashCeiling: await page.getByTestId("run-cash-ceiling").inputValue(), choices: [] };
    await page.getByTestId("run-agent-select").selectOption(training.agentId);
    if (training.selectedConnectionId) await page.getByTestId("run-connection-select").selectOption(training.selectedConnectionId);
    else {
      assert.equal(training.legacyConnection, true, "Collector requires an explicit remote connection or labelled legacy setup");
      await page.getByText("Advanced: legacy manual connection", { exact: true }).click();
      await page.getByTestId("run-legacy-connection").check();
    }
    for (const mode of ["training", "ranked"]) {
      await page.getByTestId("run-mode-select").selectOption(mode);
      launch.choices.push({ mode, text: await page.getByTestId("run-price-summary").innerText(), label: await page.getByTestId("run-intent-create").innerText() });
    }
    await page.getByTestId("run-mode-select").selectOption("training");
    launch.partialSelections = [];
    for (const selected of [["S1"], ["M1"], ["H1"], ["S1", "M1", "H1"]]) {
      for (const taskId of ["S1", "M1", "H1"]) await page.getByTestId(`run-task-checkbox-${taskId}`).setChecked(selected.includes(taskId));
      launch.partialSelections.push({ taskIds: selected, text: await page.getByTestId("run-price-summary").innerText() });
    }
    for (const taskId of ["M1", "H1"]) await page.getByTestId(`run-task-checkbox-${taskId}`).uncheck();
    const existingIntents = new Set((await snapshot(pool, ownerId)).intents.map((row) => row.id));
    const launchResponse = page.waitForResponse((row) => new URL(row.url()).pathname === resources.intents.path && row.request().method() === "POST");
    await page.getByTestId("run-intent-create").dblclick();
    launch.gesture = "double-click";
    const launched = await launchResponse;
    launch.http = await responseRecord(launched); launch.payload = launched.request().postDataJSON();
    launch.newIntents = (await snapshot(pool, ownerId)).intents.filter((row) => !existingIntents.has(row.id));
    capture.cases["PCU-SC-001"] = launch;

    const help = page.getByText("How is Training priced?", { exact: true });
    await help.focus(); await page.keyboard.press("Enter");
    const keyboardExpanded = await help.locator("..").getAttribute("open") !== null;
    await help.click(); await help.click();
    const navPage = await page.context().newPage();
    let navigationColors;
    try {
      await navPage.goto("/agents", { waitUntil: "domcontentloaded" });
      const activeNav = navPage.locator(".topnav a[aria-current='page']");
      const hoveredNav = navPage.locator(".topnav a[href='/runs']");
      await activeNav.waitFor();
      await hoveredNav.hover();
      navigationColors = await navPage.evaluate(() => {
        const active = document.querySelector(".topnav a[aria-current='page']");
        const hovered = document.querySelector(".topnav a:hover:not([aria-current='page'])");
        if (!active || !hovered) return null;
        return { activeHref: active.getAttribute("href"), activeBackground: getComputedStyle(active).backgroundColor,
          hoveredHref: hovered.getAttribute("href"), hoveredBackground: getComputedStyle(hovered).backgroundColor };
      });
    } finally { await navPage.close(); }
    const readinessPage = await page.context().newPage();
    const injectedReadinessCases = [
      { variant: "offline_client", code: "client_offline" },
      { variant: "executor_unavailable", code: "executor_unavailable" },
      { variant: "unknown_code", code: "pcu_unrecognized_readiness" },
      { variant: "malicious_error_text", code: "<script>PCU_MALICIOUS_READINESS</script>" },
    ];
    const readinessErrorMapping = { cases: [], before: await snapshot(pool, ownerId), mutationRequests: [] };
    const recordMutationRequest = (request) => {
      if (request.method() !== "GET") readinessErrorMapping.mutationRequests.push({
        method: request.method(), path: new URL(request.url()).pathname });
    };
    readinessPage.on("request", recordMutationRequest);
    let injectedCode = "";
    let readinessApiStatus = null;
    await readinessPage.route("**/api/owner/runs/catalog", async (route) => {
      const response = await route.fetch();
      readinessApiStatus = response.status();
      const body = await response.json().catch(() => null);
      if (!response.ok() || !body || typeof body !== "object") return route.fulfill({ response });
      return route.fulfill({ response, json: { ...body, readyToStart: false, readinessReason: injectedCode } });
    });
    try {
      for (const injected of injectedReadinessCases) {
        injectedCode = injected.code;
        readinessApiStatus = null;
        await readinessPage.goto("/runs", { waitUntil: "domcontentloaded" });
        const message = readinessPage.getByTestId("run-release-readiness");
        await message.waitFor();
        readinessErrorMapping.cases.push({ variant: injected.variant, codeSha256: hash(injected.code),
          apiStatus: readinessApiStatus, renderedText: await message.innerText() });
      }
      readinessErrorMapping.after = await snapshot(pool, ownerId);
    } finally {
      readinessPage.off("request", recordMutationRequest);
      await readinessPage.close();
    }
    const unknown = await deny(page, "/api/owner/billing/history?cursor=invalid");
    capture.cases["PCU-SC-004"] = { keyboardExpanded, pointerExpanded: await help.locator("..").getAttribute("open") !== null,
      navigationColors, readinessErrorMapping, readiness: await page.getByTestId("run-release-readiness").textContent().catch(() => null), unknown,
      renderedPageText: await page.getByTestId("run-launch-page").innerText() };

    capture.phase = "training_feedback";
    await page.goto("/runs", { waitUntil: "networkidle" });
    while (!(await page.getByTestId(`owner-run-${training.runId}`).count()) && await page.getByTestId("owner-runs-older").count()) await page.getByTestId("owner-runs-older").click();
    const feedbackResponse = page.waitForResponse((row) => new URL(row.url()).pathname === `/api/owner/runs/${training.runId}/results`);
    await page.getByTestId(`run-feedback-load-${training.runId}`).click(); await feedbackResponse;
    await page.getByTestId(`run-feedback-tasks-${training.runId}`).waitFor();
    const diagnostics = [];
    for (const taskId of training.taskIds ?? ["S1", "M1", "H1"]) {
      const control = page.getByTestId(`run-diagnostics-load-${training.runId}-${taskId}`);
      if (!(await control.count())) continue;
      const response = page.waitForResponse((row) => new URL(row.url()).pathname === `/api/owner/runs/${training.runId}/tasks/${taskId}/diagnostics`);
      await control.click(); diagnostics.push({ taskId, http: await responseRecord(await response) });
    }
    capture.cases["PCU-SC-005"] = { diagnostics, database: await trainingRows(pool, training.runId, ownerId),
      foreign: await deny(foreignOwnerPage, `/api/owner/runs/${training.runId}/tasks/S1/diagnostics`),
      ranked: ranked?.runId ? await deny(page, `/api/owner/runs/${ranked.runId}/tasks/S1/diagnostics`) : null,
      publicTrace: await deny(page, `/api/public/agents/${training.agentId}/runs/${training.runId}/tasks/S1/diagnostics`), negativeTasks: [] };
    for (const [variant, fixture] of [["active_training_unreleased_detail", input.activeTraining], ["active_ranked_request", input.activeRanked], ["unissued_task", input.unissuedTraining]]) {
      if (fixture) capture.cases["PCU-SC-005"].negativeTasks.push({ variant, runId: fixture.runId, taskId: fixture.taskId ?? "S1",
        http: await deny(page, `/api/owner/runs/${fixture.runId}/tasks/${fixture.taskId ?? "S1"}/diagnostics`), database: await trainingRows(pool, fixture.runId, ownerId) });
    }
    if (input.withForgedResultHash) {
      const original = await trainingRows(pool, training.runId, ownerId);
      const fault = await input.withForgedResultHash(async () => ({
        database: await trainingRows(pool, training.runId, ownerId),
        http: await deny(page, `/api/owner/runs/${training.runId}/tasks/S1/diagnostics`),
      }));
      capture.cases["PCU-SC-005"].forgedHash = { original, fault, restored: await trainingRows(pool, training.runId, ownerId) };
    }

    capture.phase = "context_report";
    const reportBefore = await snapshot(pool, ownerId);
    const reportTaskBefore = await trainingRows(pool, training.runId, ownerId);
    const runCard = page.getByTestId(`owner-run-${training.runId}`);
    const screenshot = await runCard.screenshot();
    const screenshotPath = resolve(captureRoot, "private-run-context.png");
    await writeFile(screenshotPath, screenshot, { flag: "wx", mode: 0o600 });
    await runCard.getByRole("link", { name: "Report a problem", exact: true }).click();
    await page.locator("#report-title").fill("PCU contextual browser report");
    await page.locator("#report-body").fill("Synthetic acceptance report from a real completed Training run.");
    const autofilledRunId = await page.locator("#report-run").inputValue();
    await page.getByText("Optional run context", { exact: true }).click();
    await page.locator("#report-client").fill("PCU-fixture/1.0");
    await page.locator("#report-image").setInputFiles(screenshotPath);
    const reportResponse = page.waitForResponse((row) => new URL(row.url()).pathname === "/api/owner/reports" && row.request().method() === "POST");
    await page.getByRole("button", { name: "Submit report", exact: true }).click();
    const reportHttp = await reportResponse; const report = await responseRecord(reportHttp);
    const reportId = report.body?.report?.id;
    await page.getByRole("status").filter({ hasText: "Your report was submitted." }).waitFor();
    const reportRows = await snapshot(pool, ownerId);
    assert.ok(reportId, "Actual report submission did not return a receipt");
    await adminPage.goto("/admin/reports", { waitUntil: "networkidle" });
    const adminRead = await deny(adminPage, `/api/admin/reports/${reportId}`);
    const imagePath = adminRead.body?.report?.images?.[0]?.imagePath;
    const normalizedImage = imagePath ? await adminPage.request.get(imagePath) : null;
    const replayResponse = await page.request.post("/api/owner/reports", { headers: { origin: input.publicOrigin }, data: reportHttp.request().postDataJSON() });
    const reportReplay = await responseRecord(replayResponse);
    const linkDenials = [];
    for (const [actorPage, links] of [[foreignOwnerPage, { runId: training.runId }], [page, { runId: training.runId, taskId: "S4" }], [page, { runId: training.runId, taskId: "S1", actionId: randomUUID() }]]) {
      const before = await snapshot(pool, ownerId);
      const response = await actorPage.request.post("/api/owner/reports", { headers: { origin: input.publicOrigin }, data: { operationId: randomUUID(), title: "PCU rejected foreign context", body: "Synthetic boundary check.", ...links } });
      linkDenials.push({ links, response: await responseRecord(response), before, after: await snapshot(pool, ownerId) });
    }
    const metadataBefore = await snapshot(pool, ownerId);
    const forgedMetadataResponse = await page.request.post("/api/owner/reports", { headers: { origin: input.publicOrigin }, data: {
      operationId: randomUUID(), title: "PCU rejected metadata provenance", body: "Synthetic client source forgery probe.",
      clientVersion: "PCU-fixture/1.0", clientVersionSource: "observed",
    } });
    const forgedMetadata = { before: metadataBefore, response: await responseRecord(forgedMetadataResponse), after: await snapshot(pool, ownerId) };
    capture.cases["PCU-SC-006"] = { autofilledRunId, http: report, payload: reportHttp.request().postDataJSON(), reportRows,
      adminRead, reportReplay, linkDenials, forgedMetadata, screenshot: { path: relative(repoRoot, screenshotPath).replaceAll("\\", "/"), sha256: hash(screenshot) },
      normalizedImage: normalizedImage ? { status: normalizedImage.status(), sha256: hash(await normalizedImage.body()) } : null,
      financialBefore: reportBefore.history, financialAfter: reportRows.history,
      taskBefore: reportTaskBefore, taskAfter: await trainingRows(pool, training.runId, ownerId) };
    await page.goto("/reports", { waitUntil: "networkidle" });
    await page.locator("#report-title").fill("PCU connection without a run");
    await page.locator("#report-body").fill("Synthetic unlinked connection report.");
    const genericResponse = page.waitForResponse((row) => new URL(row.url()).pathname === "/api/owner/reports" && row.request().method() === "POST");
    await page.getByRole("button", { name: "Submit report", exact: true }).click();
    capture.cases["PCU-SC-006"].unlinked = { http: await responseRecord(await genericResponse), database: await snapshot(pool, ownerId) };
    await page.getByRole("status").filter({ hasText: "Your report was submitted." }).waitFor();
    await page.locator("#report-title").fill("PCU invalid screenshot");
    await page.locator("#report-body").fill("Synthetic image decoder boundary.");
    await page.locator("#report-image").setInputFiles({ name: "corrupt.png", mimeType: "image/png", buffer: Buffer.from("invalid PNG bytes") });
    capture.phase = "report_corrupt_image";
    const corruptBefore = await snapshot(pool, ownerId);
    const corruptResponse = page.waitForResponse((row) => new URL(row.url()).pathname === "/api/owner/report-images/uploads/multipart" && row.request().method() === "POST");
    await page.getByRole("button", { name: "Submit report", exact: true }).click();
    const corruptHttp = await responseRecord(await corruptResponse);
    const unsafeImages = { corruptHttp, corruptBefore };
    capture.cases["PCU-SC-006"].unsafeImages = unsafeImages;
    await page.getByTestId("owner-report-error").waitFor();
    const corruptAfter = await snapshot(pool, ownerId);
    unsafeImages.corruptAfter = corruptAfter;
    capture.phase = "report_oversize_image";
    await page.locator("#report-image").setInputFiles({ name: "oversize.png", mimeType: "image/png", buffer: Buffer.alloc(5 * 1024 * 1024 + 1) });
    let oversizeUploadRequests = 0;
    const countUpload = (request) => { if (new URL(request.url()).pathname === "/api/owner/report-images/uploads/multipart") oversizeUploadRequests++; };
    page.on("request", countUpload);
    unsafeImages.oversize = { bytes: 5 * 1024 * 1024 + 1, uploadRequests: null };
    try {
      await page.getByRole("button", { name: "Submit report", exact: true }).click();
      await page.getByTestId("owner-report-error").filter({ hasText: "no larger than 5 MiB" }).waitFor();
    } finally {
      page.off("request", countUpload);
      unsafeImages.oversize.uploadRequests = oversizeUploadRequests;
    }
    Object.assign(unsafeImages.oversize, { alert: await page.getByTestId("owner-report-error").innerText(), after: await snapshot(pool, ownerId) });

    capture.phase = "admin_boundary";
    const anonymous = input.anonymousPage ?? await page.context().browser().newPage({ baseURL: input.publicOrigin });
    const adminCases = [];
    try {
      for (const path of ["/admin", "/admin/reports", "/admin/bonus-codes", "/admin/operations", "/admin/unknown-subroute"]) {
        for (const [actor, actorPage] of [["owner", page], ["anonymous", anonymous]]) {
          const record = await deny(actorPage, path, { headers: { "Next-Router-Prefetch": "1", "x-admin": "true", "x-owner-role": "admin" } });
          adminCases.push({ path, actor, status: record.status, cacheControl: record.cacheControl });
        }
      }
      await page.goto("/account", { waitUntil: "networkidle" });
      const ownerNav = await page.getByRole("navigation").getByRole("link", { name: "Administration", exact: true }).count();
      await adminPage.goto("/account", { waitUntil: "networkidle" });
      const adminNav = await adminPage.getByRole("navigation").getByRole("link", { name: "Administration", exact: true }).count();
      const adminBefore = await snapshot(pool, ownerId);
      const deniedMutation = await page.request.patch(`/api/admin/reports/${reportId}/status`, { headers: { origin: input.publicOrigin }, data: { operationId: randomUUID(), expectedRevision: 1, status: "closed" } });
      const csrfMutation = await adminPage.request.patch(`/api/admin/reports/${reportId}/status`, { headers: { origin: "https://untrusted.invalid" }, data: { operationId: randomUUID(), expectedRevision: 1, status: "closed" } });
      const deniedAfter = await snapshot(pool, ownerId);
      await adminPage.goto("/admin/reports", { waitUntil: "networkidle" });
      await adminPage.locator(`[data-report-id="${reportId}"]`).getByRole("button", { name: "Open", exact: true }).click();
      const authorizedMutation = adminPage.waitForResponse((row) => new URL(row.url()).pathname === `/api/admin/reports/${reportId}/status` && row.request().method() === "PATCH");
      await adminPage.getByRole("button", { name: "Mark in progress", exact: true }).click();
      capture.cases["PCU-SC-007"] = { pages: adminCases, ownerNav, adminNav, ownerApi: await deny(page, "/api/admin/bonus-codes"), anonymousApi: await deny(anonymous, "/api/admin/bonus-codes"),
        adminBefore, deniedMutation: await responseRecord(deniedMutation), csrfMutation: await responseRecord(csrfMutation), deniedAfter,
        authorizedMutation: await responseRecord(await authorizedMutation), authorizedAfter: await snapshot(pool, ownerId) };
    } finally { if (!input.anonymousPage) await anonymous.close(); }

    capture.phase = "connections";
    await page.goto("/agents", { waitUntil: "networkidle" });
    const connectionAgentId = input.connectionAgentId ?? training.agentId;
    const connections = page.getByTestId(`agent-connections-${connectionAgentId}`);
    await connections.waitFor();
    const connectionStatus = await deny(page, `/api/owner/agents/${connectionAgentId}/connections`);
    const legacy = page.getByTestId(`agent-card-${connectionAgentId}`).getByText("Advanced: legacy manual credential and revoke all access", { exact: true });
    capture.cases["PCU-SC-008"] = { agentId: connectionAgentId, status: connectionStatus, mainText: await connections.innerText(), legacyInitiallyClosed: await legacy.locator("..").getAttribute("open") === null, nativeConnectionCaptureRef };
    if (input.runReportFlood !== false) {
      const flood = { before: await snapshot(pool, ownerId), attempts: [] };
      for (let index = 0; index < 8; index++) {
        const response = await page.request.post("/api/owner/reports", { headers: { origin: input.publicOrigin }, data: { operationId: randomUUID(), title: "PCU bounded report quota probe", body: "Synthetic isolated-database report quota boundary." } });
        const record = await responseRecord(response); flood.attempts.push(record);
        if (record.status === 429) break;
        assert.ok([200, 201].includes(record.status), "Report quota prefill failed unexpectedly");
      }
      flood.after = await snapshot(pool, ownerId);
      capture.cases["PCU-SC-006"].flood = flood;
    }
    capture.after = await snapshot(pool, ownerId);
    capture.phase = "complete";
    capture.finishedAt = new Date().toISOString();
    if (input.getFinalProvenance) capture.provenance = await input.getFinalProvenance();
    assertSecretFree(capture, "pcu-browser-capture");
    const artifactPath = resolve(captureRoot, "participant-cabinet-capture.json");
    const bytes = Buffer.from(JSON.stringify(capture, null, 2) + "\n");
    await writeFile(artifactPath, bytes, { flag: "wx", mode: 0o600 });
    return { capture, artifact: { path: relative(repoRoot, artifactPath).replaceAll("\\", "/"), sha256: hash(bytes) } };
  } catch (failure) {
    capture.failure = { name: /^[A-Za-z]+$/.test(failure?.name ?? "") ? failure.name : "Error" };
    // AICODE-NOTE: Counts diagnose strict locator failures without retaining arbitrary page text or browser errors.
    capture.failure.ui = {
      alertCount: await page.getByRole("alert").count().catch(() => null),
      reportErrorMarker: "owner-report-error",
      reportErrorCount: await page.getByTestId("owner-report-error").count().catch(() => null),
    };
    assertSecretFree(capture, "pcu-partial-capture");
    await writeFile(resolve(captureRoot, "participant-cabinet-partial.json"), JSON.stringify(capture, null, 2) + "\n", { flag: "wx", mode: 0o600 });
    throw failure;
  } finally { await pool.end(); }
}

export { snapshot as participantCabinetReadonlySnapshot };
