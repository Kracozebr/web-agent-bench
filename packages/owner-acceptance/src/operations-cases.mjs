import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';

const digest = (value) => createHash('sha256').update(value).digest('hex');

async function snapshot(pool) {
  const connection = await pool.connect();
  try {
    await connection.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    const identity = (await connection.query(`SELECT current_database() AS database,
      current_user AS role,current_setting('transaction_read_only') AS read_only`)).rows[0];
    assert.match(identity.database, /^oid_acceptance_[a-f0-9]{32}$/);
    assert.equal(identity.role, 'oid_observer');
    assert.equal(identity.read_only, 'on');
    const control = (await connection.query(`SELECT mode,revision::text,operation_id
      FROM oid_beta_operations_control WHERE id=1`)).rows[0];
    const events = (await connection.query(`SELECT operation_id,revision::text,previous_mode,next_mode,
      reason_code FROM oid_beta_operations_control_event ORDER BY revision`)).rows;
    const invariants = (await connection.query(`SELECT
      (SELECT count(*)::int FROM oid_ledger_entry) AS ledger,
      (SELECT count(*)::int FROM oid_benchmark_run) AS runs,
      (SELECT count(*)::int FROM oid_run_task_action) AS actions,
      (SELECT count(*)::int FROM oid_support_report) AS reports`)).rows[0];
    await connection.query('COMMIT');
    return { identity, control, events, invariants };
  } catch (error) {
    await connection.query('ROLLBACK').catch(() => {});
    throw error;
  } finally { connection.release(); }
}

/** Supplementary local SC021 evidence. This does not publish a target acceptance manifest. */
export async function runLocalOperationsCases({ adminPage, ownerPage, observerPool, publicOrigin,
  captureRoot, reportId }) {
  const before = await snapshot(observerPool);
  assert.equal(before.control.mode, 'active');
  const responses = [];
  await adminPage.goto(new URL('/admin/operations', publicOrigin).href, { waitUntil: 'domcontentloaded' });
  await adminPage.getByTestId('operations-mode').filter({ hasText: 'Starts active' }).waitFor();
  const exportResponsePromise = adminPage.waitForResponse(response =>
    new URL(response.url()).pathname === '/api/admin/operations/usage-support-export');
  await adminPage.getByTestId('operations-usage-export').click();
  const exportResponse = await exportResponsePromise;
  assert.equal(exportResponse.status(), 503, 'Local fixtures must not fabricate a deployment client registry');
  assert.equal((await exportResponse.json()).error.code, 'BETA_USAGE_REGISTRY_UNAVAILABLE');
  responses.push({method:'GET',path:'/api/admin/operations/usage-support-export',status:503,
    code:'BETA_USAGE_REGISTRY_UNAVAILABLE'});
  await adminPage.locator('#operations-reason').selectOption('maintenance');
  for (const [testId, mode] of [['operations-pause', 'paused'], ['operations-resume', 'active']]) {
    const responsePromise = adminPage.waitForResponse(response =>
      new URL(response.url()).pathname === '/api/admin/operations/control' && response.request().method() === 'POST');
    await adminPage.getByTestId(testId).click();
    const response = await responsePromise;
    assert.equal(response.status(), 201);
    const payload = await response.json();
    const body = payload.control;
    assert.ok(body && payload.replayed === false);
    const durable = await snapshot(observerPool);
    assert.equal(durable.control.mode, mode);
    assert.equal(durable.control.operation_id, body.operationId);
    assert.equal(Number(durable.control.revision), body.revision);
    assert.deepEqual(durable.invariants, before.invariants);
    responses.push({ method:'POST',path:'/api/admin/operations/control',status:response.status(),
      operationId:body.operationId,revision:body.revision,mode });
    await adminPage.getByTestId('operations-mode').filter({ hasText: mode === 'paused' ? 'Starts paused' : 'Starts active' }).waitFor();
    if (mode === 'paused') {
      const reportRead = await ownerPage.request.get(new URL(`/api/owner/reports/${reportId}`, publicOrigin).href);
      assert.equal(reportRead.status(), 200, 'Owner report reads remain available during pause');
      const denied = await ownerPage.request.get(new URL('/api/admin/operations', publicOrigin).href);
      assert.equal(denied.status(), 403, 'Non-admin cannot read operations');
      const deniedExport = await ownerPage.request.get(new URL('/api/admin/operations/usage-support-export', publicOrigin).href);
      assert.equal(deniedExport.status(), 403, 'Non-admin cannot export usage');
      const rejected = await ownerPage.request.post(new URL('/api/admin/operations/control', publicOrigin).href,
        { headers:{Origin:publicOrigin},data:{operationId:'nonadmin_control_attempt',expectedRevision:body.revision,mode:'active',reasonCode:'maintenance'} });
      assert.equal(rejected.status(), 403, 'Non-admin cannot change operations');
      const stillPaused = await snapshot(observerPool);
      assert.deepEqual(stillPaused, durable);
      responses.push({ method:'GET',path:'/api/owner/reports/:id',status:200 },
        {method:'GET',path:'/api/admin/operations',status:403},
        {method:'GET',path:'/api/admin/operations/usage-support-export',status:403},
        {method:'POST',path:'/api/admin/operations/control',status:403});
    }
  }
  const after = await snapshot(observerPool);
  assert.equal(Number(after.control.revision), Number(before.control.revision)+2);
  assert.equal(after.events.length, before.events.length+2);
  assert.deepEqual(after.invariants, before.invariants);
  assert.deepEqual(after.events.slice(-2).map(row => [row.previous_mode,row.next_mode]),
    [['active','paused'],['paused','active']]);
  const evidence = { schemaVersion:'bpc-local-operations-observation/v1',scenarioId:'BPC-SC-021',
    boundary:'isolated_browser_api_postgresql',localStatus:'observed_partial',
    before,after,responses,blockers:['target_host_not_configured','running_worker_drain_not_exercised',
      'bounded_load_resource_exhaustion_restart_not_exercised'] };
  const bytes = JSON.stringify(evidence,null,2)+'\n';
  const path = join(captureRoot,'local-operations-observation.json');
  await writeFile(path,bytes,{mode:0o600,flag:'wx'});
  return { path,sha256:digest(bytes),localStatus:evidence.localStatus };
}
