/**
 * Synthetic PostgreSQL task-action transaction checks. This helper exercises
 * owner-identity durable admissions/cutoffs only; it uses no HTTP route,
 * participant model, runtime executor or real effect observations.
 */
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import { request as httpRequest } from 'node:http';
import pg from 'pg';

const key = () => randomUUID();
const hash = (value) => createHash('sha256').update(value).digest('hex');

export async function seedActionRun(pool, { taskId = 'S2', mode = 'training', deadline = '1 hour', taskIndex = 0,
  taskIds = taskIndex === 0 ? [taskId] : [...Array.from({ length: taskIndex }, (_, index) => ['S1', 'S2', 'S3'][index] ?? 'S1'), taskId],
  runEnvironmentId, bindingEnvironmentId, bindingGenerationMismatch = false, preparationTaskId = taskId,
  createExecutionContext = true, createBinding = true } = {}) {
  const ownerId = key(), agentId = key(), userId = key(), intentId = key(), runId = key(), grantId = key();
  const resource = 'http://task-action.example.invalid/api/agent';
  const releaseIdentity = 'synthetic-action-release';
  const manifestHash = hash(`manifest:${runId}`);
  const benchmarkHash = hash(`benchmark:${runId}`);
  const policyHash = hash(`policy:${runId}`);
  const environmentId = `synthetic-env-${runId}`;
  const runEnvId = runEnvironmentId ?? environmentId;
  const boundEnvId = bindingEnvironmentId ?? environmentId;
  const claimId = key(), preparationId = key(), leaseId = key(), generationId = key();
  const boundGenerationId = bindingGenerationMismatch ? key() : generationId;
  const caseId = `${releaseIdentity}-${taskId}`;
  const caseHash = hash(`case:${runId}:${taskId}`), initialStateHash = hash(`initial:${runId}:${taskId}`);
  const executionIdentityHash = hash(`execution:${runId}`), environmentManifestHash = hash(`environment-manifest:${runId}`);
  const applicationSourceHash = hash(`application-source:${runId}`);
  const participantId = 'synthetic-action-participant', payerAddress = `0x${'1'.repeat(40)}`;
  await pool.query("INSERT INTO oid_auth_user(id,name,email,email_verified) VALUES($1,'Synthetic action owner',$2,true)", [userId, `${userId}@example.invalid`]);
  await pool.query("INSERT INTO oid_owner(id,auth_user_id,admission_status,admitted_at) VALUES($1,$2,'admitted',clock_timestamp())", [ownerId, userId]);
  await pool.query("INSERT INTO oid_agent(id,owner_id,name) VALUES($1,$2,'Synthetic action agent')", [agentId, ownerId]);
  await pool.query('INSERT INTO oid_agent_policy(agent_id,training,ranked) VALUES($1,$2,$3)', [agentId, mode === 'training', mode === 'ranked']);
  await pool.query(`INSERT INTO oid_agent_access_grant(id,owner_id,agent_id,operation_id,resource,role,access_generation,expires_at)
    VALUES($1,$2,$3,$4,$5,'agent',1,clock_timestamp()+interval '1 hour')`, [grantId, ownerId, agentId, key(), resource]);
  await pool.query(`INSERT INTO oid_run_launch_intent(id,owner_id,agent_id,operation_id,payload_hash,mode,task_ids,release_identity,
      benchmark_version,manifest_hash,benchmark_hash,policy_hash,quote_price_units,cash_ceiling_units,owner_policy_revision,
      agent_policy_revision,status,expires_at,accepted_at)
    VALUES($1,$2,$3,$4,$5,$6,$7::text[],$8,$9,$10,$11,$12,0,0,1,1,'accepted',clock_timestamp()+interval '1 hour',clock_timestamp())`,
  [intentId, ownerId, agentId, key(), hash(`intent:${runId}`), mode, taskIds, releaseIdentity, 'synthetic-action-v1', manifestHash, benchmarkHash, policyHash]);
  await pool.query(`INSERT INTO oid_benchmark_run(id,intent_id,owner_id,agent_id,mode,task_ids,release_identity,benchmark_version,
      manifest_hash,benchmark_hash,policy_hash,quote_price_units,cash_ceiling_units,access_generation,agent_policy_revision,status,
      queued_at,queue_deadline,started_at,overall_deadline,environment_id,environment_evidence_hash)
    VALUES($1,$2,$3,$4,$5,$6::text[],$7,'synthetic-action-v1',$8,$9,$10,0,0,1,1,'running',clock_timestamp(),
      clock_timestamp()+interval '2 hours',clock_timestamp(),clock_timestamp()+interval '1 hour',$11,$12)`,
  [runId, intentId, ownerId, agentId, mode, taskIds, releaseIdentity, manifestHash, benchmarkHash, policyHash, runEnvId, hash(`environment:${runId}`)]);
  for (let index = 0; index < taskIds.length; index += 1) {
    const taskStatus = index < taskIndex ? 'completed' : index === taskIndex ? 'active' : 'queued';
    await pool.query(`INSERT INTO oid_run_task(run_id,task_index,task_id,status,snapshot_json,started_at,deadline_at,finished_at)
      VALUES($1,$2,$3,$4,'{}'::jsonb,CASE WHEN $4='queued' THEN NULL ELSE clock_timestamp() END,
        CASE WHEN $4='queued' THEN NULL ELSE clock_timestamp()+$5::interval END,
        CASE WHEN $4='completed' THEN clock_timestamp() ELSE NULL END)`, [runId, index, taskIds[index], taskStatus, deadline]);
  }
  if (createExecutionContext) await pool.query(`INSERT INTO oid_run_dispatch_claim(run_id,owner_id,agent_id,claim_id,turn_number,status,claimed_at)
    VALUES($1,$2,$3,$4,1,'claimed',clock_timestamp())`, [runId, ownerId, agentId, claimId]);
  if (createExecutionContext) await pool.query(`INSERT INTO oid_run_execution_slot(agent_id,owner_id,run_id,claim_id,state,acquired_at)
    VALUES($1,$2,$3,$4,'running',clock_timestamp())`, [agentId, ownerId, runId, claimId]);
  if (createExecutionContext) await pool.query(`INSERT INTO oid_task_preparation_intent(preparation_id,run_id,task_index,claim_id,lease_id,environment_id,
      release_identity,manifest_hash,task_id,case_id,case_hash,initial_state_sha256,execution_identity_hash,
      environment_manifest_sha256,application_source_hash)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
  [preparationId, runId, taskIndex, claimId, leaseId, environmentId, releaseIdentity, manifestHash, preparationTaskId, caseId,
    caseHash, initialStateHash, executionIdentityHash, environmentManifestHash, applicationSourceHash]);
  if (createExecutionContext) await pool.query(`INSERT INTO oid_task_environment_lease(lease_id,preparation_id,environment_id,state)
    VALUES($1,$2,$3,'leased')`, [leaseId, preparationId, environmentId]);
  if (createExecutionContext) await pool.query(`INSERT INTO oid_task_preparation_observation(preparation_id,revision,status)
    VALUES($1,1,'preparing')`, [preparationId]);
  if (createExecutionContext) await pool.query(`INSERT INTO oid_task_preparation_observation(preparation_id,revision,status,generation_id,participant_id,payer_address,
      baseline_state_sha256,fixture_evidence,baseline_evidence)
    VALUES($1,2,'ready',$2,$3,$4,$5,$6::jsonb,$7::jsonb)`,
  [preparationId, generationId, participantId, payerAddress, initialStateHash,
    JSON.stringify({ path: `synthetic-action/${runId}-fixture.json`, sha256: hash(`fixture:${runId}`), boundary: 'actual_tool_http_x402_local_evm_application_store' }),
    JSON.stringify({ path: `synthetic-action/${runId}-baseline.json`, sha256: hash(`baseline:${runId}`), boundary: 'actual_tool_http_x402_local_evm_application_store' })]);
  if (createExecutionContext && createBinding) await pool.query(`INSERT INTO oid_task_execution_binding(run_id,task_index,env_id,generation_id,manifest_hash,
      application_source_hash,participant_id,payer_address) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
  [runId, taskIndex, boundEnvId, boundGenerationId, environmentManifestHash, applicationSourceHash, participantId, payerAddress]);
  return { ownerId, agentId, grantId, resource, runId, taskIndex, taskId, mode, claimId, preparationId, leaseId, generationId,
    environmentId, environmentManifestHash, applicationSourceHash, caseId, caseHash, initialStateHash, executionIdentityHash,
    participantId, payerAddress };
}

function principal(fixture, overrides = {}) {
  return {
    ownerId: fixture.ownerId, agentId: fixture.agentId, grantId: fixture.grantId, credentialId: key(),
    resource: fixture.resource, role: 'agent', accessGeneration: 1, accessRevision: 1, policyRevision: 1,
    permissions: { training: true, ranked: true, forumMessages: false, customTopics: false },
    ...overrides,
  };
}

export async function runTaskActionCases({ databaseUrl, observerDatabaseUrl }) {
  const ownerUrl = new URL(databaseUrl), observerUrl = new URL(observerDatabaseUrl);
  assert.equal(ownerUrl.hostname, 'postgres', 'Task action tests require the Docker PostgreSQL host');
  assert.equal(observerUrl.hostname, 'postgres', 'Task action tests require the Docker PostgreSQL observer host');
  assert.ok(/^\/oid_acceptance_[a-f0-9]{32}$/.test(ownerUrl.pathname), 'Task action tests require an isolated acceptance database');
  assert.equal(ownerUrl.pathname, observerUrl.pathname, 'Owner and observer must inspect the same acceptance database');
  const [{ createDatabase }, { loadConfig }, service] = await Promise.all([
    import('../../owner-identity/dist/db.js'), import('../../owner-identity/dist/config.js'), import('../../owner-identity/dist/task-action-service.js'),
  ]);
  const { sha256CanonicalTaskJson } = await import('../../owner-identity/dist/task-release.js');
  const setup = new pg.Pool({ connectionString: databaseUrl, max: 3, application_name: 'synthetic-task-action-setup' });
  const observer = new pg.Pool({ connectionString: observerDatabaseUrl, max: 1, application_name: 'synthetic-task-action-observer' });
  const { db, client } = createDatabase(loadConfig({ ...process.env, OID_DATABASE_URL: databaseUrl }));
  try {
    const role = (await observer.query('SELECT current_user AS role,current_setting(\'transaction_read_only\') AS readonly')).rows[0];
    assert.deepEqual(role, { role: 'oid_observer', readonly: 'on' });

    const fixture = await seedActionRun(setup, { taskId: 'S2', runEnvironmentId: 'legacy-run-pointer' });
    const deps = { db };
    const actor = principal(fixture);
    const staleTaskFixture = await seedActionRun(setup, { taskId: 'S2', taskIndex: 1, taskIds: ['S1', 'S2'] });
    await assert.rejects(service.admitTaskAction(deps, principal(staleTaskFixture), {
      runId: staleTaskFixture.runId, taskIndex: 0, operationId: key(),
      command: { kind: 'transfer', amountUnits: '1', recipient: '0x1111111111111111111111111111111111111111', gasLimit: '100000' },
    }), (error) => error.code === 'TASK_NOT_ACTIVE', 'a prior task cannot act after a successor is active');
    const wrongPreparation = await seedActionRun(setup, { taskId: 'S2', preparationTaskId: 'S1' });
    await assert.rejects(service.admitTaskAction(deps, principal(wrongPreparation), {
      runId: wrongPreparation.runId, taskIndex: 0, operationId: key(),
      command: { kind: 'transfer', amountUnits: '1', recipient: '0x1111111111111111111111111111111111111111', gasLimit: '100000' },
    }), (error) => error.code === 'TASK_EXECUTION_IDENTITY_UNAVAILABLE', 'preparation must name the exact selected task');
    const wrongGeneration = await seedActionRun(setup, { taskId: 'S2', bindingGenerationMismatch: true });
    await assert.rejects(service.admitTaskAction(deps, principal(wrongGeneration), {
      runId: wrongGeneration.runId, taskIndex: 0, operationId: key(),
      command: { kind: 'transfer', amountUnits: '1', recipient: '0x1111111111111111111111111111111111111111', gasLimit: '100000' },
    }), (error) => error.code === 'TASK_EXECUTION_IDENTITY_UNAVAILABLE', 'binding must retain the ready generation for this preparation');
    const wrongEnvironment = await seedActionRun(setup, { taskId: 'S2', bindingEnvironmentId: 'foreign-task-environment' });
    await assert.rejects(service.admitTaskAction(deps, principal(wrongEnvironment), {
      runId: wrongEnvironment.runId, taskIndex: 0, operationId: key(),
      command: { kind: 'transfer', amountUnits: '1', recipient: '0x1111111111111111111111111111111111111111', gasLimit: '100000' },
    }), (error) => error.code === 'TASK_EXECUTION_IDENTITY_UNAVAILABLE', 'binding cannot name another task environment');
    await assert.rejects(service.admitTaskAction(deps, actor, {
      runId: fixture.runId, taskIndex: 0, operationId: key(), command: { kind: 'rpc', url: 'http://evil.invalid' },
    }), (error) => error.code === 'INVALID_TASK_ACTION');
    await assert.rejects(service.admitTaskAction(deps, principal(fixture, { grantId: key() }), {
      runId: fixture.runId, taskIndex: 0, operationId: key(), command: { kind: 'wrap', amountWei: '1', gasLimit: '100000' },
    }), (error) => error.code === 'AGENT_ACCESS_REVOKED');
    await assert.rejects(service.admitTaskAction(deps, principal(fixture, { accessGeneration: 2 }), {
      runId: fixture.runId, taskIndex: 0, operationId: key(), command: { kind: 'wrap', amountWei: '1', gasLimit: '100000' },
    }), (error) => error.code === 'AGENT_ACCESS_REVOKED');

    const operationA = key();
    const reverseSwap = { kind: 'swap', inputAssetId: 'USDC', outputAssetId: 'WETH', amountInUnits: '500', amountOutMinimumUnits: '1',
      recipient: '0x1111111111111111111111111111111111111111', gasLimit: '100000' };
    const concurrent = await Promise.all(Array.from({ length: 4 }, () => service.admitTaskAction(deps, actor, {
      runId: fixture.runId, taskIndex: 0, operationId: operationA, command: reverseSwap,
    })));
    assert.equal(new Set(concurrent.map((row) => row.actionId)).size, 1, 'retry race must commit one immutable action identity');
    assert.equal(concurrent.filter((row) => !row.replayed).length, 1);
    assert.equal(concurrent[0].actionSequence, '1');
    const admittedEnvironment = (await observer.query('SELECT environment_id FROM oid_run_task_action WHERE id=$1', [concurrent[0].actionId])).rows[0].environment_id;
    assert.equal(admittedEnvironment, fixture.environmentId, 'action authority comes from the task preparation, not the run compatibility pointer');
    assert.notEqual(admittedEnvironment, 'legacy-run-pointer');
    const pendingState = await service.getTaskActionState(deps, actor, { runId: fixture.runId, actionId: concurrent[0].actionId });
    assert.equal(pendingState.status, 'pending');
    assert.equal(pendingState.transactionHash, null);
    await assert.rejects(service.getTaskActionState(deps, principal(fixture, { grantId: key() }),
      { runId: fixture.runId, actionId: concurrent[0].actionId }), (error) => error.code === 'AGENT_ACCESS_REVOKED');
    assert.equal((await service.admitTaskAction(deps, actor, { runId: fixture.runId, taskIndex: 0, operationId: operationA, command: reverseSwap })).replayed, true);
    await assert.rejects(service.admitTaskAction(deps, actor, {
      runId: fixture.runId, taskIndex: 0, operationId: operationA,
      command: { ...reverseSwap, amountInUnits: '501' },
    }), (error) => error.code === 'IDEMPOTENCY_CONFLICT');

    const operationB = key();
    const second = await service.admitTaskAction(deps, actor, {
      runId: fixture.runId, taskIndex: 0, operationId: operationB, command: { kind: 'purchase', resourceId: 'resource-one', offerId: 'offer-one' },
    });
    assert.equal(second.actionSequence, '2');
    const storedCommands = await observer.query(`SELECT a.action_sequence::text,a.action_kind,a.command_json,o.status AS outbox_status,
        r.receipt_status,r.receipt_revision
      FROM oid_run_task_action a JOIN oid_run_task_action_outbox o ON o.action_id=a.id
      JOIN oid_run_task_action_receipt r ON r.action_id=a.id WHERE a.run_id=$1 ORDER BY a.action_sequence`, [fixture.runId]);
    assert.deepEqual(storedCommands.rows.map((row) => [row.action_sequence, row.action_kind, row.outbox_status, row.receipt_status, row.receipt_revision]), [
      ['1', 'swap', 'pending', 'pending', 0], ['2', 'purchase', 'pending', 'pending', 0],
    ]);
    assert.equal(JSON.stringify(storedCommands.rows).includes('payment-signature'), false);
    const immutable = await setup.query("UPDATE oid_run_task_action SET command_json='{}' WHERE run_id=$1", [fixture.runId]).then(() => null, (error) => error);
    assert.equal(immutable?.code, '55000', 'admitted action intent cannot be rewritten');

    // Out-of-order receipt arrival cannot advance the contiguous action cursor.
    const receiptTwo = await service.recordTaskActionReceipt(deps, {
      actionId: second.actionId, status: 'observed', evidenceHash: hash('receipt-two'), transactionHash: `0x${'2'.repeat(64)}`,
      evidencePath: 'artifacts/runs/task-action-fixture/receipt-two.json',
      toolResponse: { operationId: 'synthetic-tool-operation', outcome: 'success', contentHash: hash('synthetic-delivery') },
    });
    assert.equal(receiptTwo.reconciledActionSequence, '0');
    const knownState = await service.getTaskActionState(deps, actor, { runId: fixture.runId, actionId: second.actionId });
    assert.equal(knownState.status, 'observed');
    assert.equal(knownState.evidencePath, 'artifacts/runs/task-action-fixture/receipt-two.json');
    assert.deepEqual(knownState.toolResponse, { operationId: 'synthetic-tool-operation', outcome: 'success', contentHash: hash('synthetic-delivery') });
    const storedReceiptTwo = await observer.query(`SELECT evidence_path,tool_response_hash,transaction_hash
      FROM oid_run_task_action_receipt WHERE action_id=$1`, [second.actionId]);
    assert.deepEqual(storedReceiptTwo.rows, [{
      evidence_path: 'artifacts/runs/task-action-fixture/receipt-two.json',
      tool_response_hash: sha256CanonicalTaskJson(knownState.toolResponse), transaction_hash: `0x${'2'.repeat(64)}`,
    }], 'trusted artifact path and canonical response hash must persist with the receipt');
    const answer = { amountUnits: '100', network: 'eip155:8453', assetId: 'USDC', recipient: 'not-the-pinned-recipient' };
    const malformedFinish = await service.finishTask(deps, actor, { runId: fixture.runId, taskIndex: 0, operationId: key(), answer: { score: 1 } }).then(
      () => null, (error) => error,
    );
    assert.equal(malformedFinish?.code, 'INVALID_TASK_ANSWER');
    const finishOp = key();
    const finished = await service.finishTask(deps, actor, { runId: fixture.runId, taskIndex: 0, operationId: finishOp, answer });
    assert.equal(finished.actionCutoffSequence, '2');
    assert.equal(finished.reconciledActionSequence, '0');
    assert.equal(finished.closureStatus, 'closing');
    const replay = await service.finishTask(deps, actor, { runId: fixture.runId, taskIndex: 0, operationId: key(), answer });
    assert.equal(replay.closureId, finished.closureId, 'a changed finish operation key recovers the same semantic cutoff');
    assert.equal(replay.replayed, true);
    await assert.rejects(service.finishTask(deps, actor, { runId: fixture.runId, taskIndex: 0, operationId: finishOp, answer: { amountUnits: '101' } }),
      (error) => error.code === 'IDEMPOTENCY_CONFLICT');
    const answerRow = await observer.query('SELECT answer_json FROM oid_run_task_closure WHERE id=$1', [finished.closureId]);
    assert.deepEqual(answerRow.rows[0].answer_json, answer);
    await assert.rejects(service.admitTaskAction(deps, actor, {
      runId: fixture.runId, taskIndex: 0, operationId: key(), command: { kind: 'wrap', amountWei: '1', gasLimit: '100000' },
    }), (error) => error.code === 'TASK_CLOSED');

    const receiptOne = await service.recordTaskActionReceipt(deps, {
      actionId: concurrent[0].actionId, status: 'observed', evidenceHash: hash('receipt-one'), transactionHash: `0x${'1'.repeat(64)}`,
    });
    assert.equal(receiptOne.reconciledActionSequence, '2');
    assert.equal(receiptOne.closureStatus, 'closed');
    const cursor = await observer.query(`SELECT accepted_action_sequence::text,action_cutoff_sequence::text,
        reconciled_action_sequence::text,closure_status,closure_reason,closure_id::text FROM oid_run_task WHERE run_id=$1`, [fixture.runId]);
    assert.deepEqual(cursor.rows[0], {
      accepted_action_sequence: '2', action_cutoff_sequence: '2', reconciled_action_sequence: '2',
      closure_status: 'closed', closure_reason: 'agent_finish', closure_id: finished.closureId,
    });
    const finishOutbox = await observer.query('SELECT status FROM oid_run_task_finish_outbox WHERE closure_id=$1', [finished.closureId]);
    assert.deepEqual(finishOutbox.rows, [{ status: 'pending' }]);

    // Exercise the registered HTTP routes through a real local socket. The
    // synthetic Host matches the configured public origin while the socket
    // remains bound to loopback; the bearer resolver is a test-only principal
    // fixture and does not claim real credential issuance.
    const routeFixture = await seedActionRun(setup, { taskId: 'S3' });
    const routeActor = principal(routeFixture);
    const Fastify = createRequire(new URL('../../owner-identity/package.json', import.meta.url))('fastify');
    const { registerRunRoutes, registerRunIntentMcpTools } = await import('../../owner-identity/dist/run-routes.js');
    const httpApp = Fastify({ logger: false });
    const syntheticBearer = `synthetic-task-action-${key()}`;
    const taskHost = 'task-action-http.example.invalid';
    registerRunRoutes(httpApp, { db, publicOrigin: `http://${taskHost}`, rateLimitMax: 100,
      async rateLimit() {}, async requireOrigin() {}, async resolveOwner() { throw new Error('Owner route unused'); },
      async resolveAgentPrincipal(bearer) { return bearer === syntheticBearer ? routeActor : undefined; } });
    const taskFetch = (target, body, method = 'POST') => new Promise((resolve, reject) => {
      const req = httpRequest(target, { method, headers: {
        host: taskHost, authorization: `Bearer ${syntheticBearer}`, 'content-type': 'application/json',
      } }, (response) => {
        const chunks = [];
        response.on('data', (chunk) => chunks.push(chunk));
        response.on('end', () => resolve({ status: response.statusCode, headers: response.headers,
          body: JSON.parse(Buffer.concat(chunks).toString('utf8')) }));
        response.on('error', reject);
      });
      req.on('error', reject);
      req.end(JSON.stringify(body));
    });
    try {
      const listenUrl = await httpApp.listen({ host: '127.0.0.1', port: 0 });
      const taskPath = `${listenUrl}/api/agent/runs/${routeFixture.runId}/tasks/0`;
      const httpAction = { operationId: key(), command: { kind: 'purchase', resourceId: 'resource-http', offerId: 'offer-http' } };
      const httpFirst = await taskFetch(`${taskPath}/actions`, httpAction);
      const httpRetry = await taskFetch(`${taskPath}/actions`, httpAction);
      assert.equal(httpFirst.status, 202);
      assert.equal(httpRetry.status, 202);
      assert.equal(httpFirst.body.actionId, httpRetry.body.actionId);
      assert.equal(httpRetry.body.replayed, true);
      assert.equal(httpFirst.headers['cache-control'], 'no-store');
      assert.equal(httpFirst.headers.vary, 'Authorization');
      const httpState = await taskFetch(`${listenUrl}/api/agent/runs/${routeFixture.runId}/actions/${httpFirst.body.actionId}`, undefined, 'GET');
      assert.equal(httpState.status, 200);
      assert.equal(httpState.body.status, 'pending');
      assert.equal(httpState.body.transactionHash, null);
      assert.equal((await observer.query('SELECT count(*)::int AS count FROM oid_run_task_action WHERE run_id=$1', [routeFixture.runId])).rows[0].count, 1,
        'HTTP response-loss retry must persist exactly one admitted command');
      const httpFinish = await taskFetch(`${taskPath}/finish`, { operationId: key(), answer: { offerId: 'offer-http' } });
      assert.equal(httpFinish.status, 200);
      assert.equal(httpFinish.body.actionCutoffSequence, '1');
      assert.equal(httpFinish.body.closureStatus, 'closing');
      const httpAfterFinish = await taskFetch(`${taskPath}/actions`, {
        operationId: key(), command: { kind: 'wrap', amountWei: '1', gasLimit: '100000' },
      });
      assert.equal(httpAfterFinish.status, 409);
      assert.equal(httpAfterFinish.body.error.code, 'TASK_CLOSED');
    } finally { await httpApp.close(); }

    // Exercise the registered MCP handlers with the exact same durable
    // service and principal checks; no MCP client is implied by this handler
    // contract test.
    const mcpFixture = await seedActionRun(setup, { taskId: 'S2' });
    const mcpTools = new Map();
    registerRunIntentMcpTools({ registerTool(name, schema, handler) { mcpTools.set(name, { schema, handler }); } }, principal(mcpFixture), { db });
    const mcpActionInput = { runId: mcpFixture.runId, taskIndex: 0, operationId: key(),
      command: { kind: 'transfer', amountUnits: '1', recipient: '0x1111111111111111111111111111111111111111', gasLimit: '100000' } };
    const mcpAction = await mcpTools.get('runs.task_action').handler(mcpActionInput);
    const mcpActionRetry = await mcpTools.get('runs.task_action').handler(mcpActionInput);
    const mcpActionResult = JSON.parse(mcpAction.content[0].text);
    const mcpActionRetryResult = JSON.parse(mcpActionRetry.content[0].text);
    assert.equal(mcpActionResult.actionId, mcpActionRetryResult.actionId);
    const mcpState = await mcpTools.get('runs.task_action_status').handler({ runId: mcpFixture.runId, actionId: mcpActionResult.actionId });
    assert.equal(JSON.parse(mcpState.content[0].text).status, 'pending');
    assert.equal(mcpActionRetryResult.replayed, true);
    assert.equal((await observer.query('SELECT count(*)::int AS count FROM oid_run_task_action WHERE run_id=$1', [mcpFixture.runId])).rows[0].count, 1,
      'MCP response-loss retry must persist exactly one admitted command');
    const mcpFinish = await mcpTools.get('runs.finish_task').handler({ runId: mcpFixture.runId, taskIndex: 0,
      operationId: key(), answer: { amountUnits: '1', network: 'eip155:8453', assetId: 'USDC', recipient: '0x1111111111111111111111111111111111111111',
        scheme: 'exact', resourceId: 'resource-mcp', offerId: 'offer-mcp', version: '1', authFields: [] } });
    const mcpFinishResult = JSON.parse(mcpFinish.content[0].text);
    assert.equal(mcpFinish.isError, undefined);
    assert.equal(mcpFinishResult.actionCutoffSequence, '1');
    assert.equal(mcpFinishResult.closureStatus, 'closing');
    const mcpAfterFinish = await mcpTools.get('runs.task_action').handler({ ...mcpActionInput, operationId: key() });
    assert.equal(mcpAfterFinish.isError, true);
    assert.equal(JSON.parse(mcpAfterFinish.content[0].text).error.code, 'TASK_CLOSED');

    const inspectionRun = await seedActionRun(setup, { taskId: 'S2' });
    const inspectionActor = principal(inspectionRun);
    await assert.rejects(service.admitTaskAction(deps, principal(inspectionRun, { grantId: key() }), {
      runId: inspectionRun.runId, taskIndex: 0, operationId: key(), command: { kind: 'inspect_catalog' },
    }), (error) => error.code === 'AGENT_ACCESS_REVOKED');
    const catalogInput = { runId: inspectionRun.runId, taskIndex: 0, operationId: key(), command: { kind: 'inspect_catalog' } };
    const catalogAdmission = await service.admitTaskAction(deps, inspectionActor, catalogInput);
    const catalogRetry = await service.admitTaskAction(deps, inspectionActor, catalogInput);
    assert.equal(catalogAdmission.actionId, catalogRetry.actionId);
    assert.equal(catalogRetry.replayed, true);
    const offerInput = { runId: inspectionRun.runId, taskIndex: 0, operationId: key(),
      command: { kind: 'inspect_offer', resourceId: 'resource-pinned-a', offerId: 'offer-a' } };
    const offerAdmission = await service.admitTaskAction(deps, inspectionActor, offerInput);
    const catalogResponse = {
      catalog: [{ resourceId: 'resource-pinned-a', resourceSha256: hash('pinned-resource-a'), contentType: 'application/json',
        schema: 'fixture-schema-v1', provenance: { classification: 'synthetic-acceptance-fixture' }, offers: [] }],
      freeInspection: true, deliveryState: 'not_delivered',
    };
    const offerResponse = {
      operationId: 'synthetic-inspection-operation', resourceId: 'resource-pinned-a', resourceSha256: hash('pinned-resource-a'),
      contentType: 'application/json', payment: { scheme: 'exact', network: 'eip155:8453', asset: 'USDC', amount: '2500',
        payTo: '0x1111111111111111111111111111111111111111', transferMethod: 'transferWithAuthorization' },
      offers: [{ id: 'offer-a', payment: { scheme: 'exact', network: 'eip155:8453', asset: 'USDC', amount: '2500',
        payTo: '0x1111111111111111111111111111111111111111', transferMethod: 'transferWithAuthorization' } }],
      freeInspection: true, deliveryState: 'not_delivered',
    };
    const catalogReceipt = await service.recordTaskActionReceipt(deps, {
      actionId: catalogAdmission.actionId, status: 'observed', evidenceHash: hash('catalog-inspection-evidence'),
      evidencePath: 'artifacts/runs/task-action-fixture/catalog.json', toolResponse: catalogResponse,
    });
    const offerReceipt = await service.recordTaskActionReceipt(deps, {
      actionId: offerAdmission.actionId, status: 'observed', evidenceHash: hash('offer-inspection-evidence'),
      evidencePath: 'artifacts/runs/task-action-fixture/offer.json', toolResponse: offerResponse,
    });
    const catalogReceiptReplay = await service.recordTaskActionReceipt(deps, {
      actionId: catalogAdmission.actionId, status: 'observed', evidenceHash: hash('catalog-inspection-evidence'),
      evidencePath: 'artifacts/runs/task-action-fixture/catalog.json', toolResponse: catalogResponse,
    });
    const offerReceiptReplay = await service.recordTaskActionReceipt(deps, {
      actionId: offerAdmission.actionId, status: 'observed', evidenceHash: hash('offer-inspection-evidence'),
      evidencePath: 'artifacts/runs/task-action-fixture/offer.json', toolResponse: offerResponse,
    });
    assert.equal(catalogReceipt.receiptRevision, 1);
    assert.equal(offerReceipt.receiptRevision, 1);
    assert.equal(catalogReceiptReplay.replayed, true, 'an exact catalog receipt retry must not append another revision');
    assert.equal(offerReceiptReplay.replayed, true, 'an exact offer receipt retry must not append another revision');
    const catalogState = await service.getTaskActionState(deps, inspectionActor, { runId: inspectionRun.runId, actionId: catalogAdmission.actionId });
    const offerState = await service.getTaskActionState(deps, inspectionActor, { runId: inspectionRun.runId, actionId: offerAdmission.actionId });
    await assert.rejects(service.getTaskActionState(deps, principal(inspectionRun, { grantId: key() }),
      { runId: inspectionRun.runId, actionId: catalogAdmission.actionId }),
    (error) => error.code === 'AGENT_ACCESS_REVOKED');
    assert.equal(catalogState.status, 'observed');
    assert.equal(catalogState.evidencePath, 'artifacts/runs/task-action-fixture/catalog.json');
    assert.deepEqual(catalogState.toolResponse, catalogResponse);
    assert.equal(offerState.status, 'observed');
    assert.equal(offerState.evidencePath, 'artifacts/runs/task-action-fixture/offer.json');
    assert.deepEqual(offerState.toolResponse, offerResponse);
    const storedInspectionRows = await observer.query(`SELECT a.action_sequence::text,a.action_kind,r.receipt_status,r.evidence_path,r.tool_response_hash
      FROM oid_run_task_action a JOIN oid_run_task_action_receipt r ON r.action_id=a.id
      WHERE a.run_id=$1 ORDER BY a.action_sequence`, [inspectionRun.runId]);
    assert.deepEqual(storedInspectionRows.rows.map((row) => [row.action_sequence, row.action_kind, row.receipt_status, row.evidence_path, row.tool_response_hash]), [
      ['1', 'inspect_catalog', 'observed', 'artifacts/runs/task-action-fixture/catalog.json', sha256CanonicalTaskJson(catalogResponse)],
      ['2', 'inspect_offer', 'observed', 'artifacts/runs/task-action-fixture/offer.json', sha256CanonicalTaskJson(offerResponse)],
    ], 'read-only inspection intents and their observations must share the durable task action sequence');
    const storedInspectionHistory = await observer.query(`SELECT r.action_id::text,r.revision,r.evidence_path,r.tool_response_hash
      FROM oid_run_task_action_reconciliation r JOIN oid_run_task_action a ON a.id=r.action_id
      WHERE r.action_id = ANY($1::uuid[]) ORDER BY a.action_sequence,r.revision`,
    [[catalogAdmission.actionId, offerAdmission.actionId]]);
    assert.deepEqual(storedInspectionHistory.rows.map((row) => [row.action_id, row.revision, row.evidence_path, row.tool_response_hash]), [
      [catalogAdmission.actionId, 1, 'artifacts/runs/task-action-fixture/catalog.json', sha256CanonicalTaskJson(catalogResponse)],
      [offerAdmission.actionId, 1, 'artifacts/runs/task-action-fixture/offer.json', sha256CanonicalTaskJson(offerResponse)],
    ], 'receipt history must retain read observation hashes and evidence references');

    const splitRun = await seedActionRun(setup, { taskId: 'M1' });
    const splitActor = principal(splitRun);
    // Synthetic protocol tag only: no active pointer or validated-release claim.
    await setup.query(`INSERT INTO oid_task_release(release_identity,manifest_hash,benchmark_version,benchmark_hash,policy_hash,
        sealed_manifest,validation_evidence)
      SELECT release_identity,manifest_hash,benchmark_version,benchmark_hash,policy_hash,
        '{"participantToolProtocol":"separate_payment_delivery_v2"}'::jsonb,
        '[{"kind":"synthetic_protocol_tag_only"}]'::jsonb FROM oid_benchmark_run WHERE id=$1`, [splitRun.runId]);
    await assert.rejects(service.admitTaskAction(deps, splitActor, { runId: splitRun.runId, taskIndex: 0,
      operationId: key(), command: { kind: 'purchase', resourceId: 'split-resource', offerId: 'split-offer' } }),
    (error) => error.code === 'COMBINED_PURCHASE_UNAVAILABLE');
    await assert.rejects(service.admitTaskAction(deps, inspectionActor, { runId: inspectionRun.runId, taskIndex: 0,
      operationId: key(), command: { kind: 'pay', resourceId: 'split-resource', offerId: 'split-offer', offerReadActionId: offerAdmission.actionId } }),
    (error) => error.code === 'TASK_PAYMENT_PROTOCOL_UNAVAILABLE');
    const splitRead = await service.admitTaskAction(deps, splitActor, { runId: splitRun.runId, taskIndex: 0,
      operationId: key(), command: { kind: 'inspect_offer', resourceId: 'split-resource' } });
    const readOperation = key();
    const splitOffer = { operationId: readOperation, readHandle: { kind: 'offer', operationId: readOperation },
      resourceId: 'split-resource', freeInspection: true, deliveryState: 'not_delivered', offers: [{ id: 'split-offer',
        payment: { scheme: 'exact', network: 'eip155:8453', asset: `0x${'1'.repeat(40)}`,
          amount: '100000', payTo: `0x${'2'.repeat(40)}`, transferMethod: 'eip3009' } }] };
    await service.recordTaskActionReceipt(deps, { actionId: splitRead.actionId, status: 'observed', evidenceHash: hash('split-read'),
      toolResponse: splitOffer });
    const payInput = { runId: splitRun.runId, taskIndex: 0, operationId: key(), command: { kind: 'pay',
      resourceId: 'split-resource', offerId: 'split-offer', offerReadActionId: splitRead.actionId } };
    await assert.rejects(service.admitTaskAction(deps, splitActor, { ...payInput, operationId: key(),
      command: { ...payInput.command, offerReadActionId: offerAdmission.actionId } }),
    (error) => error.code === 'TASK_PAYMENT_REFERENCE_UNAVAILABLE');
    await assert.rejects(service.admitTaskAction(deps, splitActor, { ...payInput, operationId: key(),
      command: { ...payInput.command, offerId: 'uninspected-offer' } }),
    (error) => error.code === 'TASK_PAYMENT_OFFER_NOT_INSPECTED');
    await assert.rejects(service.admitTaskAction(deps, splitActor, { ...payInput, operationId: key(),
      command: { ...payInput.command, acceptedTerms: { amount: '1' } } }),
    (error) => error.code === 'INVALID_TASK_ACTION');
    const splitPay = await service.admitTaskAction(deps, splitActor, payInput);
    assert.equal((await service.admitTaskAction(deps, splitActor, payInput)).actionId, splitPay.actionId);
    const payOperation = key(), payTransaction = `0x${'5'.repeat(64)}`;
    await service.recordTaskActionReceipt(deps, { actionId: splitPay.actionId, status: 'observed', evidenceHash: hash('split-payment'),
      transactionHash: payTransaction, toolResponse: { operationId: payOperation, status: 'payment_confirmed',
        deliveryHandle: payOperation, payment: { transactionHash: payTransaction, receiptStatus: 'success' } } });
    await assert.rejects(service.admitTaskAction(deps, splitActor, { runId: splitRun.runId, taskIndex: 0,
      operationId: key(), command: { kind: 'retrieve', payActionId: splitRead.actionId } }),
    (error) => error.code === 'TASK_PAYMENT_REFERENCE_INVALID');
    const retrieveInput = { runId: splitRun.runId, taskIndex: 0, operationId: key(),
      command: { kind: 'retrieve', payActionId: splitPay.actionId } };
    const splitRetrieve = await service.admitTaskAction(deps, splitActor, retrieveInput);
    assert.equal((await service.admitTaskAction(deps, splitActor, retrieveInput)).actionId, splitRetrieve.actionId);
    const splitRows = await observer.query(`SELECT a.action_kind,a.action_sequence::text,r.receipt_status
      FROM oid_run_task_action a JOIN oid_run_task_action_receipt r ON r.action_id=a.id WHERE a.run_id=$1 ORDER BY a.action_sequence`,
    [splitRun.runId]);
    assert.deepEqual(splitRows.rows, [
      { action_kind: 'inspect_offer', action_sequence: '1', receipt_status: 'observed' },
      { action_kind: 'pay', action_sequence: '2', receipt_status: 'observed' },
      { action_kind: 'retrieve', action_sequence: '3', receipt_status: 'pending' },
    ], 'foreign, fabricated and duplicate requests add no extra payment/retrieval intent');
    await service.finishTask(deps, splitActor, { runId: splitRun.runId, taskIndex: 0, operationId: key() });
    await assert.rejects(service.admitTaskAction(deps, splitActor, { ...retrieveInput, operationId: key() }),
    (error) => error.code === 'TASK_CLOSED');

    const deadlineRun = await seedActionRun(setup, { taskId: 'S1', deadline: '-1 second' });
    const expired = await service.closeExpiredTaskActions(deps, 10);
    assert.ok(expired.closed >= 1);
    const deadlineRow = await observer.query(`SELECT action_cutoff_sequence::text,closure_status,closure_reason,closed_at IS NOT NULL AS has_closed_at
      FROM oid_run_task WHERE run_id=$1`, [deadlineRun.runId]);
    assert.deepEqual(deadlineRow.rows[0], {
      action_cutoff_sequence: '0', closure_status: 'closed', closure_reason: 'task_deadline', has_closed_at: true,
    });

    const unknownRun = await seedActionRun(setup, { taskId: 'S3' });
    const unknownAction = await service.admitTaskAction(deps, principal(unknownRun), {
      runId: unknownRun.runId, taskIndex: 0, operationId: key(), command: { kind: 'purchase', resourceId: 'resource-two', offerId: 'offer-two' },
    });
    await service.recordTaskActionReceipt(deps, {
      actionId: unknownAction.actionId, status: 'unknown', evidenceHash: hash('unknown-first'), transactionHash: `0x${'2'.repeat(64)}`,
    });
    await assert.rejects(service.admitTaskAction(deps, principal(unknownRun), {
      runId: unknownRun.runId, taskIndex: 0, operationId: key(), command: { kind: 'wrap', amountWei: '1', gasLimit: '100000' },
    }), (error) => error.code === 'TASK_RECONCILIATION_REQUIRED');
    const unknownCutoff = await service.finishTask(deps, principal(unknownRun), { runId: unknownRun.runId, taskIndex: 0, operationId: key() });
    assert.equal(unknownCutoff.closureStatus, 'unknown', 'unknown effects must not be advertised as reconciled closure');
    await assert.rejects(service.recordTaskActionReceipt(deps, {
      actionId: unknownAction.actionId, status: 'observed', evidenceHash: hash('resolved-to-other-tx'), transactionHash: `0x${'3'.repeat(64)}`,
    }), (error) => error.code === 'ACTION_RECEIPT_CONFLICT');
    for (const status of ['unknown', 'observed', 'rejected_before_execution']) {
      await assert.rejects(service.recordTaskActionReceipt(deps, {
        actionId: unknownAction.actionId, status, evidenceHash: hash(`erased-original-tx-${status}`),
      }), (error) => error.code === 'ACTION_RECEIPT_CONFLICT');
    }
    for (const replacement of [null, `0x${'3'.repeat(64)}`]) {
      await assert.rejects(setup.query(`UPDATE oid_run_task_action_receipt
        SET receipt_revision=receipt_revision+1,transaction_hash=$2 WHERE action_id=$1`, [unknownAction.actionId, replacement]),
      (error) => error.code === '55000');
    }
    const retainedUnknown = await observer.query(
      'SELECT receipt_status,transaction_hash,receipt_revision FROM oid_run_task_action_receipt WHERE action_id=$1', [unknownAction.actionId]);
    assert.deepEqual(retainedUnknown.rows, [{ receipt_status: 'unknown', transaction_hash: `0x${'2'.repeat(64)}`, receipt_revision: 1 }]);
    const recovered = await service.recordTaskActionReceipt(deps, {
      actionId: unknownAction.actionId, status: 'observed', evidenceHash: hash('recovered-original'), transactionHash: `0x${'2'.repeat(64)}`,
    });
    assert.equal(recovered.closureStatus, 'closed', 'a later receipt revision resolves uncertainty without replaying the admitted command');
    const revisions = await observer.query('SELECT revision,receipt_status FROM oid_run_task_action_reconciliation WHERE action_id=$1 ORDER BY revision', [unknownAction.actionId]);
    assert.deepEqual(revisions.rows, [{ revision: 1, receipt_status: 'unknown' }, { revision: 2, receipt_status: 'observed' }]);

    const unboundUnknownRun = await seedActionRun(setup, { taskId: 'S3' });
    const unboundUnknown = await service.admitTaskAction(deps, principal(unboundUnknownRun), {
      runId: unboundUnknownRun.runId, taskIndex: 0, operationId: key(),
      command: { kind: 'purchase', resourceId: 'resource-two', offerId: 'offer-two' },
    });
    const unboundEvidence = hash('same-observation-before-transaction-binding');
    const unboundPath = 'artifacts/runs/task-action-fixture/purchase-observation.json';
    const unboundResponse = { operationId: key(), outcome: 'unknown', deliveryState: 'not_delivered' };
    await service.recordTaskActionReceipt(deps, {
      actionId: unboundUnknown.actionId, status: 'unknown', evidenceHash: unboundEvidence,
      evidencePath: unboundPath, toolResponse: unboundResponse,
    });
    const enrichedUnknown = await service.recordTaskActionReceipt(deps, {
      actionId: unboundUnknown.actionId, status: 'unknown', evidenceHash: unboundEvidence,
      evidencePath: unboundPath, transactionHash: `0x${'4'.repeat(64)}`, toolResponse: unboundResponse,
    });
    assert.equal(enrichedUnknown.receiptRevision, 2, 'adding a newly observed transaction identity must append a durable receipt revision');
    assert.equal(enrichedUnknown.replayed, false);
    const enrichedReplay = await service.recordTaskActionReceipt(deps, {
      actionId: unboundUnknown.actionId, status: 'unknown', evidenceHash: unboundEvidence,
      evidencePath: unboundPath, transactionHash: `0x${'4'.repeat(64)}`, toolResponse: unboundResponse,
    });
    assert.equal(enrichedReplay.receiptRevision, 2);
    assert.equal(enrichedReplay.replayed, true, 'an exact retry of the enriched observation is idempotent');
    const enrichedRows = await observer.query(`SELECT revision,receipt_status,evidence_path,transaction_hash,tool_response_hash
      FROM oid_run_task_action_reconciliation WHERE action_id=$1 ORDER BY revision`, [unboundUnknown.actionId]);
    assert.deepEqual(enrichedRows.rows.map((row) => [row.revision, row.receipt_status, row.evidence_path, row.transaction_hash, row.tool_response_hash]), [
      [1, 'unknown', unboundPath, null, sha256CanonicalTaskJson(unboundResponse)],
      [2, 'unknown', unboundPath, `0x${'4'.repeat(64)}`, sha256CanonicalTaskJson(unboundResponse)],
    ], 'an enriched unknown observation keeps its original row and appends the transaction binding');

    return { status: 'passed', fullScenarioAcceptance: false, boundary: 'Actual PostgreSQL action/cutoff store with synthetic principals and observer receipts',
      observations: ['task_scoped_command_outbox', 'monotonic_per_task_action_sequence', 'exact_grant_and_generation_checks',
        'idempotent_concurrent_action_admission', 'changed_payload_conflict', 'receipt_contiguous_cursor',
        'structured_answer_shape_and_hash', 'single_finish_cutoff_and_retry', 'post_cutoff_action_rejected',
        'deadline_cutoff_across_worker_call', 'unknown_cutoff_not_closed', 'unknown_resolution_revision_without_action_replay',
        'immutable_action_intent', 'http_action_finish_routes', 'mcp_action_finish_handlers', 'route_retry_single_command',
        'http_and_mcp_command_status_does_not_invent_effects', 'unknown_effect_blocks_new_commands_until_reconciled',
        'normal_tool_response_retained_in_scoped_receipt_projection', 'evidence_path_and_response_hash_persist_with_receipt',
        'durable_pinned_read_action_sequence_and_idempotency', 'unknown_receipt_cannot_erase_original_transaction',
        'unknown_receipt_enrichment_appends_transaction_identity', 'read_action_receipt_replay_is_idempotent',
        'read_action_receipt_and_history_are_grant_scoped', 'versioned_split_payment_blocks_combined_shortcut',
        'payment_references_only_current_observed_offer', 'retrieval_references_original_confirmed_payment',
        'split_payment_cutoff_and_durable_sequence', 'active_task_preparation_overrides_run_environment_pointer',
        'prior_task_action_rejected_after_successor_starts', 'wrong_task_preparation_and_environment_or_generation_binding_rejected'],
      runIds: [fixture.runId, staleTaskFixture.runId, wrongPreparation.runId, wrongGeneration.runId, wrongEnvironment.runId,
        routeFixture.runId, mcpFixture.runId, inspectionRun.runId, splitRun.runId, deadlineRun.runId, unknownRun.runId, unboundUnknownRun.runId] };
  } finally { await client.end(); await setup.end(); await observer.end(); }
}
