import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { writeFile } from 'node:fs/promises';
import { basename, join } from 'node:path';
import postgres from 'postgres';
import { drizzle } from 'drizzle-orm/postgres-js';
import { createMcpHandler, McpServer } from '@modelcontextprotocol/server';
import type { OwnerDatabase } from './db.js';
import type { AgentPrincipal } from './agents.js';
import type { TaskReleaseQuerySource } from './task-release.js';
import { sha256CanonicalTaskJson } from './task-release.js';
import { registerRunIntentMcpTools } from './run-routes.js';
import { AGENT_MCP_INPUT_ELEMENTS } from './mcp-input-bounds.js';
import { addFixture } from './task-run-completion.test-fixture.js';

const enabled = process.env.OID_BRL_SC016_PG_TEST === '1';

// AICODE-NOTE: Real MCP JSON-RPC handler and isolated PostgreSQL rows, with synthetic
// release/evaluation inputs. This proves read/release behavior, not benchmark scoring.
test('BRL-SC-016 releases only persisted scoped feedback at the selected mode boundary', { skip: !enabled }, async () => {
  const sourceUrlValue = process.env.OID_DATABASE_URL;
  const observerUrlValue = process.env.OID_OBSERVER_DATABASE_URL;
  assert.ok(sourceUrlValue);
  assert.ok(observerUrlValue);
  const sourceUrl = new URL(sourceUrlValue);
  const observerSourceUrl = new URL(observerUrlValue);
  assert.equal(sourceUrl.hostname, 'postgres');
  assert.equal(sourceUrl.username, 'oid_owner');
  assert.equal(sourceUrl.pathname, '/owner_identity');
  assert.equal(observerSourceUrl.hostname, 'postgres');
  assert.equal(observerSourceUrl.username, 'oid_observer');
  const databaseName = 'oid_feedback_' + randomUUID().replaceAll('-', '');
  assert.match(databaseName, /^oid_feedback_[a-f0-9]{32}$/);
  const databaseUrl = new URL(sourceUrl);
  const observerUrl = new URL(observerSourceUrl);
  databaseUrl.pathname = '/' + databaseName;
  observerUrl.pathname = '/' + databaseName;
  const admin = postgres(sourceUrl.href, { max: 1, connect_timeout: 10 });
  const client = postgres(databaseUrl.href, { max: 4, connect_timeout: 10 });
  const observer = postgres(observerUrl.href, { max: 1, connect_timeout: 10 });
  const db = drizzle(client) as unknown as OwnerDatabase;
  let created = false;
  const runIds: string[] = [];
  const capture: Record<string, unknown> = {
    schemaVersion: 'benchmark-run-lifecycle-runtime-evidence/v1',
    scenarioId: 'BRL-SC-016',
    boundary: 'isolated_postgresql_and_actual_mcp_json_rpc_handler',
    cases: {},
  };

  async function fixture(options: Parameters<typeof addFixture>[1] = {}) {
    const f = await addFixture(client, { includeEvaluation: false, fence: false,
      overallDeadlineSecondsFromNow: 600, ...options });
    runIds.push(f.runId);
    const grantId = randomUUID();
    const resource = 'https://bench.example/api/agent/mcp';
    await client`INSERT INTO oid_agent_access_grant(id,owner_id,agent_id,operation_id,resource,role,access_generation,expires_at)
      VALUES(${grantId},${f.ownerId},${f.agentId},${randomUUID()},${resource},'agent',1,clock_timestamp()+interval '1 hour')`;
    const principal: AgentPrincipal = { ownerId: f.ownerId, agentId: f.agentId, grantId,
      credentialId: randomUUID(), resource, role: 'agent', accessGeneration: 1,
      accessRevision: 1, policyRevision: 1,
      permissions: { training: true, ranked: false, forumMessages: false, customTopics: false } };
    const record = { ...f.record, manifest: { ...f.record.manifest,
      executionIdentity: { ...f.record.manifest.executionIdentity, localChainId: 31337,
        localNetwork: 'synthetic', assets: [], contracts: [] },
      cases: { ...f.record.manifest.cases,
        training: f.record.manifest.cases.training.map((row) => ({ ...row, mandatoryRules: [] })) } } };
    const taskReleaseSource: TaskReleaseQuerySource = {
      async getActiveAdmissionRelease() { return null; },
      async getValidatedReleaseRecord() { return record as never; },
    };
    return { ...f, principal, taskReleaseSource };
  }

  function caller(principal: AgentPrincipal, taskReleaseSource: TaskReleaseQuerySource) {
    const handler = createMcpHandler(() => {
      const server = new McpServer({ name: 'BRL-SC-016 feedback release test', version: '1.0.0' },
        { supportedProtocolVersions: ['2025-06-18'], maxToolInputElements: AGENT_MCP_INPUT_ELEMENTS });
      registerRunIntentMcpTools(server, principal, { db, taskReleaseSource } as never);
      return server;
    });
    return {
      handler,
      async call(toolName: string, args: Record<string, unknown>) {
        const startedAt = Date.now();
        const requestBody = { jsonrpc: '2.0', id: 1, method: 'tools/call',
          params: { name: toolName, arguments: args } };
        const response = await handler.fetch(new Request('http://127.0.0.1/api/agent/mcp', {
          method: 'POST', headers: { 'content-type': 'application/json',
            accept: 'application/json, text/event-stream', 'mcp-protocol-version': '2025-06-18' },
          body: JSON.stringify(requestBody),
        }), { parsedBody: requestBody });
        const responseText = await response.text();
        const eventLine = responseText.split(/\r?\n/).find((line) => line.startsWith('data:'));
        assert.ok(eventLine, 'MCP call must return its JSON-RPC response in the HTTP exchange');
        const envelope = JSON.parse(eventLine.slice(5).trim()) as Record<string, any>;
        const result = envelope.result && typeof envelope.result === 'object' ? envelope.result as Record<string, any> : null;
        let body: unknown = result?.structuredContent;
        if (body === undefined && typeof result?.content?.[0]?.text === 'string') {
          try { body = JSON.parse(result.content[0].text); } catch { body = { text: result.content[0].text }; }
        }
        if (body === undefined && envelope.error) body = { error: envelope.error };
        return { status: response.status, elapsedMs: Date.now() - startedAt,
          request: { toolName, arguments: args }, body,
          isError: result?.isError === true, protocolError: envelope.error ?? null };
      },
      close: () => handler.close(),
    };
  }

  async function snapshot(ids: string[]) {
    await observer.unsafe('BEGIN READ ONLY');
    try {
      const identityRows = await observer.unsafe(`SELECT current_user AS role,
          current_setting('transaction_read_only') AS transaction_read_only,
          current_database() AS database`);
      assert.equal(identityRows[0]?.role, 'oid_observer');
      assert.equal(identityRows[0]?.transaction_read_only, 'on');
      const values = [ids];
      const runs = await observer.unsafe(`SELECT id::text AS id,owner_id::text AS owner_id,agent_id::text AS agent_id,
          mode,status,task_ids,terminal_reason FROM oid_benchmark_run WHERE id=ANY($1::uuid[]) ORDER BY id`, values);
      const tasks = await observer.unsafe(`SELECT run_id::text AS run_id,task_index,task_id,status,closure_reason,
          closure_status FROM oid_run_task WHERE run_id=ANY($1::uuid[]) ORDER BY run_id,task_index`, values);
      const evaluations = await observer.unsafe(`SELECT run_id::text AS run_id,task_index,task_id,result_hash,result_json
          FROM oid_run_task_evaluation WHERE run_id=ANY($1::uuid[]) ORDER BY run_id,task_index`, values);
      const actionCounts = await observer.unsafe(`SELECT run_id::text AS run_id,count(*)::int AS count
          FROM oid_run_task_action WHERE run_id=ANY($1::uuid[]) GROUP BY run_id ORDER BY run_id`, values);
      const events = await observer.unsafe(`SELECT run_id::text AS run_id,sequence::text AS sequence,event_type,payload_hash
          FROM oid_run_event WHERE run_id=ANY($1::uuid[]) ORDER BY run_id,sequence`, values);
      return { observer: identityRows[0], database: { runs, tasks, evaluations,
        actionCounts, events } };
    } finally { await observer.unsafe('COMMIT'); }
  }

  function sameReadState(before: any, after: any) {
    return JSON.stringify(before?.database) === JSON.stringify(after?.database);
  }

  async function insertClosedEvaluation(f: Awaited<ReturnType<typeof fixture>>, taskIndex: number,
    taskId: string, result: Record<string, unknown>, insertTask: boolean) {
    const taskCase = f.record.manifest.cases.ranked.find((row: { taskId: string }) => row.taskId === taskId);
    assert.ok(taskCase, `synthetic release contains ${taskId}`);
    if (insertTask) await client`INSERT INTO oid_run_task(run_id,task_index,task_id,status,started_at,deadline_at,finished_at)
      VALUES(${f.runId},${taskIndex},${taskId},'queued',clock_timestamp()-interval '2 minutes',
        clock_timestamp()+interval '5 minutes',NULL)`;
    const current = await client`SELECT closure_id FROM oid_run_task WHERE run_id=${f.runId} AND task_index=${taskIndex}`;
    assert.equal(current.length, 1);
    const needsClosure = current[0]!.closure_id == null;
    const closureId = current[0]!.closure_id ?? randomUUID();
    const payloadHash = sha256CanonicalTaskJson({ runId: f.runId, taskIndex, taskId, closureId });
    if (needsClosure) {
      await client`INSERT INTO oid_run_task_closure(id,run_id,task_index,operation_id,payload_hash,reason,
          action_cutoff_sequence,actor_kind,owner_id,agent_id)
        VALUES(${closureId},${f.runId},${taskIndex},NULL,${payloadHash},'agent_finish',0,'coordinator',${f.ownerId},${f.agentId})`;
    }
    const terminalStatus = result.outcome === 'failed' ? 'failed' : 'completed';
    if (needsClosure) {
      await client`UPDATE oid_run_task SET task_id=${taskId},status=${terminalStatus},finished_at=clock_timestamp(),
          closure_id=${closureId},closure_status='closed',action_cutoff_sequence=0,closure_reason='agent_finish',
          closure_payload_hash=${payloadHash},closed_at=clock_timestamp()
        WHERE run_id=${f.runId} AND task_index=${taskIndex}`;
    } else {
      await client`UPDATE oid_run_task SET task_id=${taskId},status=${terminalStatus},finished_at=clock_timestamp()
        WHERE run_id=${f.runId} AND task_index=${taskIndex}`;
    }
    const input = { schemaVersion: 'synthetic-feedback-input/v1', runId: f.runId, taskIndex, taskId };
    const inputHash = sha256CanonicalTaskJson(input);
    const resultHash = sha256CanonicalTaskJson(result);
    await client`INSERT INTO oid_run_task_evaluation(run_id,task_index,closure_id,task_id,release_identity,manifest_hash,
        case_hash,rubric_hash,input_hash,result_hash,evaluator_source_hash,observation_evidence,result_json,input_json)
      VALUES(${f.runId},${taskIndex},${closureId},${taskId},${f.record.releaseIdentity},${f.record.manifestHash},
        ${taskCase.caseHash},${taskCase.rubricHash},${inputHash},${resultHash},${'e'.repeat(64)},
        ${JSON.stringify({ schemaVersion: 'synthetic-feedback-evidence/v1' })}::text::jsonb,
        ${JSON.stringify(result)}::text::jsonb,${JSON.stringify(input)}::text::jsonb)`;
  }

  function mcpBody(record: any): Record<string, any> {
    return record?.body && typeof record.body === 'object' ? record.body : {};
  }
  function findSensitiveKey(value: unknown): boolean {
    if (Array.isArray(value)) return value.some(findSensitiveKey);
    if (!value || typeof value !== 'object') return false;
    return Object.entries(value).some(([key, child]) =>
      /^(?:referencePath|referenceSolution|expectedAnswer|solution|taskCase|observations|toolCalls|journal|transcript)$/i.test(key)
        || findSensitiveKey(child));
  }

  try {
    await admin.unsafe(`CREATE DATABASE "${databaseName}" TEMPLATE template0`);
    created = true;
    const migration = spawnSync('pnpm', ['--filter', '@web-agent-bench/owner-identity', 'migrate'],
      { cwd: '/workspace', env: { ...process.env, OID_DATABASE_URL: databaseUrl.href }, encoding: 'utf8' });
    assert.equal(migration.status, 0, 'isolated BRL-SC-016 schema migration');
    await admin.unsafe(`GRANT CONNECT ON DATABASE "${databaseName}" TO oid_observer`);
    await client.unsafe('GRANT USAGE ON SCHEMA public TO oid_observer');
    await client.unsafe('GRANT SELECT ON ALL TABLES IN SCHEMA public TO oid_observer');
    await client.unsafe('ALTER DEFAULT PRIVILEGES FOR ROLE oid_owner IN SCHEMA public GRANT SELECT ON TABLES TO oid_observer');

    const trainingBeforeFixture = await fixture({ actionOpen: true, multiTask: true });
    const trainingBeforeCaller = caller(trainingBeforeFixture.principal, trainingBeforeFixture.taskReleaseSource);
    try {
      const before = await snapshot([trainingBeforeFixture.runId]);
      const response = await trainingBeforeCaller.call('runs.current_task', { runId: trainingBeforeFixture.runId });
      const after = await snapshot([trainingBeforeFixture.runId]);
      const body = mcpBody(response);
      assert.equal(response.status, 200);
      assert.equal(response.isError, false);
      assert.equal(body.task?.taskId, 'S1');
      assert.equal(Object.hasOwn(body, 'feedback'), false, 'Training feedback is absent before an evaluation is stored');
      assert.ok(response.elapsedMs <= 10_000);
      assert.ok(sameReadState(before, after), 'the real MCP read leaves task, result and event rows unchanged');
      (capture.cases as any).trainingBeforeEvaluation = { response, databaseBefore: before, databaseAfter: after };
      const traceAttempt = await trainingBeforeCaller.call('runs.current_task',
        { runId: trainingBeforeFixture.runId, includeJournal: true });
      assert.ok(traceAttempt.isError || traceAttempt.protocolError);
      assert.equal(Object.hasOwn(mcpBody(traceAttempt), 'feedback'), false);
      (capture.cases as any).internalTraceRequest = traceAttempt;
    } finally { await trainingBeforeCaller.close(); }

    const trainingAfterFixture = await fixture({ multiTask: true, includeEvaluation: true });
    const trainingResult = trainingAfterFixture.result as Record<string, any>;
    await client`UPDATE oid_benchmark_run SET task_ids=${['S1', 'M1', 'S3']} WHERE id=${trainingAfterFixture.runId}`;
    const closedTrainingResult = { taskId: 'S3', status: 'known', outcome: 'failed',
      credit: { numerator: '0', denominator: '1' }, mandatoryViolation: null,
      unknownReasons: [], operatingExpenseUsdcUnits: '0' };
    await insertClosedEvaluation(trainingAfterFixture, 2, 'S3', closedTrainingResult, true);
    const trainingCaller = caller(trainingAfterFixture.principal, trainingAfterFixture.taskReleaseSource);
    try {
      const before = await snapshot([trainingAfterFixture.runId]);
      const response = await trainingCaller.call('runs.current_task', { runId: trainingAfterFixture.runId });
      const after = await snapshot([trainingAfterFixture.runId]);
      const body = mcpBody(response);
      assert.equal(response.status, 200);
      assert.equal(body.run?.status, 'running');
      assert.equal(body.task, null);
      assert.deepEqual(body.feedback?.map((row: any) => row.taskId), ['S1']);
      assert.equal(body.feedback[0]?.status, trainingResult.status);
      assert.deepEqual(body.feedback[0]?.credit, trainingResult.credit);
      assert.equal(body.feedback[0]?.diagnostic?.taskState, 'active',
        'Training feedback is released as soon as the evaluation is stored, without waiting for later task terminalization');
      assert.ok((before.database.evaluations as any[]).some((row) => row.task_id === 'S3'),
        'the adversarial closed Training result is durably present in PostgreSQL');
      assert.ok(!body.feedback.some((row: any) => row.taskId === 'S3'));
      assert.ok(sameReadState(before, after), 'feedback reads do not rewrite or regrade stored outcomes');
      assert.equal(findSensitiveKey(body.feedback), false);
      (capture.cases as any).trainingAfterEvaluation = { response, databaseBefore: before, databaseAfter: after };
    } finally { await trainingCaller.close(); }

    const rankedOpenFixture = await fixture({ multiTask: true, includeEvaluation: true });
    await client`UPDATE oid_agent_policy SET ranked=true WHERE agent_id=${rankedOpenFixture.agentId}`;
    await client`UPDATE oid_run_launch_intent SET mode='ranked' WHERE id=(SELECT intent_id FROM oid_benchmark_run WHERE id=${rankedOpenFixture.runId})`;
    await client`UPDATE oid_benchmark_run SET mode='ranked' WHERE id=${rankedOpenFixture.runId}`;
    const rankedOpenResult = rankedOpenFixture.result as Record<string, any>;
    await client`UPDATE oid_run_task SET status=${rankedOpenResult.outcome === 'failed' ? 'failed' : 'completed'},
        finished_at=clock_timestamp() WHERE run_id=${rankedOpenFixture.runId} AND task_index=0`;
    const rankedCaller = caller(rankedOpenFixture.principal, rankedOpenFixture.taskReleaseSource);
    try {
      const before = await snapshot([rankedOpenFixture.runId]);
      const response = await rankedCaller.call('runs.current_task', { runId: rankedOpenFixture.runId });
      const after = await snapshot([rankedOpenFixture.runId]);
      assert.equal(response.status, 200);
      assert.equal(mcpBody(response).run?.terminal, false);
      assert.equal(Object.hasOwn(mcpBody(response), 'feedback'), false,
        'Ranked scores stay withheld while the run is nonterminal even when an evaluation row exists');
      assert.ok((before.database.evaluations as any[]).some((row) => row.run_id === rankedOpenFixture.runId));
      assert.ok(sameReadState(before, after));
      (capture.cases as any).rankedBeforeTermination = { response, databaseBefore: before, databaseAfter: after };
      const scoreAttempt = await rankedCaller.call('runs.current_task',
        { runId: rankedOpenFixture.runId, includeScores: true });
      assert.ok(scoreAttempt.isError || scoreAttempt.protocolError);
      assert.equal(Object.hasOwn(mcpBody(scoreAttempt), 'feedback'), false);
      (capture.cases as any).rankedEarlyScoreRequest = scoreAttempt;
    } finally { await rankedCaller.close(); }

    const rankedUnknownFixture = await fixture({ multiTask: true });
    await client`UPDATE oid_agent_policy SET ranked=true WHERE agent_id=${rankedUnknownFixture.agentId}`;
    await client`UPDATE oid_run_launch_intent SET mode='ranked',task_ids=${['S3', 'M2']} WHERE id=(SELECT intent_id FROM oid_benchmark_run WHERE id=${rankedUnknownFixture.runId})`;
    await client`UPDATE oid_benchmark_run SET mode='ranked',task_ids=${['S3', 'M2']},status='unknown',
        terminal_reason='coordinator_evaluation_unknown',cancellation_reason='coordinator_evaluation_unknown',
        finished_at=clock_timestamp() WHERE id=${rankedUnknownFixture.runId}`;
    const rankedKnownResult = { taskId: 'S3', status: 'known', outcome: 'failed',
      credit: { numerator: '0', denominator: '1' }, mandatoryViolation: null,
      unknownReasons: [], operatingExpenseUsdcUnits: '0' };
    await insertClosedEvaluation(rankedUnknownFixture, 0, 'S3', rankedKnownResult, false);
    await client`UPDATE oid_run_task SET task_id='M2' WHERE run_id=${rankedUnknownFixture.runId} AND task_index=1`;
    const rankedFinalCaller = caller(rankedUnknownFixture.principal, rankedUnknownFixture.taskReleaseSource);
    try {
      const before = await snapshot([rankedUnknownFixture.runId]);
      const response = await rankedFinalCaller.call('runs.current_task', { runId: rankedUnknownFixture.runId });
      const after = await snapshot([rankedUnknownFixture.runId]);
      const body = mcpBody(response);
      assert.equal(response.status, 200);
      assert.equal(body.run?.status, 'unknown');
      assert.equal(body.run?.terminal, true);
      assert.equal(body.task, null);
      assert.deepEqual(body.feedback?.map((row: any) => row.taskId), ['S3', 'M2']);
      assert.deepEqual(body.feedback[0], { taskId: 'S3', status: 'known', outcome: 'failed',
        credit: { numerator: '0', denominator: '1' }, reason: 'goal_unmet' });
      assert.deepEqual(body.feedback[1], { taskId: 'M2', status: 'unknown', outcome: 'unknown',
        credit: null, reason: 'not_issued' });
      assert.ok(sameReadState(before, after), 'terminal feedback reads do not invoke grading or change persisted evidence');
      assert.equal(findSensitiveKey(body), false);
      (capture.cases as any).rankedUnknownTerminal = { response, databaseBefore: before, databaseAfter: after };
    } finally { await rankedFinalCaller.close(); }

    const foreignFixture = await fixture();
    const foreignCaller = caller(trainingBeforeFixture.principal, trainingBeforeFixture.taskReleaseSource);
    try {
      const response = await foreignCaller.call('runs.current_task', { runId: foreignFixture.runId });
      assert.equal(response.status, 200);
      assert.equal(response.isError, true);
      assert.equal(mcpBody(response).error?.code, 'RUN_NOT_FOUND');
      assert.equal(Object.hasOwn(mcpBody(response), 'feedback'), false);
      (capture.cases as any).foreignRunRequest = response;
    } finally { await foreignCaller.close(); }

    capture.database = await snapshot(runIds);
    capture.status = 'verified';
    const captureDirectory = process.env.OID_BRL_SC016_CAPTURE_DIR;
    if (captureDirectory) {
      assert.ok(basename(captureDirectory).startsWith('brl-sc016-'), 'capture output is restricted to the dedicated temp directory');
      await writeFile(join(captureDirectory, 'runtime-evidence.json'), JSON.stringify(capture, null, 2) + '\n', { flag: 'wx' });
    }
  } finally {
    await observer.end({ timeout: 5 });
    await client.end({ timeout: 5 });
    if (created) await admin.unsafe(`DROP DATABASE "${databaseName}" WITH (FORCE)`);
    await admin.end({ timeout: 5 });
  }
});
