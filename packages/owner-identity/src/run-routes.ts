import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import type { AgentPrincipal } from "./agents.js";
import type { OwnerDatabase } from "./db.js";
import { HttpError } from "./http-error.js";
import { getCurrentAgentTask, type CurrentTaskDependencies } from "./task-issuance.js";
import { admitTaskAction, finishTask, getTaskActionState, TaskActionCommandSchema } from "./task-action-service.js";
import { getOwnerRunFeedback } from "./task-feedback.js";
import {
  acceptLaunchIntent,
  cancelLaunchIntent,
  createLaunchIntent,
  getLaunchIntent,
  getRunCatalog,
  listLaunchIntents,
  listOwnerRuns,
  requestRunCancellation,
  type RunServiceDependencies
} from "./run-service.js";

export interface RunOwnerContext {
  owner: { id: string; admissionStatus?: string };
}

export interface RunRouteDependencies extends RunServiceDependencies {
  taskReleaseSource?: CurrentTaskDependencies["taskReleaseSource"];
  db: OwnerDatabase;
  publicOrigin: string;
  /** Configured API-listener hosts; omitted dependency keeps legacy public-origin-only behavior. */
  agentRequestHosts?: ReadonlySet<string>;
  agentRateLimitMax?: number;
  resolveOwner(request: FastifyRequest): Promise<RunOwnerContext>;
  resolveAgentPrincipal(bearer: string): Promise<AgentPrincipal | undefined>;
  requireOrigin(request: FastifyRequest): Promise<void>;
  rateLimit(request: FastifyRequest, group: string, limit: number): Promise<void>;
  rateLimitMax: number;
}

function runAgentHostAllowed(request: FastifyRequest, deps: RunRouteDependencies): boolean {
  const host = request.headers.host?.toLowerCase();
  const allowedHosts = deps.agentRequestHosts ?? new Set([new URL(deps.publicOrigin).host.toLowerCase()]);
  return host !== undefined && allowedHosts.has(host);
}

function uuid(value: unknown, field: string): string {
  if (typeof value !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)) {
    throw new HttpError(400, `INVALID_${field.toUpperCase()}`, `${field} must be a UUID`);
  }
  return value;
}

function sendError(reply: FastifyReply, error: unknown) {
  if (error instanceof HttpError) {
    return reply.code(error.status).header("Cache-Control", "no-store").send({ error: { code: error.code, message: error.message } });
  }
  return reply.code(500).header("Cache-Control", "no-store").send({ error: { code: "INTERNAL_ERROR", message: "The request could not be completed" } });
}

function sendAgentError(reply: FastifyReply, error: unknown, deps: RunRouteDependencies) {
  if (error instanceof HttpError) {
    const response = reply.code(error.status).header("Cache-Control", "no-store");
    if (error.status === 401) {
      response.header("WWW-Authenticate", `Bearer resource_metadata="${deps.publicOrigin}/.well-known/oauth-protected-resource/api/agent", scope="agent:operate"`);
    }
    return response.send({ error: { code: error.code, message: error.message } });
  }
  return reply.code(500).header("Cache-Control", "no-store").send({ error: { code: "INTERNAL_ERROR", message: "The request could not be completed" } });
}

async function ownerContext(request: FastifyRequest, deps: RunRouteDependencies) {
  const context = await deps.resolveOwner(request);
  if (context.owner.admissionStatus !== undefined && context.owner.admissionStatus !== "admitted") {
    throw new HttpError(403, "OWNER_NOT_ADMITTED", "Owner admission is required");
  }
  return context;
}

async function authorizedRunAgent(request: FastifyRequest, deps: RunRouteDependencies): Promise<AgentPrincipal> {
  const limit = deps.agentRateLimitMax ?? deps.rateLimitMax;
  await deps.rateLimit(request, "run-task-operation-ip", limit);
  if (!runAgentHostAllowed(request, deps)) {
    throw new HttpError(421, "MISDIRECTED_REQUEST", "The request host does not match the configured API origin");
  }
  if (request.headers.origin !== undefined && request.headers.origin !== deps.publicOrigin) {
    throw new HttpError(403, "ORIGIN_NOT_ALLOWED", "The request origin is not allowed");
  }
  const principal = await deps.resolveAgentPrincipal(agentBearer(request));
  if (!principal) throw new HttpError(401, "UNAUTHORIZED", "A current agent credential is required");
  await deps.rateLimit(request, `run-task-operation-${principal.credentialId}`, limit);
  return principal;
}

function agentBearer(request: FastifyRequest): string {
  const authorization = request.headers.authorization;
  const match = typeof authorization === "string" ? /^Bearer ([^\s]{1,8192})$/.exec(authorization) : null;
  if (!match) throw new HttpError(401, "UNAUTHORIZED", "A valid agent bearer credential is required");
  return match[1]!;
}

function makeAcceptResultSchema() {
  return z.object({
    run: z.object({
      id: z.string(), intentId: z.string(), agentId: z.string(), mode: z.enum(["training", "ranked"]),
      taskIds: z.array(z.string()), benchmarkVersion: z.string(), manifestHash: z.string(), benchmarkHash: z.string(), policyHash: z.string(),
      successorPreparationPolicyVersion: z.string().nullable(), successorPreparationTimeoutSeconds: z.number().int().nullable(),
      quotePrice: z.string(), cashCeiling: z.string(), status: z.enum(["queued", "preparing", "running", "cancellation_requested", "cancelled", "expired", "completed", "failed", "unknown", "disqualified"]),
      queuedAt: z.string(), queueDeadline: z.string(), startedAt: z.string().nullable(), overallDeadline: z.string().nullable(), finishedAt: z.string().nullable(),
      terminalReason: z.string().nullable(), cancellationReason: z.string().nullable(), cancellationRequestedAt: z.string().nullable(),
      cancellationEvidenceHash: z.string().nullable()
    }),
    replayed: z.boolean()
  });
}

/** Register owner REST routes and a matching-agent HTTP acceptance route. */
export function registerRunRoutes(app: FastifyInstance, deps: RunRouteDependencies): void {
  const createIntentBody = z.object({
    operationId: z.string().regex(/^[A-Za-z0-9_-]{12,128}$/),
    agentId: z.string().uuid(),
    mode: z.enum(["training", "ranked"]),
    taskIds: z.array(z.string().min(1).max(8)).min(1).max(12),
    cashCeiling: z.string().regex(/^(?:0|[1-9][0-9]{0,77})(?:\.[0-9]{1,6})?$/),
    expectedReleaseIdentity: z.string().min(1).max(128),
    expectedManifestHash: z.string().regex(/^[0-9a-f]{64}$/i),
    expectedQuotePrice: z.string().regex(/^(?:0|[1-9][0-9]{0,77})(?:\.[0-9]{1,6})?$/)
  }).strict();
  const operationBody = z.object({ operationId: z.string().regex(/^[A-Za-z0-9_-]{12,128}$/) }).strict();

  app.get<{ Params: { runId: string; actionId: string } }>("/api/agent/runs/:runId/actions/:actionId", async (request, reply) => {
    try {
      const principal = await authorizedRunAgent(request, deps);
      const result = await getTaskActionState(deps, principal, {
        runId: uuid(request.params.runId, "runId"), actionId: uuid(request.params.actionId, "actionId"),
      });
      return reply.header("Cache-Control", "no-store").header("Vary", "Authorization").send(result);
    } catch (error) { return sendAgentError(reply, error, deps); }
  });

  app.get<{ Params: { runId: string } }>("/api/owner/runs/:runId/results", async (request, reply) => {
    try {
      await deps.rateLimit(request, "run-results", deps.rateLimitMax);
      const context = await ownerContext(request, deps);
      const result = await getOwnerRunFeedback(deps.db, context.owner.id, uuid(request.params.runId, "runId"));
      return reply.header("Cache-Control", "no-store").send(result);
    } catch (error) { return sendError(reply, error); }
  });

  for (const operation of ["actions", "finish"] as const) {
    app.post<{ Params: { runId: string; taskIndex: string } }>(`/api/agent/runs/:runId/tasks/:taskIndex/${operation}`,
      { bodyLimit: 8192 }, async (request, reply) => {
      try {
        const principal = await authorizedRunAgent(request, deps);
        if (request.headers["content-type"]?.split(";", 1)[0]?.trim().toLowerCase() !== "application/json") {
          throw new HttpError(415, "UNSUPPORTED_MEDIA_TYPE", "The request must use application/json");
        }
        if (!/^(?:[0-9]|1[01])$/.test(request.params.taskIndex)) throw new HttpError(400, "INVALID_TASK_TARGET", "taskIndex must be between zero and eleven");
        const schema = operation === "actions"
          ? operationBody.extend({ command: z.unknown() }).strict()
          : operationBody.extend({ answer: z.unknown().optional() }).strict();
        const parsed = schema.safeParse(request.body);
        if (!parsed.success) throw new HttpError(400, "INVALID_REQUEST", "The request does not match the task operation schema");
        const target = { runId: uuid(request.params.runId, "runId"), taskIndex: Number(request.params.taskIndex), operationId: parsed.data.operationId };
        const result = operation === "actions"
          ? await admitTaskAction(deps, principal, { ...target, command: (parsed.data as { command?: unknown }).command })
          : await finishTask(deps, principal, { ...target, ...("answer" in parsed.data ? { answer: parsed.data.answer } : {}) });
        return reply.code(operation === "actions" && "admitted" in result && result.admitted ? 202 : 200)
          .header("Cache-Control", "no-store").header("Vary", "Authorization").send(result);
      } catch (error) { return sendAgentError(reply, error, deps); }
    });
  }

  app.get<{ Params: { runId: string } }>("/api/agent/runs/:runId/current-task", async (request, reply) => {
    try {
      await deps.rateLimit(request, "run-agent-task-ip", deps.agentRateLimitMax ?? deps.rateLimitMax);
      if (!runAgentHostAllowed(request, deps)) {
        throw new HttpError(421, "MISDIRECTED_REQUEST", "The request host does not match the configured API origin");
      }
      if (request.headers.origin !== undefined && request.headers.origin !== deps.publicOrigin) {
        throw new HttpError(403, "ORIGIN_NOT_ALLOWED", "The request origin is not allowed");
      }
      const principal = await deps.resolveAgentPrincipal(agentBearer(request));
      if (!principal) throw new HttpError(401, "UNAUTHORIZED", "A current agent credential is required");
      await deps.rateLimit(request, `run-agent-task-${principal.credentialId}`, deps.agentRateLimitMax ?? deps.rateLimitMax);
      if (!deps.taskReleaseSource) throw new HttpError(503, "PINNED_RELEASE_UNAVAILABLE", "Task issuance is unavailable");
      const result = await getCurrentAgentTask({ db: deps.db, taskReleaseSource: deps.taskReleaseSource }, principal, uuid(request.params.runId, "runId"));
      return reply.header("Cache-Control", "no-store").header("Vary", "Authorization").send(result);
    } catch (error) { return sendAgentError(reply, error, deps); }
  });

  app.get("/api/owner/runs/catalog", async (request, reply) => {
    try {
      await deps.rateLimit(request, "run-catalog", deps.rateLimitMax);
      await ownerContext(request, deps);
      const catalog = await getRunCatalog(deps);
      return reply.header("Cache-Control", "no-store").send(catalog);
    } catch (error) { return sendError(reply, error); }
  });

  app.post("/api/owner/runs/intents", { bodyLimit: 8192 }, async (request, reply) => {
    try {
      await deps.rateLimit(request, "run-intents", deps.rateLimitMax);
      await deps.requireOrigin(request);
      const context = await ownerContext(request, deps);
      const parsed = createIntentBody.safeParse(request.body);
      if (!parsed.success) throw new HttpError(400, "INVALID_REQUEST", "The request does not match the bounded launch-intent schema");
      const body = parsed.data;
      const result = await createLaunchIntent(deps, {
        ownerId: context.owner.id,
        agentId: body.agentId,
        mode: body.mode,
        taskIds: body.taskIds,
        cashCeiling: body.cashCeiling,
        operationId: body.operationId,
        expectedReleaseIdentity: body.expectedReleaseIdentity,
        expectedManifestHash: body.expectedManifestHash,
        expectedQuotePrice: body.expectedQuotePrice
      });
      return reply.code(result.replayed ? 200 : 201).header("Cache-Control", "no-store").send(result);
    } catch (error) { return sendError(reply, error); }
  });

  app.get("/api/owner/runs/intents", async (request, reply) => {
    try {
      await deps.rateLimit(request, "run-intents", deps.rateLimitMax);
      const context = await ownerContext(request, deps);
      const query = request.query as Record<string, unknown>;
      if (Object.keys(query).some((key) => key !== "agentId")) throw new HttpError(400, "INVALID_REQUEST", "The request contains unsupported query fields");
      const intents = await listLaunchIntents(deps.db, context.owner.id, typeof query.agentId === "string" ? uuid(query.agentId, "agentId") : undefined);
      return reply.header("Cache-Control", "no-store").send({ intents });
    } catch (error) { return sendError(reply, error); }
  });

  app.get<{ Params: { intentId: string } }>("/api/owner/runs/intents/:intentId", async (request, reply) => {
    try {
      await deps.rateLimit(request, "run-intents", deps.rateLimitMax);
      const context = await ownerContext(request, deps);
      const intent = await getLaunchIntent(deps.db, context.owner.id, uuid(request.params.intentId, "intentId"));
      return reply.header("Cache-Control", "no-store").send({ intent });
    } catch (error) { return sendError(reply, error); }
  });

  app.post<{ Params: { intentId: string } }>("/api/owner/runs/intents/:intentId/cancel", { bodyLimit: 2048 }, async (request, reply) => {
    try {
      await deps.rateLimit(request, "run-intents", deps.rateLimitMax);
      await deps.requireOrigin(request);
      const context = await ownerContext(request, deps);
      const parsed = operationBody.safeParse(request.body);
      if (!parsed.success) throw new HttpError(400, "INVALID_REQUEST", "The request must contain only a valid operationId");
      const result = await cancelLaunchIntent(deps, {
        ownerId: context.owner.id, intentId: uuid(request.params.intentId, "intentId"), operationId: parsed.data.operationId
      });
      return reply.header("Cache-Control", "no-store").send(result);
    } catch (error) { return sendError(reply, error); }
  });

  app.get("/api/owner/runs", async (request, reply) => {
    try {
      await deps.rateLimit(request, "runs", deps.rateLimitMax);
      const context = await ownerContext(request, deps);
      const runs = await listOwnerRuns(deps.db, context.owner.id);
      return reply.header("Cache-Control", "no-store").send({ runs });
    } catch (error) { return sendError(reply, error); }
  });

  app.post<{ Params: { runId: string } }>("/api/owner/runs/:runId/cancel", { bodyLimit: 2048 }, async (request, reply) => {
    try {
      await deps.rateLimit(request, "runs", deps.rateLimitMax);
      await deps.requireOrigin(request);
      const context = await ownerContext(request, deps);
      const parsed = operationBody.safeParse(request.body);
      if (!parsed.success) throw new HttpError(400, "INVALID_REQUEST", "The request must contain only a valid operationId");
      const result = await requestRunCancellation(deps.db, {
        ownerId: context.owner.id, runId: uuid(request.params.runId, "runId"), operationId: parsed.data.operationId
      });
      return reply.header("Cache-Control", "no-store").send(result);
    } catch (error) { return sendError(reply, error); }
  });

  app.post<{ Params: { intentId: string } }>("/api/agent/run-intents/:intentId/accept", { bodyLimit: 2048 }, async (request, reply) => {
    try {
      const agentLimit = deps.agentRateLimitMax ?? deps.rateLimitMax;
      await deps.rateLimit(request, "run-agent-accept-ip", agentLimit);
      if (!runAgentHostAllowed(request, deps)) {
        throw new HttpError(421, "MISDIRECTED_REQUEST", "The request host does not match the configured API origin");
      }
      if (request.headers.origin !== undefined && request.headers.origin !== deps.publicOrigin) {
        throw new HttpError(403, "ORIGIN_NOT_ALLOWED", "The request origin is not allowed");
      }
      const contentType = request.headers["content-type"]?.split(";", 1)[0]?.trim().toLowerCase();
      if (contentType !== "application/json") throw new HttpError(415, "UNSUPPORTED_MEDIA_TYPE", "The request must use application/json");
      // AICODE-NOTE: The existing resolver derives owner, agent and access generation from the bearer credential; request bodies never choose an admission identity.
      const principal = await deps.resolveAgentPrincipal(agentBearer(request));
      if (!principal) throw new HttpError(401, "UNAUTHORIZED", "The agent bearer credential is expired or revoked");
      await deps.rateLimit(request, `run-agent-accept-${principal.credentialId}`, agentLimit);
      const parsed = operationBody.safeParse(request.body);
      if (!parsed.success) throw new HttpError(400, "INVALID_REQUEST", "The request must contain only a valid operationId");
      const result = await acceptLaunchIntent(deps, {
        ownerId: principal.ownerId, agentId: principal.agentId, accessGeneration: principal.accessGeneration,
        verifiedGrant: { id: principal.grantId, resource: principal.resource },
        intentId: uuid(request.params.intentId, "intentId"), operationId: parsed.data.operationId
      });
      return reply.header("Cache-Control", "no-store").send(result);
    } catch (error) { return sendAgentError(reply, error, deps); }
  });
}

/** Add the matching-agent acceptance tool to the already authenticated MCP server. */
export function registerRunIntentMcpTools(server: McpServer, principal: AgentPrincipal, deps: RunServiceDependencies & { taskReleaseSource?: CurrentTaskDependencies["taskReleaseSource"] }): void {
  const taskTarget = { runId: z.string().uuid(), taskIndex: z.number().int().min(0).max(11),
    operationId: z.string().regex(/^[A-Za-z0-9_-]{12,128}$/) };
  async function mcpTaskOperation(operation: () => Promise<unknown>) {
    try {
      const result = await operation();
      return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
    } catch (error) {
      const safe = error instanceof HttpError ? { code: error.code, message: error.message }
        : { code: "INTERNAL_ERROR", message: "The request could not be completed" };
      return { content: [{ type: "text" as const, text: JSON.stringify({ error: safe }) }], isError: true };
    }
  }
  server.registerTool("runs.task_action", {
    title: "Submit a current-task tool command",
    description: "Persist one bounded command for the current task. An admission receipt identifies the queued command; it does not prove execution, settlement or delivery. Reuse operationId for a response-loss retry.",
    inputSchema: z.object({ ...taskTarget, command: TaskActionCommandSchema }).strict(),
  }, async (input) => mcpTaskOperation(() => admitTaskAction(deps, principal, input)));
  server.registerTool("runs.task_action_status", {
    title: "Read a scoped task command status",
    description: "Read the persisted pending, observed, rejected or unknown state of this agent's command. Unknown and pending do not establish an effect; no score is returned.",
    inputSchema: z.object({ runId: z.string().uuid(), actionId: z.string().uuid() }).strict(),
  }, async (input) => mcpTaskOperation(() => getTaskActionState(deps, principal, input)));
  server.registerTool("runs.finish_task", {
    title: "Close the current task to new actions",
    description: "Commit one action cutoff and the structured answer for a read-only task. Admitted effects still need reconciliation and platform grading. This operation accepts no score and does not activate the next task.",
    inputSchema: z.object({ ...taskTarget, answer: z.unknown().optional() }).strict(),
  }, async (input) => mcpTaskOperation(() => finishTask(deps, principal, input)));
  server.registerTool("runs.current_task", {
    title: "Read the active benchmark task",
    description: "Read only this agent's currently active task and its disclosed conditions. Queued, expired, cancelled and finished tasks are not issued.",
    inputSchema: z.object({ runId: z.string().uuid() }).strict()
  }, async ({ runId }) => {
    try {
      if (!deps.taskReleaseSource) throw new HttpError(503, "PINNED_RELEASE_UNAVAILABLE", "Task issuance is unavailable");
      const result = await getCurrentAgentTask({ db: deps.db, taskReleaseSource: deps.taskReleaseSource }, principal, runId);
      return { content: [{ type: "text" as const, text: JSON.stringify(result) }], structuredContent: result };
    } catch (error) {
      const safe = error instanceof HttpError ? { code: error.code, message: error.message }
        : { code: "INTERNAL_ERROR", message: "The request could not be completed" };
      return { content: [{ type: "text" as const, text: JSON.stringify({ error: safe }) }], isError: true };
    }
  });
  const outputSchema = makeAcceptResultSchema();
  server.registerTool("runs.accept_launch_intent", {
    title: "Accept a benchmark run request",
    description: "Accept this agent's pending owner-authorized benchmark run intent. Acceptance pins the existing quote and creates one queued run with source reservations; it does not start execution.",
    inputSchema: z.object({
      intentId: z.string().uuid(),
      operationId: z.string().regex(/^[A-Za-z0-9_-]{12,128}$/)
    }).strict(),
    outputSchema
  }, async ({ intentId, operationId: opId }) => {
    try {
      const result = await acceptLaunchIntent(deps, {
        ownerId: principal.ownerId, agentId: principal.agentId, accessGeneration: principal.accessGeneration,
        verifiedGrant: { id: principal.grantId, resource: principal.resource },
        intentId, operationId: opId
      });
      return { content: [{ type: "text" as const, text: JSON.stringify(result) }], structuredContent: result };
    } catch (error) {
      const safeError = error instanceof HttpError
        ? { code: error.code, message: error.message }
        : { code: "INTERNAL_ERROR", message: "The request could not be completed" };
      return { content: [{ type: "text" as const, text: JSON.stringify({ error: safeError }) }], isError: true };
    }
  });
}
