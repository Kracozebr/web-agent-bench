import type { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import type { AgentPrincipal } from "./agents.js";
import { HttpError } from "./http-error.js";
import { validateBase64Chunk } from "./report-images.js";
import {
  appendSupportImageChunk,
  beginSupportImageUpload,
  createSupportReport,
  finishSupportImageUploadForActor,
  getAgentSupportReportReceipt,
  reportSubmissionSchema,
  reportUploadBeginSchema,
  reportUploadChunkSchema,
  type ReportServiceDependencies
} from "./report-service.js";

function result(value: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(value) }], structuredContent: value as Record<string, unknown> };
}

function failure(error: unknown) {
  const safe = error instanceof HttpError
    ? { code: error.code, message: error.message }
    : { code: "INTERNAL_ERROR", message: "The report request could not be completed" };
  return { content: [{ type: "text" as const, text: JSON.stringify({ error: safe }) }], isError: true };
}

function agentReportReceipt(report: Record<string, unknown>) {
  return {
    id: report.id,
    source: report.source,
    status: report.status,
    createdAt: report.createdAt,
    imageCount: Array.isArray(report.images) ? report.images.length : 0
  };
}

/** Register report and bounded screenshot upload tools on an already authenticated agent MCP server. */
export function registerSupportReportMcpTools(
  server: McpServer,
  principal: AgentPrincipal,
  deps: ReportServiceDependencies
): void {
  const actor = { kind: "agent" as const, ownerId: principal.ownerId, agentId: principal.agentId };
  const reportInputSchema = z.object({
    operationId: z.string().regex(/^[A-Za-z0-9_-]{12,128}$/),
    title: z.string().min(1).max(160),
    body: z.string().min(1).max(4000),
    runId: z.string().uuid().optional(),
    taskId: z.string().min(1).max(128).optional(),
    actionId: z.string().uuid().optional(),
    clientVersion: z.string().min(1).max(64).regex(/^[A-Za-z0-9][A-Za-z0-9 ._+/-]{0,63}$/).optional(),
    imageUploadIds: z.array(z.string().uuid()).max(3).optional()
  }).strict();

  server.registerTool("support.report", {
    title: "Submit a private support report",
    description: "Create or recover this authenticated agent's private support report. Run, task and action links are validated against this agent; reporting does not submit task actions or change grades, timers or billing. Reuse operationId for an unchanged retry.",
    inputSchema: reportInputSchema
  }, async (input) => {
    try {
      const parsed = reportSubmissionSchema.safeParse(input);
      if (!parsed.success) throw new HttpError(400, "INVALID_REPORT", "The report fields are invalid or unsupported");
      const created = await createSupportReport(deps, actor, parsed.data);
      const receipt = { report: agentReportReceipt(created.report), replayed: created.replayed };
      return result(receipt);
    } catch (error) { return failure(error); }
  });

  server.registerTool("support.report_receipt", {
    title: "Read this agent's report receipt",
    description: "Read only the authenticated agent's own report receipt and status. It does not expose report text, administrator notes, or another owner's reports.",
    inputSchema: z.object({ reportId: z.string().uuid() }).strict()
  }, async ({ reportId }) => {
    try {
      return result({ report: await getAgentSupportReportReceipt(deps, principal.agentId, reportId) });
    } catch (error) { return failure(error); }
  });

  server.registerTool("support.screenshot.begin", {
    title: "Begin a private screenshot upload",
    description: "Reserve one bounded PNG, JPEG or WebP screenshot for this agent. Declare the original byte count and SHA-256; upload in ordered chunks and finish to normalize it before attaching it to this agent's report.",
    inputSchema: reportUploadBeginSchema
  }, async (input) => {
    try {
      return result(await beginSupportImageUpload(deps, actor, input));
    } catch (error) { return failure(error); }
  });

  server.registerTool("support.screenshot.chunk", {
    title: "Upload a screenshot chunk",
    description: "Append one ordered, idempotent screenshot chunk of at most 24 KiB decoded bytes. Reuse the same sequence and bytes to recover a lost response; different bytes for the same sequence conflict.",
    inputSchema: reportUploadChunkSchema
  }, async (input) => {
    try {
      const bytes = validateBase64Chunk(input.dataBase64);
      return result(await appendSupportImageChunk(deps, actor, input, bytes));
    } catch (error) { return failure(error); }
  });

  server.registerTool("support.screenshot.finish", {
    title: "Finish and normalize a screenshot upload",
    description: "Verify all ordered chunks and the declared SHA-256, decode one bounded nonanimated image, strip metadata and commit a private normalized preview. The returned upload ID may be attached only to this agent's report.",
    inputSchema: z.object({ uploadId: z.string().uuid() }).strict()
  }, async ({ uploadId }) => {
    try {
      return result(await finishSupportImageUploadForActor(deps, actor, uploadId));
    } catch (error) { return failure(error); }
  });
}
