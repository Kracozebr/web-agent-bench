import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { createHash } from "node:crypto";
import type { AgentPrincipal } from "./agents.js";
import type { OwnerDatabase } from "./db.js";
import { HttpError } from "./http-error.js";
import {
  appendSupportImageChunk,
  attachOwnerImagesToAgentReport,
  beginSupportImageUpload,
  changeAdminReportStatus,
  closeBetaReportRetention,
  createSupportReport,
  finishSupportImageUploadForActor,
  getAdminSupportReport,
  getAgentSupportReportReceipt,
  getOwnerSupportReport,
  getReportRetentionStatus,
  listAdminSupportReports,
  listOwnerSupportReports,
  readAdminReportImage,
  readOwnerReportImage,
  type ReportActor,
  type ReportListOptions,
  type ReportServiceDependencies,
  reportAttachImagesSchema,
  reportStatusUpdateSchema,
  reportSubmissionSchema,
  reportUploadBeginSchema,
  reportUploadChunkSchema,
  reportUploadFinishSchema,
} from "./report-service.js";
import { REPORT_IMAGE_MAX_INPUT_BYTES, validateBase64Chunk } from "./report-images.js";
import { reportUuid } from "./report-db.js";

export interface SupportReportOwnerContext {
  owner: { id: string; admissionStatus?: string };
}

export interface SupportReportAdminContext {
  context: { owner: { id: string; admissionStatus?: string } };
}

export interface SupportReportRouteDependencies {
  db: OwnerDatabase;
  service: ReportServiceDependencies;
  publicOrigin: string;
  agentRequestHosts?: ReadonlySet<string>;
  rateLimitMax: number;
  agentRateLimitMax?: number;
  imageChunkRateLimitMax?: number;
  resolveOwner(request: FastifyRequest): Promise<SupportReportOwnerContext>;
  resolveAgentPrincipal(bearer: string): Promise<AgentPrincipal | undefined>;
  requireAdmin(request: FastifyRequest): Promise<SupportReportAdminContext>;
  requireOrigin(request: FastifyRequest): Promise<void>;
  rateLimit(request: FastifyRequest, group: string, limit: number): Promise<void>;
}

function responseError(reply: FastifyReply, error: unknown, deps: SupportReportRouteDependencies, agent = false) {
  if (error instanceof HttpError) {
    const response = reply.code(error.status).header("Cache-Control", "no-store");
    if (agent) {
      response.header("Vary", "Authorization");
      if (error.status === 401) response.header("WWW-Authenticate", `Bearer resource_metadata="${deps.publicOrigin}/.well-known/oauth-protected-resource/api/agent", scope="agent:operate"`);
    }
    return response.send({ error: { code: error.code, message: error.message } });
  }
  return reply.code(500).header("Cache-Control", "no-store").send({ error: { code: "INTERNAL_ERROR", message: "The request could not be completed" } });
}

function uuid(value: unknown, field: string): string {
  if (!reportUuid(value)) throw new HttpError(400, `INVALID_${field.toUpperCase()}`, `${field} must be a UUID`);
  return value;
}

function record(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function operationBody(value: unknown): { operationId: string } {
  const body = record(value);
  if (Object.keys(body).length !== 1 || typeof body.operationId !== "string" || !/^[A-Za-z0-9_-]{12,128}$/.test(body.operationId)) {
    throw new HttpError(400, "INVALID_OPERATION_ID", "A valid report operation identifier is required");
  }
  return { operationId: body.operationId };
}

function parseListOptions(request: FastifyRequest): ReportListOptions {
  const query = record(request.query);
  const allowed = new Set(["limit", "cursor", "source", "status", "agentId", "runId"]);
  if (Object.keys(query).some((key) => !allowed.has(key))) throw new HttpError(400, "INVALID_REPORT_FILTER", "The report filter contains unsupported fields");
  const limitText = query.limit === undefined ? "25" : String(query.limit);
  if (!/^\d{1,3}$/.test(limitText)) throw new HttpError(400, "INVALID_REPORT_LIMIT", "Report page size must be between 1 and 100");
  const limit = Number(limitText);
  if (limit < 1 || limit > 100) throw new HttpError(400, "INVALID_REPORT_LIMIT", "Report page size must be between 1 and 100");
  if (query.source !== undefined && query.source !== "owner" && query.source !== "agent") throw new HttpError(400, "INVALID_REPORT_FILTER", "Report source must be owner or agent");
  if (query.status !== undefined && !["new", "in_progress", "closed"].includes(String(query.status))) throw new HttpError(400, "INVALID_REPORT_FILTER", "Report status is invalid");
  if (query.cursor !== undefined && (typeof query.cursor !== "string" || query.cursor.length > 256)) throw new HttpError(400, "INVALID_REPORT_CURSOR", "Report pagination cursor is invalid");
  return {
    limit,
    ...(typeof query.cursor === "string" ? { cursor: query.cursor } : {}),
    ...(query.source === "owner" || query.source === "agent" ? { source: query.source } : {}),
    ...(query.status === "new" || query.status === "in_progress" || query.status === "closed" ? { status: query.status } : {}),
    ...(query.agentId === undefined ? {} : { agentId: uuid(query.agentId, "agentId") }),
    ...(query.runId === undefined ? {} : { runId: uuid(query.runId, "runId") })
  };
}

async function ownerActor(request: FastifyRequest, deps: SupportReportRouteDependencies): Promise<ReportActor> {
  const context = await deps.resolveOwner(request);
  if (context.owner.admissionStatus !== undefined && context.owner.admissionStatus !== "admitted") {
    throw new HttpError(403, "OWNER_NOT_ADMITTED", "Owner admission is required");
  }
  return { kind: "owner", ownerId: context.owner.id, requestId: request.id };
}

function agentBearer(request: FastifyRequest): string {
  const authorization = request.headers.authorization;
  const match = typeof authorization === "string" ? /^Bearer ([^\s]{1,8192})$/.exec(authorization) : null;
  if (!match) throw new HttpError(401, "UNAUTHORIZED", "A current agent bearer credential is required");
  return match[1]!;
}

function agentHostAllowed(request: FastifyRequest, deps: SupportReportRouteDependencies): boolean {
  const allowed = deps.agentRequestHosts ?? new Set([new URL(deps.publicOrigin).host.toLowerCase()]);
  return typeof request.headers.host === "string" && allowed.has(request.headers.host.toLowerCase());
}

async function authenticatedAgent(request: FastifyRequest, deps: SupportReportRouteDependencies, rateClass = "request"): Promise<{ actor: ReportActor; principal: AgentPrincipal }> {
  const limit = rateClass === "image-chunk" ? deps.imageChunkRateLimitMax ?? 300 : deps.agentRateLimitMax ?? deps.rateLimitMax;
  await deps.rateLimit(request, `support-report-agent-${rateClass}-ip`, limit);
  if (!agentHostAllowed(request, deps)) throw new HttpError(421, "MISDIRECTED_REQUEST", "The request host does not match the configured API origin");
  if (request.headers.origin !== undefined && request.headers.origin !== deps.publicOrigin) throw new HttpError(403, "ORIGIN_NOT_ALLOWED", "The request origin is not allowed");
  const principal = await deps.resolveAgentPrincipal(agentBearer(request));
  if (!principal) throw new HttpError(401, "UNAUTHORIZED", "The agent bearer credential is expired or revoked");
  await deps.rateLimit(request, `support-report-agent-${rateClass}-${principal.credentialId}`, limit);
  return {
    actor: { kind: "agent", ownerId: principal.ownerId, agentId: principal.agentId, requestId: request.id },
    principal
  };
}

async function ownerRequestLimit(request: FastifyRequest, deps: SupportReportRouteDependencies, group: string) {
  await deps.rateLimit(request, `support-report-${group}`, deps.rateLimitMax);
}

function requireJson(request: FastifyRequest): void {
  if (request.headers["content-type"]?.split(";", 1)[0]?.trim().toLowerCase() !== "application/json") {
    throw new HttpError(415, "UNSUPPORTED_MEDIA_TYPE", "The request must use application/json");
  }
}

const ownerMultipartMaxBytes = REPORT_IMAGE_MAX_INPUT_BYTES + 16 * 1024;
const ownerMultipartLimits = {
  fieldNameSize: 32,
  fieldSize: 128,
  fields: 4,
  files: 1,
  fileSize: REPORT_IMAGE_MAX_INPUT_BYTES,
  headerPairs: 16,
  parts: 5
};

type MultipartPart =
  | { type: "field"; fieldname: string; value: unknown }
  | {
      type: "file";
      fieldname: string;
      filename: string;
      mimetype: string;
      file: AsyncIterable<Buffer> & { truncated: boolean };
      toBuffer(): Promise<Buffer>;
    };

function uploadChunkBody(bodyValue: unknown, pathUploadId: string): Record<string, unknown> {
  const body = record(bodyValue);
  if (Object.hasOwn(body, "uploadId")) {
    throw new HttpError(400, "INVALID_REPORT_IMAGE_CHUNK", "Screenshot upload ID must be supplied only in the request path");
  }
  return { ...body, uploadId: pathUploadId };
}

type MultipartRequest = FastifyRequest & {
  parts(options: { limits: typeof ownerMultipartLimits; throwFileSizeLimit: false }): AsyncIterable<MultipartPart>;
};

class ReportMultipartEnvelopeError extends HttpError {
  constructor() { super(413, "REPORT_IMAGE_TOO_LARGE", "Screenshot multipart request exceeds its bounded envelope"); }
}

async function streamOwnerMultipartUpload(
  request: FastifyRequest,
  deps: SupportReportRouteDependencies,
  actor: ReportActor
): Promise<{ upload: Record<string, unknown>; replayed: boolean }> {
  if (!request.headers["content-type"]?.toLowerCase().startsWith("multipart/form-data;")) {
    throw new HttpError(415, "UNSUPPORTED_MEDIA_TYPE", "The screenshot upload must use multipart/form-data");
  }
  let receivedEnvelopeBytes = 0;
  let resolveEnvelopeExceeded!: () => void;
  let envelopeExceeded = false;
  const envelopeExceededPromise = new Promise<void>((resolveExceeded) => { resolveEnvelopeExceeded = resolveExceeded; });
  const observeEnvelope = (chunk: Buffer | string) => {
    receivedEnvelopeBytes += Buffer.isBuffer(chunk) ? chunk.length : Buffer.byteLength(chunk);
    if (!envelopeExceeded && receivedEnvelopeBytes > ownerMultipartMaxBytes) {
      envelopeExceeded = true;
      request.raw.pause();
      resolveEnvelopeExceeded();
    }
  };
  // Attach after owner auth, then start parsing synchronously. @fastify/multipart consumes request.raw directly.
  request.raw.on("data", observeEnvelope);

  const parseMultipart = async () => {
    const fields: Record<string, string> = {};
    let filePart: Extract<MultipartPart, { type: "file" }> | undefined;
    let partCount = 0;
    let received = 0;
    const digest = createHash("sha256");
    const fileBuffers: Buffer[] = [];
    let inputBytes: Buffer | undefined;
    let declaration: ReturnType<typeof reportUploadBeginSchema.parse> | undefined;
    try {
      for await (const part of (request as unknown as MultipartRequest).parts({ limits: ownerMultipartLimits, throwFileSizeLimit: false })) {
        partCount++;
        if (part.type === "field") {
          if (["operationId", "expectedBytes", "sha256", "contentType"].indexOf(part.fieldname) < 0 ||
            typeof part.value !== "string" || Object.hasOwn(fields, part.fieldname) || filePart) {
            throw new HttpError(400, "INVALID_REPORT_IMAGE_MULTIPART", "Provide the four declared upload fields before one screenshot file");
          }
          fields[part.fieldname] = part.value;
        } else {
          if (part.fieldname !== "file" || filePart || Object.keys(fields).length !== 4) {
            await part.toBuffer();
            throw new HttpError(400, "INVALID_REPORT_IMAGE_MULTIPART", "Provide the four declared upload fields before one file named file");
          }
          if (part.filename.length > 255) {
            await part.toBuffer();
            throw new HttpError(400, "INVALID_REPORT_IMAGE_MULTIPART", "Screenshot filename is too long");
          }
          if (!/^\d{1,7}$/.test(fields.expectedBytes ?? "")) throw new HttpError(400, "INVALID_REPORT_IMAGE_UPLOAD", "Declared screenshot size is invalid");
          const parsed = reportUploadBeginSchema.safeParse({
            operationId: fields.operationId,
            expectedBytes: Number(fields.expectedBytes),
            sha256: fields.sha256,
            contentType: fields.contentType
          });
          if (!parsed.success) throw new HttpError(400, "INVALID_REPORT_IMAGE_UPLOAD", "Screenshot upload declaration is invalid");
          declaration = parsed.data;
          if (part.mimetype.toLowerCase() !== declaration.contentType) {
            await part.toBuffer();
            throw new HttpError(415, "REPORT_IMAGE_TYPE_UNSUPPORTED", "Screenshot file type does not match its declared content type");
          }
          filePart = part;
          for await (const value of part.file) {
            const chunk = Buffer.from(value);
            received += chunk.length;
            digest.update(chunk);
            if (received <= declaration.expectedBytes) fileBuffers.push(chunk);
          }
          if (part.file.truncated) throw new HttpError(413, "REPORT_IMAGE_TOO_LARGE", "Screenshot input exceeds the 5 MiB limit");
          if (received !== declaration.expectedBytes || digest.digest("hex") !== declaration.sha256.toLowerCase()) {
            throw new HttpError(400, "REPORT_IMAGE_UPLOAD_HASH_MISMATCH", "Screenshot bytes do not match the declared size and hash");
          }
          inputBytes = Buffer.concat(fileBuffers, received);
          fileBuffers.length = 0;
        }
      }
    } catch (error) {
      if (error instanceof HttpError) throw error;
      const multipartError = error as { code?: unknown; name?: unknown };
      if (multipartError.code === "FST_REQ_FILE_TOO_LARGE" || multipartError.name === "RequestFileTooLargeError") {
        throw new HttpError(413, "REPORT_IMAGE_TOO_LARGE", "Screenshot input exceeds the 5 MiB limit");
      }
      throw new HttpError(400, "INVALID_REPORT_IMAGE_MULTIPART", "The screenshot multipart request is malformed or exceeds its field limits");
    }
    if (partCount !== 5 || Object.keys(fields).length !== 4 || !filePart || !declaration || !inputBytes) {
      throw new HttpError(400, "INVALID_REPORT_IMAGE_MULTIPART", "Provide exactly four valid upload fields and one screenshot file");
    }
    return { inputBytes, declaration };
  };

  let parsed: Awaited<ReturnType<typeof parseMultipart>>;
  try {
    const parsePromise = parseMultipart();
    const outcome = await Promise.race([
      parsePromise.then((value) => ({ kind: "parsed" as const, value })),
      envelopeExceededPromise.then(() => ({ kind: "envelope-exceeded" as const })),
    ]);
    if (outcome.kind === "envelope-exceeded") {
      void parsePromise.catch(() => undefined);
      throw new ReportMultipartEnvelopeError();
    }
    parsed = outcome.value;
  } finally {
    request.raw.off("data", observeEnvelope);
  }

  // AICODE-NOTE: Validate the complete bounded multipart envelope before reserving durable upload state. Oversized, hash-mismatched, or extra-part bodies must not leave receiving receipts or partial chunks behind.
  const { inputBytes, declaration } = parsed;
  const uploadResult = await beginSupportImageUpload(deps.service, actor, declaration);
  if (!["receiving", "ready", "attached"].includes(uploadResult.status)) {
    throw new HttpError(409, "REPORT_IMAGE_UPLOAD_IN_PROGRESS", "Screenshot upload is already being processed");
  }
  if (uploadResult.status === "receiving") {
    for (let sequence = 0, offset = 0; offset < inputBytes.length; sequence++, offset += 24 * 1024) {
      const bytes = inputBytes.subarray(offset, Math.min(offset + 24 * 1024, inputBytes.length));
      const sha256 = createHash("sha256").update(bytes).digest("hex");
      await appendSupportImageChunk(deps.service, actor, { uploadId: uploadResult.uploadId, sequence,
        sha256, dataBase64: bytes.toString("base64") }, bytes);
    }
  }
  const finished = await finishSupportImageUploadForActor(deps.service, actor, uploadResult.uploadId);
  return { upload: finished.upload, replayed: uploadResult.replayed || finished.replayed };
}

function imageResponse(reply: FastifyReply, result: { bytes: Buffer; contentType: string; sha256: string }) {
  return reply.type(result.contentType).header("Cache-Control", "private, no-store").header("X-Content-Type-Options", "nosniff")
    .header("Content-Security-Policy", "default-src 'none'; sandbox").header("ETag", `\"${result.sha256}\"`).send(result.bytes);
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

function adminImagePaths(report: Record<string, unknown>): Record<string, unknown> {
  const images = Array.isArray(report.images) ? report.images.map((item) => {
    const image = record(item);
    return typeof image.id === "string" && typeof report.id === "string"
      ? { ...image, imagePath: `/api/admin/reports/${encodeURIComponent(report.id)}/images/${encodeURIComponent(image.id)}` }
      : image;
  }) : [];
  return { ...report, images };
}

/** Register the authenticated website and agent HTTP report surfaces. */
export function registerSupportReportRoutes(app: FastifyInstance, deps: SupportReportRouteDependencies): void {
  const service = deps.service;

  app.get("/api/owner/reports", async (request, reply) => {
    try {
      await ownerRequestLimit(request, deps, "owner-list");
      const actor = await ownerActor(request, deps);
      const result = await listOwnerSupportReports(service, actor.ownerId, parseListOptions(request));
      return reply.header("Cache-Control", "private, no-store").send(result);
    } catch (error) { return responseError(reply, error, deps); }
  });

  app.post("/api/owner/reports", { bodyLimit: 16 * 1024 }, async (request, reply) => {
    try {
      await ownerRequestLimit(request, deps, "owner-create");
      await deps.requireOrigin(request);
      requireJson(request);
      const parsed = reportSubmissionSchema.safeParse(request.body);
      if (!parsed.success) throw new HttpError(400, "INVALID_REPORT", "The report fields are invalid or unsupported");
      const result = await createSupportReport(service, await ownerActor(request, deps), parsed.data);
      return reply.code(result.replayed ? 200 : 201).header("Cache-Control", "private, no-store").send(result);
    } catch (error) { return responseError(reply, error, deps); }
  });

  app.get<{ Params: { reportId: string } }>("/api/owner/reports/:reportId", async (request, reply) => {
    try {
      await ownerRequestLimit(request, deps, "owner-read");
      const actor = await ownerActor(request, deps);
      const report = await getOwnerSupportReport(service, actor.ownerId, uuid(request.params.reportId, "reportId"));
      return reply.header("Cache-Control", "private, no-store").send({ report });
    } catch (error) { return responseError(reply, error, deps); }
  });

  app.post<{ Params: { reportId: string } }>("/api/owner/reports/:reportId/images", { bodyLimit: 4096 }, async (request, reply) => {
    try {
      await ownerRequestLimit(request, deps, "owner-attach");
      await deps.requireOrigin(request);
      requireJson(request);
      const actor = await ownerActor(request, deps);
      const body = reportAttachImagesSchema.safeParse(request.body);
      if (!body.success) throw new HttpError(400, "INVALID_REPORT_IMAGES", "Screenshot attachment request is invalid");
      const result = await attachOwnerImagesToAgentReport(service, actor.ownerId, uuid(request.params.reportId, "reportId"), body.data);
      return reply.code(result.replayed ? 200 : 201).header("Cache-Control", "private, no-store").send(result);
    } catch (error) { return responseError(reply, error, deps); }
  });

  app.get<{ Params: { reportId: string; imageId: string } }>("/api/owner/reports/:reportId/images/:imageId", async (request, reply) => {
    try {
      await ownerRequestLimit(request, deps, "owner-image");
      const actor = await ownerActor(request, deps);
      const result = await readOwnerReportImage(service, actor.ownerId, uuid(request.params.reportId, "reportId"), uuid(request.params.imageId, "imageId"));
      return imageResponse(reply, result);
    } catch (error) { return responseError(reply, error, deps); }
  });

  registerOwnerUploadRoutes(app, deps);
  registerAgentReportRoutes(app, deps);
  registerAdminReportRoutes(app, deps);
}

function registerOwnerUploadRoutes(app: FastifyInstance, deps: SupportReportRouteDependencies): void {
  const multipartActors = new WeakMap<FastifyRequest, ReportActor>();
  const rejectMultipart = (request: FastifyRequest, reply: FastifyReply, error: unknown) => {
    if (error instanceof ReportMultipartEnvelopeError) {
      reply.header("Connection", "close");
      reply.raw.once("finish", () => request.raw.destroy());
    }
    return responseError(reply, error, deps);
  };

  app.post("/api/owner/report-images/uploads/multipart", {
    bodyLimit: ownerMultipartMaxBytes,
    onRequest: async (request, reply) => {
      try {
        await ownerRequestLimit(request, deps, "owner-image-multipart");
        await deps.requireOrigin(request);
        const contentLength = request.headers["content-length"];
        if (typeof contentLength === "string" && /^\d+$/.test(contentLength) && Number(contentLength) > ownerMultipartMaxBytes) {
          throw new ReportMultipartEnvelopeError();
        }
        multipartActors.set(request, await ownerActor(request, deps));
      } catch (error) { return rejectMultipart(request, reply, error); }
    },
  }, async (request, reply) => {
    try {
      const actor = multipartActors.get(request);
      if (!actor) throw new HttpError(401, "UNAUTHORIZED", "A current owner session is required");
      const result = await streamOwnerMultipartUpload(request, deps, actor);
      return reply.code(result.replayed ? 200 : 201).header("Cache-Control", "private, no-store").send(result);
    } catch (error) { return rejectMultipart(request, reply, error); }
  });

  app.post("/api/owner/report-images/uploads", { bodyLimit: 4096 }, async (request, reply) => {
    try {
      await ownerRequestLimit(request, deps, "owner-image-begin");
      await deps.requireOrigin(request);
      requireJson(request);
      const actor = await ownerActor(request, deps);
      const parsed = reportUploadBeginSchema.safeParse(request.body);
      if (!parsed.success) throw new HttpError(400, "INVALID_REPORT_IMAGE_UPLOAD", "Screenshot upload details are invalid");
      const result = await beginSupportImageUpload(deps.service, actor, parsed.data);
      return reply.code(result.replayed ? 200 : 201).header("Cache-Control", "private, no-store").send(result);
    } catch (error) { return responseError(reply, error, deps); }
  });

  app.post<{ Params: { uploadId: string } }>("/api/owner/report-images/uploads/:uploadId/chunks", { bodyLimit: 36 * 1024 }, async (request, reply) => {
    try {
      await deps.rateLimit(request, "support-report-owner-image-chunk", deps.imageChunkRateLimitMax ?? 300);
      await deps.requireOrigin(request);
      requireJson(request);
      const actor = await ownerActor(request, deps);
      const parsed = reportUploadChunkSchema.safeParse(uploadChunkBody(request.body, request.params.uploadId));
      if (!parsed.success) throw new HttpError(400, "INVALID_REPORT_IMAGE_CHUNK", "Screenshot chunk is invalid");
      const bytes = validateBase64Chunk(parsed.data.dataBase64);
      const result = await appendSupportImageChunk(deps.service, actor, parsed.data, bytes);
      return reply.header("Cache-Control", "private, no-store").send(result);
    } catch (error) { return responseError(reply, error, deps); }
  });

  app.post<{ Params: { uploadId: string } }>("/api/owner/report-images/uploads/:uploadId/finish", { bodyLimit: 1024 }, async (request, reply) => {
    try {
      await ownerRequestLimit(request, deps, "owner-image-finish");
      await deps.requireOrigin(request);
      requireJson(request);
      const actor = await ownerActor(request, deps);
      const finishBody = record(request.body);
      if (Object.hasOwn(finishBody, "uploadId")) throw new HttpError(400, "INVALID_REPORT_IMAGE_UPLOAD", "Screenshot upload ID must be supplied only in the request path");
      const body = reportUploadFinishSchema.safeParse({ ...finishBody, uploadId: request.params.uploadId });
      if (!body.success) throw new HttpError(400, "INVALID_REPORT_IMAGE_UPLOAD", "Screenshot upload finish request is invalid");
      const result = await finishSupportImageUploadForActor(deps.service, actor, uuid(request.params.uploadId, "uploadId"));
      return reply.header("Cache-Control", "private, no-store").send(result);
    } catch (error) { return responseError(reply, error, deps); }
  });
}

function registerAgentReportRoutes(app: FastifyInstance, deps: SupportReportRouteDependencies): void {
  app.post("/api/agent/reports", { bodyLimit: 16 * 1024 }, async (request, reply) => {
    try {
      requireJson(request);
      const { actor } = await authenticatedAgent(request, deps);
      const parsed = reportSubmissionSchema.safeParse(request.body);
      if (!parsed.success) throw new HttpError(400, "INVALID_REPORT", "The report fields are invalid or unsupported");
      const result = await createSupportReport(deps.service, actor, parsed.data);
      return reply.code(result.replayed ? 200 : 201).header("Cache-Control", "private, no-store").header("Vary", "Authorization")
        .send({ report: agentReportReceipt(result.report), replayed: result.replayed });
    } catch (error) { return responseError(reply, error, deps, true); }
  });

  app.get<{ Params: { reportId: string } }>("/api/agent/reports/:reportId", async (request, reply) => {
    try {
      const { principal } = await authenticatedAgent(request, deps);
      const receipt = await getAgentSupportReportReceipt(deps.service, principal.agentId, uuid(request.params.reportId, "reportId"));
      return reply.header("Cache-Control", "private, no-store").header("Vary", "Authorization").send({ report: receipt });
    } catch (error) { return responseError(reply, error, deps, true); }
  });

  app.post("/api/agent/report-images/uploads", { bodyLimit: 4096 }, async (request, reply) => {
    try {
      requireJson(request);
      const { actor } = await authenticatedAgent(request, deps);
      const parsed = reportUploadBeginSchema.safeParse(request.body);
      if (!parsed.success) throw new HttpError(400, "INVALID_REPORT_IMAGE_UPLOAD", "Screenshot upload details are invalid");
      const result = await beginSupportImageUpload(deps.service, actor, parsed.data);
      return reply.code(result.replayed ? 200 : 201).header("Cache-Control", "no-store").header("Vary", "Authorization").send(result);
    } catch (error) { return responseError(reply, error, deps, true); }
  });

  app.post<{ Params: { uploadId: string } }>("/api/agent/report-images/uploads/:uploadId/chunks", { bodyLimit: 36 * 1024 }, async (request, reply) => {
    try {
      const { actor } = await authenticatedAgent(request, deps, "image-chunk");
      const parsed = reportUploadChunkSchema.safeParse(uploadChunkBody(request.body, request.params.uploadId));
      if (!parsed.success) throw new HttpError(400, "INVALID_REPORT_IMAGE_CHUNK", "Screenshot chunk is invalid");
      const bytes = validateBase64Chunk(parsed.data.dataBase64);
      const result = await appendSupportImageChunk(deps.service, actor, parsed.data, bytes);
      return reply.header("Cache-Control", "no-store").header("Vary", "Authorization").send(result);
    } catch (error) { return responseError(reply, error, deps, true); }
  });

  app.post<{ Params: { uploadId: string } }>("/api/agent/report-images/uploads/:uploadId/finish", { bodyLimit: 1024 }, async (request, reply) => {
    try {
      requireJson(request);
      const { actor } = await authenticatedAgent(request, deps);
      const finishBody = record(request.body);
      if (Object.hasOwn(finishBody, "uploadId")) throw new HttpError(400, "INVALID_REPORT_IMAGE_UPLOAD", "Screenshot upload ID must be supplied only in the request path");
      const body = reportUploadFinishSchema.safeParse({ ...finishBody, uploadId: request.params.uploadId });
      if (!body.success) throw new HttpError(400, "INVALID_REPORT_IMAGE_UPLOAD", "Screenshot upload finish request is invalid");
      const result = await finishSupportImageUploadForActor(deps.service, actor, uuid(request.params.uploadId, "uploadId"));
      return reply.header("Cache-Control", "no-store").header("Vary", "Authorization").send(result);
    } catch (error) { return responseError(reply, error, deps, true); }
  });
}

function registerAdminReportRoutes(app: FastifyInstance, deps: SupportReportRouteDependencies): void {
  async function adminOwnerId(request: FastifyRequest): Promise<string> {
    await deps.rateLimit(request, "support-report-admin", deps.rateLimitMax);
    const admin = await deps.requireAdmin(request);
    if (admin.context.owner.admissionStatus !== undefined && admin.context.owner.admissionStatus !== "admitted") {
      throw new HttpError(403, "OWNER_NOT_ADMITTED", "Administrator admission is required");
    }
    return admin.context.owner.id;
  }

  app.get("/api/admin/reports", async (request, reply) => {
    try {
      await adminOwnerId(request);
      const result = await listAdminSupportReports(deps.service, parseListOptions(request));
      return reply.header("Cache-Control", "private, no-store").send(result);
    } catch (error) { return responseError(reply, error, deps); }
  });

  app.get<{ Params: { reportId: string } }>("/api/admin/reports/:reportId", async (request, reply) => {
    try {
      await adminOwnerId(request);
      const report = await getAdminSupportReport(deps.service, uuid(request.params.reportId, "reportId"));
      return reply.header("Cache-Control", "private, no-store").send({ report: adminImagePaths(report) });
    } catch (error) { return responseError(reply, error, deps); }
  });

  app.patch<{ Params: { reportId: string } }>("/api/admin/reports/:reportId/status", { bodyLimit: 2048 }, async (request, reply) => {
    try {
      await deps.requireOrigin(request);
      requireJson(request);
      const actorOwnerId = await adminOwnerId(request);
      const parsed = reportStatusUpdateSchema.safeParse(request.body);
      if (!parsed.success) throw new HttpError(400, "INVALID_REPORT_STATUS", "Report status operation is invalid");
      const result = await changeAdminReportStatus(deps.service, actorOwnerId, uuid(request.params.reportId, "reportId"), parsed.data);
      return reply.header("Cache-Control", "private, no-store").send({ report: result.report, replayed: result.replayed });
    } catch (error) { return responseError(reply, error, deps); }
  });

  app.get<{ Params: { reportId: string; imageId: string } }>("/api/admin/reports/:reportId/images/:imageId", async (request, reply) => {
    try {
      await adminOwnerId(request);
      const result = await readAdminReportImage(deps.service, uuid(request.params.reportId, "reportId"), uuid(request.params.imageId, "imageId"));
      return imageResponse(reply, result);
    } catch (error) { return responseError(reply, error, deps); }
  });

  app.get("/api/admin/reports/retention", async (request, reply) => {
    try {
      await adminOwnerId(request);
      const status = await getReportRetentionStatus(deps.service);
      return reply.header("Cache-Control", "private, no-store").send(status);
    } catch (error) { return responseError(reply, error, deps); }
  });

  app.post("/api/admin/reports/retention/close", { bodyLimit: 1024 }, async (request, reply) => {
    try {
      await deps.requireOrigin(request);
      requireJson(request);
      const actorOwnerId = await adminOwnerId(request);
      const body = operationBody(request.body);
      const result = await closeBetaReportRetention(deps.service, actorOwnerId, body.operationId);
      return reply.code(result.replayed ? 200 : 201).header("Cache-Control", "private, no-store").send(result);
    } catch (error) { return responseError(reply, error, deps); }
  });
}
