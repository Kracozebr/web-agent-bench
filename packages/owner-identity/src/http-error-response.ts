import type { FastifyReply } from "fastify";
import { HttpError } from "./http-error.js";

export type SafeRequestErrorLogger = (error: unknown) => void;

// AICODE-NOTE: Fastify body parsing can reject an oversized request before a route handler runs;
// map only its stable size-limit code to a safe 413 response instead of the generic 500 path.
export function responseError(reply: FastifyReply, error: unknown, logSafeError?: SafeRequestErrorLogger) {
  if (error instanceof HttpError) {
    return reply.code(error.status).header("Cache-Control", "no-store").send({
      error: { code: error.code, message: error.message }
    });
  }
  if (error instanceof Error && /unique|duplicate key/i.test(error.message)) {
    return reply.code(409).header("Cache-Control", "no-store").send({
      error: { code: "IDENTITY_ALREADY_LINKED", message: "This identity is already linked to another owner" }
    });
  }
  const code = error !== null && typeof error === "object" && "code" in error ? error.code : undefined;
  if (code === "FST_ERR_CTP_BODY_TOO_LARGE") {
    return reply.code(413).header("Cache-Control", "no-store").send({
      error: { code: "REQUEST_BODY_TOO_LARGE", message: "Request body exceeds the configured limit" }
    });
  }
  if (logSafeError) logSafeError(error);
  else {
    const kind = error instanceof Error ? error.name : "UnknownError";
    reply.log.error({ kind }, "owner-identity request failed");
  }
  return reply.code(500).header("Cache-Control", "no-store").send({
    error: { code: "INTERNAL_ERROR", message: "The request could not be completed" }
  });
}
