import { createHash } from "node:crypto";
import sharp, { type OutputInfo } from "sharp";
import { HttpError } from "./http-error.js";

export const REPORT_IMAGE_MAX_INPUT_BYTES = 5 * 1024 * 1024;
export const REPORT_IMAGE_MAX_OUTPUT_BYTES = 5 * 1024 * 1024;
export const REPORT_IMAGE_MAX_PIXELS = 16_000_000;
export const REPORT_IMAGE_MAX_PER_REPORT = 3;
export const REPORT_IMAGE_MAX_CHUNK_BYTES = 24 * 1024;
export const REPORT_IMAGE_DECODER_MAX_PENDING = 8;

let decoderTail: Promise<void> = Promise.resolve();
let decoderPending = 0;

/** Serialize libvips work and cap retained image buffers waiting for a decoder slot. */
export async function withReportImageDecoder<T>(decode: () => Promise<T>): Promise<T> {
  if (decoderPending >= REPORT_IMAGE_DECODER_MAX_PENDING) {
    throw new HttpError(503, "REPORT_IMAGE_DECODER_BUSY", "Screenshot processing is busy; retry after the current uploads finish");
  }
  decoderPending++;
  const previous = decoderTail;
  let release!: () => void;
  decoderTail = new Promise<void>((resolve) => { release = resolve; });
  await previous;
  decoderPending--;
  try {
    return await decode();
  } finally {
    release();
  }
}

const allowedMimeByFormat: Readonly<Record<string, string>> = {
  png: "image/png",
  jpeg: "image/jpeg",
  webp: "image/webp"
};

function invalidImage(): HttpError {
  return new HttpError(400, "INVALID_REPORT_IMAGE", "Upload a valid PNG, JPEG, or WebP image within the configured size and pixel limits");
}

export interface NormalizedReportImage {
  bytes: Buffer;
  sha256: string;
  inputSha256: string;
  contentType: "image/webp";
  width: number;
  height: number;
  inputBytes: number;
}

/**
 * Decode a single PNG/JPEG/WebP frame, orient it, strip metadata and emit a
 * bounded WebP preview. The input is never written to disk or logs.
 */
export async function normalizeReportImage(input: Buffer, declaredMime?: string): Promise<NormalizedReportImage> {
  if (!Buffer.isBuffer(input) || input.length < 1 || input.length > REPORT_IMAGE_MAX_INPUT_BYTES) throw invalidImage();
  const inputSha256 = createHash("sha256").update(input).digest("hex");
  try {
    const pipeline = sharp(input, {
      limitInputPixels: REPORT_IMAGE_MAX_PIXELS,
      failOn: "warning",
      sequentialRead: true,
      animated: false
    });
    const metadata = await pipeline.metadata();
    if (!metadata.format || !Object.hasOwn(allowedMimeByFormat, metadata.format) ||
      !metadata.width || !metadata.height || metadata.width * metadata.height > REPORT_IMAGE_MAX_PIXELS ||
      (metadata.pages !== undefined && metadata.pages !== 1)) throw invalidImage();
    const inputMime = allowedMimeByFormat[metadata.format]!;
    if (declaredMime && declaredMime !== inputMime) throw invalidImage();

    let quality = 82;
    let scale = Math.min(1, 4096 / metadata.width, 4096 / metadata.height);
    let output: { data: Buffer; info: OutputInfo };
    for (;;) {
      const width = Math.max(1, Math.floor(metadata.width * scale));
      const height = Math.max(1, Math.floor(metadata.height * scale));
      output = await sharp(input, {
        limitInputPixels: REPORT_IMAGE_MAX_PIXELS,
        failOn: "warning",
        sequentialRead: true,
        animated: false
      })
        .rotate()
        .resize({ width, height, fit: "inside", withoutEnlargement: true })
        .webp({ quality, effort: 4 })
        .toBuffer({ resolveWithObject: true });
      if (output.data.length <= REPORT_IMAGE_MAX_OUTPUT_BYTES) break;
      if (quality > 50) quality -= 12;
      else if (scale > 0.5) scale *= 0.75;
      else throw invalidImage();
    }
    if (!output.info.width || !output.info.height || output.info.width * output.info.height > REPORT_IMAGE_MAX_PIXELS) throw invalidImage();
    return {
      bytes: output.data,
      sha256: createHash("sha256").update(output.data).digest("hex"),
      inputSha256,
      contentType: "image/webp",
      width: output.info.width,
      height: output.info.height,
      inputBytes: input.length
    };
  } catch (error) {
    if (error instanceof HttpError) throw error;
    throw invalidImage();
  }
}

export function validateBase64Chunk(encoded: unknown): Buffer {
  if (typeof encoded !== "string" || encoded.length < 1 || encoded.length > Math.ceil(REPORT_IMAGE_MAX_CHUNK_BYTES / 3) * 4) {
    throw new HttpError(400, "INVALID_REPORT_IMAGE_CHUNK", "Screenshot chunk must contain 1 to 24 KiB of base64-encoded image bytes");
  }
  const bytes = Buffer.from(encoded, "base64");
  if (bytes.length < 1 || bytes.length > REPORT_IMAGE_MAX_CHUNK_BYTES || bytes.toString("base64") !== encoded) {
    throw new HttpError(400, "INVALID_REPORT_IMAGE_CHUNK", "Screenshot chunk must be canonical base64 with at most 24 KiB decoded bytes");
  }
  return bytes;
}
