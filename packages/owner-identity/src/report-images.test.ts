import assert from "node:assert/strict";
import test from "node:test";
import sharp from "sharp";
import { HttpError } from "./http-error.js";
import {
  normalizeReportImage,
  REPORT_IMAGE_DECODER_MAX_PENDING,
  REPORT_IMAGE_MAX_INPUT_BYTES,
  REPORT_IMAGE_MAX_PIXELS,
  validateBase64Chunk,
  withReportImageDecoder
} from "./report-images.js";

async function image(format: "png" | "jpeg" | "webp", width = 8, height = 5): Promise<Buffer> {
  const raw = await sharp({
    create: { width, height, channels: 3, background: { r: 35, g: 80, b: 120 } }
  }).raw().toBuffer();
  const pipeline = sharp(raw, { raw: { width, height, channels: 3 } });
  if (format === "png") return pipeline.png().toBuffer();
  if (format === "jpeg") return pipeline.jpeg().toBuffer();
  return pipeline.webp().toBuffer();
}

function rejectionCode(code: string) {
  return (error: unknown) => error instanceof HttpError && error.code === code;
}

test("normalizes supported formats to bounded metadata-free WebP", async () => {
  for (const format of ["png", "jpeg", "webp"] as const) {
    const source = await image(format);
    const result = await normalizeReportImage(source, `image/${format === "jpeg" ? "jpeg" : format}`);
    assert.equal(result.contentType, "image/webp");
    assert.equal(result.inputBytes, source.length);
    assert.ok(result.bytes.length > 0 && result.bytes.length <= 5 * 1024 * 1024);
    assert.equal(result.width, 8);
    assert.equal(result.height, 5);
    assert.match(result.sha256, /^[0-9a-f]{64}$/);
    assert.match(result.inputSha256, /^[0-9a-f]{64}$/);
    const metadata = await sharp(result.bytes).metadata();
    assert.equal(metadata.format, "webp");
    assert.equal(metadata.exif, undefined);
    assert.equal(metadata.iptc, undefined);
    assert.equal(metadata.xmp, undefined);
  }
});

test("rejects unsupported, mismatched, corrupt, and over-bound image inputs", async () => {
  const valid = await image("png");
  await assert.rejects(normalizeReportImage(valid, "image/jpeg"), rejectionCode("INVALID_REPORT_IMAGE"));
  await assert.rejects(normalizeReportImage(Buffer.from("<svg><script>alert(1)</script></svg>"), "image/png"), rejectionCode("INVALID_REPORT_IMAGE"));
  await assert.rejects(normalizeReportImage(Buffer.from("not an image"), "image/png"), rejectionCode("INVALID_REPORT_IMAGE"));
  await assert.rejects(normalizeReportImage(Buffer.alloc(REPORT_IMAGE_MAX_INPUT_BYTES + 1), "image/png"), rejectionCode("INVALID_REPORT_IMAGE"));
  const oversizedPixels = await image("png", 4001, 4000);
  await assert.rejects(normalizeReportImage(oversizedPixels, "image/png"), rejectionCode("INVALID_REPORT_IMAGE"));
  assert.ok(4001 * 4000 > REPORT_IMAGE_MAX_PIXELS);
});

test("accepts only canonical base64 chunks no larger than 24 KiB", () => {
  const bytes = Buffer.alloc(24 * 1024, 0x5a);
  assert.deepEqual(validateBase64Chunk(bytes.toString("base64")), bytes);
  assert.throws(() => validateBase64Chunk(`${bytes.toString("base64")}A`), rejectionCode("INVALID_REPORT_IMAGE_CHUNK"));
  assert.throws(() => validateBase64Chunk(Buffer.alloc(24 * 1024 + 1, 0x5a).toString("base64")), rejectionCode("INVALID_REPORT_IMAGE_CHUNK"));
  assert.throws(() => validateBase64Chunk("%%%"), rejectionCode("INVALID_REPORT_IMAGE_CHUNK"));
});

test("serializes image decoding and caps retained waiters", async () => {
  let releaseFirst!: () => void;
  let markStarted!: () => void;
  const firstGate = new Promise<void>((resolve) => { releaseFirst = resolve; });
  const started = new Promise<void>((resolve) => { markStarted = resolve; });
  let active = 0;
  let maximumActive = 0;
  const first = withReportImageDecoder(async () => {
    active++;
    maximumActive = Math.max(maximumActive, active);
    markStarted();
    await firstGate;
    active--;
  });
  await started;
  const queued = Array.from({ length: REPORT_IMAGE_DECODER_MAX_PENDING }, () => withReportImageDecoder(async () => {
    active++;
    maximumActive = Math.max(maximumActive, active);
    await Promise.resolve();
    active--;
  }));
  await assert.rejects(withReportImageDecoder(async () => undefined), rejectionCode("REPORT_IMAGE_DECODER_BUSY"));
  releaseFirst();
  await Promise.all([first, ...queued]);
  assert.equal(maximumActive, 1);
});
