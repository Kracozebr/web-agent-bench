import { createHash } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import type { ProbeArtifact, ProbeObservation, RawObservation } from './types.js';

const SECRET_KEY = /(?:authorization|run.?token|private.?key|secret|signature|admin.?key|service.?key|password|credential)/i;
const REDACTED = '[REDACTED]';

export function sha256Bytes(value: Uint8Array): string {
  return createHash('sha256').update(value).digest('hex');
}

export function sanitizeHeaders(
  headers: Record<string, string>,
  additionalSecretValues: readonly string[] = [],
): Record<string, string> {
  const redactedNames = new Set([
    'authorization',
    'proxy-authorization',
    'payment-signature',
    'x-payment-signature',
    'x-bef-admin-key',
    'x-bef-service-key',
    'set-cookie',
  ]);
  const secrets = additionalSecretValues.filter(Boolean);
  return Object.fromEntries(
    Object.entries(headers).map(([name, value]) => {
      if (redactedNames.has(name.toLowerCase())) return [name, REDACTED];
      let safeValue = value;
      for (const secret of secrets) safeValue = safeValue.replaceAll(secret, REDACTED);
      return [name, safeValue];
    }),
  );
}

export function sanitizeValue(value: unknown, additionalSecretValues: readonly string[] = []): unknown {
  if (value instanceof Date) {
    if (Number.isNaN(value.getTime())) throw new Error('probe_invalid_date_observation');
    return value.toISOString();
  }
  if (Array.isArray(value)) return value.map((entry) => sanitizeValue(entry, additionalSecretValues));
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([key, child]) => [
        key,
        SECRET_KEY.test(key) ? REDACTED : sanitizeValue(child, additionalSecretValues),
      ]),
    );
  }
  if (typeof value === 'string') {
    return additionalSecretValues.filter(Boolean).reduce(
      (safeValue, secret) => safeValue.replaceAll(secret, REDACTED),
      value,
    );
  }
  return value;
}

function resolveChildPath(baseDirectory: string, relativePath: string): string {
  if (!relativePath || isAbsolute(relativePath)) throw new Error('Evidence artifact path must be relative');
  const destination = resolve(baseDirectory, relativePath);
  const remainder = relative(baseDirectory, destination);
  if (!remainder || remainder === '..' || remainder.startsWith(`..${sep}`) || isAbsolute(remainder)) {
    throw new Error('Evidence artifact path escapes its output directory');
  }
  return destination;
}

export class EvidenceWriter {
  readonly directory: string;
  readonly artifacts: ProbeArtifact[] = [];
  readonly observations: ProbeObservation[] = [];

  constructor(directory: string) {
    this.directory = resolve(directory);
  }

  async initialize(): Promise<void> {
    await mkdir(this.directory, { recursive: true });
  }

  async writeManifestCopy(rawBytes: Uint8Array): Promise<{ path: 'manifest.json'; sha256: string }> {
    const path = 'manifest.json';
    await this.writeFile(path, rawBytes);
    const sha256 = sha256Bytes(rawBytes);
    this.artifacts.push({ path, sha256, contentType: 'application/json', boundary: 'runtime-manifest' });
    return { path, sha256 };
  }

  async writeObservation(
    relativePath: string,
    observationId: string,
    body: Omit<RawObservation, 'operationId' | 'variantId'> & {
      operationId: string | null;
      variantId: string | null;
    },
  ): Promise<string> {
    const safeBody = {
      ...body,
      operationId: body.operationId,
      variantId: body.variantId,
    } as RawObservation;
    const bytes = Buffer.from(`${JSON.stringify(safeBody, null, 2)}\n`, 'utf8');
    await this.writeFile(relativePath, bytes);
    this.artifacts.push({
      path: relativePath,
      sha256: sha256Bytes(bytes),
      contentType: 'application/json',
      boundary: String(body.boundary),
    });
    this.observations.push({ id: observationId, sourceArtifact: relativePath });
    return relativePath;
  }

  async writeRawJson(relativePath: string, bytes: Uint8Array, boundary: string): Promise<string> {
    const path = resolveChildPath(this.directory, relativePath);
    await mkdir(resolve(path, '..'), { recursive: true });
    await writeFile(path, bytes, { flag: 'wx' });
    this.artifacts.push({
      path: relativePath,
      sha256: sha256Bytes(bytes),
      contentType: 'application/json',
      boundary,
    });
    return relativePath;
  }

  async writeProbe<T extends object>(payload: T): Promise<void> {
    const path = resolveChildPath(this.directory, 'probe.json');
    await writeFile(path, `${JSON.stringify(payload, null, 2)}\n`, { encoding: 'utf8', flag: 'wx' });
  }

  private async writeFile(relativePath: string, bytes: Uint8Array): Promise<void> {
    const path = resolveChildPath(this.directory, relativePath);
    await mkdir(resolve(path, '..'), { recursive: true });
    await writeFile(path, bytes, { flag: 'wx' });
  }
}
