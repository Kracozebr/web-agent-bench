import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import type { RuntimeManifest } from './manifest.js';

export type ResourceBytes = {
  bytes: Buffer;
  hash: string;
  parsed: Record<string, unknown>;
};

export async function loadPinnedResource(manifest: RuntimeManifest): Promise<ResourceBytes> {
  const bytes = await readFile(resolve(process.cwd(), manifest.x402.resourcePath));
  const hash = createHash('sha256').update(bytes).digest('hex');
  if (hash !== manifest.x402.resourceSha256) throw new Error('Resource bytes differ from the pinned manifest hash');
  let parsed: unknown;
  try { parsed = JSON.parse(bytes.toString('utf8')) as unknown; } catch { throw new Error('Pinned resource is not valid JSON'); }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('Pinned resource must be a JSON object');
  if ((parsed as Record<string, unknown>).resourceId !== manifest.x402.resourceId) throw new Error('Pinned resource id differs from the manifest');
  return { bytes, hash, parsed: parsed as Record<string, unknown> };
}

export function mismatchedResource(resource: ResourceBytes): ResourceBytes {
  const data = JSON.parse(resource.bytes.toString('utf8')) as Record<string, unknown>;
  const content = data.content;
  if (!content || typeof content !== 'object' || Array.isArray(content)) throw new Error('Mismatch fixture requires a content object');
  const body = (content as Record<string, unknown>).body;
  if (typeof body !== 'string' || body.length === 0) throw new Error('Mismatch fixture requires a text body');
  const mutated = { ...data, content: { ...(content as Record<string, unknown>), body: `${body} [controlled local resource mutation]` } };
  const bytes = Buffer.from(`${JSON.stringify(mutated, null, 2)}\n`, 'utf8');
  const hash = createHash('sha256').update(bytes).digest('hex');
  if (hash === resource.hash) throw new Error('Mismatch fixture unexpectedly matches the declared resource');
  return { bytes, hash, parsed: mutated };
}
