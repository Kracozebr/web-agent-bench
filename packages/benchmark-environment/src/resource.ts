import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import type { RuntimeManifest } from './manifest.js';
import { pinnedResources } from './offers.js';

export type ResourceBytes = {
  resourceId: string;
  contentType: string;
  schema?: string;
  provenance?: Record<string, unknown>;
  bytes: Buffer;
  hash: string;
  parsed: Record<string, unknown>;
};

async function loadResource(input: {
  resourceId: string;
  resourcePath: string;
  resourceSha256: string;
  contentType: string;
  schema?: string;
  provenance?: Record<string, unknown>;
}, verifyCatalogMetadata: boolean): Promise<ResourceBytes> {
  const root = resolve(process.cwd());
  const path = resolve(root, input.resourcePath);
  if (!path.startsWith(`${root}\\`) && !path.startsWith(`${root}/`)) throw new Error('Pinned resource path escaped the runtime root');
  const bytes = await readFile(path);
  const hash = createHash('sha256').update(bytes).digest('hex');
  if (hash !== input.resourceSha256) throw new Error(`Resource bytes differ from the pinned manifest hash: ${input.resourceId}`);
  let parsed: unknown;
  try { parsed = JSON.parse(bytes.toString('utf8')) as unknown; } catch { throw new Error('Pinned resource is not valid JSON'); }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('Pinned resource must be a JSON object');
  const record = parsed as Record<string, unknown>;
  if (record.resourceId !== input.resourceId) throw new Error('Pinned resource id differs from the manifest');
  if (verifyCatalogMetadata && (record.schema !== input.schema ||
      (record.provenance !== undefined && JSON.stringify(record.provenance) !== JSON.stringify(input.provenance)))) {
    throw new Error(`Pinned resource schema or provenance differs from the manifest: ${input.resourceId}`);
  }
  return { ...input, bytes, hash, parsed: record };
}

export async function loadPinnedResources(manifest: RuntimeManifest): Promise<Map<string, ResourceBytes>> {
  const resources = new Map<string, ResourceBytes>();
  for (const entry of pinnedResources(manifest)) {
    const loaded = await loadResource({
      resourceId: entry.resourceId,
      resourcePath: entry.resourcePath,
      resourceSha256: entry.resourceSha256,
      contentType: entry.contentType,
      schema: entry.schema,
      provenance: entry.provenance,
    }, manifest.x402.catalog !== undefined);
    if (resources.has(loaded.resourceId)) throw new Error('Pinned resource catalog contains duplicate identifiers');
    resources.set(loaded.resourceId, loaded);
  }
  return resources;
}

export async function loadPinnedResource(manifest: RuntimeManifest): Promise<ResourceBytes> {
  const resources = await loadPinnedResources(manifest);
  const resource = resources.get(manifest.x402.resourceId);
  if (!resource) throw new Error('Legacy pinned resource is absent from the catalog');
  return resource;
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
  return { ...resource, bytes, hash, parsed: mutated };
}
