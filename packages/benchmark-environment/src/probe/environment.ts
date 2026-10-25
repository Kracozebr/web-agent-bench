import { createHash, randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { readdir, readFile } from 'node:fs/promises';
import { basename, relative, resolve } from 'node:path';
import { loadManifest, type RuntimeManifest } from '../manifest.js';
import { sha256Bytes } from './evidence.js';

export type ProbeEnvironment = {
  root: string;
  apiBaseUrl: string;
  databaseObserverUrl: string;
  adminKey: string;
  serviceKey: string;
  sourceProxyUrl: string;
  localRpcUrl: string;
  facilitatorUrl: string;
  envId: string;
};

export type LoadedProbeRuntime = {
  root: string;
  manifest: RuntimeManifest;
  manifestPath: string;
  manifestBytes: Uint8Array;
  manifestSha256: string;
  appSourceSha256: string;
  probeSourceSha256: string;
  runtimeVersions: Record<string, string>;
};

export function findRepositoryRoot(start = process.cwd()): string {
  const candidates = [start, resolve(start, '..'), resolve(start, '../..'), resolve(start, '../../..')];
  for (const candidate of candidates) {
    if (existsSync(resolve(candidate, 'infrastructure/benchmark-environment/manifest.json'))
      && existsSync(resolve(candidate, 'packages/benchmark-environment/src/probe.ts'))) return candidate;
  }
  throw new Error('probe_repository_root_unavailable');
}

function requiredValue(name: string, minLength = 1): string {
  if (process.env[`${name}_FILE`]) throw new Error(`file_secret_not_allowed:${name}`);
  const value = process.env[name];
  if (!value || value.length < minLength) throw new Error(`missing_environment_value:${name}`);
  return value;
}

function validatedUrl(name: string, value: string): string {
  try {
    const url = new URL(value);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) throw new Error();
    return url.toString().replace(/\/$/, '');
  } catch {
    throw new Error(`invalid_environment_url:${name}`);
  }
}

export function runtimeEnvironment(manifest: RuntimeManifest, envId: string): ProbeEnvironment {
  const apiBaseUrl = validatedUrl('BEF_API_BASE_URL', requiredValue('BEF_API_BASE_URL'));
  const databaseObserverUrl = requiredValue('BEF_DATABASE_OBSERVER_URL');
  let dbUrl: URL;
  try {
    dbUrl = new URL(databaseObserverUrl);
  } catch {
    throw new Error('invalid_environment_url:BEF_DATABASE_OBSERVER_URL');
  }
  if (!['postgres:', 'postgresql:'].includes(dbUrl.protocol) || !dbUrl.username || !dbUrl.password) {
    throw new Error('invalid_environment_url:BEF_DATABASE_OBSERVER_URL');
  }
  const adminKey = requiredValue('BEF_ADMIN_KEY', 32);
  const serviceKey = requiredValue('BEF_SERVICE_KEY', 32);
  const sourceProxyUrl = validatedUrl('BEF_SOURCE_PROXY_URL', requiredValue('BEF_SOURCE_PROXY_URL'));
  const suffix = envId.toUpperCase().replaceAll('-', '_');
  const localRpcUrl = validatedUrl(`BEF_LOCAL_RPC_PROXY_URL_${suffix}`, requiredValue(`BEF_LOCAL_RPC_PROXY_URL_${suffix}`));
  const facilitatorUrl = validatedUrl(`BEF_FACILITATOR_URL_${suffix}`, requiredValue(`BEF_FACILITATOR_URL_${suffix}`));
  if (!manifest.local.environments.some((entry) => entry.id === envId)) throw new Error('probe_unknown_environment');
  return { root: process.cwd(), apiBaseUrl, databaseObserverUrl, adminKey, serviceKey, sourceProxyUrl, localRpcUrl, facilitatorUrl, envId };
}

async function walkFiles(directory: string): Promise<string[]> {
  const entries = await readdir(directory, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    const path = resolve(directory, entry.name);
    if (entry.isDirectory()) files.push(...await walkFiles(path));
    else if (entry.isFile()) files.push(path);
  }
  return files;
}

async function treeDigest(root: string, paths: string[]): Promise<string> {
  const hash = createHash('sha256');
  const sorted = paths.map((path) => ({
    path,
    rel: relative(root, path).replaceAll('\\', '/'),
  })).sort((left, right) => left.rel < right.rel ? -1 : left.rel > right.rel ? 1 : 0);
  for (const { path, rel } of sorted) {
    const bytes = await readFile(path);
    hash.update(rel);
    hash.update('\0');
    hash.update(bytes);
    hash.update('\0');
  }
  return hash.digest('hex');
}

export async function sourceDigests(root: string): Promise<{ appSourceSha256: string; probeSourceSha256: string }> {
  const srcDir = resolve(root, 'packages/benchmark-environment/src');
  const allTs = (await walkFiles(srcDir)).filter((path) => path.endsWith('.ts'));
  const probeDir = resolve(srcDir, 'probe');
  const probeFiles = allTs.filter((path) => path === resolve(srcDir, 'probe.ts') || path.startsWith(`${probeDir}/`) || path.startsWith(`${probeDir}\\`));
  const appFiles = allTs.filter((path) => !probeFiles.includes(path));
  const staticFiles = [
    resolve(root, 'package.json'),
    resolve(root, 'pnpm-workspace.yaml'),
    resolve(root, 'pnpm-lock.yaml'),
    resolve(root, 'tsconfig.json'),
    resolve(root, 'packages/benchmark-environment/package.json'),
    resolve(root, 'packages/benchmark-environment/tsconfig.json'),
    ...await walkFiles(resolve(root, 'infrastructure/benchmark-environment/migrations')),
    resolve(root, 'infrastructure/benchmark-environment/manifest.json'),
    resolve(root, 'infrastructure/benchmark-environment/resource.json'),
  ];
  const uniqueAppFiles = [...new Set([...appFiles, ...staticFiles])].filter((path) => existsSync(path));
  return {
    appSourceSha256: await treeDigest(root, uniqueAppFiles),
    probeSourceSha256: await treeDigest(root, probeFiles),
  };
}

export async function loadProbeRuntime(): Promise<LoadedProbeRuntime> {
  const root = findRepositoryRoot();
  process.chdir(root);
  const manifestPath = resolve(root, 'infrastructure/benchmark-environment/manifest.json');
  const manifestBytes = await readFile(manifestPath);
  const loaded = await loadManifest();
  const digests = await sourceDigests(root);
  return {
    root,
    manifest: loaded.manifest,
    manifestPath,
    manifestBytes,
    manifestSha256: sha256Bytes(manifestBytes),
    ...digests,
    runtimeVersions: {
      probeNode: process.version,
      apiNode: 'unknown',
      facilitatorNode: 'unknown',
      anvil: 'unknown',
      postgresql: 'unknown',
    },
  };
}

export function newParticipantId(scenarioId: string): string {
  return `probe-${scenarioId.toLowerCase()}-${randomUUID()}`;
}

export function apiPath(baseUrl: string, path: string): string {
  const normalizedPath = path.startsWith('/') ? path : `/${path}`;
  return `${baseUrl}${normalizedPath}`;
}

export function safeEnvFileName(value: string): string {
  return basename(value).replace(/[^a-zA-Z0-9_.-]/g, '_');
}
