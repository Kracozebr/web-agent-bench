import { createHash } from 'node:crypto';
import { readdir, readFile } from 'node:fs/promises';
import { relative, resolve } from 'node:path';
import { existsSync } from 'node:fs';
import pg from 'pg';
import { keccak256, type Address } from 'viem';
import { assertAnvilIdentity, type AnvilIdentity } from './chain.js';
import { readApiConfig, type ApiRuntimeConfig } from './config.js';
import { loadPinnedResource, type ResourceBytes } from './resource.js';
import { loadManifest, type LoadedManifest, type RuntimeManifest } from './manifest.js';
import { poolFor, registerManifest, verifySchema, withEnvironmentAdvisoryLock, withTransaction } from './db.js';
import { EphemeralSignerStore } from './ephemeral-signer-store.js';

const { Pool } = pg;

export type RuntimeEnvironment = {
  id: string;
  adminRpcUrl: string;
  observerRpcUrl: string;
  facilitatorUrl: string;
  facilitatorAddress: Address;
  anvilIdentity: AnvilIdentity;
  facilitatorIdentity: Record<string, unknown>;
};

export type ApplicationRuntime = {
  loadedManifest: LoadedManifest;
  manifest: RuntimeManifest;
  config: ApiRuntimeConfig;
  pool: pg.Pool;
  signerStore: EphemeralSignerStore;
  resource: ResourceBytes;
  envs: Map<string, RuntimeEnvironment>;
  postgresVersion: string;
  apiPackageVersion: string;
  dependencyVersions: Record<string, string>;
  applicationSourceSha256: string;
};

async function listFiles(directory: string): Promise<string[]> {
  const entries = await readdir(directory, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    const file = resolve(directory, entry.name);
    if (entry.isDirectory()) files.push(...await listFiles(file));
    else if (entry.isFile()) files.push(file);
  }
  return files;
}

async function treeDigest(root: string, paths: string[]): Promise<string> {
  const hash = createHash('sha256');
  const sorted = [...new Set(paths)].map((path) => ({
    path,
    rel: relative(root, path).replaceAll('\\', '/'),
  })).sort((left, right) => left.rel < right.rel ? -1 : left.rel > right.rel ? 1 : 0);
  for (const { path, rel } of sorted) {
    hash.update(rel);
    hash.update('\0');
    hash.update(await readFile(path));
    hash.update('\0');
  }
  return hash.digest('hex');
}

async function sourceDigest(root: string): Promise<string> {
  const sourceDir = resolve(root, 'packages/benchmark-environment/src');
  const allTs = (await listFiles(sourceDir)).filter((path) => path.endsWith('.ts'));
  const probeDir = resolve(sourceDir, 'probe');
  const probeFiles = allTs.filter((path) => path === resolve(sourceDir, 'probe.ts') || path.startsWith(`${probeDir}/`) || path.startsWith(`${probeDir}\\`));
  const appFiles = allTs.filter((path) => !probeFiles.includes(path));
  const migrations = await listFiles(resolve(root, 'infrastructure/benchmark-environment/migrations'));
  const staticFiles = [
    resolve(root, 'package.json'),
    resolve(root, 'pnpm-workspace.yaml'),
    resolve(root, 'pnpm-lock.yaml'),
    resolve(root, 'tsconfig.json'),
    resolve(root, 'packages/benchmark-environment/package.json'),
    resolve(root, 'packages/benchmark-environment/tsconfig.json'),
    ...migrations,
    resolve(root, 'infrastructure/benchmark-environment/manifest.json'),
    resolve(root, 'infrastructure/benchmark-environment/resource.json'),
  ];
  return treeDigest(root, [...appFiles, ...staticFiles].filter(existsSync));
}

async function packageMetadata(): Promise<{ version: string; dependencies: Record<string, string> }> {
  const text = await readFile(resolve(process.cwd(), 'packages/benchmark-environment/package.json'), 'utf8');
  const parsed = JSON.parse(text) as { version?: unknown; dependencies?: unknown };
  if (typeof parsed.version !== 'string' || !parsed.dependencies || typeof parsed.dependencies !== 'object') throw new Error('BEF package metadata is invalid');
  return { version: parsed.version, dependencies: parsed.dependencies as Record<string, string> };
}

async function installedVersion(name: string): Promise<string> {
  const metadata = JSON.parse(await readFile(resolve(process.cwd(), 'packages/benchmark-environment/node_modules', name, 'package.json'), 'utf8')) as { version?: unknown };
  if (typeof metadata.version !== 'string') throw new Error(`Installed dependency metadata unavailable: ${name}`);
  return metadata.version;
}

async function verifyPackagePins(manifest: RuntimeManifest): Promise<{ apiPackageVersion: string; versions: Record<string, string> }> {
  if (process.version !== `v${manifest.local.nodeVersion}`) throw new Error('BEF Node runtime does not match the exact manifest version');
  const pkg = await packageMetadata();
  const expected: Record<string, string> = {
    '@x402/core': manifest.local.versions.x402Core,
    '@x402/evm': manifest.local.versions.x402Evm,
    '@x402/fastify': manifest.local.versions.x402Fastify,
    fastify: manifest.local.fastifyVersion,
    pg: manifest.local.versions.postgresDriver,
    viem: manifest.local.versions.viem,
  };
  const versions: Record<string, string> = {};
  for (const [name, pinned] of Object.entries(expected)) {
    if (pkg.dependencies[name] !== pinned) throw new Error(`BEF package manifest version mismatch: ${name}`);
    versions[name] = await installedVersion(name);
    if (versions[name] !== pinned) throw new Error(`Installed BEF dependency differs from the manifest: ${name}`);
  }
  return { apiPackageVersion: pkg.version, versions };
}

async function rpc(url: string, method: string, params: unknown[]): Promise<unknown> {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 73, method, params }),
    signal: AbortSignal.timeout(20_000),
  });
  if (!response.ok) throw new Error('BEF runtime identity RPC failed');
  const result = await response.json() as { id?: number; result?: unknown; error?: unknown };
  if (result.id !== 73 || result.error || !Object.hasOwn(result, 'result')) throw new Error('BEF runtime identity RPC returned no result');
  return result.result;
}

function decodeAbiString(value: unknown): string {
  if (typeof value !== 'string' || !/^0x(?:[0-9a-f]{2})+$/i.test(value)) throw new Error('USDC EIP-712 metadata RPC result is malformed');
  const encoded = value.slice(2);
  const offset = Number(BigInt(`0x${encoded.slice(0, 64)}`));
  if (!Number.isSafeInteger(offset) || offset % 32 !== 0 || offset < 32 || offset * 2 + 64 > encoded.length) {
    throw new Error('USDC EIP-712 metadata ABI offset is invalid');
  }
  const lengthStart = offset * 2;
  const byteLength = Number(BigInt(`0x${encoded.slice(lengthStart, lengthStart + 64)}`));
  const valueStart = lengthStart + 64;
  if (!Number.isSafeInteger(byteLength) || byteLength > 128 || valueStart + byteLength * 2 > encoded.length) {
    throw new Error('USDC EIP-712 metadata ABI string length is invalid');
  }
  return Buffer.from(encoded.slice(valueStart, valueStart + byteLength * 2), 'hex').toString('utf8');
}

async function verifyChainBoundary(url: string, manifest: RuntimeManifest, local: boolean): Promise<void> {
  const chainId = await rpc(url, 'eth_chainId', []) as string;
  if (chainId.toLowerCase() !== '0x2105') throw new Error('RPC chain id does not match the pinned Base domain');
  const block = await rpc(url, 'eth_getBlockByNumber', [manifest.source.blockNumber, false]) as Record<string, unknown> | null;
  if (!block || String(block.number).toLowerCase() !== manifest.source.blockNumber.toLowerCase() || String(block.hash).toLowerCase() !== manifest.source.blockHash.toLowerCase()) {
    throw new Error('RPC block is not the manifest-pinned Base source block');
  }
  for (const [address, expected] of [
    [manifest.contracts.usdc.address, manifest.contracts.usdc.proxyCodeHash],
    [manifest.contracts.usdc.implementation, manifest.contracts.usdc.implementationCodeHash],
    [manifest.contracts.weth.address, manifest.contracts.weth.codeHash],
    [manifest.contracts.factory.address, manifest.contracts.factory.codeHash],
    [manifest.contracts.swapRouter02.address, manifest.contracts.swapRouter02.codeHash],
    [manifest.contracts.quoterV2.address, manifest.contracts.quoterV2.codeHash],
    [manifest.contracts.pool.address, manifest.contracts.pool.codeHash],
  ] as const) {
    const code = await rpc(url, 'eth_getCode', [address, manifest.source.blockNumber]) as `0x${string}`;
    if (keccak256(code).toLowerCase() !== expected.toLowerCase()) throw new Error(`RPC pinned code hash mismatch at ${address}`);
  }
  const slot = await rpc(url, 'eth_getStorageAt', [manifest.contracts.usdc.address, manifest.contracts.usdc.implementationSlot, manifest.source.blockNumber]) as string;
  if (`0x${slot.slice(-40)}`.toLowerCase() !== manifest.contracts.usdc.implementation.toLowerCase()) throw new Error('RPC USDC proxy implementation slot mismatch');
  const [nameResult, versionResult] = await Promise.all([
    rpc(url, 'eth_call', [{ to: manifest.contracts.usdc.address, data: '0x06fdde03' }, manifest.source.blockNumber]),
    rpc(url, 'eth_call', [{ to: manifest.contracts.usdc.address, data: '0x54fd4d50' }, manifest.source.blockNumber]),
  ]);
  if (decodeAbiString(nameResult) !== manifest.x402.eip712Domain.name || decodeAbiString(versionResult) !== manifest.x402.eip712Domain.version) {
    throw new Error('Pinned USDC EIP-712 domain differs from the runtime manifest');
  }
  if (local) {
    const quoter = await rpc(url, 'eth_getCode', [manifest.contracts.quoterV2.address, 'latest']) as `0x${string}`;
    if (keccak256(quoter).toLowerCase() !== manifest.contracts.quoterV2.codeHash.toLowerCase()) throw new Error('Local fork contract state differs from pinned source at latest');
  }
}

async function getHealth(url: string): Promise<Record<string, unknown>> {
  const response = await fetch(`${url}/healthz`, { signal: AbortSignal.timeout(10_000) });
  if (!response.ok) throw new Error('BEF private service health check failed');
  const body = await response.json() as unknown;
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error('BEF private service health response invalid');
  return body as Record<string, unknown>;
}

async function fenceProcessLostGenerations(pool: pg.Pool, envIds: string[]): Promise<void> {
  for (const envId of envIds) {
    await withEnvironmentAdvisoryLock(pool, envId, async () => {
      await withTransaction(pool, async (client) => {
        const active = await client.query<{ generation_id: string }>(
          `SELECT generation_id FROM bef_generation WHERE env_id=$1 AND status='active' FOR UPDATE`,
          [envId],
        );
        if (!active.rowCount) return;
        const generationIds = active.rows.map((row) => row.generation_id);
        await client.query(
          `UPDATE bef_generation SET status='fenced',fenced_at=COALESCE(fenced_at,clock_timestamp())
            WHERE env_id=$1 AND generation_id=ANY($2::uuid[]) AND status='active'`,
          [envId, generationIds],
        );
        // Actions without a durable transaction hash were never broadcast and
        // cannot be resumed because their signer was lost with the process.
        // Hash-bound/unknown operations remain untouched for reconciliation.
        await client.query(
          `UPDATE bef_operation SET status='rejected',receipt_status='not_submitted',completed_at=clock_timestamp()
            WHERE env_id=$1 AND generation_id=ANY($2::uuid[])
              AND status IN ('accepted','awaiting_payment') AND transaction_hash IS NULL
              AND receipt_status IN ('unknown','not_submitted')`,
          [envId, generationIds],
        );
      });
    });
  }
}

export async function loadApplicationRuntime(): Promise<ApplicationRuntime> {
  const root = process.cwd();
  const loadedManifest = await loadManifest();
  const { manifest } = loadedManifest;
  const config = readApiConfig(manifest);
  const packagePins = await verifyPackagePins(manifest);
  const resource = await loadPinnedResource(manifest);
  const pool = poolFor(config.databaseUrl);
  const signerStore = new EphemeralSignerStore();
  const versions = await pool.query<{ version: string; current_user: string }>('SELECT version(), current_user');
  const postgresVersion = versions.rows[0]?.version ?? 'unknown';
  if (!postgresVersion.includes(`PostgreSQL ${manifest.local.postgresqlVersion}`) || versions.rows[0]?.current_user !== 'bef_api') {
    await pool.end();
    throw new Error('BEF PostgreSQL version or least-privilege runtime role differs from manifest');
  }
  await verifySchema(pool);
  const tableCheck = await pool.query<{ table_name: string }>(
    `SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_name LIKE 'bef_%'`,
  );
  const requiredTables = ['bef_environment', 'bef_generation', 'bef_operation', 'bef_payment', 'bef_x402_observation', 'bef_delivery', 'bef_denial'];
  if (requiredTables.some((name) => !tableCheck.rows.some((row) => row.table_name === name))) {
    await pool.end();
    throw new Error('BEF PostgreSQL migration prerequisites are incomplete');
  }
  // A restart loses the RAM-only generation signing keys. Fence every prior
  // active generation before publishing the current manifest; never reset Anvil
  // or alter operations with a durable original transaction hash here.
  await fenceProcessLostGenerations(pool, config.envs.map((environment) => environment.id));
  for (const environment of config.envs) await registerManifest(pool, environment.id, loadedManifest.sha256);

  const sourceHealth = await getHealth(config.sourceProxyUrl);
  if (sourceHealth.manifestSha256 !== loadedManifest.sha256 || sourceHealth.boundary !== 'source-readonly-proxy') throw new Error('Pinned source proxy identity mismatch');
  await verifyChainBoundary(config.sourceProxyUrl, manifest, false);

  const envs = new Map<string, RuntimeEnvironment>();
  for (const envConfig of config.envs) {
    const declared = manifest.local.environments.find((candidate) => candidate.id === envConfig.id);
    if (!declared) throw new Error('Configured environment missing from the manifest');
    const anvilIdentity = await assertAnvilIdentity(envConfig.adminRpcUrl, manifest);
    const localHealth = await getHealth(envConfig.observerRpcUrl);
    if (localHealth.manifestSha256 !== loadedManifest.sha256 || localHealth.envId !== envConfig.id || localHealth.boundary !== 'local-chain-readonly-proxy') {
      throw new Error('Pinned local RPC proxy identity mismatch');
    }
    await verifyChainBoundary(envConfig.observerRpcUrl, manifest, true);
    const identityResponse = await fetch(`${envConfig.facilitatorUrl}/internal/admin/identity`, {
      headers: { 'X-BEF-Service-Key': config.serviceKey },
      signal: AbortSignal.timeout(10_000),
    });
    if (!identityResponse.ok) throw new Error('Private facilitator identity is unavailable');
    const identity = await identityResponse.json() as unknown;
    if (!identity || typeof identity !== 'object' || Array.isArray(identity)) throw new Error('Private facilitator identity response invalid');
    const facilitatorIdentity = identity as Record<string, unknown>;
    if (facilitatorIdentity.envId !== envConfig.id || facilitatorIdentity.manifestSha256 !== loadedManifest.sha256 ||
        typeof facilitatorIdentity.address !== 'string' || !/^0x[0-9a-f]{40}$/i.test(facilitatorIdentity.address) ||
        facilitatorIdentity.chainId !== '0x2105' || facilitatorIdentity.forkBlockHash?.toString().toLowerCase() !== manifest.source.blockHash.toLowerCase()) {
      throw new Error('Private facilitator is not bound to this manifest environment');
    }
    const facilitatorHealth = await getHealth(envConfig.facilitatorUrl);
    if (facilitatorHealth.envId !== envConfig.id || facilitatorHealth.chainId !== manifest.local.chainId || facilitatorHealth.sdk !== manifest.x402.version) {
      throw new Error('Private facilitator health identity mismatch');
    }
    if (facilitatorHealth.facilitatorNodeVersion !== `v${manifest.local.nodeVersion}` ||
        facilitatorHealth.facilitatorPackageVersion !== packagePins.apiPackageVersion ||
        facilitatorIdentity.facilitatorNodeVersion !== `v${manifest.local.nodeVersion}` ||
        facilitatorIdentity.facilitatorPackageVersion !== packagePins.apiPackageVersion) {
      throw new Error('Private facilitator runtime version does not match the manifest package/runtime');
    }
    const facilitatorVersions = facilitatorHealth.dependencyVersions;
    if (!facilitatorVersions || typeof facilitatorVersions !== 'object' || Array.isArray(facilitatorVersions)) {
      throw new Error('Private facilitator installed SDK version observations are missing');
    }
    const actualFacilitatorVersions = facilitatorVersions as Record<string, unknown>;
    if (actualFacilitatorVersions.x402Core !== manifest.local.versions.x402Core ||
        actualFacilitatorVersions.x402Evm !== manifest.local.versions.x402Evm ||
        actualFacilitatorVersions.viem !== manifest.local.versions.viem) {
      throw new Error('Private facilitator installed SDK versions do not match the manifest');
    }
    envs.set(envConfig.id, {
      id: envConfig.id,
      adminRpcUrl: envConfig.adminRpcUrl,
      observerRpcUrl: envConfig.observerRpcUrl,
      facilitatorUrl: envConfig.facilitatorUrl,
      facilitatorAddress: facilitatorIdentity.address as Address,
      anvilIdentity,
      facilitatorIdentity: { ...facilitatorIdentity, ...facilitatorHealth },
    });
  }
  const applicationSourceSha256 = await sourceDigest(root);
  return {
    loadedManifest,
    manifest,
    config,
    pool,
    signerStore,
    resource,
    envs,
    postgresVersion,
    apiPackageVersion: packagePins.apiPackageVersion,
    dependencyVersions: packagePins.versions,
    applicationSourceSha256,
  };
}
