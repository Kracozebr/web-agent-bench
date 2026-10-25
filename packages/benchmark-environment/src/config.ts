import { readFileSync } from 'node:fs';
import { z } from 'zod';

function requiredUrl(name: string): URL {
  const raw = process.env[name];
  if (!raw) throw new Error(`Missing runtime prerequisite: ${name}`);
  try {
    const url = new URL(raw);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) throw new Error();
    return url;
  } catch {
    throw new Error(`Invalid URL runtime prerequisite: ${name}`);
  }
}

function internalHttpUrl(name: string, hostname: string): string {
  const url = requiredUrl(name);
  if (url.protocol !== 'http:' || url.hostname !== hostname || url.username || url.password || url.search || url.hash) {
    throw new Error(`Runtime endpoint ${name} must target its manifest-declared private service host`);
  }
  return url.toString().replace(/\/$/, '');
}

export function readRuntimeValue(name: string, minLength = 1): string {
  const direct = process.env[name];
  const file = process.env[`${name}_FILE`];
  if (direct && file) throw new Error(`Configure only one secret source for ${name}`);
  if (file) {
    try {
      const value = readFileSync(file, 'utf8').trim();
      if (value.length < minLength) throw new Error();
      return value;
    } catch {
      throw new Error(`Secret file prerequisite unavailable or too short: ${name}_FILE`);
    }
  }
  if (!direct || direct.length < minLength) throw new Error(`Secret prerequisite missing or too short: ${name}`);
  return direct;
}

export const readSecret = (name: string) => readRuntimeValue(name, 32);

const EnvId = z.string().regex(/^[a-z][a-z0-9-]{1,31}$/);
const Port = z.coerce.number().int().min(1).max(65535);

export type ApiRuntimeConfig = {
  port: number;
  bindAddress: string;
  adminKey: string;
  serviceKey: string;
  databaseUrl: string;
  sourceProxyUrl: string;
  envs: Array<{
    id: string;
    adminRpcUrl: string;
    observerRpcUrl: string;
    facilitatorUrl: string;
  }>;
};

export function readApiConfig(manifest: import('./manifest.js').RuntimeManifest): ApiRuntimeConfig {
  const port = Port.parse(process.env.BEF_API_PORT ?? '3000');
  const bindAddress = process.env.BEF_API_BIND ?? '0.0.0.0';
  if (bindAddress !== '0.0.0.0' && bindAddress !== '127.0.0.1' && bindAddress !== '::1') {
    throw new Error('BEF_API_BIND must be a loopback or container-network address');
  }
  const adminKey = readSecret('BEF_ADMIN_KEY');
  const serviceKey = readSecret('BEF_SERVICE_KEY');
  const databaseUrl = readRuntimeValue('BEF_DATABASE_URL', 1);
  const db = new URL(databaseUrl);
  if ((db.protocol !== 'postgres:' && db.protocol !== 'postgresql:') || db.hostname !== manifest.local.databaseHost || db.search || db.hash) {
    throw new Error('BEF_DATABASE_URL must target the manifest-declared PostgreSQL service');
  }
  const sourceProxyUrl = internalHttpUrl('BEF_SOURCE_PROXY_URL', manifest.local.sourceProxyHost);
  const envs = manifest.local.environments.map(({ id, anvilHost, localProxyHost, facilitatorHost }) => {
    const envId = EnvId.parse(id);
    const suffix = envId.toUpperCase().replaceAll('-', '_');
    return {
      id: envId,
      adminRpcUrl: internalHttpUrl(`BEF_ANVIL_ADMIN_RPC_URL_${suffix}`, anvilHost),
      observerRpcUrl: internalHttpUrl(`BEF_LOCAL_RPC_PROXY_URL_${suffix}`, localProxyHost),
      facilitatorUrl: internalHttpUrl(`BEF_FACILITATOR_URL_${suffix}`, facilitatorHost),
    };
  });
  return { port, bindAddress, adminKey, serviceKey, databaseUrl, sourceProxyUrl, envs };
}

export type FacilitatorRuntimeConfig = {
  port: number;
  bindAddress: string;
  envId: string;
  rpcUrl: string;
  serviceKey: string;
};

export function readFacilitatorConfig(manifest: import('./manifest.js').RuntimeManifest): FacilitatorRuntimeConfig {
  const envId = EnvId.parse(process.env.BEF_ENV_ID);
  const environment = manifest.local.environments.find((candidate) => candidate.id === envId);
  if (!environment) throw new Error('BEF_ENV_ID is not declared in the pinned manifest');
  return {
    port: Port.parse(process.env.BEF_FACILITATOR_PORT ?? '4021'),
    bindAddress: process.env.BEF_FACILITATOR_BIND ?? '0.0.0.0',
    envId,
    rpcUrl: internalHttpUrl('BEF_ANVIL_ADMIN_RPC_URL', environment.anvilHost),
    serviceKey: readSecret('BEF_SERVICE_KEY'),
  };
}

export function readProxyConfig(manifest: import('./manifest.js').RuntimeManifest): { port: number; bindAddress: string; targetUrl: string; mode: 'source' | 'local'; envId?: string } {
  const mode = z.enum(['source', 'local']).parse(process.env.BEF_PROXY_MODE);
  const port = Port.parse(process.env.BEF_PROXY_PORT ?? '8545');
  const targetUrl = mode === 'source'
    ? readRuntimeValue('BEF_SOURCE_RPC_URL')
    : requiredUrl('BEF_RPC_TARGET_URL').toString().replace(/\/$/, '');
  if (mode === 'source') {
    try {
      const url = new URL(targetUrl);
      if (!['https:', 'http:'].includes(url.protocol)) throw new Error();
    } catch {
      throw new Error('BEF_SOURCE_RPC_URL must be an HTTP(S) endpoint');
    }
  }
  const bindAddress = process.env.BEF_PROXY_BIND ?? '0.0.0.0';
  if (bindAddress !== '0.0.0.0' && bindAddress !== '127.0.0.1' && bindAddress !== '::1') throw new Error('Invalid proxy bind address');
  const envId = process.env.BEF_ENV_ID ? EnvId.parse(process.env.BEF_ENV_ID) : undefined;
  if (mode === 'local') {
    const environment = manifest.local.environments.find((candidate) => candidate.id === envId);
    if (!environment) throw new Error('Local observer proxy requires a manifest-declared BEF_ENV_ID');
    const url = new URL(targetUrl);
    if (url.protocol !== 'http:' || url.hostname !== environment.anvilHost || url.username || url.password || url.search || url.hash) {
      throw new Error('Local observer proxy target must be its manifest-declared private Anvil host');
    }
  }
  return { port, bindAddress, targetUrl, mode, ...(envId ? { envId } : {}) };
}
