import type { FastifyInstance, FastifyRequest } from 'fastify';
import { keccak256, type Hex } from 'viem';
import { z } from 'zod';
import type { ApplicationRuntime, RuntimeEnvironment } from './runtime.js';

type RpcObservation = { method: string; params: unknown[]; result: unknown };
type IdentityObservations = {
  source: { chainId: RpcObservation; block: RpcObservation; code?: RpcObservation };
  local: { chainId: RpcObservation; block: RpcObservation };
};

const negativeRequestSchema = z.object({
  variantId: z.enum(['wrong_block', 'wrong_chain', 'missing_code', 'per_trial_latest']),
  candidate: z.unknown(),
}).strict();
const positiveRequestSchema = z.object({
  candidateType: z.enum(['source_block', 'source_chain', 'required_code']),
  candidate: z.unknown(),
}).strict();
const requestSchema = z.union([negativeRequestSchema, positiveRequestSchema]);
const blockCandidateSchema = z.object({
  blockNumber: z.string().regex(/^0x[0-9a-f]+$/i),
  blockHash: z.string().regex(/^0x[0-9a-f]{64}$/i),
}).strict();
const chainCandidateSchema = z.object({ chainId: z.number().int().positive() }).strict();
const codeCandidateSchema = z.object({
  contractAddress: z.string().regex(/^0x[0-9a-f]{40}$/i),
  codeHash: z.string().regex(/^0x[0-9a-f]{64}$/i),
}).strict();
const latestCandidateSchema = z.object({ requestedBlock: z.literal('latest') }).strict();
const zeroAddress = `0x${'0'.repeat(40)}`;

async function rpcObservation(url: string, method: string, params: unknown[]): Promise<RpcObservation> {
  let response: Response;
  try {
    response = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
      redirect: 'error',
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    throw new Error('prerequisite_observation_unavailable');
  }
  if (!response.ok) throw new Error('prerequisite_observation_unavailable');
  let envelope: unknown;
  try {
    envelope = await response.json() as unknown;
  } catch {
    throw new Error('prerequisite_observation_invalid');
  }
  if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) {
    throw new Error('prerequisite_observation_invalid');
  }
  const value = envelope as Record<string, unknown>;
  if (value.id !== 1 || value.error || !Object.hasOwn(value, 'result')) {
    throw new Error('prerequisite_observation_unavailable');
  }
  return { method, params, result: value.result };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function identityMatches(runtime: ApplicationRuntime, observations: IdentityObservations): boolean {
  const { manifest } = runtime;
  const sourceChain = observations.source.chainId.result;
  const localChain = observations.local.chainId.result;
  const sourceBlock = observations.source.block.result;
  const localBlock = observations.local.block.result;
  if (!isRecord(sourceBlock) || !isRecord(localBlock)) return false;
  return String(sourceChain).toLowerCase() === `0x${manifest.source.chainId.toString(16)}`
    && String(localChain).toLowerCase() === `0x${manifest.local.chainId.toString(16)}`
    && String(sourceBlock.number).toLowerCase() === manifest.source.blockNumber.toLowerCase()
    && String(sourceBlock.hash).toLowerCase() === manifest.source.blockHash.toLowerCase()
    && String(localBlock.number).toLowerCase() === manifest.local.forkBlock.toLowerCase()
    && String(localBlock.hash).toLowerCase() === manifest.source.blockHash.toLowerCase();
}

async function captureIdentity(runtime: ApplicationRuntime, environment: RuntimeEnvironment): Promise<IdentityObservations> {
  const sourceUrl = runtime.config.sourceProxyUrl;
  const localUrl = environment.observerRpcUrl;
  const sourceBlock = runtime.manifest.source.blockNumber;
  const localBlock = runtime.manifest.local.forkBlock;
  const [sourceChainId, sourceBlockObservation, localChainId, localBlockObservation] = await Promise.all([
    rpcObservation(sourceUrl, 'eth_chainId', []),
    rpcObservation(sourceUrl, 'eth_getBlockByNumber', [sourceBlock, false]),
    rpcObservation(localUrl, 'eth_chainId', []),
    rpcObservation(localUrl, 'eth_getBlockByNumber', [localBlock, false]),
  ]);
  const observations: IdentityObservations = {
    source: { chainId: sourceChainId, block: sourceBlockObservation },
    local: { chainId: localChainId, block: localBlockObservation },
  };
  if (!identityMatches(runtime, observations)) throw new Error('prerequisite_environment_identity_mismatch');
  return observations;
}

async function authorizeCodeCandidate(
  runtime: ApplicationRuntime,
  candidate: z.infer<typeof codeCandidateSchema>,
): Promise<RpcObservation> {
  const address = candidate.contractAddress.toLowerCase();
  const usdcAddress = runtime.manifest.contracts.usdc.address.toLowerCase();
  if (![zeroAddress, usdcAddress].includes(address)
    || candidate.codeHash.toLowerCase() !== runtime.manifest.contracts.usdc.proxyCodeHash.toLowerCase()) {
    throw new Error('invalid_prerequisite_candidate');
  }
  return rpcObservation(runtime.config.sourceProxyUrl, 'eth_getCode', [
    candidate.contractAddress,
    runtime.manifest.source.blockNumber,
  ]);
}

export function registerPrerequisiteValidationRoute(
  app: FastifyInstance,
  runtime: ApplicationRuntime,
  isAuthorized: (request: FastifyRequest) => boolean,
): void {
  app.post<{ Params: { envId: string } }>(
    '/internal/admin/environments/:envId/prerequisite-validations',
    async (request, reply) => {
      if (!isAuthorized(request)) return reply.code(403).send({ error: 'forbidden' });
      const environment = runtime.envs.get(request.params.envId);
      if (!environment) return reply.code(404).send({ error: 'environment_not_found' });
      const parsed = requestSchema.safeParse(request.body);
      if (!parsed.success) return reply.code(400).send({ error: 'invalid_prerequisite_validation_request' });

      let candidate: unknown;
      const positive = 'candidateType' in parsed.data;
      const variantId = 'variantId' in parsed.data ? parsed.data.variantId : null;
      const candidateType = 'candidateType' in parsed.data ? parsed.data.candidateType : null;
      const kind = candidateType ?? variantId;
      switch (kind) {
        case 'wrong_block':
        case 'source_block': {
          const value = blockCandidateSchema.safeParse(parsed.data.candidate);
          if (!value.success) return reply.code(400).send({ error: 'invalid_prerequisite_candidate' });
          candidate = value.data;
          break;
        }
        case 'wrong_chain':
        case 'source_chain': {
          const value = chainCandidateSchema.safeParse(parsed.data.candidate);
          if (!value.success) return reply.code(400).send({ error: 'invalid_prerequisite_candidate' });
          candidate = value.data;
          break;
        }
        case 'missing_code':
        case 'required_code': {
          const value = codeCandidateSchema.safeParse(parsed.data.candidate);
          if (!value.success) return reply.code(400).send({ error: 'invalid_prerequisite_candidate' });
          if (![zeroAddress, runtime.manifest.contracts.usdc.address.toLowerCase()].includes(value.data.contractAddress.toLowerCase())
            || value.data.codeHash.toLowerCase() !== runtime.manifest.contracts.usdc.proxyCodeHash.toLowerCase()) return reply.code(400).send({ error: 'invalid_prerequisite_candidate' });
          candidate = value.data;
          break;
        }
        case 'per_trial_latest': {
          const value = latestCandidateSchema.safeParse(parsed.data.candidate);
          if (!value.success) return reply.code(400).send({ error: 'invalid_prerequisite_candidate' });
          candidate = value.data;
          break;
        }
      }

      try {
        const observations = await captureIdentity(runtime, environment);
        const sourceBlock = observations.source.block.result as Record<string, unknown>;
        const sourceChain = observations.source.chainId.result;
        const candidateRecord = candidate as Record<string, unknown>;
        let accepted = false;
        let reasonCode = 'prerequisites_match';
        if (kind === 'wrong_block' || kind === 'source_block') {
          accepted = String(candidateRecord.blockNumber).toLowerCase() === String(sourceBlock.number).toLowerCase()
            && String(candidateRecord.blockHash).toLowerCase() === String(sourceBlock.hash).toLowerCase();
          if (!accepted) reasonCode = 'source_block_mismatch';
        } else if (kind === 'wrong_chain' || kind === 'source_chain') {
          accepted = BigInt(String(candidateRecord.chainId)) === BigInt(String(sourceChain));
          if (!accepted) reasonCode = 'source_chain_mismatch';
        } else if (kind === 'missing_code' || kind === 'required_code') {
          const code = await authorizeCodeCandidate(runtime, candidate as z.infer<typeof codeCandidateSchema>);
          observations.source = { ...observations.source, code };
          const actualHash = typeof code.result === 'string' && code.result !== '0x' ? keccak256(code.result as `0x${string}`) : null;
          accepted = actualHash !== null && actualHash.toLowerCase() === String(candidateRecord.codeHash).toLowerCase()
            && String(candidateRecord.contractAddress).toLowerCase() === runtime.manifest.contracts.usdc.address.toLowerCase();
          if (!accepted) reasonCode = 'required_code_missing';
        } else if (kind === 'per_trial_latest') {
          accepted = false;
          reasonCode = 'latest_block_disallowed';
        }

        if (positive) {
          return {
            boundary: 'private-admin-prerequisite-validation',
            envId: environment.id,
            candidateType,
            candidate,
            accepted,
            reasonCode,
            manifestSha256: runtime.loadedManifest.sha256,
            applicationSourceSha256: runtime.applicationSourceSha256,
            observations,
          };
        }
        if (!variantId) return reply.code(400).send({ error: 'invalid_prerequisite_validation_request' });
        const requestedVariantId = variantId;
        return {
          boundary: 'private-admin-prerequisite-validation',
          envId: environment.id,
          variantId: requestedVariantId,
          manifestSha256: runtime.loadedManifest.sha256,
          applicationSourceSha256: runtime.applicationSourceSha256,
          candidate,
          accepted,
          reasonCode,
          ...(requestedVariantId === 'per_trial_latest' ? { requestedBlock: 'latest', forwarded: false } : {}),
          observations,
        };
      } catch {
        return reply.code(503).send({ error: 'prerequisite_observation_unavailable' });
      }
    },
  );
}
