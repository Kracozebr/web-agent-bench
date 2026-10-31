import { randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { privateKeyToAccount } from 'viem/accounts';
import type { Address, Hex } from 'viem';
import { resetAnvilFork } from './chain.js';
import { withEnvironmentAdvisoryLock, withTransaction, runTokenHash } from './db.js';
import {
  GenerationFixtureFailure,
  fundGenerationFixture,
  observeOriginalGenerationFixtureReceipt,
} from './fixtures.js';
import type { ApplicationRuntime, RuntimeEnvironment } from './runtime.js';
import {
  bindFixtureTransactionHash,
  bindPreparationGeneration,
  confirmPreparationFence,
  markPreparationUnknown,
  preparationRequestHash,
  publicPreparationStatus,
  recordPreparationFixture,
  recordPreparationResetProof,
  recordRecoveredFixtureReceipt,
  reservePreparation,
  selectPreparation,
  type PreparationRequestPins,
} from './preparation-state.js';
import { bindGenerationSigner } from './selected-execution.js';

const uuidSchema = z.string().uuid();
const addressPattern = /^0x[0-9a-fA-F]{40}$/;
const preparationInput = z.object({
  publicPinsSha256: z.string().regex(/^[0-9a-f]{64}$/i),
  participantId: z.string().min(1).max(128).regex(/^[\x21-\x7e]+$/),
  payerAddress: z.string().regex(addressPattern),
  resourceVariant: z.enum(['canonical', 'mismatched_data', 'verification_without_receipt']),
  payerPrivateKey: z.string().regex(/^0x[0-9a-fA-F]{64}$/).optional(),
}).strict();

function sameSecret(candidate: unknown, expected: string): boolean {
  if (typeof candidate !== 'string') return false;
  const supplied = Buffer.from(candidate);
  const configured = Buffer.from(expected);
  return supplied.length === configured.length && timingSafeEqual(supplied, configured);
}

function authorized(request: FastifyRequest, runtime: ApplicationRuntime): boolean {
  return sameSecret(request.headers['x-bef-admin-key'], runtime.config.adminKey);
}

function isPlainEmptyObject(value: unknown): boolean {
  return value === undefined || (
    value !== null && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === 0
  );
}

function environmentFor(runtime: ApplicationRuntime, envId: string): RuntimeEnvironment | null {
  return runtime.envs.get(envId) ?? null;
}

async function recoverFacilitator(runtime: ApplicationRuntime, environment: RuntimeEnvironment): Promise<void> {
  const response = await fetch(`${environment.facilitatorUrl}/internal/admin/recover-after-fork-reset`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'X-BEF-Service-Key': runtime.config.serviceKey,
    },
    body: JSON.stringify({ manifestSha256: runtime.loadedManifest.sha256 }),
    signal: AbortSignal.timeout(30_000),
  });
  if (!response.ok) throw new Error('facilitator_recovery_failed');
  const result = await response.json() as unknown;
  if (!result || typeof result !== 'object' || Array.isArray(result)) throw new Error('facilitator_recovery_response_invalid');
  const body = result as Record<string, unknown>;
  if (body.status !== 'ready' || body.envId !== environment.id ||
      typeof body.address !== 'string' || body.address.toLowerCase() !== environment.facilitatorAddress.toLowerCase() ||
      body.fundedWei !== runtime.manifest.funding.facilitatorNativeEthWei) {
    throw new Error('facilitator_recovery_identity_mismatch');
  }
}

async function preparationReadiness(runtime: ApplicationRuntime, envId: string): Promise<'ready' | 'active' | 'unfinished' | 'unresolved'> {
  return withTransaction(runtime.pool, async (client) => {
    const active = await client.query(
      `SELECT 1 FROM bef_generation WHERE env_id=$1 AND status='active' LIMIT 1`,
      [envId],
    );
    if (active.rowCount) return 'active';
    const unfinished = await client.query(
      `SELECT 1 FROM bef_preparation WHERE env_id=$1 AND status <> 'fenced' LIMIT 1`,
      [envId],
    );
    if (unfinished.rowCount) return 'unfinished';
    const unresolved = await client.query(
      `SELECT 1 FROM bef_operation WHERE env_id=$1 AND status IN ('verifying','settling','settlement_unknown') LIMIT 1`,
      [envId],
    );
    if (unresolved.rowCount) return 'unresolved';
    await client.query(
      `UPDATE bef_operation SET status='rejected',receipt_status='not_submitted',completed_at=clock_timestamp()
        WHERE env_id=$1 AND status IN ('accepted','awaiting_payment') AND transaction_hash IS NULL
          AND receipt_status IN ('unknown','not_submitted')`,
      [envId],
    );
    return 'ready';
  });
}

export function registerPreparationRoutes(app: FastifyInstance, runtime: ApplicationRuntime): void {
  app.put<{ Params: { envId: string; preparationId: string } }>(
    '/internal/admin/environments/:envId/preparations/:preparationId',
    async (request, reply) => {
      if (!authorized(request, runtime)) return reply.code(403).send({ error: 'forbidden' });
      const { envId, preparationId } = request.params;
      const environment = environmentFor(runtime, envId);
      if (!environment) return reply.code(404).send({ error: 'environment_not_found' });
      const parsedId = uuidSchema.safeParse(preparationId);
      const parsedBody = preparationInput.safeParse(request.body);
      if (!parsedId.success || !parsedBody.success || !isPlainEmptyObject(request.query)) {
        return reply.code(400).send({ error: 'invalid_preparation_request' });
      }
      reply.header('cache-control', 'no-store');

      const input = parsedBody.data;
      const payerAddress = input.payerAddress.toLowerCase() as Address;
      if (payerAddress === runtime.manifest.funding.donor.toLowerCase() ||
          payerAddress === environment.facilitatorAddress.toLowerCase()) {
        return reply.code(400).send({ error: 'payer_address_not_ephemeral' });
      }
      let payerPrivateKey: Hex | undefined;
      if (input.payerPrivateKey) {
        try {
          const derivedAddress = privateKeyToAccount(input.payerPrivateKey as Hex).address;
          if (derivedAddress.toLowerCase() !== payerAddress.toLowerCase()) {
            return reply.code(400).send({ error: 'payer_signer_address_mismatch' });
          }
          payerPrivateKey = input.payerPrivateKey as Hex;
        } catch {
          return reply.code(400).send({ error: 'payer_signer_invalid' });
        }
      }

      // AICODE-NOTE: The owner adapter hashes its canonical public task intent into
      // publicPinsSha256. BEF binds that hash to environment/participant pins; secrets never enter it.
      const pins: PreparationRequestPins = {
        preparationId,
        envId,
        publicPinsSha256: input.publicPinsSha256.toLowerCase(),
        participantId: input.participantId,
        payerAddress,
        resourceVariant: input.resourceVariant,
        manifestSha256: runtime.loadedManifest.sha256,
      };
      const requestSha256 = preparationRequestHash(pins);
      const expiresInSeconds = runtime.manifest.guardrails.maxTrialSeconds;
      let attemptedGenerationId: string | null = null;

      try {
        const result = await withEnvironmentAdvisoryLock(runtime.pool, envId, async () => {
          const prior = await withTransaction(runtime.pool, (client) => selectPreparation(client, preparationId));
          if (prior) {
            if (prior.env_id !== envId || prior.request_sha256?.trim() !== requestSha256) return { kind: 'identity_conflict' as const };
            if (prior.status === 'ready') {
              const cached = runtime.preparationResponses.get(envId, preparationId, requestSha256);
              if (cached && prior.generation_id === cached.generationId) return { kind: 'created' as const, response: cached };
              return { kind: 'secret_unavailable' as const, status: prior.status, generationId: prior.generation_id };
            }
            return { kind: 'not_ready' as const, status: prior.status, generationId: prior.generation_id };
          }

          const readiness = await preparationReadiness(runtime, envId);
          if (readiness !== 'ready') return { kind: readiness as 'active' | 'unfinished' | 'unresolved' };

          const reserved = await withTransaction(runtime.pool, async (client) =>
            reservePreparation(client, pins));
          if (reserved !== 'created') return { kind: 'identity_conflict' as const };

          let generationId: string | null = null;
          try {
            // A new task always starts from a reset fork. The environment lock
            // remains held across reset, facilitator recovery, and fixture setup.
            const resetIdentity = await resetAnvilFork(environment.adminRpcUrl, runtime.config.sourceProxyUrl, runtime.manifest);
            await recoverFacilitator(runtime, environment);
            await recordPreparationResetProof(runtime.pool, {
              preparationId,
              envId,
              resetIdentity: {
                ...resetIdentity,
                manifestSha256: runtime.loadedManifest.sha256,
                facilitatorRecovered: true,
              },
            });

            generationId = randomUUID();
            attemptedGenerationId = generationId;
            const runToken = randomBytes(32).toString('base64url');
            const initialExpiry = new Date(Date.now() + (expiresInSeconds + 60) * 1_000);
            await bindPreparationGeneration(runtime.pool, {
              pins,
              generationId,
              runTokenSha256: runTokenHash(runToken),
              expiresAt: initialExpiry,
            });

            const fixture = await fundGenerationFixture(runtime.manifest, {
              id: environment.id,
              adminRpcUrl: environment.adminRpcUrl,
              observerRpcUrl: environment.observerRpcUrl,
            }, payerAddress, {
              onTransactionHash: (transactionHash) => bindFixtureTransactionHash(runtime.pool, {
                preparationId,
                envId,
                generationId: generationId!,
                transactionHash,
              }),
            });
            const expiresAt = await recordPreparationFixture(runtime.pool, {
              preparationId,
              envId,
              generationId,
              participantId: input.participantId,
              fixture,
              expiresAtSeconds: expiresInSeconds,
            });
            if (payerPrivateKey) {
              bindGenerationSigner(runtime.signerStore, {
                envId,
                generationId,
                privateKey: payerPrivateKey,
                payerAddress,
                expiresAtMs: Date.parse(expiresAt),
              });
            }
            const response = {
              envId,
              preparationId,
              generationId,
              participantId: input.participantId,
              payerAddress,
              runToken,
              expiresAt,
              fixture: {
                transactionHash: fixture.transactionHash,
                blockHash: fixture.blockHash,
                amountUnits: fixture.amountUnits,
                payerTokenBefore: fixture.payerTokenBefore,
                payerTokenAfter: fixture.payerTokenAfter,
                donorTokenBefore: fixture.donorTokenBefore,
                donorTokenAfter: fixture.donorTokenAfter,
                payerNativeBalance: fixture.payerNativeBalance,
                receiptObservation: fixture.receiptObservation,
              },
            };
            runtime.preparationResponses.put(requestSha256, response, Date.parse(expiresAt));
            return { kind: 'created' as const, response };
          } catch (error) {
            runtime.preparationResponses.erasePreparation(envId, preparationId);
            if (generationId) runtime.signerStore.eraseGeneration({ envId, generationId });
            await markPreparationUnknown(runtime.pool, { preparationId, envId }).catch(() => undefined);
            const fixturePhase = error instanceof GenerationFixtureFailure ? error.phase : 'unknown';
            const fixtureCauseClass = error instanceof GenerationFixtureFailure ? error.causeClass : null;
            return {
              kind: 'failed' as const,
              fixturePhase,
              fixtureCauseClass,
              fixtureAdminRpc: error instanceof GenerationFixtureFailure ? error.adminRpcDiagnostic : null,
              fixtureState: 'unknown' as const,
            };
          }
        });

        if (result.kind === 'identity_conflict') return reply.code(409).send({ error: 'preparation_identity_conflict' });
        if (result.kind === 'secret_unavailable') {
          return reply.code(409).send({
            error: 'preparation_secret_unavailable',
            status: result.status,
            generationId: result.generationId,
          });
        }
        if (result.kind === 'not_ready') {
          return reply.code(409).send({
            error: 'preparation_not_replayable',
            status: result.status,
            generationId: result.generationId,
          });
        }
        if (result.kind === 'active') return reply.code(409).send({ error: 'active_generation_requires_fence' });
        if (result.kind === 'unfinished') return reply.code(409).send({ error: 'prior_preparation_requires_fence' });
        if (result.kind === 'unresolved') return reply.code(409).send({ error: 'unresolved_operation_blocks_preparation' });
        if (result.kind === 'failed') {
          return reply.code(503).send({
            error: 'preparation_failed',
            fixturePhase: result.fixturePhase,
            fixtureCauseClass: result.fixtureCauseClass,
            fixtureAdminRpc: result.fixtureAdminRpc,
            fixtureState: result.fixtureState,
          });
        }
        return reply.code(201).send(result.response);
      } catch {
        runtime.preparationResponses.erasePreparation(envId, preparationId);
        if (attemptedGenerationId) runtime.signerStore.eraseGeneration({ envId, generationId: attemptedGenerationId });
        return reply.code(503).send({ error: 'preparation_unavailable', outcome: 'unknown' });
      }
    },
  );

  app.get<{ Params: { envId: string; preparationId: string } }>(
    '/internal/admin/environments/:envId/preparations/:preparationId',
    async (request, reply) => {
      if (!authorized(request, runtime)) return reply.code(403).send({ error: 'forbidden' });
      const { envId, preparationId } = request.params;
      if (!environmentFor(runtime, envId)) return reply.code(404).send({ error: 'environment_not_found' });
      if (!uuidSchema.safeParse(preparationId).success || !isPlainEmptyObject(request.query)) {
        return reply.code(400).send({ error: 'invalid_preparation_status_request' });
      }
      reply.header('cache-control', 'no-store');
      try {
        const record = await withEnvironmentAdvisoryLock(runtime.pool, envId, () =>
          withTransaction(runtime.pool, (client) => selectPreparation(client, preparationId, envId)));
        if (!record) return reply.code(404).send({ error: 'preparation_not_found' });
        return publicPreparationStatus(record);
      } catch {
        return reply.code(503).send({ error: 'preparation_status_unavailable' });
      }
    },
  );

  app.post<{ Params: { envId: string; preparationId: string } }>(
    '/internal/admin/environments/:envId/preparations/:preparationId/reconcile',
    async (request, reply) => {
      if (!authorized(request, runtime)) return reply.code(403).send({ error: 'forbidden' });
      const { envId, preparationId } = request.params;
      const environment = environmentFor(runtime, envId);
      if (!environment) return reply.code(404).send({ error: 'environment_not_found' });
      if (!uuidSchema.safeParse(preparationId).success || !isPlainEmptyObject(request.body) || !isPlainEmptyObject(request.query)) {
        return reply.code(400).send({ error: 'invalid_preparation_reconciliation_request' });
      }
      reply.header('cache-control', 'no-store');
      try {
        const result = await withEnvironmentAdvisoryLock(runtime.pool, envId, async () => {
          const record = await withTransaction(runtime.pool, (client) => selectPreparation(client, preparationId, envId));
          if (!record) return { kind: 'missing' as const };
          if (!record.fixture_transaction_hash || !record.payer_address) {
            return { kind: 'unknown' as const, record };
          }
          if (record.fixture_state === 'observed' || record.fixture_state === 'reconciled') {
            return { kind: 'observed' as const, record };
          }
          try {
            const observed = await observeOriginalGenerationFixtureReceipt(
              runtime.manifest,
              environment,
              record.payer_address as Address,
              record.fixture_transaction_hash as Hex,
            );
            return withTransaction(runtime.pool, async (client) => {
              const updated = await recordRecoveredFixtureReceipt(client, {
                preparationId,
                envId,
                transactionHash: observed.transactionHash,
                blockHash: observed.blockHash,
                fixtureFacts: {
                  transactionHash: observed.transactionHash,
                  amountUnits: observed.amountUnits,
                  transferEventObserved: true,
                  receiptObservation: observed.receiptObservation,
                },
              });
              return updated ? { kind: 'observed' as const, record: updated } : { kind: 'unknown' as const, record };
            });
          } catch {
            return { kind: 'unknown' as const, record };
          }
        });
        if (result.kind === 'missing') return reply.code(404).send({ error: 'preparation_not_found' });
        if (result.kind === 'unknown') {
          return reply.code(409).send({
            outcome: 'unknown',
            preparationId,
            generationId: result.record.generation_id,
            transactionHash: result.record.fixture_transaction_hash,
            status: result.record.status,
            fixtureState: result.record.fixture_state,
          });
        }
        return { outcome: 'observed', ...publicPreparationStatus(result.record) };
      } catch {
        return reply.code(503).send({ outcome: 'unknown', error: 'preparation_reconciliation_unavailable' });
      }
    },
  );

  app.post<{ Params: { envId: string; preparationId: string } }>(
    '/internal/admin/environments/:envId/preparations/:preparationId/fence',
    async (request, reply) => {
      if (!authorized(request, runtime)) return reply.code(403).send({ error: 'forbidden' });
      const { envId, preparationId } = request.params;
      if (!environmentFor(runtime, envId)) return reply.code(404).send({ error: 'environment_not_found' });
      if (!uuidSchema.safeParse(preparationId).success || !isPlainEmptyObject(request.body) || !isPlainEmptyObject(request.query)) {
        return reply.code(400).send({ error: 'invalid_preparation_fence_request' });
      }
      reply.header('cache-control', 'no-store');
      runtime.preparationResponses.erasePreparation(envId, preparationId);
      try {
        const outcome = await withEnvironmentAdvisoryLock(runtime.pool, envId, async () => {
          const state = await withTransaction(runtime.pool, (client) => confirmPreparationFence(client, { envId, preparationId }));
          if (state.kind === 'foreign') return state;
          if (state.record.generation_id) {
            runtime.signerStore.eraseGeneration({ envId, generationId: state.record.generation_id });
            runtime.preparationResponses.eraseGeneration(envId, state.record.generation_id);
          }
          return state;
        });
        if (outcome.kind === 'foreign') return reply.code(409).send({ error: 'preparation_id_unavailable' });
        return {
          ...publicPreparationStatus(outcome.record),
          fenceConfirmed: true,
          signerErased: true,
          chainState: 'not_touched',
        };
      } catch {
        return reply.code(503).send({ error: 'preparation_fence_unconfirmed', outcome: 'unknown' });
      }
    },
  );
}
