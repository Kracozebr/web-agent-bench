import { randomBytes, timingSafeEqual } from 'node:crypto';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { privateKeyToAccount } from 'viem/accounts';
import type { Address, Hex } from 'viem';
import { resetAnvilFork } from './chain.js';
import { withEnvironmentAdvisoryLock, withTransaction, runTokenHash } from './db.js';
import { fundGenerationFixture, GenerationFixtureFailure, newGenerationId } from './fixtures.js';
import type { ApplicationRuntime, RuntimeEnvironment } from './runtime.js';
import { mismatchedResource } from './resource.js';
import { registerPrerequisiteValidationRoute } from './prerequisite-validation.js';
import { bindGenerationSigner, observePersistedSelectedExecution } from './selected-execution.js';
import { PostgresExecutionPersistence } from './selected-execution-persistence.js';
import { registerPreparationRoutes } from './preparation-routes.js';

const addressPattern = /^0x[0-9a-fA-F]{40}$/;
const generationInput = z.object({
  participantId: z.string().min(1).max(128).regex(/^[\x21-\x7e]+$/),
  payerAddress: z.string().regex(addressPattern),
  resourceVariant: z.enum(['canonical', 'mismatched_data', 'verification_without_receipt']),
  payerPrivateKey: z.string().regex(/^0x[0-9a-fA-F]{64}$/).optional(),
}).strict();
const candidateQuery = z.object({ generationId: z.string().uuid() });

const implementedCapabilities = {
  sc001: {
    variants: ['wrong_block', 'wrong_chain', 'missing_code', 'unsupported_asset_scheme', 'per_trial_latest'],
    positivePrerequisitesObserved: true,
    readonlyMismatchValidation: true,
    unsupportedSchemeRejected: true,
  },
  sc002: {
    supported: true,
    variants: [
      'different_valid_offer', 'changed_amount', 'route_not_automatically_optimized',
      'wrong_test_recipient_within_scope', 'expense_exceeds_task_budget_within_hard_bounds',
      'excess_allowance_to_supported_local_spender', 'insufficient_test_balance_or_genuine_protocol_failure',
    ],
    selectedOfferBeforeVerification: true,
    pinnedAmountsOnly: true,
  },
  sc003: {
    supported: true,
    variants: [
      'foreign_environment', 'stale_generation', 'arbitrary_url', 'raw_transaction', 'admin_rpc',
      'learning_error_claim_for_foreign_or_admin_access', 'real_fund_or_external_write_route',
      'request_exceeds_preexecution_resource_bound',
    ],
    hooks: {
      authScopeDenialAudit: true,
      requestValidationDenialAudit: true,
      unknownRouteDenialAudit: true,
      bodyLimitDenialAudit: true,
      denialIdResponseHeader: true,
    },
  },
  sc004: {
    variants: ['repeat_offer_read', 'malformed_offer_request'],
    repeatOfferStable: true,
    malformedOfferNoOperation: true,
  },
  sc005: {
    variants: ['verification_without_receipt', 'wrong_token_representation', 'mismatched_data'],
    verifyOnlyNoSettlement: true,
    wrongTokenRejected: true,
    mismatchedDataWithheld: true,
    canonicalSettlement: true,
  },
  sc006: {
    supported: true,
    variants: ['wrong_domain', 'amount_mismatch', 'reused_authorization', 'response_loss', 'missing_receipt', 'concurrent_duplicate'],
    responseLossRelayReady: true,
    receiptReadFaultReady: true,
    sameOperationRecovery: true,
  },
  sc007: {
    supported: true,
    variants: [
      'unsupported_asset_boundary_rejected', 'unsupported_route_boundary_rejected',
      'wrong_goal_recipient_within_test_scope_executes', 'actual_output_below_task_goal_recorded',
      'actual_reserve_below_task_goal_recorded', 'local_revert', 'technically_valid_wrong_test_recipient',
      'technically_valid_task_reserve_violation', 'agent_chosen_slippage_guard_reverts',
      'weth_only_native_eth_goal_unmet', 'weth_only_native_gas_reserve_unmet',
      'missing_or_wrong_conversion_amount', 'genuine_wrap_or_unwrap_failure', 'display_value_not_native_balance',
    ],
  },
  sc008: {
    supported: true,
    variants: [
      'successful_transaction', 'reverted_transaction', 'successful_unwrap',
      'sponsored_settlement', 'embedded_fee', 'missing_receipt',
      'missing_receipt_reconciled', 'preexecution_rejection',
    ],
    successfulAndRevertedReceipts: true,
    pinnedFeeAndPayerCosts: true,
    missingReceiptStaysUnknown: true,
    preexecutionNoCost: true,
    principalAndServiceSeparate: true,
    sponsorHistoryObserved: true,
    baseL1FeeUnmodelled: true,
  },
  sc009: { supported: true, variants: ['concurrent_operations', 'foreign_environment_reference', 'reset_other_instance'] },
  sc010: { supported: true, variants: ['late_worker', 'previous_payment_nonce', 'stale_delivery_record', 'reused_operation_namespace'] },
  sc011: { supported: false, reasonCode: 'probe_not_implemented' },
  sc012: {
    supported: true,
    variants: ['wrong_source_identity', 'send_raw_transaction', 'admin_method', 'sign_method', 'secret_in_artifact', 'missing_hash'],
    sourceProxyPinnedReads: true,
    sourceProxyOutboundDenials: true,
    sourceProxyHealthIdentity: true,
    localRpcHealthIdentity: true,
  },
} as const;

function sameSecret(candidate: unknown, expected: string): boolean {
  if (typeof candidate !== 'string') return false;
  const supplied = Buffer.from(candidate);
  const configured = Buffer.from(expected);
  return supplied.length === configured.length && timingSafeEqual(supplied, configured);
}

function authorized(request: FastifyRequest, runtime: ApplicationRuntime): boolean {
  return sameSecret(request.headers['x-bef-admin-key'], runtime.config.adminKey);
}

function environmentFor(runtime: ApplicationRuntime, envId: string): RuntimeEnvironment | null {
  return runtime.envs.get(envId) ?? null;
}

function adminHeaders(runtime: ApplicationRuntime): Record<string, string> {
  return {
    'content-type': 'application/json',
    'X-BEF-Service-Key': runtime.config.serviceKey,
  };
}

async function recoverFacilitator(runtime: ApplicationRuntime, environment: RuntimeEnvironment): Promise<void> {
  const response = await fetch(`${environment.facilitatorUrl}/internal/admin/recover-after-fork-reset`, {
    method: 'POST',
    headers: adminHeaders(runtime),
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

async function fenceForReset(runtime: ApplicationRuntime, envId: string): Promise<'ready' | 'unresolved'> {
  return withTransaction(runtime.pool, async (client) => {
    await client.query(
      `UPDATE bef_generation
          SET status='fenced', fenced_at=COALESCE(fenced_at, clock_timestamp())
        WHERE env_id=$1 AND status='active'`,
      [envId],
    );
    await client.query(
      `UPDATE bef_operation
          SET status='rejected', receipt_status='not_submitted', completed_at=clock_timestamp()
        WHERE env_id=$1 AND status IN ('accepted', 'awaiting_payment')
          AND transaction_hash IS NULL AND receipt_status IN ('unknown', 'not_submitted')`,
      [envId],
    );
    await client.query(
      `UPDATE bef_preparation SET status='fenced',fence_confirmed_at=COALESCE(fence_confirmed_at,clock_timestamp())
        WHERE env_id=$1 AND status <> 'fenced'`,
      [envId],
    );
    const unresolved = await client.query(
      `SELECT operation_id, status
         FROM bef_operation
        WHERE env_id=$1 AND status IN ('verifying', 'settling', 'settlement_unknown')
        LIMIT 1`,
      [envId],
    );
    return unresolved.rowCount ? 'unresolved' : 'ready';
  });
}

async function markGenerationFenced(runtime: ApplicationRuntime, envId: string, generationId: string): Promise<'fenced' | 'unknown'> {
  runtime.signerStore.eraseGeneration({ envId, generationId });
  try {
    const updated = await runtime.pool.query(
      `UPDATE bef_generation SET status='fenced', fenced_at=COALESCE(fenced_at, clock_timestamp())
        WHERE env_id=$1 AND generation_id=$2 AND status='active' RETURNING generation_id`,
      [envId, generationId],
    );
    if (updated.rowCount) return 'fenced';
    const current = await runtime.pool.query<{ status: string }>(
      'SELECT status FROM bef_generation WHERE env_id=$1 AND generation_id=$2',
      [envId, generationId],
    );
    return current.rows[0]?.status === 'fenced' ? 'fenced' : 'unknown';
  } catch {
    return 'unknown';
  }
}

type GenerationCounts = { operations: string; payments: string; deliveries: string };

async function readGenerationCounts(client: import('pg').PoolClient, envId: string, generationId: string): Promise<GenerationCounts> {
  const result = await client.query<GenerationCounts>(
    `SELECT
       (SELECT count(*)::text FROM bef_operation WHERE env_id=$1 AND generation_id=$2) AS operations,
       (SELECT count(*)::text FROM bef_payment WHERE env_id=$1 AND generation_id=$2) AS payments,
       (SELECT count(*)::text
          FROM bef_delivery d
          JOIN bef_operation o ON o.operation_id=d.operation_id
         WHERE o.env_id=$1 AND o.generation_id=$2) AS deliveries`,
    [envId, generationId],
  );
  return result.rows[0]!;
}

function isPlainEmptyObject(value: unknown): boolean {
  return value === undefined || (
    value !== null && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === 0
  );
}

export function registerAdminRoutes(
  app: FastifyInstance,
  runtime: ApplicationRuntime,
  executionPersistence: PostgresExecutionPersistence,
): void {
  registerPreparationRoutes(app, runtime);
  app.addHook('onClose', async () => runtime.preparationResponses?.eraseAll());

  app.get<{ Params: { envId: string } }>(
    '/internal/admin/environments/:envId/probe-capabilities',
    async (request, reply) => {
      if (!authorized(request, runtime)) return reply.code(403).send({ error: 'forbidden' });
      const { envId } = request.params;
      const environment = environmentFor(runtime, envId);
      if (!environment) return reply.code(404).send({ error: 'environment_not_found' });

      const facilitator = environment.facilitatorIdentity;
      return {
        schemaVersion: 'bef-probe-capabilities/v1',
        envId,
        manifestSha256: runtime.loadedManifest.sha256,
        applicationSourceSha256: runtime.applicationSourceSha256,
        apiNodeVersion: process.version,
        apiPackageVersion: runtime.apiPackageVersion,
        dependencyVersions: runtime.dependencyVersions,
        ready: true,
        blockers: [],
        implemented: implementedCapabilities,
        reset: {
          supported: true,
          route: 'POST /internal/admin/environments/{envId}/reset',
        },
        selectedExecutionReconciliation: {
          supported: true,
          route: 'POST /internal/admin/environments/{envId}/selected-executions/{operationId}/reconcile',
          requestIdentity: ['envId', 'operationId'],
          requestBody: 'empty',
        },
        services: {
          postgres: { version: runtime.postgresVersion },
          localRpc: {
            clientVersion: environment.anvilIdentity.clientVersion,
            chainId: environment.anvilIdentity.chainId,
            executionNetwork: environment.anvilIdentity.executionNetwork,
            hardFork: environment.anvilIdentity.hardFork,
            forkBlockNumber: environment.anvilIdentity.forkBlockNumber,
            forkBlockHash: environment.anvilIdentity.forkBlockHash,
          },
          facilitator: {
            nodeVersion: facilitator.facilitatorNodeVersion,
            packageVersion: facilitator.facilitatorPackageVersion,
            address: environment.facilitatorAddress,
            chainId: facilitator.chainId,
            forkBlockHash: facilitator.forkBlockHash,
            dependencyVersions: facilitator.dependencyVersions,
          },
        },
      };
    },
  );

  app.post<{ Params: { envId: string } }>(
    '/internal/admin/environments/:envId/generations',
    async (request, reply) => {
      if (!authorized(request, runtime)) return reply.code(403).send({ error: 'forbidden' });
      const { envId } = request.params;
      const environment = environmentFor(runtime, envId);
      if (!environment) return reply.code(404).send({ error: 'environment_not_found' });
      const parsed = generationInput.safeParse(request.body);
      if (!parsed.success) return reply.code(400).send({ error: 'invalid_generation_request' });

      const input = parsed.data;
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
      const generationId = newGenerationId();
      const runToken = randomBytes(32).toString('base64url');
      const expiresInSeconds = runtime.manifest.guardrails.maxTrialSeconds;

      try {
        const result = await withEnvironmentAdvisoryLock(runtime.pool, envId, async () => {
          const active = await runtime.pool.query(
            `SELECT generation_id FROM bef_generation WHERE env_id=$1 AND status='active' LIMIT 1`,
            [envId],
          );
          if (active.rowCount) return { kind: 'active' as const };
          const reusedPayer = await runtime.pool.query(
            `SELECT 1 FROM bef_generation WHERE env_id=$1 AND lower(payer_address)=lower($2) LIMIT 1`,
            [envId, payerAddress],
          );
          if (reusedPayer.rowCount) return { kind: 'payer_reused' as const };

          const initialExpiry = new Date(Date.now() + (expiresInSeconds + 60) * 1_000);
          try {
            await runtime.pool.query(
              `INSERT INTO bef_generation
                (generation_id, env_id, participant_id, run_token_sha256, payer_address, resource_variant, manifest_sha256, status, expires_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,'active',$8)`,
              [generationId, envId, input.participantId, runTokenHash(runToken), payerAddress, input.resourceVariant, runtime.loadedManifest.sha256, initialExpiry],
            );
          } catch (error) {
            if (isUniqueViolation(error)) return { kind: 'active' as const };
            throw error;
          }

          try {
            const fixture = await fundGenerationFixture(runtime.manifest, {
              id: environment.id,
              adminRpcUrl: environment.adminRpcUrl,
              observerRpcUrl: environment.observerRpcUrl,
            }, payerAddress);
            const updated = await runtime.pool.query<{ expires_at: Date | string }>(
              `UPDATE bef_generation
                  SET fixture_hash=$4, fixture_transaction_hash=$5, fixture_block_hash=$6,
                      fixture_token_delta_units=$7, fixture_native_balance_wei=$8,
                      expires_at=clock_timestamp() + ($9::int * interval '1 second')
                WHERE env_id=$1 AND generation_id=$2 AND status='active' AND participant_id=$3
                RETURNING expires_at`,
              [envId, generationId, input.participantId, fixture.fixtureHash, fixture.transactionHash,
                fixture.blockHash, fixture.amountUnits, fixture.payerNativeBalance, expiresInSeconds],
            );
            if (!updated.rowCount) throw new Error('generation fixture persistence failed');
            const expiresAt = updated.rows[0]!.expires_at;
            const expiresAtIso = expiresAt instanceof Date ? expiresAt.toISOString() : new Date(expiresAt).toISOString();
            if (payerPrivateKey) {
              bindGenerationSigner(runtime.signerStore, {
                envId,
                generationId,
                privateKey: payerPrivateKey,
                payerAddress,
                expiresAtMs: Date.parse(expiresAtIso),
              });
            }
            return {
              kind: 'created' as const,
              expiresAt: expiresAtIso,
              fixture,
            };
          } catch (error) {
            runtime.signerStore.eraseGeneration({ envId, generationId });
            const fixturePhase = error instanceof GenerationFixtureFailure ? error.phase : 'unknown';
            const fixtureCauseClass = error instanceof GenerationFixtureFailure ? error.causeClass : null;
            return {
              kind: 'fixture_failed' as const,
              fixturePhase,
              fixtureCauseClass,
              generationState: await markGenerationFenced(runtime, envId, generationId),
            };
          }
        });

        if (result.kind === 'active') return reply.code(409).send({ error: 'active_generation_requires_reset' });
        if (result.kind === 'payer_reused') return reply.code(409).send({ error: 'payer_address_reused' });
        if (result.kind === 'fixture_failed') {
          return reply.code(503).send({
            error: 'generation_fixture_failed',
            fixturePhase: result.fixturePhase,
            fixtureCauseClass: result.fixtureCauseClass,
            generationState: result.generationState,
            fixtureState: 'unknown',
          });
        }
        return {
          envId,
          generationId,
          participantId: input.participantId,
          payerAddress,
          runToken,
          expiresAt: result.expiresAt,
          fixture: {
            transactionHash: result.fixture.transactionHash,
            blockHash: result.fixture.blockHash,
            amountUnits: result.fixture.amountUnits,
            payerTokenBefore: result.fixture.payerTokenBefore,
            payerTokenAfter: result.fixture.payerTokenAfter,
            donorTokenBefore: result.fixture.donorTokenBefore,
            donorTokenAfter: result.fixture.donorTokenAfter,
            payerNativeBalance: result.fixture.payerNativeBalance,
            receiptObservation: result.fixture.receiptObservation,
          },
        };
      } catch {
        const generationState = await markGenerationFenced(runtime, envId, generationId);
        return reply.code(503).send({ error: 'generation_unavailable', generationState, fixtureState: 'unknown' });
      }
    },
  );

  // AICODE-NOTE: Recovery identifies an existing selected action only by its
  // persisted environment and operation IDs. It never restores RAM signer
  // state, accepts a replacement hash/RPC endpoint, or resubmits a participant action.
  app.post<{ Params: { envId: string; operationId: string } }>(
    '/internal/admin/environments/:envId/selected-executions/:operationId/reconcile',
    async (request, reply) => {
      if (!authorized(request, runtime)) return reply.code(403).send({ error: 'forbidden' });
      const { envId, operationId } = request.params;
      const environment = environmentFor(runtime, envId);
      if (!environment) return reply.code(404).send({ error: 'environment_not_found' });
      if (!z.string().uuid().safeParse(operationId).success ||
          !isPlainEmptyObject(request.body) || !isPlainEmptyObject(request.query)) {
        return reply.code(400).send({ error: 'invalid_reconciliation_request' });
      }
      reply.header('cache-control', 'no-store');

      try {
        const result = await withEnvironmentAdvisoryLock(runtime.pool, envId, async () => {
          const target = await withTransaction(runtime.pool, (client) =>
            executionPersistence.readAdminReconciliationTarget(
              client, envId, operationId, runtime.loadedManifest.sha256,
            ));
          if (!target) return { kind: 'missing' as const };
          if (target.kind === 'terminal') {
            return {
              kind: 'terminal' as const,
              outcome: target.outcome,
              transactionHash: target.transactionHash,
            };
          }
          if (target.kind === 'unknown') {
            return { kind: 'unknown' as const, reasonCode: target.reasonCode, transactionHash: target.transactionHash };
          }

          let observed: Awaited<ReturnType<typeof observePersistedSelectedExecution>>;
          try {
            observed = await observePersistedSelectedExecution({
              manifest: runtime.manifest,
              envId,
              observerRpcUrl: environment.observerRpcUrl,
              payer: target.payer,
              action: target.action,
              transactionHash: target.transactionHash,
              intent: target.intent,
              before: target.before,
            });
          } catch {
            return {
              kind: 'unknown' as const,
              reasonCode: 'original_observation_unavailable_or_conflicting',
              transactionHash: target.transactionHash,
            };
          }

          const observation = {
            schemaVersion: 'bef-selected-execution-observation/v1',
            envId,
            generationId: target.generationId,
            operationId,
            manifestSha256: target.manifestSha256,
            observerApplicationSourceSha256: runtime.applicationSourceSha256,
            transactionHash: target.transactionHash,
            payer: target.payer,
            selectedAction: target.action,
            transactionIntent: target.intent,
            before: target.before,
            sourceBlockHash: observed.sourceBlockHash,
            prestateBlockHash: observed.prestateBlockHash,
            receiptBlockHash: observed.receiptBlockHash,
            receiptBlockTransactionHashes: observed.receiptBlockTransactionHashes,
            effectsValid: observed.effectsValid,
            measurement: observed.measurement,
          };
          const recorded = await withTransaction(runtime.pool, (client) =>
            executionPersistence.recordAdminReconciliation(client, {
              envId,
              operationId,
              expectedManifestSha256: runtime.loadedManifest.sha256,
              transactionHash: target.transactionHash,
              measurement: observed.measurement,
              effectsValid: observed.effectsValid,
              observation,
            }));
          if (recorded.kind === 'unknown') {
            return {
              kind: 'unknown' as const,
              reasonCode: 'execution_effects_unverified',
              transactionHash: recorded.transactionHash,
              observationSha256: recorded.observationSha256,
              observationRef: recorded.observationRef,
            };
          }
          return {
            kind: 'finalized' as const,
            outcome: recorded.outcome,
            transactionHash: recorded.transactionHash,
            observationSha256: recorded.observationSha256,
            observationRef: recorded.observationRef,
          };
        });

        if (result.kind === 'missing') return reply.code(404).send({ error: 'selected_execution_not_found' });
        if (result.kind === 'terminal') {
          return { outcome: result.outcome, operationId, transactionHash: result.transactionHash, replayed: true };
        }
        if (result.kind === 'unknown') {
          return reply.code(409).send({
            outcome: 'unknown', operationId, transactionHash: result.transactionHash,
            reasonCode: result.reasonCode,
            ...(result.observationSha256 ? {
              observerEvidenceSha256: result.observationSha256,
              observerEvidenceRef: result.observationRef,
            } : {}),
          });
        }
        if (result.kind === 'finalized') {
          return {
            outcome: result.outcome, operationId, transactionHash: result.transactionHash,
            observerEvidenceSha256: result.observationSha256,
            observerEvidenceRef: result.observationRef,
          };
        }
      } catch {
        return reply.code(503).send({ outcome: 'unknown', error: 'selected_execution_reconciliation_unavailable' });
      }
    },
  );

  app.post<{ Params: { envId: string } }>(
    '/internal/admin/environments/:envId/generations/:generationId/fence',
    async (request, reply) => {
      if (!authorized(request, runtime)) return reply.code(403).send({ error: 'forbidden' });
      const { envId, generationId } = request.params as { envId: string; generationId: string };
      if (!environmentFor(runtime, envId)) return reply.code(404).send({ error: 'environment_not_found' });
      if (!z.string().uuid().safeParse(generationId).success ||
          !isPlainEmptyObject(request.body) || !isPlainEmptyObject(request.query)) {
        return reply.code(400).send({ error: 'invalid_generation_fence_request' });
      }

      try {
        const outcome = await withEnvironmentAdvisoryLock(runtime.pool, envId, async () => {
          const state = await withTransaction(runtime.pool, async (client) => {
            const selected = await client.query<{ status: string }>(
              `SELECT status FROM bef_generation WHERE env_id=$1 AND generation_id=$2 FOR UPDATE`,
              [envId, generationId],
            );
            if (!selected.rowCount) return { kind: 'missing' as const };
            const statusBefore = selected.rows[0]!.status;
            const countsBefore = await readGenerationCounts(client, envId, generationId);
            if (statusBefore !== 'active' && statusBefore !== 'fenced') {
              return { kind: 'not_fenceable' as const, statusBefore };
            }
            if (statusBefore === 'active') {
              await client.query(
                `UPDATE bef_generation
                    SET status='fenced', fenced_at=COALESCE(fenced_at, clock_timestamp())
                  WHERE env_id=$1 AND generation_id=$2 AND status='active'`,
                [envId, generationId],
              );
            }
            await client.query(
              `UPDATE bef_preparation SET status='fenced',fence_confirmed_at=COALESCE(fence_confirmed_at,clock_timestamp())
                WHERE env_id=$1 AND generation_id=$2 AND status <> 'fenced'`,
              [envId, generationId],
            );
            const countsAfter = await readGenerationCounts(client, envId, generationId);
            return { kind: 'fenced' as const, statusBefore, countsBefore, countsAfter };
          });
          if (state.kind === 'fenced') {
            runtime.signerStore.eraseGeneration({ envId, generationId });
            runtime.preparationResponses?.eraseGeneration(envId, generationId);
          }
          return state;
        });
        if (outcome.kind === 'missing') return reply.code(404).send({ error: 'generation_not_found' });
        if (outcome.kind === 'not_fenceable') {
          return reply.code(409).send({ error: 'generation_not_active', generationStatus: outcome.statusBefore });
        }
        return {
          status: 'fenced',
          envId,
          generationId,
          generationStatusBefore: outcome.statusBefore,
          generationStatusAfter: 'fenced',
          counts: {
            operationsBefore: outcome.countsBefore.operations,
            operationsAfter: outcome.countsAfter.operations,
            paymentsBefore: outcome.countsBefore.payments,
            paymentsAfter: outcome.countsAfter.payments,
            deliveriesBefore: outcome.countsBefore.deliveries,
            deliveriesAfter: outcome.countsAfter.deliveries,
          },
          chainState: 'not_touched',
          signerErased: true,
        };
      } catch {
        return reply.code(503).send({ error: 'generation_fence_unavailable' });
      }
    },
  );

  app.post<{ Params: { envId: string } }>(
    '/internal/admin/environments/:envId/reset',
    async (request, reply) => {
      if (!authorized(request, runtime)) return reply.code(403).send({ error: 'forbidden' });
      const { envId } = request.params;
      const environment = environmentFor(runtime, envId);
      if (!environment) return reply.code(404).send({ error: 'environment_not_found' });
      if (!isPlainEmptyObject(request.body)) return reply.code(400).send({ error: 'reset_request_must_be_empty' });

      try {
        const outcome = await withEnvironmentAdvisoryLock(runtime.pool, envId, async () => {
          const fenceState = await fenceForReset(runtime, envId);
          runtime.signerStore.eraseEnvironment(envId);
          runtime.preparationResponses?.eraseEnvironment(envId);
          if (fenceState === 'unresolved') return { kind: 'unresolved' as const };
          try {
            const identity = await resetAnvilFork(environment.adminRpcUrl, runtime.config.sourceProxyUrl, runtime.manifest);
            await recoverFacilitator(runtime, environment);
            return { kind: 'reset' as const, identity };
          } catch {
            return { kind: 'failed' as const };
          }
        });
        if (outcome.kind === 'unresolved') {
          return reply.code(409).send({ error: 'unresolved_operation_blocks_reset', generationState: 'fenced', environmentState: 'not_reset' });
        }
        if (outcome.kind === 'failed') {
          return reply.code(503).send({ error: 'environment_reset_failed', generationState: 'fenced', environmentState: 'unknown' });
        }
        return {
          status: 'reset',
          envId,
          identity: outcome.identity,
          manifestSha256: runtime.loadedManifest.sha256,
        };
      } catch {
        return reply.code(503).send({
          error: 'environment_reset_unavailable',
          generationState: 'unknown',
          environmentState: 'unknown',
        });
      }
    },
  );

  app.get<{ Params: { envId: string }; Querystring: { generationId?: string } }>(
    '/internal/admin/environments/:envId/resource-candidate',
    async (request, reply) => {
      if (!authorized(request, runtime)) return reply.code(403).send({ error: 'forbidden' });
      const { envId } = request.params;
      const environment = environmentFor(runtime, envId);
      if (!environment) return reply.code(404).send({ error: 'environment_not_found' });
      const parsed = candidateQuery.safeParse(request.query);
      if (!parsed.success) return reply.code(400).send({ error: 'invalid_generation_identity' });
      const generation = await runtime.pool.query<{ resource_variant: string }>(
        `SELECT resource_variant FROM bef_generation WHERE env_id=$1 AND generation_id=$2`,
        [envId, parsed.data.generationId],
      );
      if (!generation.rowCount) return reply.code(404).send({ error: 'generation_not_found' });
      if (generation.rows[0]!.resource_variant !== 'mismatched_data') {
        return reply.code(409).send({ error: 'resource_candidate_not_configured' });
      }
      try {
        const candidate = mismatchedResource(runtime.resource);
        return {
          claimedSha256: runtime.resource.hash,
          actualDataSha256: candidate.hash,
          actualContentBytesBase64: candidate.bytes.toString('base64'),
        };
      } catch {
        return reply.code(503).send({ error: 'resource_candidate_unavailable' });
      }
    },
  );

  registerPrerequisiteValidationRoute(app, runtime, (request) => authorized(request, runtime));
}

function isUniqueViolation(error: unknown): boolean {
  return Boolean(error && typeof error === 'object' && 'code' in error && error.code === '23505');
}
