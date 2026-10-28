import { readFile, readdir } from 'node:fs/promises';
import { isAbsolute, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { capturePinnedResourceCatalogPurchases } from './task-resource-catalog-capture.js';
import { captureSelectedUsdcTransfer, captureSelectedUsdcToWethSwap } from './task-transfer-capture.js';
import { captureM1SinglePurchase, captureS2ReadonlyOffer } from './task-reference-case-drivers.js';
import { captureH2ExactPayoutReference, projectH1TwoComponentCandidate } from './task-reference-h1h2-drivers.js';
import { captureM2MinimumPurchase, captureS3ReadonlyCatalog } from './task-reference-catalog-drivers.js';
import {
  buildTaskReferenceCaseIndex,
  projectDeliveryEnvelope,
  type DataComponentProjection,
  type PrimitiveCapture,
  type ReferenceArtifact,
} from './task-reference-cases.js';
import { findRepositoryRoot, loadProbeRuntime, runtimeEnvironment, sourceDigests } from './environment.js';
import { EvidenceWriter, sanitizeValue, sha256Bytes } from './evidence.js';
import { DatabaseObserver } from './observer.js';
import { ReadOnlyRpcEvidence } from './rpc.js';
import { HttpEvidenceTransport } from './transport.js';
import { captureCapabilities, missingCapabilityPrerequisites, type ProbeCapabilityDocument, type ProbeContext } from './runner.js';

type Options = { envId: 'bef-env-b'; evidenceDirectory: string; amountUnits: string };

function parseArguments(args: string[]): Options {
  let evidenceDirectory: string | undefined;
  let envId = 'bef-env-b';
  let amountUnits = '100000';
  const offset = args[0] === '--' ? 1 : 0;
  for (let index = offset; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === '--env-id') envId = args[++index] ?? '';
    else if (argument === '--evidence-dir') evidenceDirectory = args[++index];
    else if (argument === '--amount-units') amountUnits = args[++index] ?? '';
    else throw new Error('task_reference_usage');
  }
  if (envId !== 'bef-env-b' || !evidenceDirectory || !/^(?:0|[1-9][0-9]*)$/.test(amountUnits) || BigInt(amountUnits) <= 0n) {
    throw new Error('task_reference_usage');
  }
  return { envId: 'bef-env-b', evidenceDirectory, amountUnits };
}

function safeErrorCode(error: unknown): string {
  const message = error instanceof Error ? error.message : '';
  if (/^(?:probe|task_transfer|task_reverse_swap|task_resource_catalog|task_reference)_[a-z0-9_]+(?:_\d{3})?$/i.test(message)) return message;
  return 'task_reference_capture_failed';
}

function artifactReferences(artifacts: readonly { path: string; sha256: string; boundary: string }[]): ReferenceArtifact[] {
  return artifacts.map(({ path, sha256, boundary }) => ({ path, sha256, boundary }));
}

function recordOf(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

function string(value: unknown): string | null { return typeof value === 'string' ? value : null; }

function safeRelativeArtifact(directory: string, artifactPath: string): string {
  if (!artifactPath || artifactPath.includes('\\') || artifactPath.startsWith('/')
    || artifactPath.split('/').some((part) => part === '' || part === '.' || part === '..')) {
    throw new Error('task_reference_artifact_path_invalid');
  }
  const root = resolve(directory);
  const resolved = resolve(root, ...artifactPath.split('/'));
  const remainder = relative(root, resolved);
  if (!remainder || remainder === '..' || remainder.startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`) || isAbsolute(remainder)) {
    throw new Error('task_reference_artifact_path_invalid');
  }
  return resolved;
}

async function projectCatalogDeliveries(ctx: ProbeContext, catalogCapture: unknown): Promise<{
  projections: Array<{ operationId: string; projectionPath: string; rawContentPath: string; projection: unknown; component: DataComponentProjection; contentHash: string }>;
  errors: Array<{ operationId: string | null; code: string }>;
}> {
  const capture = recordOf(catalogCapture);
  const purchases = Array.isArray(capture?.purchases) ? capture.purchases : [];
  const projections: Array<{ operationId: string; projectionPath: string; rawContentPath: string; projection: unknown; component: DataComponentProjection; contentHash: string }> = [];
  const errors: Array<{ operationId: string | null; code: string }> = [];
  for (let index = 0; index < purchases.length; index += 1) {
    const purchase = recordOf(purchases[index]);
    const operationId = string(purchase?.operationId);
    try {
      if (!purchase || !operationId) throw new Error('task_reference_delivery_operation_missing');
      const observationId = `task-resource-catalog-${index}-signed-purchase`;
      const observation = ctx.evidence.observations.find((item) => item.id === observationId);
      const artifact = observation && ctx.evidence.artifacts.find((item) => item.path === observation.sourceArtifact);
      if (!artifact) throw new Error('task_reference_delivery_raw_response_missing');
      const artifactPath = safeRelativeArtifact(ctx.evidence.directory, artifact.path);
      const artifactBytes = await readFile(artifactPath);
      if (sha256Bytes(artifactBytes) !== artifact.sha256) throw new Error('task_reference_delivery_raw_response_hash_mismatch');
      const httpObservation = recordOf(JSON.parse(artifactBytes.toString('utf8')));
      const response = recordOf(httpObservation?.response);
      const bodyBase64 = string(response?.bodyBase64);
      if (!bodyBase64) throw new Error('task_reference_delivery_raw_body_bytes_missing');
      const rawBody = Buffer.from(bodyBase64, 'base64');
      if (!rawBody.length || rawBody.toString('base64').replace(/=+$/, '') !== bodyBase64.replace(/=+$/, '')) {
        throw new Error('task_reference_delivery_raw_body_bytes_invalid');
      }
      const envelope = recordOf(JSON.parse(rawBody.toString('utf8')));
      const manifestResource = ctx.runtime.manifest.x402.catalog?.find((resource) => resource.resourceId === purchase.resourceId);
      if (!envelope || !manifestResource || envelope.resourceId !== purchase.resourceId
        || envelope.contentHash !== purchase.resourceSha256 || envelope.contentHash !== manifestResource.resourceSha256
        || envelope.contentType !== manifestResource.contentType) {
        throw new Error('task_reference_delivery_manifest_binding_mismatch');
      }
      const validated = projectDeliveryEnvelope({
        envelope,
        expectedResourceId: manifestResource.resourceId,
        expectedContentHash: manifestResource.resourceSha256,
        provenanceId: manifestResource.provenance.classification,
      });
      const contentBytes = Buffer.from(validated.projection.contentBytes, 'base64');
      const contentPath = `task-reference/delivery/${operationId}-content.json`;
      await ctx.evidence.writeRawJson(contentPath, contentBytes, 'actual-tool-http-delivered-content');
      const projectionPath = `task-reference/delivery/${operationId}-projection.json`;
      await ctx.evidence.writeObservation(projectionPath, `task-reference-delivery-projection-${operationId}`, {
        schemaVersion: 'bef-resource-observation/v1',
        boundary: 'actual-tool-http',
        operationId,
        variantId: 'task_reference_delivery_projection',
        projectionSchema: 'bef-delivery-envelope/v1',
        projection: validated.projection,
        component: validated.component,
        rawContentArtifact: { path: contentPath, sha256: validated.contentBytesSha256 },
        httpResponseArtifact: { path: artifact.path, sha256: artifact.sha256 },
      });
      const rawContentArtifact = ctx.evidence.artifacts.find((item) => item.path === contentPath);
      if (!rawContentArtifact || rawContentArtifact.sha256 !== validated.contentBytesSha256) {
        throw new Error('task_reference_delivery_raw_content_artifact_mismatch');
      }
      projections.push({
        operationId,
        projectionPath,
        rawContentPath: contentPath,
        projection: validated.projection,
        component: validated.component,
        contentHash: validated.contentBytesSha256,
      });
    } catch (error) {
      errors.push({ operationId, code: safeErrorCode(error) });
    }
  }
  return { projections, errors };
}

async function main(): Promise<void> {
  let options: Options;
  try {
    options = parseArguments(process.argv.slice(2));
    process.chdir(findRepositoryRoot());
  } catch {
    process.stderr.write('task_reference_usage: --env-id bef-env-b --evidence-dir PATH [--amount-units BASE_UNITS]\n');
    process.exitCode = 2;
    return;
  }

  let evidence: EvidenceWriter | null = null;
  let database: DatabaseObserver | null = null;
  let context: ProbeContext | null = null;
  let manifestCopy: { path: 'manifest.json'; sha256: string } | null = null;
  let phase = 'runtime';
  const missingPrerequisites: string[] = [];
  const primitiveCaptures: PrimitiveCapture[] = [];
  const deliveryProjections: Array<{ operationId: string; projectionPath: string; rawContentPath: string; projection: unknown; component: DataComponentProjection; contentHash: string }> = [];
  const deliveryProjectionErrors: Array<{ operationId: string | null; code: string }> = [];
  const runtime = await loadProbeRuntime().catch(() => null);
  if (!runtime) {
    process.stderr.write('status=error phase=runtime code=task_reference_runtime_unavailable\n');
    process.exitCode = 2;
    return;
  }
  try {
    const env = runtimeEnvironment(runtime.manifest, options.envId);
    phase = 'evidence_setup';
    evidence = new EvidenceWriter(options.evidenceDirectory);
    await evidence.initialize();
    if ((await readdir(evidence.directory)).length > 0) throw new Error('task_reference_evidence_directory_not_empty');
    manifestCopy = await evidence.writeManifestCopy(runtime.manifestBytes);
    database = new DatabaseObserver(env.databaseObserverUrl, evidence);
    phase = 'database_observer';
    await database.verifyReadOnlyRole();
    await database.writePrivilegeObservation();
    const secrets = [env.adminKey, env.serviceKey];
    context = {
      scenarioId: 'BEF-SC-007',
      runtime,
      env,
      evidence,
      transport: new HttpEvidenceTransport(evidence, secrets, 10_000, runtime.manifest.guardrails.maxResourceScenarioSeconds * 1_000),
      rpc: new ReadOnlyRpcEvidence(evidence),
      database,
      secretValues: secrets,
      operations: new Map(),
      replayedOriginalCaptures: [],
      capability: {
        schemaVersion: 'bef-probe-capabilities/v1', envId: env.envId, manifestSha256: runtime.manifestSha256,
        ready: false, implemented: {},
      } satisfies ProbeCapabilityDocument,
      primaryGeneration: null,
      primarySession: null,
      sequence: 0,
    };
    phase = 'capabilities';
    context.capability = await captureCapabilities(context);
    missingPrerequisites.push(...missingCapabilityPrerequisites(
      'BEF-SC-007', context.capability, runtime.manifestSha256, runtime.appSourceSha256, options.envId,
    ));
    if (missingPrerequisites.length) throw new Error('task_reference_required_capabilities_missing');
    context.rpc.setDeadlineAt(Date.now() + runtime.manifest.guardrails.maxTrialSeconds * 1_000);
    phase = 'local_rpc_identity';
    await context.rpc.bindLocalEndpoint({
      url: env.localRpcUrl,
      environmentId: env.envId,
      manifestSha256: runtime.manifestSha256,
      label: 'task-reference-local-rpc-identity',
    });

    const attempts: Array<{ captureId: PrimitiveCapture['captureId']; action: () => Promise<unknown>; deadlineSeconds: number }> = [
      { captureId: 's1-transfer', action: () => captureSelectedUsdcTransfer(context!, options.amountUnits), deadlineSeconds: runtime.manifest.guardrails.maxSwapScenarioSeconds },
      { captureId: 's2-readonly-offer', action: () => captureS2ReadonlyOffer(context!), deadlineSeconds: runtime.manifest.guardrails.maxResourceScenarioSeconds },
      { captureId: 'm1-single-purchase', action: () => captureM1SinglePurchase(context!), deadlineSeconds: runtime.manifest.guardrails.maxResourceScenarioSeconds },
      { captureId: 'resource-catalog', action: () => capturePinnedResourceCatalogPurchases(context!), deadlineSeconds: runtime.manifest.guardrails.maxResourceScenarioSeconds },
      { captureId: 'h2-exact-payouts', action: () => captureH2ExactPayoutReference(context!), deadlineSeconds: runtime.manifest.guardrails.maxTrialSeconds },
      { captureId: 's3-readonly-catalog', action: () => captureS3ReadonlyCatalog(context!), deadlineSeconds: runtime.manifest.guardrails.maxResourceScenarioSeconds },
      { captureId: 'm2-minimum-purchase', action: () => captureM2MinimumPurchase(context!), deadlineSeconds: runtime.manifest.guardrails.maxResourceScenarioSeconds },
      { captureId: 'reverse-swap', action: () => captureSelectedUsdcToWethSwap(context!, options.amountUnits), deadlineSeconds: runtime.manifest.guardrails.maxSwapScenarioSeconds },
    ];
    for (const attempt of attempts) {
      const start = evidence.artifacts.length;
      const attemptStartedAt = Date.now();
      try {
        phase = `${attempt.captureId.replaceAll('-', '_')}_capture`;
        const deadlineAt = Date.now() + attempt.deadlineSeconds * 1_000;
        context.transport.setDeadlineAt(deadlineAt);
        context.rpc.setDeadlineAt(deadlineAt);
        database.setDeadlineAt(deadlineAt);
        let capture = await attempt.action();
        if (attempt.captureId === 'resource-catalog') {
          const projected = await projectCatalogDeliveries(context, capture);
          deliveryProjections.push(...projected.projections);
          deliveryProjectionErrors.push(...projected.errors);
          let h1ObjectiveCandidate: Record<string, unknown> | null = null;
          let h1ObjectiveError: string | null = null;
          try {
            h1ObjectiveCandidate = await projectH1TwoComponentCandidate(context, {
              catalogCapture: capture,
              deliveryProjections: projected.projections,
              elapsedMs: Date.now() - attemptStartedAt,
            });
          } catch (error) {
            h1ObjectiveError = safeErrorCode(error);
          }
          const captured = recordOf(capture);
          capture = {
            ...(captured ?? {}),
            h1ObjectiveCandidate,
            ...(h1ObjectiveError ? { h1ObjectiveError } : {}),
          };
        }
        const primitiveCapture: PrimitiveCapture = { captureId: attempt.captureId, capture, artifacts: artifactReferences(evidence.artifacts.slice(start)) };
        primitiveCaptures.push(primitiveCapture);
        const derivedArtifactStart = evidence.artifacts.length;
        await evidence.writeObservation(`task-reference/captures/${attempt.captureId}.json`, `task-reference-capture-${attempt.captureId}`, {
          schemaVersion: 'bts-task-reference-primitive-observation/v1',
          boundary: 'bts-reference-derived-observation',
          operationId: null,
          variantId: `task_reference_${attempt.captureId.replaceAll('-', '_')}`,
          captureId: attempt.captureId,
          classification: 'derived_from_actual_public_tool_and_observer_evidence_not_bts_task_acceptance',
          sourceArtifacts: primitiveCapture.artifacts,
          capture: sanitizeValue(capture, context.secretValues),
        });
        primitiveCapture.artifacts.push(...artifactReferences(evidence.artifacts.slice(derivedArtifactStart)));
        if (attempt.captureId === 'm2-minimum-purchase') {
          const captureValue = recordOf(capture);
          const selected = recordOf(captureValue?.selectedOffer);
          const delivery = recordOf(captureValue?.delivery);
          const contentArtifact = recordOf(delivery?.rawContentArtifact);
          const component = recordOf(delivery?.component);
          const operationId = string(selected?.operationId);
          const projectionPath = string(delivery?.projectionArtifact);
          const rawContentPath = string(contentArtifact?.path);
          const contentHash = string(delivery?.contentHash);
          const projection = recordOf(delivery?.projection);
          if (operationId && projectionPath && rawContentPath && contentHash && component && projection) {
            deliveryProjections.push({
              operationId, projectionPath, rawContentPath, projection,
              component: component as unknown as DataComponentProjection, contentHash,
            });
          }
        }
      } catch (error) {
        primitiveCaptures.push({ captureId: attempt.captureId, capture: null, errorCode: safeErrorCode(error), artifacts: artifactReferences(evidence.artifacts.slice(start)) });
      }
    }

    phase = 'reference_index';
    const uniqueComponents = new Map<string, DataComponentProjection>();
    for (const { component } of deliveryProjections) {
      const prior = uniqueComponents.get(component.resourceId);
      if (prior && JSON.stringify(prior) !== JSON.stringify(component)) throw new Error('task_reference_delivery_component_conflict');
      uniqueComponents.set(component.resourceId, component);
    }
    const referenceIndex = buildTaskReferenceCaseIndex({
      captures: primitiveCaptures,
      dataComponents: [...uniqueComponents.values()],
    });
    const indexArtifactPath = 'task-reference/case-index.json';
    await evidence.writeObservation(indexArtifactPath, 'task-reference-case-index', {
      schemaVersion: 'bef-resource-observation/v1',
      boundary: 'actual-tool-http',
      operationId: null,
      variantId: 'task_reference_case_index',
      index: referenceIndex,
      deliveryProjections,
      deliveryProjectionErrors,
    });
    const indexArtifact = evidence.artifacts.find((artifact) => artifact.path === indexArtifactPath);
    if (!indexArtifact) throw new Error('task_reference_index_artifact_missing');

    phase = 'source_integrity';
    const finalDigests = await sourceDigests(runtime.root);
    if (finalDigests.appSourceSha256 !== runtime.appSourceSha256 || finalDigests.probeSourceSha256 !== runtime.probeSourceSha256) {
      throw new Error('task_reference_source_changed_during_capture');
    }
    const observedCount = referenceIndex.observedCaptureIds.length;
    await evidence.writeProbe({
      schemaVersion: 'bts-task-reference-capture/v1',
      classification: 'local_fork_public_tool_evidence_not_bts_task_acceptance',
      captureStatus: observedCount === primitiveCaptures.length ? 'captured' : 'partial',
      releaseReadiness: 'blocked',
      manifest: manifestCopy,
      environment: { envId: env.envId, chainId: runtime.manifest.local.chainId, forkBlock: runtime.manifest.local.forkBlock },
      applicationSourceSha256: runtime.appSourceSha256,
      probeSourceSha256: runtime.probeSourceSha256,
      sourceBlock: { number: runtime.manifest.source.blockNumber, hash: runtime.manifest.source.blockHash },
      referenceIndex: { path: indexArtifact.path, sha256: indexArtifact.sha256 },
      taskOrder: referenceIndex.taskOrder,
      taskCases: referenceIndex.cases,
      captures: referenceIndex.captures,
      deliveryProjectionErrors,
      observations: evidence.observations,
      artifacts: evidence.artifacts,
    });
    process.stdout.write(`status=${observedCount === primitiveCaptures.length ? 'captured' : 'partial'} observed_primitives=${observedCount} tasks=${referenceIndex.cases.length} release_readiness=blocked artifacts=${evidence.artifacts.length}\n`);
    if (observedCount !== primitiveCaptures.length) process.exitCode = 2;
  } catch (error) {
    const errorCode = safeErrorCode(error);
    if (evidence && !evidence.artifacts.some((artifact) => artifact.path === 'probe.json')) {
      await evidence.writeProbe({
        schemaVersion: 'bts-task-reference-capture/v1',
        classification: 'local_fork_public_tool_evidence_not_bts_task_acceptance',
        captureStatus: 'error',
        releaseReadiness: 'blocked',
        phase,
        errorCode,
        missingPrerequisites,
        manifest: manifestCopy,
        environment: context?.primaryGeneration ? { envId: context.primaryGeneration.envId } : { envId: options.envId },
        applicationSourceSha256: runtime.appSourceSha256,
        probeSourceSha256: runtime.probeSourceSha256,
        captures: primitiveCaptures,
        deliveryProjectionErrors,
        observations: evidence.observations,
        artifacts: evidence.artifacts,
      }).catch(() => undefined);
    }
    process.stderr.write(`status=error phase=${phase} code=${errorCode}\n`);
    process.exitCode = 2;
  } finally {
    await database?.close().catch(() => undefined);
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) void main();
