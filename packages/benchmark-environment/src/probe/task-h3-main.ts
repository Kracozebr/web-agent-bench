/** Run the H3 reference foundation against one isolated local BEF fork. */
import { readdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { apiPath, findRepositoryRoot, loadProbeRuntime, runtimeEnvironment, sourceDigests } from './environment.js';
import { EvidenceWriter } from './evidence.js';
import { DatabaseObserver } from './observer.js';
import { ReadOnlyRpcEvidence } from './rpc.js';
import { HttpEvidenceTransport } from './transport.js';
import {
  captureCapabilities, missingCapabilityPrerequisites, startCanonicalGeneration,
  type ProbeCapabilityDocument, type ProbeContext,
} from './runner.js';
import { captureH3PaidRouteSwapInSession, fenceH3Generation } from './task-h3-capture.js';

type Options = { envId: 'bef-env-a'; evidenceDirectory: string };

function parseArguments(args: string[]): Options {
  let envId = 'bef-env-a';
  let evidenceDirectory: string | undefined;
  const offset = args[0] === '--' ? 1 : 0;
  for (let index = offset; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === '--env-id') envId = args[++index] ?? '';
    else if (argument === '--evidence-dir') evidenceDirectory = args[++index];
    else throw new Error('task_h3_usage');
  }
  if (envId !== 'bef-env-a' || !evidenceDirectory) throw new Error('task_h3_usage');
  return { envId: 'bef-env-a', evidenceDirectory };
}

function safeErrorCode(error: unknown): string {
  const message = error instanceof Error ? error.message : '';
  if (/^(?:probe|task_h3)_[a-z0-9_]+(?:_\d{3})?$/i.test(message)) return message;
  return 'task_h3_capture_failed';
}

async function main(): Promise<void> {
  let options: Options;
  try {
    options = parseArguments(process.argv.slice(2));
    process.chdir(findRepositoryRoot());
  } catch {
    process.stderr.write('task_h3_usage: --env-id bef-env-a --evidence-dir PATH\n');
    process.exitCode = 2;
    return;
  }

  const runtime = await loadProbeRuntime().catch(() => null);
  if (!runtime) {
    process.stderr.write('status=error phase=runtime code=task_h3_runtime_unavailable\n');
    process.exitCode = 2;
    return;
  }
  let evidence: EvidenceWriter | null = null;
  let database: DatabaseObserver | null = null;
  let context: ProbeContext | null = null;
  let manifestCopy: { path: 'manifest.json'; sha256: string } | null = null;
  let phase = 'runtime';
  let missingPrerequisites: string[] = [];
  let capture: Record<string, unknown> | null = null;
  let fence: Record<string, unknown> | null = null;
  let fenceAttempted = false;
  try {
    const env = runtimeEnvironment(runtime.manifest, options.envId);
    phase = 'evidence_setup';
    evidence = new EvidenceWriter(options.evidenceDirectory);
    await evidence.initialize();
    if ((await readdir(evidence.directory)).length > 0) throw new Error('task_h3_evidence_directory_not_empty');
    manifestCopy = await evidence.writeManifestCopy(runtime.manifestBytes);
    database = new DatabaseObserver(env.databaseObserverUrl, evidence);
    phase = 'database_observer';
    await database.verifyReadOnlyRole();
    await database.writePrivilegeObservation();
    const secrets = [env.adminKey, env.serviceKey];
    context = {
      scenarioId: 'BEF-SC-009', runtime, env, evidence,
      transport: new HttpEvidenceTransport(evidence, secrets, 10_000, runtime.manifest.guardrails.maxSwapScenarioSeconds * 1_000),
      rpc: new ReadOnlyRpcEvidence(evidence), database, secretValues: secrets, operations: new Map(),
      replayedOriginalCaptures: [],
      capability: { schemaVersion: 'bef-probe-capabilities/v1', envId: env.envId, manifestSha256: runtime.manifestSha256, ready: false, implemented: {} } satisfies ProbeCapabilityDocument,
      primaryGeneration: null, primarySession: null, sequence: 0,
    };
    phase = 'capabilities';
    context.capability = await captureCapabilities(context);
    missingPrerequisites = missingCapabilityPrerequisites(
      'BEF-SC-009', context.capability, runtime.manifestSha256, runtime.appSourceSha256, options.envId,
    );
    if (missingPrerequisites.length) throw new Error('task_h3_required_capabilities_missing');
    const deadlineAt = Date.now() + runtime.manifest.guardrails.maxSwapScenarioSeconds * 1_000;
    context.transport.setDeadlineAt(deadlineAt);
    context.rpc.setDeadlineAt(deadlineAt);
    database.setDeadlineAt(deadlineAt);
    phase = 'local_rpc_identity';
    await context.rpc.bindLocalEndpoint({
      url: env.localRpcUrl, environmentId: env.envId, manifestSha256: runtime.manifestSha256,
      label: 'task-h3-local-rpc-identity',
    });
    phase = 'generation';
    const session = await startCanonicalGeneration(context, 'task-h3-start-one-generation');
    const baseline = await database.snapshot({
      envId: session.envId, generationId: session.generationId, variantId: 'bts_h3_paid_route_swap_foundation',
      label: 'task-h3-generation-baseline',
    });
    if (baseline.generation.length !== 1 || baseline.operations.length !== 0 || baseline.payments.length !== 0
      || baseline.deliveries.length !== 0 || baseline.denials.length !== 0) {
      throw new Error('task_h3_generation_baseline_not_clean');
    }
    phase = 'paid_route_swap_capture';
    capture = await captureH3PaidRouteSwapInSession(context, session);
    phase = 'generation_fence';
    fenceAttempted = true;
    fence = await fenceH3Generation(context, session);
    phase = 'source_integrity';
    const finalDigests = await sourceDigests(runtime.root);
    if (finalDigests.appSourceSha256 !== runtime.appSourceSha256 || finalDigests.probeSourceSha256 !== runtime.probeSourceSha256) {
      throw new Error('task_h3_source_changed_during_capture');
    }
    await evidence.writeProbe({
      schemaVersion: 'bts-task-h3-capture/v1',
      classification: 'local_fork_public_tool_evidence_not_bts_task_acceptance',
      status: 'captured', releaseReadiness: 'blocked', taskId: 'H3', manifest: manifestCopy,
      environment: { envId: env.envId, chainId: runtime.manifest.local.chainId, forkBlock: runtime.manifest.local.forkBlock,
        generationId: session.generationId, participantId: session.participantId, payerAddress: session.payerAddress },
      applicationSourceSha256: runtime.appSourceSha256, probeSourceSha256: runtime.probeSourceSha256,
      sourceBlock: { number: runtime.manifest.source.blockNumber, hash: runtime.manifest.source.blockHash },
      caseArtifact: capture.artifact, generationFence: fence,
      capture, observations: evidence.observations, artifacts: evidence.artifacts,
      noReleaseActivation: true, noGradePosted: true,
    });
    process.stdout.write(`status=captured task=H3 generation_fenced=true release_readiness=blocked artifacts=${evidence.artifacts.length}\n`);
  } catch (error) {
    const errorCode = safeErrorCode(error);
    if (context?.primarySession && !fenceAttempted) {
      fenceAttempted = true;
      fence = await fenceH3Generation(context, context.primarySession).catch(() => null);
    }
    if (evidence && !evidence.artifacts.some((artifact) => artifact.path === 'probe.json')) {
      await evidence.writeProbe({
        schemaVersion: 'bts-task-h3-capture/v1',
        classification: 'local_fork_public_tool_evidence_not_bts_task_acceptance',
        status: 'error', releaseReadiness: 'blocked', taskId: 'H3', phase, errorCode,
        ...(missingPrerequisites.length ? { missingPrerequisites } : {}), manifest: manifestCopy,
        environment: context?.primaryGeneration ? { ...context.primaryGeneration } : { envId: options.envId },
        applicationSourceSha256: runtime.appSourceSha256, probeSourceSha256: runtime.probeSourceSha256,
        capture, generationFence: fence, observations: evidence.observations, artifacts: evidence.artifacts,
        noReleaseActivation: true, noGradePosted: true,
      }).catch(() => undefined);
    }
    process.stderr.write(`status=error phase=${phase} code=${errorCode}\n`);
    process.exitCode = 2;
  } finally {
    await database?.close().catch(() => undefined);
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) void main();
