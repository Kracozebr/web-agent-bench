/** One task/mode per run; only local-fork reference evidence is produced. */
import { createHash } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { findRepositoryRoot, loadProbeRuntime, runtimeEnvironment, sourceDigests } from './environment.js';
import { EvidenceWriter } from './evidence.js';
import { DatabaseObserver } from './observer.js';
import { ReadOnlyRpcEvidence } from './rpc.js';
import { HttpEvidenceTransport } from './transport.js';
import {
  captureCapabilities, missingCapabilityPrerequisites,
  type ProbeCapabilityDocument, type ProbeContext,
} from './runner.js';
import type { ProbeScenarioId } from './types.js';
import {
  captureDifficultyV2Task,
  fenceDifficultyV2Generation,
  loadDifficultyProfileV2,
  type DifficultyMode,
  type DifficultyProfileSource,
  type DifficultyTaskId,
  type DifficultyV2TaskCapture,
} from './task-difficulty-v2-capture.js';
import type { LoadedProbeRuntime } from './environment.js';
import { referenceRecipientOption } from './task-transfer-recipient.js';

type Options = { taskId: DifficultyTaskId; mode: DifficultyMode; envId: string; evidenceDirectory: string; recipient?: string };
type SourceCheck = {
  before: { appSourceSha256: string; probeSourceSha256: string; manifestSha256: string; profileSha256: string };
  after: { appSourceSha256: string; probeSourceSha256: string; manifestSha256: string; profileSha256: string } | null;
  matches: boolean;
};

const SCENARIO_BY_TASK: Record<DifficultyTaskId, ProbeScenarioId> = {
  S1: 'BEF-SC-002', S2: 'BEF-SC-004', S3: 'BEF-SC-004', S4: 'BEF-SC-002',
  M1: 'BEF-SC-005', M2: 'BEF-SC-006', M3: 'BEF-SC-007', H1: 'BEF-SC-009', H2: 'BEF-SC-008', M4: 'BEF-SC-007', H3: 'BEF-SC-007',
};

type SourceHashes = NonNullable<SourceCheck['after']>;

function hashBytes(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

async function sourceHashes(runtime: LoadedProbeRuntime, profilePath: string): Promise<SourceHashes> {
  const [tree, manifestBytes, profileBytes] = await Promise.all([
    sourceDigests(runtime.root),
    readFile(runtime.manifestPath),
    readFile(resolve(runtime.root, profilePath)),
  ]);
  return {
    ...tree,
    manifestSha256: hashBytes(manifestBytes),
    profileSha256: hashBytes(profileBytes),
  };
}

function sourceBaseline(runtime: LoadedProbeRuntime, source: DifficultyProfileSource): SourceCheck['before'] {
  return {
    appSourceSha256: runtime.appSourceSha256,
    probeSourceSha256: runtime.probeSourceSha256,
    manifestSha256: runtime.manifestSha256,
    profileSha256: source.sha256,
  };
}

function sourceCheckMatches(before: SourceCheck['before'], after: SourceHashes): boolean {
  return before.appSourceSha256 === after.appSourceSha256
    && before.probeSourceSha256 === after.probeSourceSha256
    && before.manifestSha256 === after.manifestSha256
    && before.profileSha256 === after.profileSha256;
}

function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown> : null;
}

export function parseDifficultyV2Arguments(args: string[]): Options {
  const values = new Map<string, string>();
  const offset = args[0] === '--' ? 1 : 0;
  for (let index = offset; index < args.length; index += 1) {
    const argument = args[index];
    if (!['--task-id', '--mode', '--env-id', '--evidence-dir', '--recipient'].includes(argument ?? '')
      || values.has(argument!)) throw new Error('task_difficulty_v2_usage');
    const value = args[++index];
    if (!value || value.startsWith('--')) throw new Error('task_difficulty_v2_usage');
    values.set(argument!, value);
  }
  const taskId = values.get('--task-id');
  const mode = values.get('--mode');
  const envId = values.get('--env-id');
  const evidenceDirectory = values.get('--evidence-dir');
  if ((taskId !== 'S1' && taskId !== 'S2' && taskId !== 'S3' && taskId !== 'S4'
    && taskId !== 'M1' && taskId !== 'M2' && taskId !== 'M3' && taskId !== 'H1' && taskId !== 'H2' && taskId !== 'M4' && taskId !== 'H3')
    || (mode !== 'ranked' && mode !== 'training')
    || (taskId === 'S3' && mode !== 'ranked')
    || !envId || !/^[a-z][a-z0-9-]{1,31}$/.test(envId)
    || !evidenceDirectory || evidenceDirectory.trim().length === 0) {
    throw new Error('task_difficulty_v2_usage');
  }
  if (taskId === 'M2' && mode !== 'ranked') throw new Error('task_difficulty_v2_m2_ranked_only');
  if (taskId === 'H3' && mode !== 'ranked') throw new Error('task_difficulty_v2_h3_ranked_only');
  const recipient = referenceRecipientOption(taskId, mode, values.get('--recipient'));
  return { taskId, mode, envId, evidenceDirectory, ...(recipient === undefined ? {} : { recipient }) };
}

function safeErrorCode(error: unknown): string {
  const message = error instanceof Error ? error.message.replaceAll('-', '_') : '';
  if (/^(?:probe|task_transfer|task_native|task_reference|task_split|task_difficulty_v2|task_v2_reverse)_[a-z0-9_]+(?:_\d{3})?$/i.test(message)) return message;
  const name = error instanceof Error ? error.name : '';
  if (name === 'TypeError' || name === 'RangeError') return `task_difficulty_v2_uncaught_${name.toLowerCase()}`;
  return 'task_difficulty_v2_capture_failed';
}

function expectedActionKinds(taskId: DifficultyTaskId): string[] {
  if (taskId === 'S1') return ['transfer'];
  if (taskId === 'S2') return ['inspect_offer'];
  if (taskId === 'S3') return ['inspect_catalog'];
  if (taskId === 'S4') return ['revoke'];
  if (taskId === 'M3') return ['approve', 'swap', 'unwrap'];
  if (taskId === 'M1') return ['inspect_offer', 'pay', 'retrieve'];
  if (taskId === 'M2') return ['inspect_catalog', 'pay', 'retrieve'];
  if (taskId === 'H1') return ['inspect_catalog', 'pay', 'retrieve', 'pay', 'retrieve', 'pay', 'retrieve'];
  if (taskId === 'M4') return ['wrap', 'approve', 'swap'];
  if (taskId === 'H3') return ['inspect_offer', 'pay', 'retrieve', 'wrap', 'approve', 'swap'];
  if (taskId === 'H2') return Array.from({ length: 6 }, () => 'transfer');
  return Array.from({ length: 6 }, () => 'transfer');
}

function validateCaptureTrace(capture: DifficultyV2TaskCapture, runtimeProtocol: string): void {
  const expected = expectedActionKinds(capture.taskId);
  if (capture.participantActions.length !== expected.length
    || capture.participantActions.some((action, index) => action.kind !== expected[index]
      || !action.operationId || !action.rawResponsePath || !/^[0-9a-f]{64}$/i.test(action.rawResponseSha256))) {
    throw new Error(`task_difficulty_v2_${capture.taskId.toLowerCase()}_participant_action_trace_invalid`);
  }
  if (capture.capture.participantToolProtocol !== runtimeProtocol) {
    throw new Error('task_difficulty_v2_participant_protocol_not_recorded');
  }
}

function profileReference(source: DifficultyProfileSource, artifactPath: string): Record<string, unknown> {
  return {
    profileId: 'bts-task-difficulty-v2',
    sourcePath: source.path,
    sourceSha256: source.sha256,
    evidencePath: artifactPath,
    evidenceSha256: source.sha256,
  };
}

async function main(): Promise<void> {
  let options: Options;
  try {
    options = parseDifficultyV2Arguments(process.argv.slice(2));
    process.chdir(findRepositoryRoot());
  } catch {
    process.stderr.write('task_difficulty_v2_usage: --task-id S1|S2|S3|S4|M1|M2|M3|M4|H1|H2|H3 --mode ranked|training (S3/M2/H3 ranked only) --env-id ID --evidence-dir PATH\n');
    process.exitCode = 2;
    return;
  }

  let runtime: LoadedProbeRuntime | null = null;
  let evidence: EvidenceWriter | null = null;
  let database: DatabaseObserver | null = null;
  let context: ProbeContext | null = null;
  let source: DifficultyProfileSource | null = null;
  let manifestCopy: { path: 'manifest.json'; sha256: string } | null = null;
  let profileEvidencePath: string | null = null;
  let captureResult: DifficultyV2TaskCapture | null = null;
  let generationFence: Record<string, unknown> | null = null;
  let generationFenceAttempted = false;
  let generationFenceErrorCode: string | null = null;
  let sourceCheck: SourceCheck | null = null;
  let phase = 'runtime';
  let missingPrerequisites: string[] = [];

  try {
    runtime = await loadProbeRuntime();
    const env = runtimeEnvironment(runtime.manifest, options.envId);
    phase = 'evidence_setup';
    evidence = new EvidenceWriter(options.evidenceDirectory);
    await evidence.initialize();
    if ((await readdir(evidence.directory)).length !== 0) throw new Error('task_difficulty_v2_evidence_directory_not_empty');
    manifestCopy = await evidence.writeManifestCopy(runtime.manifestBytes);
    source = await loadDifficultyProfileV2({ runtime });
    profileEvidencePath = 'profile/difficulty-profile-v2.json';
    await evidence.writeRawJson(profileEvidencePath, source.bytes, 'task-case-input-profile');

    database = new DatabaseObserver(env.databaseObserverUrl, evidence);
    phase = 'database_observer';
    await database.verifyReadOnlyRole();
    await database.writePrivilegeObservation();
    const secrets = [env.adminKey, env.serviceKey];
    context = {
      scenarioId: SCENARIO_BY_TASK[options.taskId], runtime, env, evidence,
      transport: new HttpEvidenceTransport(evidence, secrets, 10_000, runtime.manifest.guardrails.maxTrialSeconds * 1_000),
      rpc: new ReadOnlyRpcEvidence(evidence), database, secretValues: secrets, operations: new Map(),
      replayedOriginalCaptures: [],
      capability: { schemaVersion: 'bef-probe-capabilities/v1', envId: env.envId,
        manifestSha256: runtime.manifestSha256, ready: false, implemented: {} } satisfies ProbeCapabilityDocument,
      primaryGeneration: null, primarySession: null, sequence: 0,
    };
    phase = 'capabilities';
    context.capability = await captureCapabilities(context);
    missingPrerequisites = missingCapabilityPrerequisites(
      SCENARIO_BY_TASK[options.taskId], context.capability,
      runtime.manifestSha256, runtime.appSourceSha256, options.envId,
    );
    if (missingPrerequisites.length) throw new Error('task_difficulty_v2_required_capabilities_missing');
    if (runtime.manifest.tools.participantProtocol !== 'separate_payment_delivery_v2') {
      throw new Error('task_difficulty_v2_participant_protocol_not_pinned');
    }
    const deadlineAt = Date.now() + runtime.manifest.guardrails.maxTrialSeconds * 1_000;
    context.transport.setDeadlineAt(deadlineAt);
    context.rpc.setDeadlineAt(deadlineAt);
    database.setDeadlineAt(deadlineAt);

    phase = 'local_rpc_identity';
    await context.rpc.bindLocalEndpoint({
      url: env.localRpcUrl, environmentId: env.envId, manifestSha256: runtime.manifestSha256,
      label: `task-difficulty-v2-${options.taskId.toLowerCase()}-local-rpc-identity`,
    });
    phase = 'task_capture';
    captureResult = await captureDifficultyV2Task(context, { taskId: options.taskId, mode: options.mode, source,
      ...(options.recipient === undefined ? {} : { recipient: options.recipient }) });
    validateCaptureTrace(captureResult, runtime.manifest.tools.participantProtocol);

    phase = 'generation_fence';
    if (options.taskId === 'M4' || options.taskId === 'H3') {
      const captureFence = record(captureResult.capture.actualGenerationFence);
      const fencedGeneration = record(captureFence?.generation);
      if (captureFence?.status !== 'fenced' || captureFence.signerErased !== true
        || !fencedGeneration || fencedGeneration.status !== 'fenced'
        || String(fencedGeneration.generation_id).toLowerCase() !== captureResult.session.generationId.toLowerCase()
        || String(fencedGeneration.participant_id) !== captureResult.session.participantId
        || String(fencedGeneration.payer_address).toLowerCase() !== captureResult.session.payerAddress.toLowerCase()) {
        throw new Error(`task_difficulty_v2_${options.taskId.toLowerCase()}_actual_generation_fence_not_confirmed`);
      }
      const snapshot = await context.database.snapshot({
        envId: captureResult.session.envId, generationId: captureResult.session.generationId,
        variantId: `bts-${options.taskId.toLowerCase()}-${options.mode}-difficulty-v2-final-fence-check`,
        label: `bts-${options.taskId.toLowerCase()}-${options.mode}-difficulty-v2-final-fence-check`,
      });
      const generation = snapshot.generation.length === 1 ? snapshot.generation[0]! : null;
      const unresolved = snapshot.operations.filter((row) => ['awaiting_payment', 'verifying', 'settling', 'settlement_unknown']
        .includes(String(row.status)) || String(row.receipt_status) === 'unknown');
      if (!generation || String(generation.generation_id).toLowerCase() !== captureResult.session.generationId.toLowerCase()
        || String(generation.participant_id) !== captureResult.session.participantId
        || String(generation.payer_address).toLowerCase() !== captureResult.session.payerAddress.toLowerCase()
        || generation.status !== 'fenced') {
        throw new Error(`task_difficulty_v2_${options.taskId.toLowerCase()}_actual_generation_fence_not_independently_confirmed`);
      }
      generationFenceAttempted = true;
      generationFence = {
        status: 'fenced', signerErased: true,
        envId: captureResult.session.envId, generationId: captureResult.session.generationId,
        independentObserver: {
          status: generation.status, participantId: generation.participant_id,
          payerAddress: String(generation.payer_address).toLowerCase(),
          economicOutcome: unresolved.length ? 'unresolved' : 'settled_or_absent',
          unresolvedOperationCount: unresolved.length,
          unresolvedOperations: unresolved.map((row) => ({
            operationId: String(row.operation_id ?? ''), status: String(row.status ?? 'unknown'),
            receiptStatus: row.receipt_status === null || row.receipt_status === undefined ? null : String(row.receipt_status),
          })),
        },
      };
    } else {
      generationFenceAttempted = true;
      generationFence = await fenceDifficultyV2Generation(context, captureResult.session,
        `bts_${options.taskId.toLowerCase()}_${options.mode}_difficulty_v2_reference`);
    }

    phase = 'source_integrity';
    const finalDigests = await sourceHashes(runtime, source.path);
    const before = sourceBaseline(runtime, source);
    sourceCheck = {
      before,
      after: finalDigests,
      matches: sourceCheckMatches(before, finalDigests),
    };
    if (!sourceCheck.matches) throw new Error('task_difficulty_v2_source_changed_during_capture');

    phase = 'final_probe';
    const actions = captureResult.participantActions;
    await evidence.writeProbe({
      schemaVersion: 'bts-difficulty-v2-reference-probe/v1',
      classification: 'local_fork_reference_evidence_not_bts_task_acceptance',
      status: 'captured', phase: 'complete', taskId: options.taskId, mode: options.mode,
      participantToolProtocol: runtime.manifest.tools.participantProtocol,
      manifest: manifestCopy,
      difficultyProfile: profileReference(source, profileEvidencePath),
      environment: {
        envId: env.envId, chainId: runtime.manifest.local.chainId,
        forkBlock: runtime.manifest.local.forkBlock,
        generationId: captureResult.session.generationId,
        participantId: captureResult.session.participantId,
        payerAddress: captureResult.session.payerAddress.toLowerCase(),
      },
      sourceDigests: sourceCheck,
      capture: captureResult.capture,
      captureReferences: {
        caseArtifact: captureResult.caseArtifact,
        participantActions: actions,
        participantActionCount: actions.length,
      },
      participantActionCount: actions.length,
      generationFence,
      releaseReadiness: 'blocked', noTaskGrade: true,
      noReleaseActivation: true, noAcceptanceClaim: true,
      observations: evidence.observations, artifacts: evidence.artifacts,
    });
    process.stdout.write(`status=captured task=${options.taskId} mode=${options.mode} participant_actions=${actions.length} generation_fenced=true release_readiness=blocked artifacts=${evidence.artifacts.length}\n`);
  } catch (error) {
    const errorCode = safeErrorCode(error);
    if (context?.primarySession && !generationFenceAttempted) {
      generationFenceAttempted = true;
      try {
        generationFence = await fenceDifficultyV2Generation(context, context.primarySession,
          `bts_${options.taskId.toLowerCase()}_${options.mode}_difficulty_v2_reference`);
      } catch (fenceError) {
        generationFenceErrorCode = safeErrorCode(fenceError);
      }
    }
    if (runtime && !sourceCheck) {
      try {
        const finalDigests = source ? await sourceHashes(runtime, source.path) : null;
        sourceCheck = {
          before: source ? sourceBaseline(runtime, source) : {
            appSourceSha256: runtime.appSourceSha256,
            probeSourceSha256: runtime.probeSourceSha256,
            manifestSha256: runtime.manifestSha256,
            profileSha256: '',
          },
          after: finalDigests,
          matches: source !== null && finalDigests !== null && sourceCheckMatches(sourceBaseline(runtime, source), finalDigests),
        };
      } catch {
        sourceCheck = {
          before: source ? sourceBaseline(runtime, source) : {
            appSourceSha256: runtime.appSourceSha256,
            probeSourceSha256: runtime.probeSourceSha256,
            manifestSha256: runtime.manifestSha256,
            profileSha256: '',
          },
          after: null, matches: false,
        };
      }
    }
    if (evidence && !evidence.artifacts.some((artifact) => artifact.path === 'probe.json')) {
      await evidence.writeProbe({
        schemaVersion: 'bts-difficulty-v2-reference-probe/v1',
        classification: 'local_fork_reference_evidence_not_bts_task_acceptance',
        status: 'error', phase, taskId: options.taskId, mode: options.mode, errorCode,
        ...(missingPrerequisites.length ? { missingPrerequisites } : {}),
        manifest: manifestCopy,
        difficultyProfile: source && profileEvidencePath ? profileReference(source, profileEvidencePath) : null,
        environment: context?.primaryGeneration ? { ...context.primaryGeneration } : { envId: options.envId },
        sourceDigests: sourceCheck,
        capture: captureResult?.capture ?? null,
        captureReferences: captureResult ? {
          caseArtifact: captureResult.caseArtifact,
          participantActions: captureResult.participantActions,
          participantActionCount: captureResult.participantActions.length,
        } : null,
        generationFence,
        generationFenceAttempted,
        generationFenceErrorCode,
        releaseReadiness: 'blocked', noTaskGrade: true,
        noReleaseActivation: true, noAcceptanceClaim: true,
        observations: evidence.observations, artifacts: evidence.artifacts,
      }).catch(() => undefined);
    }
    process.stderr.write(`status=error phase=${phase} code=${errorCode} generation_fenced=${generationFence?.status === 'fenced'}${generationFenceErrorCode ? ` fence_error=${generationFenceErrorCode}` : ''}\n`);
    process.exitCode = 2;
  } finally {
    await database?.close().catch(() => undefined);
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) void main();
