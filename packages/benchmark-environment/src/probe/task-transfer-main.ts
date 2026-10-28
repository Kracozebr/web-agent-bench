import { readdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { captureSelectedUsdcTransfer } from './task-transfer-capture.js';
import { findRepositoryRoot, loadProbeRuntime, runtimeEnvironment, sourceDigests } from './environment.js';
import { EvidenceWriter } from './evidence.js';
import { DatabaseObserver } from './observer.js';
import { ReadOnlyRpcEvidence } from './rpc.js';
import { HttpEvidenceTransport } from './transport.js';
import { captureCapabilities, missingCapabilityPrerequisites, type ProbeCapabilityDocument, type ProbeContext } from './runner.js';

type Options = { envId: string; evidenceDirectory: string; amountUnits: string };

function parseArguments(args: string[]): Options {
  let envId: string | undefined;
  let evidenceDirectory: string | undefined;
  let amountUnits = '100000';
  const offset = args[0] === '--' ? 1 : 0;
  for (let index = offset; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === '--env-id') envId = args[++index];
    else if (argument === '--evidence-dir') evidenceDirectory = args[++index];
    else if (argument === '--amount-units') amountUnits = args[++index] ?? '';
    else throw new Error('task_transfer_usage');
  }
  if (!envId || !evidenceDirectory || !/^(?:0|[1-9][0-9]*)$/.test(amountUnits) || BigInt(amountUnits) <= 0n) {
    throw new Error('task_transfer_usage');
  }
  return { envId, evidenceDirectory, amountUnits };
}

function safeErrorCode(error: unknown): string {
  const message = error instanceof Error ? error.message : '';
  if (/^probe_[a-z0-9_]+$/i.test(message)) return message;
  return /^task_transfer_[a-z0-9_]+(?:_\d{3})?$/i.test(message) ? message : 'task_transfer_capture_failed';
}

async function main(): Promise<void> {
  let options: Options;
  try {
    options = parseArguments(process.argv.slice(2));
    const root = findRepositoryRoot();
    process.chdir(root);
  } catch {
    process.stderr.write('task_transfer_usage: --env-id ID --evidence-dir PATH [--amount-units BASE_UNITS]\n');
    process.exitCode = 2;
    return;
  }

  let evidence: EvidenceWriter | null = null;
  let database: DatabaseObserver | null = null;
  let context: ProbeContext | null = null;
  let manifestCopy: { path: 'manifest.json'; sha256: string } | null = null;
  let phase = 'runtime';
  let missingPrerequisites: string[] = [];
  try {
    const runtime = await loadProbeRuntime();
    const env = runtimeEnvironment(runtime.manifest, options.envId);
    phase = 'evidence_setup';
    evidence = new EvidenceWriter(options.evidenceDirectory);
    await evidence.initialize();
    if ((await readdir(evidence.directory)).length > 0) throw new Error('task_transfer_evidence_directory_not_empty');
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
      transport: new HttpEvidenceTransport(evidence, secrets, 10_000, runtime.manifest.guardrails.maxSwapScenarioSeconds * 1_000),
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
    const capability = await captureCapabilities(context);
    context.capability = capability;
    missingPrerequisites = missingCapabilityPrerequisites(
      'BEF-SC-007', capability, runtime.manifestSha256, runtime.appSourceSha256, options.envId,
    );
    if (missingPrerequisites.length) throw new Error('task_transfer_required_capabilities_missing');
    const deadlineAt = Date.now() + runtime.manifest.guardrails.maxSwapScenarioSeconds * 1_000;
    context.transport.setDeadlineAt(deadlineAt);
    context.rpc.setDeadlineAt(deadlineAt);
    database.setDeadlineAt(deadlineAt);
    phase = 'local_rpc_identity';
    await context.rpc.bindLocalEndpoint({
      url: env.localRpcUrl,
      environmentId: env.envId,
      manifestSha256: runtime.manifestSha256,
      label: 'task-transfer-local-rpc-identity',
    });
    phase = 'transfer_capture';
    const capture = await captureSelectedUsdcTransfer(context, options.amountUnits);
    phase = 'source_integrity';
    const finalDigests = await sourceDigests(runtime.root);
    if (finalDigests.appSourceSha256 !== runtime.appSourceSha256 || finalDigests.probeSourceSha256 !== runtime.probeSourceSha256) {
      throw new Error('task_transfer_source_changed_during_capture');
    }
    await evidence.writeProbe({
      schemaVersion: 'bts-transfer-probe/v1',
      classification: 'selected_executor_primitive_capture_not_bts_acceptance',
      status: 'captured',
      phase: 'complete',
      manifest: manifestCopy,
      environment: capture.environment,
      capture,
      applicationSourceSha256: runtime.appSourceSha256,
      probeSourceSha256: runtime.probeSourceSha256,
      sourceBlock: { number: runtime.manifest.source.blockNumber, hash: runtime.manifest.source.blockHash },
      observations: evidence.observations,
      artifacts: evidence.artifacts,
    });
    process.stdout.write(`status=captured primitive=selected_usdc_transfer operation=${String((capture.operation as Record<string, unknown>).operationId)} artifacts=${evidence.artifacts.length}\n`);
  } catch (error) {
    const errorCode = safeErrorCode(error);
    if (evidence) {
      await evidence.writeProbe({
        schemaVersion: 'bts-transfer-probe/v1',
        classification: 'selected_executor_primitive_capture_not_bts_acceptance',
        status: 'error',
        phase,
        errorCode,
        ...(missingPrerequisites.length ? { missingPrerequisites } : {}),
        manifest: manifestCopy,
        environment: context?.primaryGeneration ? {
          envId: context.primaryGeneration.envId,
          generationId: context.primaryGeneration.generationId,
          participantId: context.primaryGeneration.participantId,
          payerAddress: context.primaryGeneration.payerAddress,
        } : null,
        applicationSourceSha256: context?.runtime.appSourceSha256 ?? null,
        probeSourceSha256: context?.runtime.probeSourceSha256 ?? null,
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
