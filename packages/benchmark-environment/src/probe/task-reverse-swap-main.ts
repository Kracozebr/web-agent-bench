import { readdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { captureSelectedUsdcToWethSwap } from './task-transfer-capture.js';
import { findRepositoryRoot, loadProbeRuntime, runtimeEnvironment, sourceDigests } from './environment.js';
import { EvidenceWriter } from './evidence.js';
import { DatabaseObserver } from './observer.js';
import { ReadOnlyRpcEvidence } from './rpc.js';
import { HttpEvidenceTransport } from './transport.js';
import { captureCapabilities, missingCapabilityPrerequisites, type ProbeCapabilityDocument, type ProbeContext } from './runner.js';

type Options = { envId: string; evidenceDirectory: string; amountUnits: string; feeTier: 500 | 3000 };

function parseArguments(args: string[]): Options {
  let envId: string | undefined;
  let evidenceDirectory: string | undefined;
  let amountUnits = '100000';
  let feeTier: 500 | 3000 = 500;
  const offset = args[0] === '--' ? 1 : 0;
  for (let index = offset; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === '--env-id') envId = args[++index];
    else if (argument === '--evidence-dir') evidenceDirectory = args[++index];
    else if (argument === '--amount-units') amountUnits = args[++index] ?? '';
    else if (argument === '--fee-tier') {
      const value = args[++index];
      if (value !== '500' && value !== '3000') throw new Error('task_reverse_swap_usage');
      feeTier = Number(value) as 500 | 3000;
    }
    else throw new Error('task_reverse_swap_usage');
  }
  if (!envId || !evidenceDirectory || !/^(?:0|[1-9][0-9]*)$/.test(amountUnits) || BigInt(amountUnits) <= 0n) {
    throw new Error('task_reverse_swap_usage');
  }
  return { envId, evidenceDirectory, amountUnits, feeTier };
}

function safeErrorCode(error: unknown): string {
  const message = error instanceof Error ? error.message : '';
  if (/^probe_[a-z0-9_]+$/i.test(message)) return message;
  if (/^task_transfer_[a-z0-9_]+$/i.test(message)) return message;
  if (/^task_reverse_swap_[a-z0-9_]+(?:_\d{3})?$/i.test(message)) return message;
  const name = error instanceof Error ? error.name : '';
  if (name === 'TypeError' || name === 'RangeError') return `task_reverse_swap_uncaught_${name.toLowerCase()}`;
  if (name && /^[a-z][a-z0-9_]{1,40}$/i.test(name)) return `task_reverse_swap_uncaught_${name.toLowerCase()}`;
  return 'task_reverse_swap_capture_failed';
}

async function main(): Promise<void> {
  let options: Options;
  try {
    options = parseArguments(process.argv.slice(2));
    const root = findRepositoryRoot();
    process.chdir(root);
  } catch {
    process.stderr.write('task_reverse_swap_usage: --env-id ID --evidence-dir PATH [--amount-units BASE_UNITS] [--fee-tier 500|3000]\n');
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
    if ((await readdir(evidence.directory)).length > 0) throw new Error('task_reverse_swap_evidence_directory_not_empty');
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
    context.capability = await captureCapabilities(context);
    missingPrerequisites = missingCapabilityPrerequisites(
      'BEF-SC-007', context.capability, runtime.manifestSha256, runtime.appSourceSha256, options.envId,
    );
    if (missingPrerequisites.length) throw new Error('task_reverse_swap_required_capabilities_missing');
    const deadlineAt = Date.now() + runtime.manifest.guardrails.maxSwapScenarioSeconds * 1_000;
    context.transport.setDeadlineAt(deadlineAt);
    context.rpc.setDeadlineAt(deadlineAt);
    database.setDeadlineAt(deadlineAt);
    phase = 'local_rpc_identity';
    await context.rpc.bindLocalEndpoint({
      url: env.localRpcUrl,
      environmentId: env.envId,
      manifestSha256: runtime.manifestSha256,
      label: 'task-reverse-swap-local-rpc-identity',
    });
    phase = 'reverse_swap_capture';
    const capture = await captureSelectedUsdcToWethSwap(context, options.amountUnits, options.feeTier);
    phase = 'source_integrity';
    const finalDigests = await sourceDigests(runtime.root);
    if (finalDigests.appSourceSha256 !== runtime.appSourceSha256 || finalDigests.probeSourceSha256 !== runtime.probeSourceSha256) {
      throw new Error('task_reverse_swap_source_changed_during_capture');
    }
    await evidence.writeProbe({
      schemaVersion: 'bts-reverse-swap-probe/v1',
      classification: 'selected_executor_reverse_swap_capture_not_bts_acceptance',
      status: 'captured', phase: 'complete', manifest: manifestCopy,
      capture,
      applicationSourceSha256: runtime.appSourceSha256,
      probeSourceSha256: runtime.probeSourceSha256,
      sourceBlock: { number: runtime.manifest.source.blockNumber, hash: runtime.manifest.source.blockHash },
      observations: evidence.observations,
      artifacts: evidence.artifacts,
    });
    const swap = capture.swap as Record<string, unknown>;
    const primitive = options.feeTier === 3000 ? 'selected_usdc_to_weth_swap_fee3000' : 'selected_usdc_to_weth_swap';
    process.stdout.write(`status=captured primitive=${primitive} operation=${String(swap.operationId)} artifacts=${evidence.artifacts.length}\n`);
  } catch (error) {
    const errorCode = safeErrorCode(error);
    if (evidence) {
      await evidence.writeProbe({
        schemaVersion: 'bts-reverse-swap-probe/v1',
        classification: 'selected_executor_reverse_swap_capture_not_bts_acceptance',
        status: 'error', phase, errorCode,
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
