import { mkdir, readdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { findRepositoryRoot, loadProbeRuntime, runtimeEnvironment, sourceDigests } from './probe/environment.js';
import { EvidenceWriter } from './probe/evidence.js';
import { DatabaseObserver } from './probe/observer.js';
import { ReadOnlyRpcEvidence } from './probe/rpc.js';
import { HttpEvidenceTransport } from './probe/transport.js';
import { normalizeObservedDependencyVersions } from './probe/versions.js';
import { captureCapabilities, missingCapabilityPrerequisites, runScenario002, runScenario004, runScenario005, runScenario006, runScenario008, type ProbeCapabilityDocument, type ProbeContext } from './probe/runner.js';
import { runScenario001 } from './probe/prerequisites.js';
import { runScenario003 } from './probe/scope.js';
import { runScenario007 } from './probe/sc007.js';
import { runScenario009, runScenario010 } from './probe/sc009010.js';
import { runSourceEvidenceScenario } from './probe/source.js';
import { probeFetch } from './probe/fetch-types.js';
import type { BlockedProbe, ErrorProbe, ProbeOperation, ProbeScenarioId } from './probe/types.js';

const SUPPORTED_SCENARIOS = new Set<ProbeScenarioId>([
  'BEF-SC-001', 'BEF-SC-002', 'BEF-SC-003', 'BEF-SC-004', 'BEF-SC-005', 'BEF-SC-006',
  'BEF-SC-007', 'BEF-SC-008', 'BEF-SC-009', 'BEF-SC-010', 'BEF-SC-011', 'BEF-SC-012',
]);

type Options = {
  scenarioId: ProbeScenarioId;
  evidenceDirectory: string;
  sc004EvidenceDirectory?: string;
  sc005EvidenceDirectory?: string;
};

function parseArguments(args: string[]): Options {
  let scenario: string | undefined;
  let evidenceDirectory: string | undefined;
  let sc004EvidenceDirectory: string | undefined;
  let sc005EvidenceDirectory: string | undefined;
  const firstArgument = args[0] === '--' ? 1 : 0;
  for (let index = firstArgument; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === '--scenario') scenario = args[++index];
    else if (arg === '--evidence-dir') evidenceDirectory = args[++index];
    else if (arg === '--sc004-evidence-dir') sc004EvidenceDirectory = args[++index];
    else if (arg === '--sc005-evidence-dir') sc005EvidenceDirectory = args[++index];
    else throw new Error('usage: probe --scenario BEF-SC-001..012 --evidence-dir PATH');
  }
  if (!scenario || !SUPPORTED_SCENARIOS.has(scenario as ProbeScenarioId) || !evidenceDirectory) {
    throw new Error('usage: probe --scenario BEF-SC-001..012 --evidence-dir PATH');
  }
  if (scenario === 'BEF-SC-012' && (!sc004EvidenceDirectory || !sc005EvidenceDirectory)) {
    return { scenarioId: scenario as ProbeScenarioId, evidenceDirectory };
  }
  return {
    scenarioId: scenario as ProbeScenarioId,
    evidenceDirectory,
    ...(sc004EvidenceDirectory ? { sc004EvidenceDirectory } : {}),
    ...(sc005EvidenceDirectory ? { sc005EvidenceDirectory } : {}),
  };
}

async function prepareEvidenceDirectory(path: string): Promise<EvidenceWriter> {
  const evidence = new EvidenceWriter(path);
  await evidence.initialize();
  const entries = await readdir(evidence.directory);
  if (entries.length) throw new Error('probe_evidence_directory_not_empty');
  return evidence;
}

async function emitBlocked(evidence: EvidenceWriter, scenarioId: ProbeScenarioId, reasonCode: string, missingPrerequisites: string[]): Promise<void> {
  const payload: BlockedProbe = {
    schemaVersion: 'bef-runtime-probe/v1',
    scenarioId,
    status: 'blocked',
    reasonCode,
    missingPrerequisites: [...new Set(missingPrerequisites)].sort(),
    manifest: null,
    environment: null,
    operations: [],
    observations: [],
    artifacts: [],
  };
  await evidence.writeProbe(payload);
}

function errorCode(error: unknown): string {
  const message = error instanceof Error ? error.message : '';
  if (/^probe_[a-z0-9_]+$/i.test(message)) return message;
  const statusCode = message.match(/^(probe_[a-z0-9_]+_)(\d{3})$/i);
  if (statusCode) return `${statusCode[1]}${statusCode[2]}`;
  return 'probe_unexpected_error';
}

function missingEnvironmentName(error: unknown): string | null {
  const message = error instanceof Error ? error.message : '';
  const match = message.match(/^(?:missing_environment_value|file_secret_not_allowed|invalid_environment_url):([A-Z0-9_]+)$/);
  return match?.[1] ?? null;
}

async function readCapabilitiesWithoutEvidence(baseUrl: string, envId: string, adminKey: string): Promise<ProbeCapabilityDocument> {
  let response;
  try {
    response = await probeFetch(`${baseUrl}/internal/admin/environments/${envId}/probe-capabilities`, {
      method: 'GET',
      headers: { 'X-BEF-Admin-Key': adminKey },
      redirect: 'error',
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    throw new Error('probe_capabilities_endpoint_unavailable');
  }
  if (!response.ok) throw new Error('probe_capabilities_endpoint_unavailable');
  try {
    return await response.json() as ProbeCapabilityDocument;
  } catch {
    throw new Error('probe_capabilities_document_invalid');
  }
}

async function assertEmptyOrCreate(directory: string): Promise<EvidenceWriter> {
  await mkdir(directory, { recursive: true });
  return prepareEvidenceDirectory(directory);
}

function setObservedRuntimeVersions(runtime: { runtimeVersions: Record<string, string> }, databaseVersion: string, capability: ProbeCapabilityDocument): void {
  runtime.runtimeVersions.postgresql = databaseVersion || 'unknown';
  const observed: Record<string, unknown> = {
    apiNode: capability.apiNodeVersion,
    apiPackage: capability.apiPackageVersion,
  };
  const dependencies = normalizeObservedDependencyVersions(capability.dependencyVersions);
  for (const key of ['fastify', 'x402Core', 'x402Evm', 'x402Fastify', 'viem', 'postgresDriver']) {
    observed[key] = dependencies[key];
  }
  const services = capability.services ?? {};
  const facilitator = services.facilitator;
  const facilitatorRecord = facilitator && typeof facilitator === 'object' && !Array.isArray(facilitator)
    ? facilitator as Record<string, unknown>
    : null;
  const rpc = services.localRpc;
  const rpcRecord = rpc && typeof rpc === 'object' && !Array.isArray(rpc) ? rpc as Record<string, unknown> : null;
  observed.facilitatorNode = facilitatorRecord?.nodeVersion;
  observed.anvil = rpcRecord?.clientVersion;
  observed.anvilExecutionNetwork = rpcRecord?.executionNetwork;
  observed.anvilHardFork = rpcRecord?.hardFork;
  for (const [key, value] of Object.entries(observed)) {
    if (typeof value === 'string' && value.length > 0 && value.length <= 128) runtime.runtimeVersions[key] = value;
  }
}

function observedOperations(contexts: readonly ProbeContext[]): ProbeOperation[] {
  const operations = new Map<string, ProbeOperation>();
  for (const context of contexts) {
    for (const [operationId, operation] of context.operations) {
      const existing = operations.get(operationId);
      if (existing && JSON.stringify(existing) !== JSON.stringify(operation)) {
        throw new Error('probe_operation_identity_collision');
      }
      operations.set(operationId, operation);
    }
  }
  return [...operations.values()];
}

async function run(): Promise<void> {
  let options: Options;
  try {
    options = parseArguments(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : 'invalid arguments'}\n`);
    process.exitCode = 2;
    return;
  }

  let root: string;
  try {
    root = findRepositoryRoot();
    process.chdir(root);
  } catch {
    process.stderr.write('probe repository root unavailable\n');
    process.exitCode = 2;
    return;
  }
  const evidenceDirectory = resolve(root, options.evidenceDirectory);
  let evidence: EvidenceWriter;
  try {
    evidence = await assertEmptyOrCreate(evidenceDirectory);
  } catch (error) {
    process.stderr.write(`${errorCode(error)}\n`);
    process.exitCode = 2;
    return;
  }

  if (options.scenarioId === 'BEF-SC-011') {
    await emitBlocked(evidence, options.scenarioId, 'probe_not_implemented', ['scenario_probe:BEF-SC-011:adapter_owned']);
    process.stdout.write(`status=blocked scenario=${options.scenarioId} reason=probe_not_implemented\n`);
    process.exitCode = 2;
    return;
  }

  if (options.scenarioId !== 'BEF-SC-001' && options.scenarioId !== 'BEF-SC-002' && options.scenarioId !== 'BEF-SC-003'
    && options.scenarioId !== 'BEF-SC-004' && options.scenarioId !== 'BEF-SC-005' && options.scenarioId !== 'BEF-SC-006'
    && options.scenarioId !== 'BEF-SC-007' && options.scenarioId !== 'BEF-SC-008'
    && options.scenarioId !== 'BEF-SC-009' && options.scenarioId !== 'BEF-SC-010' && options.scenarioId !== 'BEF-SC-012') {
    await emitBlocked(evidence, options.scenarioId, 'missing_probe_capability', [`scenario_probe:${options.scenarioId}`]);
    process.stdout.write(`status=blocked scenario=${options.scenarioId} reason=missing_probe_capability\n`);
    process.exitCode = 2;
    return;
  }

  if (options.scenarioId === 'BEF-SC-012' && (!options.sc004EvidenceDirectory || !options.sc005EvidenceDirectory)) {
    await emitBlocked(evidence, options.scenarioId, 'missing_replay_evidence_inputs', [
      ...(!options.sc004EvidenceDirectory ? ['BEF_SC004_EVIDENCE_DIR'] : []),
      ...(!options.sc005EvidenceDirectory ? ['BEF_SC005_EVIDENCE_DIR'] : []),
    ]);
    process.stdout.write(`status=blocked scenario=${options.scenarioId} reason=missing_replay_evidence_inputs\n`);
    process.exitCode = 2;
    return;
  }

  let runtime;
  try {
    runtime = await loadProbeRuntime();
  } catch {
    await emitBlocked(evidence, options.scenarioId, 'runtime_manifest_unavailable', ['valid_runtime_manifest_and_pinned_source_artifacts']);
    process.stdout.write(`status=blocked scenario=${options.scenarioId} reason=runtime_manifest_unavailable\n`);
    process.exitCode = 2;
    return;
  }

  let environments: ReturnType<typeof runtimeEnvironment>[];
  try {
    const configured = runtime.manifest.local.environments;
    if (options.scenarioId === 'BEF-SC-009'
        && (configured.length !== 2 || configured[0]!.id === configured[1]!.id)) {
      throw new Error('probe_sc009010_two_distinct_environments_required');
    }
    const envIds = options.scenarioId === 'BEF-SC-009'
      ? configured.map((entry) => entry.id)
      : [options.scenarioId === 'BEF-SC-005' ? configured[1]!.id : configured[0]!.id];
    environments = envIds.map((envId) => runtimeEnvironment(runtime.manifest, envId));
  } catch (error) {
    const name = missingEnvironmentName(error);
    const missing = name ? [name] : ['runtime_environment_configuration'];
    await emitBlocked(evidence, options.scenarioId, 'runtime_prerequisite_unavailable', missing);
    process.stdout.write(`status=blocked scenario=${options.scenarioId} reason=runtime_prerequisite_unavailable\n`);
    process.exitCode = 2;
    return;
  }

  const env = environments[0]!;

  const secretValues = environments.flatMap((entry) => [entry.adminKey, entry.serviceKey]);
  const database = new DatabaseObserver(env.databaseObserverUrl, evidence);
  try {
    await database.verifyReadOnlyRole();
  } catch {
    await database.close().catch(() => undefined);
    await emitBlocked(evidence, options.scenarioId, 'readonly_database_observer_unavailable', ['BEF_DATABASE_OBSERVER_URL:read_only_role']);
    process.stdout.write(`status=blocked scenario=${options.scenarioId} reason=readonly_database_observer_unavailable\n`);
    process.exitCode = 2;
    return;
  }

  let capabilities: ProbeCapabilityDocument[];
  try {
    capabilities = await Promise.all(environments.map((entry) =>
      readCapabilitiesWithoutEvidence(entry.apiBaseUrl, entry.envId, entry.adminKey)));
  } catch (error) {
    await database.close().catch(() => undefined);
    const reason = errorCode(error);
    await emitBlocked(evidence, options.scenarioId, reason, ['private_admin_probe_capabilities_endpoint']);
    process.stdout.write(`status=blocked scenario=${options.scenarioId} reason=${reason}\n`);
    process.exitCode = 2;
    return;
  }
  const missingCapabilities = environments.flatMap((entry, index) =>
    missingCapabilityPrerequisites(options.scenarioId, capabilities[index], runtime.manifestSha256, runtime.appSourceSha256, entry.envId));
  if (missingCapabilities.length) {
    await database.close().catch(() => undefined);
    await emitBlocked(evidence, options.scenarioId, 'missing_probe_capability', missingCapabilities);
    process.stdout.write(`status=blocked scenario=${options.scenarioId} reason=missing_probe_capability\n`);
    process.exitCode = 2;
    return;
  }

  const transport = new HttpEvidenceTransport(
    evidence,
    secretValues,
    10_000,
    runtime.manifest.guardrails.maxTrialSeconds * 1_000,
  );
  const rpc = new ReadOnlyRpcEvidence(evidence);
  const contexts: ProbeContext[] = environments.map((entry, index) => ({
    scenarioId: options.scenarioId,
    runtime,
    env: entry,
    evidence,
    transport,
    rpc,
    database,
    secretValues,
    operations: new Map(),
    replayedOriginalCaptures: [],
    capability: capabilities[index]!,
    primaryGeneration: null,
    primarySession: null,
    sequence: 0,
  }));
  const context = contexts[0]!;
  let manifestCopy: { path: 'manifest.json'; sha256: string } | null = null;
  let finalWritten = false;
  try {
    manifestCopy = await evidence.writeManifestCopy(runtime.manifestBytes);
    await database.writePrivilegeObservation();
    const capturedCapabilities = await Promise.all(contexts.map((entry) => captureCapabilities(entry)));
    for (const captured of capturedCapabilities) setObservedRuntimeVersions(runtime, database.observedPostgresVersion, captured);
    const capturedMissing = contexts.flatMap((entry, index) =>
      missingCapabilityPrerequisites(options.scenarioId, capturedCapabilities[index], runtime.manifestSha256, runtime.appSourceSha256, entry.env.envId));
    if (capturedMissing.length) throw new Error('probe_capability_drift_detected');
    const preflightMissing = contexts.flatMap((entry, index) =>
      missingCapabilityPrerequisites(options.scenarioId, capabilities[index], runtime.manifestSha256, runtime.appSourceSha256, entry.env.envId));
    if (preflightMissing.length) throw new Error('probe_capability_drift_detected');

    const outerScenarioSeconds = options.scenarioId === 'BEF-SC-007' || options.scenarioId === 'BEF-SC-009' || options.scenarioId === 'BEF-SC-010'
      ? runtime.manifest.guardrails.maxSwapScenarioSeconds
      : runtime.manifest.guardrails.maxTrialSeconds;
    const trialDeadline = Date.now() + outerScenarioSeconds * 1_000;
    transport.setDeadlineAt(trialDeadline);
    rpc.setDeadlineAt(trialDeadline);
    database.setDeadlineAt(trialDeadline);

    const result = options.scenarioId === 'BEF-SC-012'
      ? await runSourceEvidenceScenario(context, {
        sc004EvidenceDirectory: options.sc004EvidenceDirectory!,
        sc005EvidenceDirectory: options.sc005EvidenceDirectory!,
      })
      : await (options.scenarioId === 'BEF-SC-001'
        ? runScenario001(context)
        : options.scenarioId === 'BEF-SC-002' ? runScenario002(context)
        : options.scenarioId === 'BEF-SC-003' ? runScenario003(context)
        : options.scenarioId === 'BEF-SC-004' ? runScenario004(context)
        : options.scenarioId === 'BEF-SC-006' ? runScenario006(context)
        : options.scenarioId === 'BEF-SC-007' ? runScenario007(context)
        : options.scenarioId === 'BEF-SC-008' ? runScenario008(context)
        : options.scenarioId === 'BEF-SC-009' ? runScenario009(context, contexts[1]!)
        : options.scenarioId === 'BEF-SC-010' ? runScenario010(context) : runScenario005(context));
    const currentDigests = await sourceDigests(runtime.root);
    if (currentDigests.appSourceSha256 !== runtime.appSourceSha256 || currentDigests.probeSourceSha256 !== runtime.probeSourceSha256) {
      throw new Error('probe_source_changed_during_execution');
    }
    const payload = {
      schemaVersion: 'bef-runtime-probe/v1' as const,
      scenarioId: options.scenarioId,
      status: 'captured' as const,
      manifest: manifestCopy,
      environment: result.environment,
      operations: observedOperations(contexts),
      ...(context.replayedOriginalCaptures.length ? { replayedOriginalCaptures: context.replayedOriginalCaptures } : {}),
      observations: evidence.observations,
      artifacts: evidence.artifacts,
      applicationSourceSha256: runtime.appSourceSha256,
      probeSourceSha256: runtime.probeSourceSha256,
      runtimeVersions: runtime.runtimeVersions,
      sourceBlock: { number: runtime.manifest.source.blockNumber, hash: runtime.manifest.source.blockHash },
    };
    await evidence.writeProbe(payload);
    finalWritten = true;
    process.stdout.write(`status=captured scenario=${options.scenarioId} operations=${context.operations.size} artifacts=${evidence.artifacts.length}\n`);
  } catch (error) {
    const payload: ErrorProbe = {
      schemaVersion: 'bef-runtime-probe/v1',
      scenarioId: options.scenarioId,
      status: 'error',
      errorCode: errorCode(error),
      manifest: manifestCopy,
      environment: context.primaryGeneration ? { envId: context.primaryGeneration.envId, generation: {
        generationId: context.primaryGeneration.generationId,
        participantId: context.primaryGeneration.participantId,
        payerAddress: context.primaryGeneration.payerAddress,
      } } : null,
      operations: observedOperations(contexts),
      ...(context.replayedOriginalCaptures.length ? { replayedOriginalCaptures: context.replayedOriginalCaptures } : {}),
      observations: evidence.observations,
      artifacts: evidence.artifacts,
      ...(manifestCopy ? {
        applicationSourceSha256: runtime.appSourceSha256,
        probeSourceSha256: runtime.probeSourceSha256,
        runtimeVersions: runtime.runtimeVersions,
        sourceBlock: { number: runtime.manifest.source.blockNumber, hash: runtime.manifest.source.blockHash },
      } : {}),
    };
    await evidence.writeProbe(payload);
    finalWritten = true;
    process.stderr.write(`status=error scenario=${options.scenarioId} code=${payload.errorCode}\n`);
    process.exitCode = 1;
  } finally {
    await database.close().catch(() => undefined);
  }
  if (!finalWritten) process.exitCode = 1;
}

void run().catch(() => {
  process.stderr.write('status=error scenario=unknown code=probe_unhandled_error\n');
  process.exitCode = 1;
});
