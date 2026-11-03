import type { FastifyInstance, FastifyReply } from 'fastify';
import type { TaskMode } from './task-catalog.js';
import { PUBLIC_TASK_CATALOG, CURRENT_TRAINING_TASK_IDS, TASK_IDS } from './task-catalog.js';
import type { RunAdmissionRelease, TaskReleaseProvider } from './task-release.js';
import type { PublicBenchmarkHistoryProvider } from './public-benchmark-history-provider.js';

type PublicRelease = {
  taskIds: readonly string[];
  weights: readonly number[];
  priceUnits: string;
  precision: 6;
};

type PublicVersion = {
  slug: string;
  displayName: string;
  status: 'current' | 'completed';
  firstActivatedAt: string;
  ranked: PublicRelease;
  training: PublicRelease;
};

const PUBLIC_BENCHMARK_VERSIONS: Readonly<Record<string, { slug: string; displayName: string; order: number }>> = Object.freeze({
  'BTS-LOCAL-V2': { slug: 'web3-agent-bench-v1', displayName: 'Web3 Agent Bench v1', order: 1 },
});

function isExpectedRelease(mode: TaskMode, release: RunAdmissionRelease | null): release is RunAdmissionRelease {
  if (!release || release.mode !== mode || release.precision !== 6 || !/^(?:0|[1-9][0-9]{0,77})$/.test(release.priceUnits)) return false;
  const expectedIds = mode === 'ranked' ? TASK_IDS : CURRENT_TRAINING_TASK_IDS;
  if (release.taskIds.length !== expectedIds.length || release.weights.length !== expectedIds.length) return false;
  if (release.taskIds.some((taskId, index) => taskId !== expectedIds[index])) return false;
  return release.weights.every((weight, index) =>
    weight === PUBLIC_TASK_CATALOG.find((item) => item.taskId === expectedIds[index])?.weight);
}

function safeProjection(release: RunAdmissionRelease): PublicRelease {
  return {
    taskIds: [...release.taskIds],
    weights: [...release.weights],
    priceUnits: release.priceUnits,
    precision: 6,
  };
}

function publicMetadataMatches(provider: TaskReleaseProvider): boolean {
  const publicTasks = provider.getPublicCatalog();
  return publicTasks.length === PUBLIC_TASK_CATALOG.length &&
    publicTasks.every((task, index) => {
      const expected = PUBLIC_TASK_CATALOG[index];
      return task.taskId === expected?.taskId && task.level === expected.level && task.weight === expected.weight &&
        task.trainingAvailable === expected.trainingAvailable && task.scoringPolicy === expected.scoringPolicy;
    });
}

function unavailableHistory(reply: FastifyReply) {
  return reply.code(200).header('Cache-Control', 'no-store').send({
    catalogStatus: 'unavailable',
    versions: [],
    tasks: PUBLIC_TASK_CATALOG,
  });
}

export function registerPublicBenchmarkCatalogRoutes(
  app: FastifyInstance,
  deps: { provider: TaskReleaseProvider; historyProvider?: PublicBenchmarkHistoryProvider; resultsConfigured: boolean },
): void {
  app.get('/api/public/catalog', async (_request, reply) => {
    try {
      const [ranked, training] = await Promise.all([
        deps.provider.getActiveAdmissionRelease('ranked'),
        deps.provider.getActiveAdmissionRelease('training'),
      ]);
      const releasesMatch = isExpectedRelease('ranked', ranked) && isExpectedRelease('training', training) &&
        ranked.benchmarkVersion === training.benchmarkVersion;
      const version = ranked ? PUBLIC_BENCHMARK_VERSIONS[ranked.benchmarkVersion.toUpperCase()] : undefined;
      if (!publicMetadataMatches(deps.provider) || !releasesMatch || !version) {
        return reply.code(200).header('Cache-Control', 'no-store').send({
          catalogStatus: 'unavailable',
          resultsStatus: deps.resultsConfigured ? 'configured' : 'not_configured',
          tasks: PUBLIC_TASK_CATALOG,
        });
      }
      return reply.code(200).header('Cache-Control', 'no-store').send({
        catalogStatus: 'active',
        resultsStatus: deps.resultsConfigured ? 'configured' : 'not_configured',
        benchmarkVersion: ranked.benchmarkVersion,
        displayName: version.displayName,
        ranked: safeProjection(ranked),
        training: safeProjection(training),
        tasks: PUBLIC_TASK_CATALOG,
      });
    } catch {
      return reply.code(503).header('Cache-Control', 'no-store').send({
        error: { code: 'PUBLIC_CATALOG_UNAVAILABLE', message: 'The current public catalog is unavailable.' },
      });
    }
  });

  app.get('/api/public/benchmarks', async (_request, reply) => {
    try {
      const snapshots = await deps.historyProvider?.getActivatedReleaseSnapshots();
      if (!snapshots) return unavailableHistory(reply);
      if (!publicMetadataMatches(deps.provider)) return unavailableHistory(reply);

      const groupedVersions = new Map<string, {
        label: (typeof PUBLIC_BENCHMARK_VERSIONS)[string];
        firstActivatedAt: string;
        snapshot: (typeof snapshots)[number];
      }>();
      let currentCount = 0;
      for (const snapshot of snapshots) {
        const ranked = snapshot.ranked;
        const training = snapshot.training;
        const versionKey = ranked.benchmarkVersion.toUpperCase();
        const label = PUBLIC_BENCHMARK_VERSIONS[versionKey];
        const activatedAt = Date.parse(snapshot.firstActivatedAt);
        if (!label || !Number.isFinite(activatedAt) ||
            !isExpectedRelease('ranked', ranked) || !isExpectedRelease('training', training) ||
            ranked.benchmarkVersion.toUpperCase() !== training.benchmarkVersion.toUpperCase()) {
          return unavailableHistory(reply);
        }
        if (snapshot.isActive) currentCount += 1;
        const existing = groupedVersions.get(versionKey);
        if (!existing) {
          groupedVersions.set(versionKey, { label, firstActivatedAt: snapshot.firstActivatedAt, snapshot });
          continue;
        }
        const earliest = Math.min(Date.parse(existing.firstActivatedAt), activatedAt);
        const selectedSnapshot = snapshot.isActive || !existing.snapshot.isActive ? snapshot : existing.snapshot;
        groupedVersions.set(versionKey, {
          label,
          firstActivatedAt: new Date(earliest).toISOString(),
          snapshot: selectedSnapshot,
        });
      }
      if (currentCount > 1) return unavailableHistory(reply);
      const versions: PublicVersion[] = [...groupedVersions.values()].map(({ label, firstActivatedAt, snapshot }) => ({
        slug: label.slug,
        displayName: label.displayName,
        status: snapshot.isActive ? 'current' : 'completed',
        firstActivatedAt,
        ranked: safeProjection(snapshot.ranked),
        training: safeProjection(snapshot.training),
      }));
      if (new Set(versions.map((version) => version.slug)).size !== versions.length) return unavailableHistory(reply);
      versions.sort((left, right) => {
        const leftOrder = Object.values(PUBLIC_BENCHMARK_VERSIONS).find((version) => version.slug === left.slug)?.order ?? Number.MAX_SAFE_INTEGER;
        const rightOrder = Object.values(PUBLIC_BENCHMARK_VERSIONS).find((version) => version.slug === right.slug)?.order ?? Number.MAX_SAFE_INTEGER;
        return leftOrder - rightOrder;
      });
      const catalogStatus = currentCount === 1 ? 'active' : versions.length ? 'history_only' : 'unavailable';
      return reply.code(200).header('Cache-Control', 'no-store').send({
        catalogStatus,
        versions,
        tasks: PUBLIC_TASK_CATALOG,
      });
    } catch {
      return reply.code(503).header('Cache-Control', 'no-store').send({
        error: { code: 'PUBLIC_BENCHMARK_HISTORY_UNAVAILABLE', message: 'The public benchmark catalogue is unavailable.' },
      });
    }
  });
}
