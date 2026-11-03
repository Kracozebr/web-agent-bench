import type { FastifyInstance } from 'fastify';
import type { TaskMode } from './task-catalog.js';
import { PUBLIC_TASK_CATALOG, CURRENT_TRAINING_TASK_IDS, TASK_IDS } from './task-catalog.js';
import type { TaskReleaseProvider } from './task-release.js';

type PublicRelease = {
  taskIds: readonly string[];
  weights: readonly number[];
  priceUnits: string;
  precision: 6;
};

function isExpectedRelease(
  mode: TaskMode,
  release: Awaited<ReturnType<TaskReleaseProvider['getActiveAdmissionRelease']>>,
): release is NonNullable<typeof release> {
  if (!release || release.mode !== mode || release.precision !== 6 || !/^(?:0|[1-9][0-9]{0,77})$/.test(release.priceUnits)) return false;
  const expectedIds = mode === 'ranked' ? TASK_IDS : CURRENT_TRAINING_TASK_IDS;
  if (release.taskIds.length !== expectedIds.length || release.weights.length !== expectedIds.length) return false;
  if (release.taskIds.some((taskId, index) => taskId !== expectedIds[index])) return false;
  return release.weights.every((weight, index) => weight === PUBLIC_TASK_CATALOG.find((item) => item.taskId === expectedIds[index])?.weight);
}

function safeProjection(release: NonNullable<Awaited<ReturnType<TaskReleaseProvider['getActiveAdmissionRelease']>>>): PublicRelease {
  return {
    taskIds: [...release.taskIds],
    weights: [...release.weights],
    priceUnits: release.priceUnits,
    precision: 6,
  };
}

export function registerPublicBenchmarkCatalogRoutes(
  app: FastifyInstance,
  deps: { provider: TaskReleaseProvider; resultsConfigured: boolean },
): void {
  app.get('/api/public/catalog', async (_request, reply) => {
    try {
      const [ranked, training] = await Promise.all([
        deps.provider.getActiveAdmissionRelease('ranked'),
        deps.provider.getActiveAdmissionRelease('training'),
      ]);
      const publicTasks = deps.provider.getPublicCatalog();
      const metadataMatches = publicTasks.length === PUBLIC_TASK_CATALOG.length &&
        publicTasks.every((task, index) => {
          const expected = PUBLIC_TASK_CATALOG[index];
          return task.taskId === expected?.taskId && task.level === expected.level && task.weight === expected.weight &&
            task.trainingAvailable === expected.trainingAvailable && task.scoringPolicy === expected.scoringPolicy;
        });
      const releasesMatch = isExpectedRelease('ranked', ranked) && isExpectedRelease('training', training) &&
        ranked.benchmarkVersion === training.benchmarkVersion;
      if (!metadataMatches || !releasesMatch) {
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
}
