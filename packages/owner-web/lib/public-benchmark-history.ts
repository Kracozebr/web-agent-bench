import { PUBLIC_TASKS, taskProjectionMatches } from './public-benchmark';

export type PublicReleaseProjection = {
  taskIds: string[];
  weights: number[];
  priceUnits: string;
  precision: 6;
};

export type PublicBenchmarkVersion = {
  slug: string;
  displayName: string;
  status: 'current' | 'completed';
  firstActivatedAt: string;
  ranked: PublicReleaseProjection;
  training: PublicReleaseProjection;
};

export type PublicBenchmarkHistory = {
  catalogStatus: 'active' | 'history_only';
  versions: PublicBenchmarkVersion[];
};

function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

function releaseProjection(value: unknown, mode: 'ranked' | 'training'): PublicReleaseProjection | null {
  const candidate = record(value);
  if (!candidate || candidate.precision !== 6 || typeof candidate.priceUnits !== 'string' ||
      !/^(?:0|[1-9][0-9]{0,77})$/.test(candidate.priceUnits) ||
      !Array.isArray(candidate.taskIds) || !Array.isArray(candidate.weights)) return null;
  const expectedTasks = mode === 'ranked' ? PUBLIC_TASKS : PUBLIC_TASKS.filter((task) => task.training);
  if (candidate.taskIds.length !== expectedTasks.length || candidate.weights.length !== expectedTasks.length ||
      !candidate.taskIds.every((id, index) => id === expectedTasks[index]?.id) ||
      !candidate.weights.every((weight, index) => weight === expectedTasks[index]?.weight)) return null;
  return {
    taskIds: [...candidate.taskIds] as string[],
    weights: [...candidate.weights] as number[],
    priceUnits: candidate.priceUnits,
    precision: 6,
  };
}

export function parsePublicBenchmarkHistory(value: unknown): PublicBenchmarkHistory | null {
  const body = record(value);
  if (!body || !taskProjectionMatches(body.tasks) || !Array.isArray(body.versions)) return null;
  if (body.catalogStatus !== 'active' && body.catalogStatus !== 'history_only') return null;
  const versions: PublicBenchmarkVersion[] = [];
  const slugs = new Set<string>();
  const labels = new Set<string>();
  for (const item of body.versions) {
    const candidate = record(item);
    if (!candidate || typeof candidate.slug !== 'string' || !/^[a-z0-9-]{1,80}$/.test(candidate.slug) ||
        typeof candidate.displayName !== 'string' || !/^Web3 Agent Bench v[1-9][0-9]*$/.test(candidate.displayName) ||
        (candidate.status !== 'current' && candidate.status !== 'completed') ||
        typeof candidate.firstActivatedAt !== 'string' || Number.isNaN(Date.parse(candidate.firstActivatedAt)) ||
        slugs.has(candidate.slug) || labels.has(candidate.displayName)) return null;
    const ranked = releaseProjection(candidate.ranked, 'ranked');
    const training = releaseProjection(candidate.training, 'training');
    if (!ranked || !training) return null;
    slugs.add(candidate.slug);
    labels.add(candidate.displayName);
    versions.push({
      slug: candidate.slug,
      displayName: candidate.displayName,
      status: candidate.status,
      firstActivatedAt: candidate.firstActivatedAt,
      ranked,
      training,
    });
  }
  const currentCount = versions.filter((version) => version.status === 'current').length;
  if (!versions.length || (body.catalogStatus === 'active' && currentCount !== 1) ||
      (body.catalogStatus === 'history_only' && currentCount !== 0)) return null;
  return { catalogStatus: body.catalogStatus, versions };
}

export function formatPublicUsdc(units: string, precision: number): string {
  if (!/^(?:0|[1-9][0-9]{0,77})$/.test(units) || precision !== 6) throw new Error('invalid_public_price');
  const value = BigInt(units);
  const precisionUnits = BigInt('1000000');
  const whole = (value / precisionUnits).toString();
  const fraction = (value % precisionUnits).toString().padStart(6, '0').replace(/0+$/, '').padEnd(2, '0');
  return `${whole}.${fraction} USDC`;
}
