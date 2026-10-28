/** Public, case-free task inventory and deterministic selection pricing. */

export const TASK_IDS = [
  'S1', 'S2', 'S3', 'S4', 'M1', 'M2', 'M3', 'M4', 'H1', 'H2', 'H3', 'U1',
] as const;

export type TaskId = (typeof TASK_IDS)[number];
export type TaskLevel = 'simple' | 'medium' | 'hard' | 'ultra';
export type TaskMode = 'training' | 'ranked';

const OPEN_TRAINING_IDS = ['S1', 'S2', 'S4', 'M1', 'M3', 'M4', 'H1', 'H2'] as const satisfies readonly TaskId[];
export const CLOSED_RANKED_IDS = ['S3', 'M2', 'H3', 'U1'] as const satisfies readonly TaskId[];
export type OpenTrainingTaskId = (typeof OPEN_TRAINING_IDS)[number];

export type PublicTaskMetadata = {
  taskId: TaskId;
  level: TaskLevel;
  weight: 1 | 2 | 3 | 5;
  trainingAvailable: boolean;
  scoringPolicy: string;
};

/**
 * Public projection only. It intentionally carries no case values, account
 * bindings, reference paths, validators, or ranked-only conditions.
 */
export const PUBLIC_TASK_CATALOG: readonly PublicTaskMetadata[] = Object.freeze([
  { taskId: 'S1', level: 'simple', weight: 1, trainingAvailable: true, scoringPolicy: 'Exact USDC transfer and native reserve; binary credit.' },
  { taskId: 'S2', level: 'simple', weight: 1, trainingAvailable: true, scoringPolicy: 'Complete read-only offer answer: amount 0.4, payment tuple 0.3, offer identity 0.3.' },
  { taskId: 'S3', level: 'simple', weight: 1, trainingAvailable: false, scoringPolicy: 'Select any scoped offer satisfying every pinned predicate; binary credit and no purchase.' },
  { taskId: 'S4', level: 'simple', weight: 1, trainingAvailable: true, scoringPolicy: 'Revoke the specified positive allowance without unrelated state changes; binary credit.' },
  { taskId: 'M1', level: 'medium', weight: 2, trainingAvailable: true, scoringPolicy: 'One permitted settlement and validated delivery within the operating budget; binary credit.' },
  { taskId: 'M2', level: 'medium', weight: 2, trainingAvailable: false, scoringPolicy: 'Qualifying delivery 0.4; add 0.6 for any minimum advertised qualifying price.' },
  { taskId: 'M3', level: 'medium', weight: 2, trainingAvailable: true, scoringPolicy: 'Exact input through an allowed route to the native ETH minimum and reserve; binary credit.' },
  { taskId: 'M4', level: 'medium', weight: 2, trainingAvailable: true, scoringPolicy: 'Required exchange 0.7; add 0.3 for cleanup after the exchange.' },
  { taskId: 'H1', level: 'hard', weight: 3, trainingAvailable: true, scoringPolicy: 'Distinct validated required data components divided by the release-fixed component count.' },
  { taskId: 'H2', level: 'hard', weight: 3, trainingAvailable: true, scoringPolicy: 'Distinct exact payout obligations fulfilled divided by the release-fixed obligation count.' },
  { taskId: 'H3', level: 'hard', weight: 3, trainingAvailable: false, scoringPolicy: 'Paid reference delivery 0.3; add 0.7 for a satisfying trade after delivery.' },
  { taskId: 'U1', level: 'ultra', weight: 5, trainingAvailable: false, scoringPolicy: 'Data 0.20, final allocation 0.25, exact payouts 0.35, guarded cleanup 0.20.' },
]);

const metadataById = new Map(PUBLIC_TASK_CATALOG.map((task) => [task.taskId, task]));
const taskOrder = new Map(TASK_IDS.map((taskId, index) => [taskId, index]));

export type TaskSelectionResult =
  | { ok: true; mode: TaskMode; taskIds: readonly TaskId[]; weightSum: number }
  | { ok: false; reason: 'invalid_mode' | 'selection_required' | 'invalid_task_id' | 'duplicate_task_id' | 'closed_training_task' | 'ranked_selection_must_be_complete' };

/** Rejects invalid/closed requests as a whole and returns the fixed release order. */
export function selectTaskIds(mode: TaskMode, requestedTaskIds?: readonly string[]): TaskSelectionResult {
  if (mode !== 'training' && mode !== 'ranked') return { ok: false, reason: 'invalid_mode' };
  if (!Array.isArray(requestedTaskIds) || requestedTaskIds.length === 0) return { ok: false, reason: 'selection_required' };

  const requested = new Set<TaskId>();
  for (const value of requestedTaskIds) {
    if (!TASK_IDS.includes(value as TaskId)) return { ok: false, reason: 'invalid_task_id' };
    const taskId = value as TaskId;
    if (requested.has(taskId)) return { ok: false, reason: 'duplicate_task_id' };
    if (mode === 'training' && !OPEN_TRAINING_IDS.includes(taskId as OpenTrainingTaskId)) {
      return { ok: false, reason: 'closed_training_task' };
    }
    requested.add(taskId);
  }

  if (mode === 'ranked' && (requested.size !== TASK_IDS.length || TASK_IDS.some((taskId) => !requested.has(taskId)))) {
    return { ok: false, reason: 'ranked_selection_must_be_complete' };
  }

  const taskIds = [...requested].sort((left, right) => taskOrder.get(left)! - taskOrder.get(right)!);
  const weightSum = taskIds.reduce((sum, taskId) => sum + metadataById.get(taskId)!.weight, 0);
  return { ok: true, mode, taskIds, weightSum };
}

export type TrainingQuote = {
  taskIds: readonly TaskId[];
  selectedWeight: number;
  denominatorWeight: 15;
  fullOpenPriceUnits: string;
  priceUnits: string;
  precision: 6;
  rounding: 'ceil_once_per_request';
};

/** Prices a nonempty open selection once using integer six-decimal USDC units. */
export function quoteOpenTrainingSelection(
  requestedTaskIds: readonly string[],
  fullOpenPriceUnits: string,
): TrainingQuote | TaskSelectionResult | { ok: false; reason: 'invalid_price' } {
  const selection = selectTaskIds('training', requestedTaskIds);
  if (!selection.ok) return selection;
  if (!/^(?:0|[1-9][0-9]{0,77})$/.test(fullOpenPriceUnits)) return { ok: false, reason: 'invalid_price' };
  const numerator = BigInt(fullOpenPriceUnits) * BigInt(selection.weightSum);
  const denominator = 15n;
  const priceUnits = numerator === 0n ? 0n : (numerator + denominator - 1n) / denominator;
  return {
    taskIds: selection.taskIds,
    selectedWeight: selection.weightSum,
    denominatorWeight: 15,
    fullOpenPriceUnits,
    priceUnits: priceUnits.toString(),
    precision: 6,
    rounding: 'ceil_once_per_request',
  };
}

export function fullRankedSelection(): { taskIds: readonly TaskId[]; weightSum: 26 } {
  return { taskIds: TASK_IDS, weightSum: 26 };
}

export function isOpenTrainingTask(taskId: string): taskId is OpenTrainingTaskId {
  return OPEN_TRAINING_IDS.includes(taskId as OpenTrainingTaskId);
}

export function isClosedRankedTask(taskId: string): taskId is (typeof CLOSED_RANKED_IDS)[number] {
  return CLOSED_RANKED_IDS.includes(taskId as (typeof CLOSED_RANKED_IDS)[number]);
}
