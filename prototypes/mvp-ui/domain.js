import { PRICING_MICRO, SCORE_SCALE, TASKS, openTasks, taskById } from "./mock-data.js";

// These helpers keep quote and score arithmetic independent of the browser UI.
export function calcQuote(mode, taskIds) {
  if (!Array.isArray(taskIds) || !taskIds.length || new Set(taskIds).size !== taskIds.length) return null;
  if (mode === "ranked") {
    return taskIds.length === TASKS.length && TASKS.every((task) => taskIds.includes(task.id))
      ? PRICING_MICRO.ranked
      : null;
  }
  if (mode !== "training") return null;
  const selected = taskIds.map(taskById);
  if (selected.some((task) => !task || !task.open)) return null;
  const weight = selected.reduce((sum, task) => sum + task.weight, 0);
  const openWeight = openTasks().reduce((sum, task) => sum + task.weight, 0);
  return Math.ceil(PRICING_MICRO.fullTraining * weight / openWeight);
}

export function aggregateRun(taskIds, creditsByTask) {
  const tasks = taskIds.map(taskById).filter(Boolean);
  const weightTotal = tasks.reduce((sum, task) => sum + task.weight, 0);
  // AICODE-NOTE: Missing observations remain unknown; only an explicit zero is a failed outcome.
  const valid = tasks.length > 0 && tasks.length === taskIds.length && new Set(taskIds).size === taskIds.length
    && tasks.every((task) => Number.isInteger(creditsByTask?.[task.id]) && creditsByTask[task.id] >= 0 && creditsByTask[task.id] <= SCORE_SCALE);
  if (!valid) return { weightedUnits: null, weightTotal, score: null,
    byLevel: Object.fromEntries(["Simple", "Medium", "Hard", "Ultra"].map((level) => [level, null])) };
  const weightedUnits = tasks.reduce((sum, task) => sum + task.weight * Number(creditsByTask[task.id] || 0), 0);
  const byLevel = {};
  ["Simple", "Medium", "Hard", "Ultra"].forEach((level) => {
    const levelTasks = tasks.filter((task) => task.level === level);
    const units = levelTasks.reduce((sum, task) => sum + Number(creditsByTask[task.id] || 0), 0);
    byLevel[level] = levelTasks.length ? 100 * units / (SCORE_SCALE * levelTasks.length) : null;
  });
  return {
    weightedUnits,
    weightTotal,
    score: weightTotal ? 100 * weightedUnits / (SCORE_SCALE * weightTotal) : null,
    byLevel,
  };
}

export function assignRanks(rows) {
  const ordered = rows.filter((row) => row.score?.score != null && Number.isFinite(row.score.weightedUnits))
    .sort((left, right) => right.score.weightedUnits - left.score.weightedUnits);
  let priorUnits = null;
  let priorRank = 0;
  ordered.forEach((row, index) => {
    if (priorUnits !== row.score.weightedUnits) priorRank = index + 1;
    row.rank = priorRank;
    priorUnits = row.score.weightedUnits;
  });
  return ordered;
}
