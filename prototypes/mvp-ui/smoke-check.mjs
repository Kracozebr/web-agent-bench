import assert from "node:assert/strict";
import { aggregateRun, assignRanks, calcQuote } from "./domain.js";
import {
  ALTERNATE_RUN_CREDITS,
  PRICING_MICRO,
  SELECTED_RUN_CREDITS,
  TASKS,
  openTasks,
} from "./mock-data.js";

assert.equal(TASKS.length, 12);
assert.deepEqual(
  ["Simple", "Medium", "Hard", "Ultra"].map((level) => TASKS.filter((task) => task.level === level).length),
  [4, 4, 3, 1],
);
assert.deepEqual(TASKS.filter((task) => !task.open).map((task) => task.id), ["S3", "M2", "H3", "U1"]);
assert.equal(TASKS.reduce((sum, task) => sum + task.weight, 0), 26);
assert.equal(openTasks().length, 8);
assert.equal(openTasks().reduce((sum, task) => sum + task.weight, 0), 15);

assert.equal(calcQuote("ranked", TASKS.map((task) => task.id)), PRICING_MICRO.ranked);
assert.equal(calcQuote("training", openTasks().map((task) => task.id)), PRICING_MICRO.fullTraining);
assert.equal(calcQuote("training", ["S1", "H1"]), 133_334); // ceil(500000 * 4 / 15)
assert.equal(calcQuote("training", ["S1", "S1"]), null);
assert.equal(calcQuote("training", ["M2"]), null);

const creditsByTask = Object.fromEntries(TASKS.map((task, index) => [task.id, SELECTED_RUN_CREDITS[index]]));
const score = aggregateRun(TASKS.map((task) => task.id), creditsByTask);
assert.equal(aggregateRun(["S1"], {}).score, null);
assert.equal(aggregateRun(["S1"], { S1: null }).score, null);
assert.equal(aggregateRun(["S1"], { S1: 0 }).score, 0);
assert.equal(aggregateRun(["S1"], { S1: 61 }).score, null);
assert.deepEqual(assignRanks([{ id: "unknown", score: aggregateRun(["S1"], {}) }]), []);
assert.equal(score.weightTotal, 26);
assert.equal(score.score.toFixed(2), "61.73");
assert.equal(score.byLevel.Simple, 92.5);
assert.equal(score.byLevel.Medium, 77.5);
assert.equal(score.byLevel.Hard, 100 * 98 / 180);
assert.equal(score.byLevel.Ultra, 25);
assert.equal(SELECTED_RUN_CREDITS.length, TASKS.length);
assert.deepEqual(
  ["S2", "M2", "M4", "H1", "H2", "H3", "U1"].map((id) => SELECTED_RUN_CREDITS[TASKS.findIndex((task) => task.id === id)]),
  [42, 24, 42, 40, 40, 18, 15],
); // H3 gets 30% only for delivered data; its dependent swap is missed.

const fullCredits = Object.fromEntries(TASKS.map((task, index) => [task.id, ALTERNATE_RUN_CREDITS[index]]));
const rows = assignRanks([
  { id: "slower", score, duration: 30 },
  { id: "faster-tie", score: aggregateRun(TASKS.map((task) => task.id), creditsByTask), duration: 5 },
  { id: "best", score: aggregateRun(TASKS.map((task) => task.id), fullCredits), duration: 100 },
]);
assert.deepEqual(rows.map((row) => [row.id, row.rank]), [["best", 1], ["slower", 2], ["faster-tie", 2]]);

console.log("MVP UI domain smoke checks passed: inventory, quotes, weighted score, and score-only ranks.");
