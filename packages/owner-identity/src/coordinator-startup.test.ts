import assert from "node:assert/strict";
import test from "node:test";
import { acquireCoordinatorForStartup, type CoordinatorStartupLease } from "./coordinator-startup.js";

function coordinator(input: {
  acquire: () => Promise<boolean>;
  ownsLease: () => boolean;
  stop: () => Promise<void>;
}): CoordinatorStartupLease {
  return input;
}

test("startup retries lock contention with a fresh coordinator and returns only the lease owner", async () => {
  const events: string[] = [];
  let clock = 0;
  const first = coordinator({
    async acquire() { events.push("acquire-first"); return false; },
    ownsLease() { return false; },
    async stop() { events.push("stop-first"); },
  });
  const second = coordinator({
    async acquire() { events.push("acquire-second"); return true; },
    ownsLease() { events.push("owns-second"); return true; },
    async stop() { events.push("stop-second"); },
  });
  let created = 0;

  const acquired = await acquireCoordinatorForStartup(async () => {
    created += 1;
    events.push(`create-${created}`);
    return created === 1 ? first : second;
  }, {
    maxElapsedMs: 100,
    maxAttempts: 2,
    retryDelayMs: 10,
    now: () => clock,
    sleep: async (milliseconds) => { events.push(`sleep-${milliseconds}`); clock += milliseconds; },
  });

  assert.equal(acquired, second);
  assert.deepEqual(events, ["create-1", "acquire-first", "stop-first", "sleep-10",
    "create-2", "acquire-second", "owns-second"]);
});

test("startup fails closed after bounded contention and stops every unsuccessful instance", async () => {
  let clock = 0;
  let created = 0;
  let stopped = 0;
  await assert.rejects(acquireCoordinatorForStartup(async () => {
    created += 1;
    return coordinator({ async acquire() { return false; }, ownsLease() { return false; },
      async stop() { stopped += 1; } });
  }, {
    maxElapsedMs: 100,
    maxAttempts: 3,
    retryDelayMs: 10,
    now: () => clock,
    sleep: async (milliseconds) => { clock += milliseconds; },
  }), { message: "bef_task_coordinator_startup_lease_unavailable" });
  assert.equal(created, 3);
  assert.equal(stopped, 3);
});

test("an acquired but unowned lease is stopped and never returned as API-ready", async () => {
  let clock = 0;
  let created = 0;
  let stoppedUnowned = 0;
  const owned = coordinator({ async acquire() { return true; }, ownsLease() { return true; }, async stop() {} });
  const acquired = await acquireCoordinatorForStartup(async () => {
    created += 1;
    if (created === 1) return coordinator({ async acquire() { return true; }, ownsLease() { return false; },
      async stop() { stoppedUnowned += 1; } });
    return owned;
  }, { maxElapsedMs: 100, maxAttempts: 2, retryDelayMs: 1,
    now: () => clock, sleep: async (milliseconds) => { clock += milliseconds; } });
  assert.equal(stoppedUnowned, 1);
  assert.equal(acquired, owned);
});

test("startup never retries an instance whose failed acquisition marked it lost", async () => {
  let acquireCalls = 0;
  let stopCalls = 0;
  const lost = coordinator({
    async acquire() { acquireCalls += 1; return false; },
    ownsLease() { return false; },
    async stop() { stopCalls += 1; },
  });
  await assert.rejects(acquireCoordinatorForStartup(async () => lost, {
    maxElapsedMs: 100,
    maxAttempts: 3,
    retryDelayMs: 1,
    now: () => 0,
    sleep: async () => {},
  }), { message: "bef_task_coordinator_startup_instance_reused" });
  assert.equal(acquireCalls, 1);
  assert.equal(stopCalls, 1);
});

test("a lease acquired after the startup deadline is released before any API-ready result", async () => {
  let clock = 0;
  let stopped = 0;
  await assert.rejects(acquireCoordinatorForStartup(async () => coordinator({
    async acquire() { clock = 101; return true; },
    ownsLease() { return true; },
    async stop() { stopped += 1; },
  }), { maxElapsedMs: 100, now: () => clock }),
  { message: "bef_task_coordinator_startup_lease_unavailable" });
  assert.equal(stopped, 1);
});
