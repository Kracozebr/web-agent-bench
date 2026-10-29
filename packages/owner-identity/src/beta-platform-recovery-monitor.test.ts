import assert from 'node:assert/strict';
import test from 'node:test';
import { betaRecoveryClockExclusionDelta } from './beta-platform-recovery-monitor.js';

test('clock exclusion is cumulative, capped at 180 seconds, and never changes the wall recovery cutoff', () => {
  const startedAt = new Date('2026-10-29T10:00:00.000Z');
  const recovery = {
    started_at: startedAt,
    deadline_at: new Date(startedAt.getTime() + 180_000),
    clock_excluded_ms: 45_000,
  };

  assert.equal(betaRecoveryClockExclusionDelta(recovery, new Date(startedAt.getTime() + 30_000)), 0);
  assert.equal(betaRecoveryClockExclusionDelta(recovery, new Date(startedAt.getTime() + 75_000)), 30_000);
  assert.equal(betaRecoveryClockExclusionDelta(recovery, new Date(startedAt.getTime() + 180_000)), 135_000);
  assert.equal(betaRecoveryClockExclusionDelta(recovery, new Date(startedAt.getTime() + 240_000)), 135_000);
  assert.equal(recovery.deadline_at.getTime(), startedAt.getTime() + 180_000);
});
