import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdtemp, open, readFile, writeFile, unlink, lstat, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { createAgentConnectionInvalidationStore, initializeAgentConnectionInvalidationState } from './agent-connection-invalidation-state.js';

const delay = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));
const intent = () => ({ kind: 'connection_revoke' as const, operationId: `concurrent_${randomUUID()}`,
  ownerId: randomUUID(), agentId: randomUUID(), connectionId: randomUUID() });

test('independent journal instances wait for live writers and never observe a half-published floor', async () => {
  const root = await mkdtemp(join(tmpdir(), 'aci-journal-consistency-'));
  const journalPath = join(root, 'journal'), floorPath = join(root, 'floor'), journalId = randomUUID();
  const options = { journalPath, floorPath, expectedJournalId: journalId };
  try {
    await initializeAgentConnectionInvalidationState({ journalPath, floorPath, journalId });
    const lock = await open(`${journalPath}.lock`, 'wx', 0o600); await lock.sync();
    let settled = false;
    const append = createAgentConnectionInvalidationStore(options).appendIntent(intent()).finally(() => { settled = true; });
    await delay(100); assert.equal(settled, false, 'a live lock owner is contention, not a corrupt journal');
    await lock.close(); await unlink(`${journalPath}.lock`);
    assert.equal((await append).sequence, 1);
    const oldJournal = await readFile(journalPath), oldFloor = await readFile(floorPath);
    await createAgentConnectionInvalidationStore(options).appendIntent(intent());
    const nextJournal = await readFile(journalPath), nextFloor = await readFile(floorPath);
    await writeFile(journalPath, oldJournal); await writeFile(floorPath, oldFloor);
    const publishing = await open(`${journalPath}.lock`, 'wx', 0o600); await publishing.sync();
    await writeFile(journalPath, nextJournal);
    settled = false;
    const read = createAgentConnectionInvalidationStore(options).read().finally(() => { settled = true; });
    await delay(100); assert.equal(settled, false, 'read must wait across a valid journal-before-floor publication interval');
    await writeFile(floorPath, nextFloor); await publishing.close(); await unlink(`${journalPath}.lock`);
    assert.equal((await read).sequence, 2);
    const actors = Array.from({ length: 16 }, () => createAgentConnectionInvalidationStore(options));
    const committed = await Promise.all(actors.map((store) => store.appendIntent(intent())));
    assert.deepEqual(committed.map((state) => state.sequence).sort((a,b) => a-b), Array.from({ length: 16 }, (_,index) => index+3));
    const final = await createAgentConnectionInvalidationStore(options).read();
    assert.equal(final.sequence, 18); assert.equal(final.events.length, 18);
    assert.equal(new Set(final.events.map((event) => event.operationHash)).size, 18);
    // A writer crashed without completing its floor: with no live lock, this is corruption,
    // not an interval that readers may normalize, retry into success, or repair silently.
    await writeFile(floorPath, oldFloor);
    await assert.rejects(createAgentConnectionInvalidationStore(options).read());
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('orphaned journal lock times out without deleting or stealing operator authority', { timeout: 20_000 }, async () => {
  const root = await mkdtemp(join(tmpdir(), 'aci-journal-orphan-'));
  const journalPath = join(root, 'journal'), floorPath = join(root, 'floor'), journalId = randomUUID();
  try {
    await initializeAgentConnectionInvalidationState({ journalPath, floorPath, journalId });
    const orphan = await open(`${journalPath}.lock`, 'wx', 0o600); await orphan.sync(); await orphan.close();
    const beforeJournal = await readFile(journalPath), beforeFloor = await readFile(floorPath), start = Date.now();
    const options = { journalPath, floorPath, expectedJournalId: journalId };
    const outcomes = await Promise.allSettled([createAgentConnectionInvalidationStore(options).read(),
      createAgentConnectionInvalidationStore(options).appendIntent(intent())]);
    assert.ok(outcomes.every((outcome) => outcome.status === 'rejected'));
    assert.ok(Date.now() - start >= 9_000, 'contention must receive the bounded wait, not an immediate authority failure');
    assert.equal((await lstat(`${journalPath}.lock`)).isFile(), true);
    assert.deepEqual(await readFile(journalPath), beforeJournal); assert.deepEqual(await readFile(floorPath), beforeFloor);
    await unlink(`${journalPath}.lock`);
    assert.equal((await createAgentConnectionInvalidationStore(options).read()).sequence, 0);
  } finally { await rm(root, { recursive: true, force: true }); }
});
