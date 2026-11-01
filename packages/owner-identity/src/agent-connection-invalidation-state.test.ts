import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { createAgentConnectionInvalidationStore, initializeAgentConnectionInvalidationState, externalConnectionAllowed } from './agent-connection-invalidation-state.js';

test('operator journal/floor require explicit initialization and reject partial, truncated, tampered or regressed state', async () => {
  const root = await mkdtemp(join(tmpdir(), 'aci-invalidation-'));
  const journalPath = join(root, 'journal.json'), floorPath = join(root, 'floor.json'), journalId = randomUUID();
  const store = createAgentConnectionInvalidationStore({ journalPath, floorPath, expectedJournalId: journalId });
  try {
    await assert.rejects(store.read());
    await initializeAgentConnectionInvalidationState({ journalPath, floorPath, journalId });
    await assert.rejects(initializeAgentConnectionInvalidationState({ journalPath, floorPath, journalId }));
    const oldJournal = await readFile(journalPath), oldFloor = await readFile(floorPath);
    const scope = { ownerId: randomUUID(), agentId: randomUUID(), connectionId: randomUUID() };
    const intent = { ...scope, kind: 'connection_revoke' as const, operationId: 'revoke_fixture_operation' };
    const first = await store.appendIntent(intent);
    assert.equal(first.sequence, 1);
    assert.equal((await store.appendIntent(intent)).sequence, 1, 'response-loss retry is idempotent');
    await assert.rejects(store.appendIntent({ ...intent, connectionId: randomUUID() }));
    const goodJournal = await readFile(journalPath), goodFloor = await readFile(floorPath);
    await writeFile(journalPath, oldJournal); await assert.rejects(store.read(), 'journal rollback below external floor');
    await writeFile(journalPath, goodJournal); await writeFile(floorPath, oldFloor);
    await assert.rejects(store.read(), 'crash after journal write before floor write');
    await writeFile(floorPath, goodFloor); await writeFile(journalPath, '{'); await assert.rejects(store.read());
    const tampered = JSON.parse(goodJournal.toString()); tampered.events[0].connectionId = randomUUID();
    await writeFile(journalPath, JSON.stringify(tampered)); await assert.rejects(store.read());
    await writeFile(journalPath, goodJournal);
    const principal = { ...scope, grantId: scope.connectionId, accessGeneration: 1 };
    assert.equal(await externalConnectionAllowed(store, principal), false);
    assert.equal(await externalConnectionAllowed(store, { ...principal, grantId: randomUUID() }), true);
    if (process.platform !== 'win32') {
      await chmod(floorPath, 0o644); await assert.rejects(store.read()); await chmod(floorPath, 0o600);
    }
    await rm(floorPath); await assert.rejects(store.read(), 'missing floor must never auto-initialize');
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('agent generation floor preserves other agents and newly authorized generations', async () => {
  const root = await mkdtemp(join(tmpdir(), 'aci-invalidation-'));
  const journalPath = join(root, 'journal.json'), floorPath = join(root, 'floor.json'), journalId = randomUUID();
  try {
    await initializeAgentConnectionInvalidationState({ journalPath, floorPath, journalId });
    const store = createAgentConnectionInvalidationStore({ journalPath, floorPath, expectedJournalId: journalId });
    const principal = { ownerId: randomUUID(), agentId: randomUUID(), grantId: randomUUID(), accessGeneration: 1 };
    await store.appendIntent({ kind: 'agent_revoke', operationId: 'generation_fixture_operation', ownerId: principal.ownerId, agentId: principal.agentId, generationFloor: 2 });
    assert.equal(await externalConnectionAllowed(store, principal), false);
    assert.equal(await externalConnectionAllowed(store, { ...principal, accessGeneration: 2 }), true);
    assert.equal(await externalConnectionAllowed(store, { ...principal, agentId: randomUUID() }), true);
    const bytes = (await readFile(journalPath, 'utf8')) + (await readFile(floorPath, 'utf8'));
    assert.equal(bytes.includes('generation_fixture_operation'), false, 'raw operation text is not persisted');
    await assert.rejects(createAgentConnectionInvalidationStore({ journalPath, floorPath, expectedJournalId: randomUUID() }).read());
  } finally { await rm(root, { recursive: true, force: true }); }
});
