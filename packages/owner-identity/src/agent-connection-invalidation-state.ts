import { createHash, randomUUID } from 'node:crypto';
import { lstat, open, readFile, rename, unlink } from 'node:fs/promises';
import { dirname, isAbsolute, parse, resolve, sep } from 'node:path';
import { sql } from 'drizzle-orm';
import type { OwnerDatabase } from './db.js';

type Kind = 'connection_revoke' | 'agent_revoke' | 'refresh_consume' | 'diagnostic_refresh_consume' | 'diagnostic_code_consume';
export interface ConnectionInvalidationIntent {
  kind: Kind; operationId: string; ownerId: string; agentId: string;
  connectionId?: string; generationFloor?: number; consumedRefreshHash?: string;
}
export interface ConnectionInvalidationEvent extends Omit<ConnectionInvalidationIntent, 'operationId'> {
  eventId: string; operationHash: string; sequence: number; previousSha256: string; createdAt: string; sha256: string;
}
export interface ConnectionInvalidationSnapshot {
  journalId: string; sequence: number; headSha256: string; events: ConnectionInvalidationEvent[];
}
export interface AgentConnectionInvalidationStore {
  read(): Promise<ConnectionInvalidationSnapshot>;
  appendIntent(intent: ConnectionInvalidationIntent): Promise<ConnectionInvalidationSnapshot>;
}
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const HEX = /^[a-f0-9]{64}$/;
const ZERO = '0'.repeat(64);
const MAX_BYTES = 64 * 1024 * 1024;
const sha = (value: string) => createHash('sha256').update(value).digest('hex');
function canonical(value: unknown): string {
  if (!value || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  const row = value as Record<string, unknown>;
  return `{${Object.keys(row).sort().map((key) => `${JSON.stringify(key)}:${canonical(row[key])}`).join(',')}}`;
}
function fail(): never { throw new Error('agent_connection_invalidation_state_unavailable'); }
function validateScope(value: Omit<ConnectionInvalidationIntent, 'operationId'>) {
  if (!UUID.test(value.ownerId) || !UUID.test(value.agentId)) fail();
  if (value.kind === 'agent_revoke') {
    if (!Number.isSafeInteger(value.generationFloor) || value.generationFloor! < 1 || value.connectionId || value.consumedRefreshHash) fail();
  } else if (value.kind === 'connection_revoke' || value.kind === 'refresh_consume' || value.kind === 'diagnostic_refresh_consume' || value.kind === 'diagnostic_code_consume') {
    if (!value.connectionId || !UUID.test(value.connectionId) || value.generationFloor !== undefined ||
        (value.kind !== 'connection_revoke' ? !/^[A-Za-z0-9_-]{43}$/.test(value.consumedRefreshHash ?? '') : value.consumedRefreshHash !== undefined)) fail();
  } else fail();
}
async function safePath(path: string, missingFinal = false) {
  let current = parse(path).root;
  for (const part of path.slice(current.length).split(sep).filter(Boolean)) {
    current = resolve(current, part);
    const info = await lstat(current).catch((error: NodeJS.ErrnoException) => {
      if (missingFinal && current === path && error.code === 'ENOENT') return null;
      return fail();
    });
    if (info?.isSymbolicLink() || (info && current !== path && !info.isDirectory())) fail();
    if (info && current === path && (!info.isFile() || (process.platform !== 'win32' && (info.mode & 0o077) !== 0))) fail();
  }
}
async function atomic(path: string, value: unknown) {
  const temporary = `${path}.${randomUUID()}.tmp`;
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    handle = await open(temporary, 'wx', 0o600);
    await handle.writeFile(`${canonical(value)}\n`); await handle.sync(); await handle.close(); handle = undefined;
    await rename(temporary, path);
    const directory = await open(dirname(path), 'r');
    try { await directory.sync(); } finally { await directory.close(); }
  } catch (error) {
    await handle?.close().catch(() => undefined); await unlink(temporary).catch(() => undefined); throw error;
  }
}
async function jsonFile(path: string) {
  await safePath(path); const info = await lstat(path); if (info.size > MAX_BYTES) fail();
  try { return JSON.parse(await readFile(path, 'utf8')) as Record<string, unknown>; } catch { return fail(); }
}

/** Operator-owned journal AND monotonic floor must remain outside restored database/private-data/checkpoint trees. Missing or divergent files are never auto-initialized. */
export function createAgentConnectionInvalidationStore(options: { journalPath: string; floorPath: string; expectedJournalId: string }): AgentConnectionInvalidationStore {
  if (!isAbsolute(options.journalPath) || !isAbsolute(options.floorPath) || resolve(options.journalPath) === resolve(options.floorPath) || !UUID.test(options.expectedJournalId)) fail();
  const journalPath = resolve(options.journalPath), floorPath = resolve(options.floorPath);
  let observedSequence = -1;
  // Readers and writers share the same bounded cross-process lock. A live
  // writer's journal/floor publication interval is not a corrupt checkpoint.
  // A crashed owner's lock is never removed automatically: timeout fails closed.
  async function withJournalLock<T>(action: () => Promise<T>): Promise<T> {
    const lockPath = `${journalPath}.lock`;
    await safePath(journalPath); await safePath(floorPath);
    const deadline = Date.now() + 10_000;
    let lock: Awaited<ReturnType<typeof open>>;
    while (true) {
      await safePath(lockPath, true);
      try { lock = await open(lockPath, 'wx', 0o600); break; }
      catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'EEXIST' || Date.now() >= deadline) fail();
        await new Promise<void>((done) => setTimeout(done, 20));
      }
    }
    try { await lock.sync(); return await action(); }
    finally {
      await lock.close(); await unlink(lockPath);
      const directory = await open(dirname(journalPath), 'r');
      try { await directory.sync(); } finally { await directory.close(); }
    }
  }
  async function read(): Promise<ConnectionInvalidationSnapshot> { return withJournalLock(readUnlocked); }
  async function readUnlocked(): Promise<ConnectionInvalidationSnapshot> {
    const [journal, floor] = await Promise.all([jsonFile(journalPath), jsonFile(floorPath)]);
    if (journal.schemaVersion !== 'agent-connection-invalidation/v1' || floor.schemaVersion !== 'agent-connection-invalidation-floor/v1' ||
        Object.keys(journal).some((key) => !['schemaVersion','journalId','events'].includes(key)) ||
        Object.keys(floor).some((key) => !['schemaVersion','journalId','sequence','headSha256'].includes(key)) ||
        journal.journalId !== options.expectedJournalId || floor.journalId !== options.expectedJournalId ||
        !Array.isArray(journal.events) || journal.events.length > 100_000) fail();
    let previous = ZERO, sequence = 0;
    const seen = new Set<string>();
    for (const raw of journal.events) {
      if (!raw || typeof raw !== 'object' || Array.isArray(raw)) fail();
      const event = raw as ConnectionInvalidationEvent;
      const { sha256, ...unsigned } = event;
      if (Object.keys(event).some((key) => !['kind','ownerId','agentId','connectionId','generationFloor','consumedRefreshHash','eventId','operationHash','sequence','previousSha256','createdAt','sha256'].includes(key))) fail();
      validateScope(event);
      if (!UUID.test(event.eventId) || !HEX.test(event.operationHash) || seen.has(event.operationHash) ||
          event.sequence !== ++sequence || event.previousSha256 !== previous || !HEX.test(sha256) ||
          sha(canonical(unsigned)) !== sha256 || !Number.isFinite(Date.parse(event.createdAt))) fail();
      seen.add(event.operationHash); previous = sha256;
    }
    if (floor.sequence !== sequence || floor.headSha256 !== previous || sequence < observedSequence) fail();
    observedSequence = sequence;
    return { journalId: options.expectedJournalId, sequence, headSha256: previous, events: journal.events as ConnectionInvalidationEvent[] };
  }
  return { read, async appendIntent(intent) {
    validateScope(intent);
    if (Object.keys(intent).some((key) => !['kind','operationId','ownerId','agentId','connectionId','generationFloor','consumedRefreshHash'].includes(key))) fail();
    if (typeof intent.operationId !== 'string' || intent.operationId.length < 12 || intent.operationId.length > 256) fail();
    return withJournalLock(async () => {
      // Already owns the file lock; recursive public read() would deadlock.
      const state = await readUnlocked(); const operationHash = sha(intent.operationId);
      const { operationId: _operation, ...scope } = intent;
      const existing = state.events.find((event) => event.operationHash === operationHash);
      if (existing) {
        const actualScope = { kind: existing.kind, ownerId: existing.ownerId, agentId: existing.agentId,
          ...(existing.connectionId ? { connectionId: existing.connectionId } : {}),
          ...(existing.generationFloor ? { generationFloor: existing.generationFloor } : {}),
          ...(existing.consumedRefreshHash ? { consumedRefreshHash: existing.consumedRefreshHash } : {}) };
        if (canonical(actualScope) !== canonical(scope)) fail();
        return state;
      }
      if (state.events.length >= 100_000) fail();
      const unsigned = { ...scope, eventId: randomUUID(), operationHash, sequence: state.sequence + 1,
        previousSha256: state.headSha256, createdAt: new Date().toISOString() };
      const event = { ...unsigned, sha256: sha(canonical(unsigned)) };
      const next = { schemaVersion: 'agent-connection-invalidation/v1', journalId: state.journalId, events: [...state.events, event] };
      if (Buffer.byteLength(canonical(next)) > MAX_BYTES) fail();
      await atomic(journalPath, next);
      await atomic(floorPath, { schemaVersion: 'agent-connection-invalidation-floor/v1', journalId: state.journalId, sequence: event.sequence, headSha256: event.sha256 });
      return await readUnlocked();
    });
  } };
}

export async function initializeAgentConnectionInvalidationState(options: { journalPath: string; floorPath: string; journalId: string }) {
  if (!isAbsolute(options.journalPath) || !isAbsolute(options.floorPath) || !UUID.test(options.journalId) || resolve(options.journalPath) === resolve(options.floorPath)) fail();
  for (const [path, value] of [[options.journalPath, { schemaVersion: 'agent-connection-invalidation/v1', journalId: options.journalId, events: [] }],
    [options.floorPath, { schemaVersion: 'agent-connection-invalidation-floor/v1', journalId: options.journalId, sequence: 0, headSha256: ZERO }]] as const) {
    await safePath(resolve(path), true); const handle = await open(path, 'wx', 0o600);
    try { await handle.writeFile(`${canonical(value)}\n`); await handle.sync(); } finally { await handle.close(); }
    const directory = await open(dirname(path), 'r'); try { await directory.sync(); } finally { await directory.close(); }
  }
}

export async function externalConnectionAllowed(store: AgentConnectionInvalidationStore | undefined,
  principal: { ownerId: string; agentId: string; grantId: string; accessGeneration: number }, db?: OwnerDatabase): Promise<boolean> {
  if (!store) return true;
  const state = await store.read();
  if (state.events.some((event) => event.ownerId === principal.ownerId && event.agentId === principal.agentId &&
    (event.kind === 'connection_revoke' && event.connectionId === principal.grantId ||
      event.kind === 'agent_revoke' && principal.accessGeneration < event.generationFloor!))) return false;
  const consumptions = state.events.filter((event) => event.kind === 'refresh_consume' && event.ownerId === principal.ownerId && event.agentId === principal.agentId && event.connectionId === principal.grantId);
  if (consumptions.length && !db) return false;
  for (const event of consumptions) {
    const rows = await db!.execute(sql`SELECT id FROM oid_oauth_refresh_token WHERE reference_id=${principal.grantId} AND token=${event.consumedRefreshHash!} AND rotated_at IS NOT NULL AND revoked IS NOT NULL`) as unknown as Array<{id:string}>;
    if (!rows.length) return false;
  }
  return true;
}

/** Read external files before opening SQL transactions: no file lock is held while waiting on AAP/BRL locks. */
export async function reconcileAgentConnectionInvalidation(db: OwnerDatabase, store: AgentConnectionInvalidationStore) {
  const snapshot = await store.read();
  const result = await db.transaction(async (tx) => {
    const prior = await tx.execute(sql`SELECT metadata FROM oid_audit WHERE event_type='agent.connection.invalidation_reconciled' ORDER BY (metadata->>'sequence')::bigint DESC,created_at DESC LIMIT 1`) as unknown as Array<{metadata: {journalId?: string; sequence?: number}}>;
    if (prior[0] && (prior[0].metadata.journalId !== snapshot.journalId || (prior[0].metadata.sequence ?? -1) > snapshot.sequence)) fail();
    let fencedConnections = 0;
    for (const event of snapshot.events) {
      // AICODE-NOTE: Helper consumptions belong to their own OAuth tables. Never
      // reconcile them as native refresh failures or revoke a solver connection.
      if (event.kind === 'diagnostic_refresh_consume' || event.kind === 'diagnostic_code_consume') continue;
      const agents = await tx.execute(sql`SELECT id,access_generation FROM oid_agent WHERE id=${event.agentId} AND owner_id=${event.ownerId} FOR NO KEY UPDATE`) as unknown as Array<{id:string; access_generation:number}>;
      if (!agents.length) continue;
      if (event.kind === 'agent_revoke') {
        if (agents[0]!.access_generation >= event.generationFloor!) continue;
        await tx.execute(sql`UPDATE oid_agent SET access_generation=${event.generationFloor!},access_revision=access_revision+1,access_revoked_at=COALESCE(access_revoked_at,now()) WHERE id=${event.agentId}`);
        await tx.execute(sql`UPDATE oid_agent_access_grant SET revoked_at=COALESCE(revoked_at,now()),revocation_reason=COALESCE(revocation_reason,'owner_global_revoke') WHERE agent_id=${event.agentId} AND owner_id=${event.ownerId} AND access_generation<${event.generationFloor!}`);
        await tx.execute(sql`UPDATE oid_oauth_refresh_token SET revoked=COALESCE(revoked,now()),rotation_replay_response=NULL,rotation_replay_expires_at=NULL WHERE reference_id IN (SELECT id::text FROM oid_agent_access_grant WHERE agent_id=${event.agentId} AND owner_id=${event.ownerId} AND access_generation<${event.generationFloor!})`);
        await tx.execute(sql`UPDATE oid_oauth_access_token SET revoked=COALESCE(revoked,now()) WHERE reference_id IN (SELECT id::text FROM oid_agent_access_grant WHERE agent_id=${event.agentId} AND owner_id=${event.ownerId} AND access_generation<${event.generationFloor!})`);
        await tx.execute(sql`INSERT INTO oid_agent_cancellation_outbox(event_id,owner_id,agent_id,access_generation,operation_id,event_type,status,payload_json,created_at)
          VALUES (${event.eventId},${event.ownerId},${event.agentId},${event.generationFloor!},${`reconcile_${event.eventId.replaceAll('-','')}`},'agent.access.revoked','pending','{"scope":"all","reason":"owner_global_revoke"}'::jsonb,now()) ON CONFLICT DO NOTHING`);
      } else {
        if (event.kind === 'refresh_consume') {
          const consumed = await tx.execute(sql`SELECT id FROM oid_oauth_refresh_token WHERE token=${event.consumedRefreshHash!} AND reference_id=${event.connectionId!} AND rotated_at IS NOT NULL AND revoked IS NOT NULL`) as unknown as Array<{id:string}>;
          if (consumed.length) continue;
        }
        const fenced = await tx.execute(sql`UPDATE oid_agent_access_grant SET revoked_at=COALESCE(revoked_at,now()),revocation_reason=COALESCE(revocation_reason,'owner_connection_revoke') WHERE id=${event.connectionId!} AND owner_id=${event.ownerId} AND agent_id=${event.agentId} RETURNING id`) as unknown as Array<{id:string}>;
        fencedConnections += fenced.length;
        await tx.execute(sql`UPDATE oid_oauth_refresh_token SET revoked=COALESCE(revoked,now()),rotation_replay_response=NULL,rotation_replay_expires_at=NULL WHERE reference_id=${event.connectionId!}`);
        await tx.execute(sql`UPDATE oid_oauth_access_token SET revoked=COALESCE(revoked,now()) WHERE reference_id=${event.connectionId!}`);
      }
    }
    await tx.execute(sql`INSERT INTO oid_audit(id,event_type,operation_id,metadata) VALUES (${randomUUID()},'agent.connection.invalidation_reconciled',${`invalidation_${randomUUID().replaceAll('-','')}`},${JSON.stringify({journalId:snapshot.journalId,sequence:snapshot.sequence,headSha256:snapshot.headSha256})}::jsonb)`);
    return { ...snapshot, fencedConnections };
  });
  const after = await store.read();
  if (after.sequence !== snapshot.sequence || after.headSha256 !== snapshot.headSha256) fail();
  return { journalId: result.journalId, sequence: result.sequence, headSha256: result.headSha256, fencedConnections: result.fencedConnections };
}
