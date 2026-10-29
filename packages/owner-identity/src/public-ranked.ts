import type { FastifyInstance, FastifyRequest } from 'fastify';
import { sql } from 'drizzle-orm';
import type { OwnerIdentityConfig } from './config.js';
import type { OwnerDatabase } from './db.js';
import { HttpError } from './http-error.js';
import { isQualificationReadPeerAllowed } from './beta-profile.js';
import { sha256CanonicalTaskJson } from './task-release.js';

type JsonObject = Record<string, unknown>;
type PublicScore = { numerator: string; denominator: string };
export interface PublicRankedAgent {
  id: string;
  name: string;
  description: string;
  clientMetadata: { clientName: string | null; modelName: string | null };
  declaredVersion: string | null;
  benchmarkVersion: string;
  overall: PublicScore;
  tiers: Record<'simple' | 'medium' | 'hard' | 'ultra', PublicScore>;
}

interface PublicAgentRow {
  agent_id: string; name: string; description: string; client_metadata: unknown; declared_version: string | null;
  marker_owner_id: string; marker_source_kind: string; marker_source_id: string; marker_source_hash: string;
  marker_run_id: string | null; marker_handoff_hash: string | null; marker_handoff_json: unknown;
  marker_aggregate_hash: string | null; marker_completion_event_hash: string | null;
  marker_benchmark_version: string; marker_manifest_hash: string; marker_benchmark_hash: string; marker_policy_hash: string;
  marker_version_snapshot_hash: string; marker_version_snapshot_json: unknown; marker_run_mode: string; marker_run_status: string;
  marker_result_aggregate_hash: string; marker_result_aggregate_json: unknown;
  owner_id: string; best_run_id: string; mode: string; status: string; run_benchmark_version: string;
  manifest_hash: string; benchmark_hash: string; policy_hash: string;
  best_handoff_hash: string; best_handoff_json: unknown; completion_event_hash: string;
  aggregate_hash: string; aggregate_json: unknown; version_snapshot_hash: string; version_snapshot_json: unknown;
}

function object(value: unknown): JsonObject | null {
  if (typeof value === 'string') {
    try { return object(JSON.parse(value) as unknown); } catch { return null; }
  }
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as JsonObject : null;
}

function fraction(value: unknown): PublicScore | null {
  const candidate = object(value);
  if (!candidate || Object.keys(candidate).sort().join(',') !== 'denominator,numerator' ||
      typeof candidate.numerator !== 'string' || typeof candidate.denominator !== 'string' ||
      !/^(?:0|[1-9][0-9]{0,77})$/.test(candidate.numerator) || !/^[1-9][0-9]{0,77}$/.test(candidate.denominator)) return null;
  const numerator = BigInt(candidate.numerator), denominator = BigInt(candidate.denominator);
  if (numerator > denominator * 100n) return null;
  return { numerator: candidate.numerator, denominator: candidate.denominator };
}

function checkHandoff(row: PublicAgentRow, marker: boolean): boolean {
  const handoff = object(marker ? row.marker_handoff_json : row.best_handoff_json);
  const hash = marker ? row.marker_handoff_hash : row.best_handoff_hash;
  if (!handoff || !hash || sha256CanonicalTaskJson(handoff) !== hash ||
      handoff.schemaVersion !== 'ranked-run-handoff/v1' ||
      handoff.runId !== (marker ? row.marker_source_id : row.best_run_id) ||
      handoff.ownerId !== row.owner_id || handoff.agentId !== row.agent_id) return false;
  if (marker) return row.marker_run_id === row.marker_source_id && row.marker_source_kind === 'ranked_run' &&
    row.marker_owner_id === row.owner_id && row.marker_source_hash === hash && row.marker_run_mode === 'ranked' &&
    row.marker_run_status === 'completed' && handoff.benchmarkVersion === row.marker_benchmark_version &&
    handoff.manifestHash === row.marker_manifest_hash && handoff.benchmarkHash === row.marker_benchmark_hash &&
    handoff.policyHash === row.marker_policy_hash && handoff.aggregateHash === row.marker_aggregate_hash &&
    handoff.aggregateHash === row.marker_result_aggregate_hash && handoff.completionEventHash === row.marker_completion_event_hash &&
    handoff.versionSnapshotHash === row.marker_version_snapshot_hash;
  if (handoff.benchmarkVersion !== row.run_benchmark_version || handoff.manifestHash !== row.manifest_hash ||
      handoff.benchmarkHash !== row.benchmark_hash || handoff.policyHash !== row.policy_hash) return false;
  return handoff.aggregateHash === row.aggregate_hash && handoff.versionSnapshotHash === row.version_snapshot_hash &&
    handoff.completionEventHash === row.completion_event_hash;
}

function project(row: PublicAgentRow, expectedVersion: string): PublicRankedAgent | null {
  if (row.status !== 'completed' || row.mode !== 'ranked' || row.run_benchmark_version !== expectedVersion ||
      !checkHandoff(row, true) || !checkHandoff(row, false)) return null;
  const aggregate = object(row.aggregate_json);
  if (!aggregate || aggregate.schemaVersion !== 'ranked-outcome-aggregate/v1' ||
      aggregate.benchmarkVersion !== expectedVersion || aggregate.manifestHash !== row.manifest_hash ||
      aggregate.benchmarkHash !== row.benchmark_hash || aggregate.policyHash !== row.policy_hash ||
      aggregate.aggregateHash !== row.aggregate_hash || !Array.isArray(aggregate.taskProofs) || aggregate.taskProofs.length !== 12) return null;
  const { aggregateHash, ...aggregateBody } = aggregate;
  if (typeof aggregateHash !== 'string' || sha256CanonicalTaskJson(aggregateBody) !== aggregateHash) return null;
  const snapshot = object(row.version_snapshot_json);
  if (!snapshot || sha256CanonicalTaskJson(snapshot) !== row.version_snapshot_hash ||
      snapshot.runId !== row.best_run_id || snapshot.ownerId !== row.owner_id || snapshot.agentId !== row.agent_id) return null;
  const markerSnapshot = object(row.marker_version_snapshot_json);
  const markerAggregate = object(row.marker_result_aggregate_json);
  if (!markerSnapshot || sha256CanonicalTaskJson(markerSnapshot) !== row.marker_version_snapshot_hash ||
      markerSnapshot.runId !== row.marker_source_id || markerSnapshot.ownerId !== row.owner_id || markerSnapshot.agentId !== row.agent_id ||
      !markerAggregate || markerAggregate.aggregateHash !== row.marker_result_aggregate_hash) return null;
  const { aggregateHash: markerAggregateHash, ...markerAggregateBody } = markerAggregate;
  if (typeof markerAggregateHash !== 'string' || sha256CanonicalTaskJson(markerAggregateBody) !== markerAggregateHash ||
      markerAggregate.benchmarkVersion !== row.marker_benchmark_version || markerAggregate.manifestHash !== row.marker_manifest_hash) return null;
  if (snapshot.declaredVersion !== null && typeof snapshot.declaredVersion !== 'string') return null;
  const eventProofs = aggregate.taskProofs as unknown[];
  if (eventProofs.some((item) => {
    const proof = object(item);
    return !proof || typeof proof.resultHash !== 'string' || !/^[0-9a-f]{64}$/i.test(proof.resultHash) ||
      !proof.result || sha256CanonicalTaskJson(proof.result) !== proof.resultHash;
  })) return null;
  const overall = fraction(aggregate.overall);
  const rawTiers = object(aggregate.tiers);
  if (!overall || !rawTiers || Object.keys(rawTiers).sort().join(',') !== 'hard,medium,simple,ultra') return null;
  const simple = fraction(rawTiers.simple), medium = fraction(rawTiers.medium), hard = fraction(rawTiers.hard), ultra = fraction(rawTiers.ultra);
  if (!simple || !medium || !hard || !ultra) return null;
  const metadata = object(row.client_metadata);
  if (!metadata || Object.keys(metadata).some((key) => key !== 'clientName' && key !== 'modelName')) return null;
  const clientName = metadata.clientName === null || typeof metadata.clientName === 'string' ? metadata.clientName : undefined;
  const modelName = metadata.modelName === null || typeof metadata.modelName === 'string' ? metadata.modelName : undefined;
  if (clientName === undefined || modelName === undefined) return null;
  return {
    id: row.agent_id, name: row.name, description: row.description,
    clientMetadata: { clientName, modelName }, declaredVersion: snapshot.declaredVersion,
    benchmarkVersion: expectedVersion, overall,
    tiers: { simple, medium, hard, ultra }
  };
}

async function publicRows(db: OwnerDatabase, expectedVersion: string, agentId?: string): Promise<PublicAgentRow[]> {
  return await db.execute(sql`
    SELECT a.id::text AS agent_id,a.name,a.description,a.client_metadata,a.declared_version,
      marker.owner_id::text AS marker_owner_id,marker.source_kind AS marker_source_kind,
      marker.source_id AS marker_source_id,marker.source_hash AS marker_source_hash,
      marker_handoff.run_id::text AS marker_run_id,marker_handoff.handoff_hash AS marker_handoff_hash,
      marker_handoff.handoff_json AS marker_handoff_json,marker_handoff.aggregate_hash AS marker_aggregate_hash,
      marker_handoff.completion_event_hash AS marker_completion_event_hash,
      marker_handoff.benchmark_version AS marker_benchmark_version,marker_handoff.manifest_hash AS marker_manifest_hash,
      marker_handoff.version_snapshot_hash AS marker_version_snapshot_hash,
      marker_result.version_snapshot_json AS marker_version_snapshot_json,
      marker_handoff.completion_event_hash AS marker_completion_event_hash,
      marker_run.benchmark_hash AS marker_benchmark_hash,marker_run.policy_hash AS marker_policy_hash,
      marker_run.mode AS marker_run_mode,marker_run.status AS marker_run_status,
      marker_result.aggregate_hash AS marker_result_aggregate_hash,marker_result.aggregate_json AS marker_result_aggregate_json,
      run.owner_id::text AS owner_id,run.id::text AS best_run_id,run.mode,run.status,
      run.benchmark_version AS run_benchmark_version,run.manifest_hash,run.benchmark_hash,run.policy_hash,
      handoff.handoff_hash AS best_handoff_hash,handoff.handoff_json AS best_handoff_json,
      handoff.completion_event_hash,
      result.aggregate_hash,result.aggregate_json,result.version_snapshot_hash,result.version_snapshot_json
    FROM oid_agent_first_public_action marker
    JOIN oid_agent a ON a.id=marker.agent_id AND a.owner_id=marker.owner_id
    JOIN oid_ranked_run_handoff marker_handoff ON marker.source_kind='ranked_run'
      AND marker_handoff.run_id::text=marker.source_id AND marker_handoff.owner_id=marker.owner_id AND marker_handoff.agent_id=marker.agent_id
    JOIN oid_ranked_verified_result marker_result ON marker_result.run_id=marker_handoff.run_id
      AND marker_result.owner_id=marker_handoff.owner_id AND marker_result.agent_id=marker_handoff.agent_id
      AND marker_result.benchmark_version=marker_handoff.benchmark_version
    JOIN oid_benchmark_run marker_run ON marker_run.id=marker_handoff.run_id
      AND marker_run.owner_id=marker_handoff.owner_id AND marker_run.agent_id=marker_handoff.agent_id
    JOIN oid_ranked_best_result best ON best.agent_id=a.id AND best.benchmark_version=${expectedVersion}
    JOIN oid_ranked_verified_result result ON result.run_id=best.run_id AND result.agent_id=best.agent_id AND result.benchmark_version=best.benchmark_version
    JOIN oid_ranked_run_handoff handoff ON handoff.run_id=result.run_id AND handoff.owner_id=result.owner_id AND handoff.agent_id=result.agent_id
    JOIN oid_benchmark_run run ON run.id=result.run_id AND run.owner_id=result.owner_id AND run.agent_id=result.agent_id
    WHERE run.benchmark_version=${expectedVersion} ${agentId ? sql`AND a.id=${agentId}` : sql``}
    ORDER BY lower(a.name),a.id LIMIT 100
  `) as unknown as PublicAgentRow[];
}

async function completionEventMatches(db: OwnerDatabase, runId: string, expectedHash: string): Promise<boolean> {
  const events = await db.execute(sql`SELECT source,payload_hash,payload_json FROM oid_run_event
    WHERE run_id=${runId} AND event_type='run.completed' LIMIT 2`) as unknown as Array<{ source: string; payload_hash: string; payload_json: unknown }>;
  const event = events[0], payload = event && object(event.payload_json);
  return events.length === 1 && Boolean(event && payload) && event!.source === 'coordinator' &&
    event!.payload_hash === expectedHash && sha256CanonicalTaskJson(payload) === event!.payload_hash &&
    payload!.runId === runId && payload!.mode === 'ranked' && Array.isArray(payload!.tasks) && payload!.tasks.length === 12;
}

export function registerPublicRankedRoutes(app: FastifyInstance, deps: { db: OwnerDatabase; config: OwnerIdentityConfig }): void {
  const rowsForRequest = async (request: FastifyRequest, agentId?: string) => {
    const manifest = deps.config.betaManifest;
    if (!manifest) throw new HttpError(404, 'PUBLIC_RESULTS_UNAVAILABLE', 'Public benchmark results are unavailable');
    if (manifest.state === 'qualification' &&
        !isQualificationReadPeerAllowed(request.raw.socket.remoteAddress, manifest)) {
      throw new HttpError(403, 'QUALIFICATION_READ_NOT_ALLOWED', 'This network is not allowed to read qualification results');
    }
    const rows = await publicRows(deps.db, manifest.release.benchmarkVersion, agentId);
    const checked: PublicRankedAgent[] = [];
    for (const row of rows) {
      if (!row.marker_run_id || !row.marker_completion_event_hash ||
          !await completionEventMatches(deps.db, row.marker_run_id, row.marker_completion_event_hash) ||
          !await completionEventMatches(deps.db, row.best_run_id, row.completion_event_hash)) continue;
      const projected = project(row, manifest.release.benchmarkVersion);
      if (projected) checked.push(projected);
    }
    return checked;
  };
  const cacheHeader = () => deps.config.betaManifest?.state === 'cohort_release'
    ? 'public, max-age=30, stale-while-revalidate=30' : 'no-store';
  app.get('/api/public/agents', async (request, reply) => {
    try {
      const agents = await rowsForRequest(request);
      return reply.header('Cache-Control', cacheHeader()).send({ agents });
    } catch (error) {
      if (error instanceof HttpError) return reply.code(error.status).header('Cache-Control', 'no-store')
        .send({ error: { code: error.code, message: error.message } });
      return reply.code(500).header('Cache-Control', 'no-store').send({ error: { code: 'INTERNAL_ERROR', message: 'The request could not be completed' } });
    }
  });
  app.get<{ Params: { agentId: string } }>('/api/public/agents/:agentId', async (request, reply) => {
    try {
      if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(request.params.agentId)) {
        return reply.code(404).header('Cache-Control', 'no-store').send({ error: { code: 'NOT_FOUND', message: 'The public result was not found' } });
      }
      const agents = await rowsForRequest(request, request.params.agentId);
      const agent = agents[0];
      if (!agent) return reply.code(404).header('Cache-Control', 'no-store').send({ error: { code: 'NOT_FOUND', message: 'The public result was not found' } });
      return reply.header('Cache-Control', cacheHeader()).send({ agent });
    } catch (error) {
      if (error instanceof HttpError) return reply.code(error.status).header('Cache-Control', 'no-store')
        .send({ error: { code: error.code, message: error.message } });
      return reply.code(500).header('Cache-Control', 'no-store').send({ error: { code: 'INTERNAL_ERROR', message: 'The request could not be completed' } });
    }
  });
}
