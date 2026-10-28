/** Internal local ranked handoff. It has no participant write API or public leaderboard projection. */
import {randomUUID} from 'node:crypto';
import {sql} from 'drizzle-orm';
import type {OwnerDatabase} from './db.js';
import {HttpError} from './http-error.js';
import {canonicalTaskJson,sha256CanonicalTaskJson} from './task-release.js';
import {compareExactRankedFractions,type RankedOutcomeAggregate} from './task-ranked-aggregate.js';
type Tx=Parameters<Parameters<OwnerDatabase['transaction']>[0]>[0];
type Row=Record<string,unknown>;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function fail(code:string):never{throw new HttpError(409,code,'Ranked completion proof is unavailable or inconsistent');}
function object(value:unknown):Row|null{if(typeof value==='string'){try{return object(JSON.parse(value));}catch{return null;}}return value!==null&&typeof value==='object'&&!Array.isArray(value)?value as Row:null;}
async function rows<T>(tx:Tx,statement:ReturnType<typeof sql>):Promise<T[]>{return await tx.execute(statement) as unknown as T[];}
function targetIds(input:{runId:string;ownerId:string;agentId:string}){if(![input.runId,input.ownerId,input.agentId].every(id=>UUID.test(id)))fail('RANKED_TARGET_INVALID');}
export type RankedVersionSnapshot={snapshotHash:string;snapshot:Row;createdAt:string};
async function readSnapshot(tx:Tx,target:{runId:string;ownerId:string;agentId:string}):Promise<RankedVersionSnapshot|null>{
  const found=await rows<{owner_id:string;agent_id:string;snapshot_hash:string;snapshot_json:unknown;created_at:Date|string}>(tx,
    sql`SELECT owner_id,agent_id,snapshot_hash,snapshot_json,created_at FROM oid_ranked_run_version_snapshot WHERE run_id=${target.runId}`);
  if(found.length===0)return null;const row=found[0]!,snapshot=object(row.snapshot_json);
  if(found.length!==1||!snapshot||row.owner_id!==target.ownerId||row.agent_id!==target.agentId||snapshot.runId!==target.runId||
    snapshot.ownerId!==target.ownerId||snapshot.agentId!==target.agentId||snapshot.schemaVersion!=='ranked-agent-version-snapshot/v1'||
    sha256CanonicalTaskJson(snapshot)!==row.snapshot_hash)fail('RANKED_VERSION_SNAPSHOT_CONFLICT');
  const createdAt=new Date(row.created_at).toISOString();return{snapshotHash:row.snapshot_hash,snapshot,createdAt};
}
/** Must run in the original ranked admission transaction; start only verifies this snapshot and never backfills. */
export async function captureRankedVersionSnapshot(tx:Tx,target:{runId:string;ownerId:string;agentId:string},at:string):Promise<RankedVersionSnapshot>{
  targetIds(target);if(!Number.isFinite(Date.parse(at)))fail('RANKED_START_TIME_INVALID');
  const found=await rows<{mode:string;status:string;name:string;declared_version:string|null;revision:number}>(tx,
    sql`SELECT r.mode,r.status,a.name,a.declared_version,a.revision FROM oid_benchmark_run r JOIN oid_agent a ON a.id=r.agent_id AND a.owner_id=r.owner_id
      WHERE r.id=${target.runId} AND r.owner_id=${target.ownerId} AND r.agent_id=${target.agentId} FOR NO KEY UPDATE OF a`);
  if(found.length!==1||found[0]!.mode!=='ranked')fail('RANKED_RUN_REQUIRED');
  const existing=await readSnapshot(tx,target);if(existing)return existing;
  const row=found[0]!;if(row.status!=='queued')fail('RANKED_VERSION_SNAPSHOT_MISSING');
  const snapshot={schemaVersion:'ranked-agent-version-snapshot/v1',runId:target.runId,ownerId:target.ownerId,agentId:target.agentId,
    profileRevision:row.revision,name:row.name,declaredVersion:row.declared_version};
  const snapshotHash=sha256CanonicalTaskJson(snapshot);
  await tx.execute(sql`INSERT INTO oid_ranked_run_version_snapshot(run_id,owner_id,agent_id,snapshot_hash,snapshot_json,created_at)
    VALUES(${target.runId},${target.ownerId},${target.agentId},${snapshotHash},${canonicalTaskJson(snapshot)}::jsonb,${at})`);
  return{snapshotHash,snapshot,createdAt:at};
}
/** Called only by the evidence-verifying finalizer inside its terminal transaction. Replay verifies, it never republishes. */
export async function publishRankedHandoff(tx:Tx,input:{runId:string;ownerId:string;agentId:string;aggregate:RankedOutcomeAggregate;
  completionEventHash:string;finishedAt:string;replayed:boolean}):Promise<{handoffHash:string;aggregateHash:string}>{
  targetIds(input);const a=input.aggregate;const {aggregateHash,...aggregateBody}=a;
  if(sha256CanonicalTaskJson(aggregateBody)!==aggregateHash||a.taskProofs.length!==12)fail('RANKED_AGGREGATE_INVALID');
  const runRows=await rows<{mode:string;status:string;manifest_hash:string;benchmark_version:string;release_identity:string;benchmark_hash:string;policy_hash:string;started_at:Date|string;finished_at:Date|string}>(tx,
    sql`SELECT mode,status,manifest_hash,benchmark_version,release_identity,benchmark_hash,policy_hash,started_at,finished_at FROM oid_benchmark_run WHERE id=${input.runId}
      AND owner_id=${input.ownerId} AND agent_id=${input.agentId} FOR UPDATE`);
  const run=runRows[0];if(runRows.length!==1||!run||run.mode!=='ranked'||run.status!=='completed'||run.manifest_hash!==a.manifestHash||
    run.benchmark_version!==a.benchmarkVersion||run.release_identity!==a.releaseIdentity||run.benchmark_hash!==a.benchmarkHash||run.policy_hash!==a.policyHash||new Date(run.finished_at).getTime()!==Date.parse(input.finishedAt))fail('RANKED_TERMINAL_BINDING_MISMATCH');
  await tx.execute(sql`SELECT id FROM oid_agent WHERE id=${input.agentId} AND owner_id=${input.ownerId} FOR NO KEY UPDATE`);
  const snapshot=await readSnapshot(tx,input);if(!snapshot)fail('RANKED_VERSION_SNAPSHOT_MISSING');
  if(Date.parse(snapshot.createdAt)>new Date(run.started_at).getTime()||Date.parse(snapshot.createdAt)>Date.parse(input.finishedAt))fail('RANKED_VERSION_SNAPSHOT_CONFLICT');
  const events=await rows<{payload_hash:string;payload_json:unknown;source:string}>(tx,
    sql`SELECT payload_hash,payload_json,source FROM oid_run_event WHERE run_id=${input.runId} AND event_type='run.completed'`);
  const event=events[0],payload=event&&object(event.payload_json);
  if(events.length!==1||!event||!payload||event.source!=='coordinator'||event.payload_hash!==input.completionEventHash||
    sha256CanonicalTaskJson(payload)!==event.payload_hash||payload.runId!==input.runId||payload.mode!=='ranked'||!Array.isArray(payload.tasks)||payload.tasks.length!==12||
    payload.tasks.some((task:unknown,index:number)=>{const p=object(task),proof=a.taskProofs[index]!;return !p||p.taskIndex!==index||p.taskId!==proof.taskId||p.inputHash!==proof.inputHash||p.resultHash!==proof.resultHash||p.fenceEvidenceHash!==proof.fenceEvidenceHash;}))fail('RANKED_COMPLETION_EVENT_MISMATCH');
  const body={schemaVersion:'ranked-run-handoff/v1',runId:input.runId,ownerId:input.ownerId,agentId:input.agentId,releaseIdentity:a.releaseIdentity,
    benchmarkVersion:a.benchmarkVersion,benchmarkHash:a.benchmarkHash,policyHash:a.policyHash,manifestHash:a.manifestHash,
    versionSnapshotHash:snapshot.snapshotHash,aggregateHash,completionEventHash:input.completionEventHash,finishedAt:input.finishedAt,
    taskProofs:a.taskProofs.map(({result,...proof})=>proof)};
  const handoffHash=sha256CanonicalTaskJson(body);
  const eligibilityEvents=await rows<{payload_hash:string;payload_json:unknown;source:string}>(tx,
    sql`SELECT payload_hash,payload_json,source FROM oid_run_event WHERE run_id=${input.runId} AND event_type='run.ranked_eligible'`);
  const previous=await rows<{handoff_hash:string;handoff_json:unknown;aggregate_hash:string}>(tx,
    sql`SELECT handoff_hash,handoff_json,aggregate_hash FROM oid_ranked_run_handoff WHERE run_id=${input.runId}`);
  if(previous.length){const p=previous[0]!;if(previous.length!==1||p.handoff_hash!==handoffHash||p.aggregate_hash!==aggregateHash||
      canonicalTaskJson(object(p.handoff_json))!==canonicalTaskJson(body))fail('RANKED_HANDOFF_REPLAY_CONFLICT');
    const retained=await rows<{aggregate_hash:string;aggregate_json:unknown;version_snapshot_hash:string}>(tx,
      sql`SELECT aggregate_hash,aggregate_json,version_snapshot_hash FROM oid_ranked_verified_result WHERE run_id=${input.runId}`);
    if(retained.length!==1||retained[0]!.aggregate_hash!==aggregateHash||retained[0]!.version_snapshot_hash!==snapshot.snapshotHash||
      canonicalTaskJson(object(retained[0]!.aggregate_json))!==canonicalTaskJson(a))fail('RANKED_RESULT_REPLAY_CONFLICT');
    if(eligibilityEvents.length!==1||eligibilityEvents[0]!.source!=='coordinator'||eligibilityEvents[0]!.payload_hash!==handoffHash||
      canonicalTaskJson(object(eligibilityEvents[0]!.payload_json))!==canonicalTaskJson(body))fail('RANKED_ELIGIBILITY_REPLAY_CONFLICT');
    const markers=await rows<{owner_id:string}>(tx,sql`SELECT owner_id FROM oid_agent_first_public_action WHERE agent_id=${input.agentId}`);
    if(markers.length!==1||markers[0]!.owner_id!==input.ownerId)fail('RANKED_PUBLIC_MARKER_REPLAY_CONFLICT');
    const best=await rows<{aggregate_hash:string;aggregate_json:unknown}>(tx,sql`SELECT r.aggregate_hash,r.aggregate_json FROM oid_ranked_best_result b
      JOIN oid_ranked_verified_result r ON r.run_id=b.run_id WHERE b.benchmark_version=${a.benchmarkVersion} AND b.agent_id=${input.agentId}`);
    const bestAggregate=best[0]&&object(best[0].aggregate_json);
    if(best.length!==1||!bestAggregate||bestAggregate.aggregateHash!==best[0]!.aggregate_hash)fail('RANKED_BEST_REPLAY_CONFLICT');
    const {aggregateHash:bestHash,...bestBody}=bestAggregate;
    if(sha256CanonicalTaskJson(bestBody)!==bestHash||bestAggregate.manifestHash!==a.manifestHash||
      compareExactRankedFractions(bestAggregate.overall as RankedOutcomeAggregate['overall'],a.overall)<0)fail('RANKED_BEST_REPLAY_CONFLICT');
    return{handoffHash,aggregateHash};
  }
  if(input.replayed)fail('RANKED_HANDOFF_REPLAY_MISSING');
  if(eligibilityEvents.length!==0)fail('RANKED_ELIGIBILITY_CONFLICT');
  await tx.execute(sql`INSERT INTO oid_ranked_run_handoff(run_id,owner_id,agent_id,benchmark_version,manifest_hash,version_snapshot_hash,
    aggregate_hash,completion_event_hash,handoff_hash,handoff_json,created_at) VALUES(${input.runId},${input.ownerId},${input.agentId},${a.benchmarkVersion},
    ${a.manifestHash},${snapshot.snapshotHash},${aggregateHash},${input.completionEventHash},${handoffHash},${canonicalTaskJson(body)}::jsonb,${input.finishedAt})`);
  await tx.execute(sql`INSERT INTO oid_ranked_verified_result(run_id,owner_id,agent_id,benchmark_version,aggregate_hash,aggregate_json,
    version_snapshot_hash,version_snapshot_json,created_at) VALUES(${input.runId},${input.ownerId},${input.agentId},${a.benchmarkVersion},
    ${aggregateHash},${canonicalTaskJson(a)}::jsonb,${snapshot.snapshotHash},${canonicalTaskJson(snapshot.snapshot)}::jsonb,${input.finishedAt})`);
  await tx.execute(sql`INSERT INTO oid_agent_first_public_action(agent_id,owner_id,source_kind,source_id,source_hash,occurred_at)
    VALUES(${input.agentId},${input.ownerId},'ranked_run',${input.runId},${handoffHash},${input.finishedAt}) ON CONFLICT(agent_id) DO NOTHING`);
  const bestRows=await rows<{run_id:string;aggregate_hash:string;aggregate_json:unknown}>(tx,sql`SELECT b.run_id,r.aggregate_hash,r.aggregate_json FROM oid_ranked_best_result b
    JOIN oid_ranked_verified_result r ON r.run_id=b.run_id WHERE b.benchmark_version=${a.benchmarkVersion} AND b.agent_id=${input.agentId} FOR UPDATE OF b`);
  if(bestRows.length>1)fail('RANKED_BEST_CONFLICT');
  const prior=bestRows[0]&&object(bestRows[0].aggregate_json);
  if(prior){const {aggregateHash:priorHash,...priorBody}=prior;
    if(priorHash!==bestRows[0]!.aggregate_hash||sha256CanonicalTaskJson(priorBody)!==priorHash)fail('RANKED_BEST_CONFLICT');}
  if(prior&&prior.manifestHash!==a.manifestHash)fail('RANKED_BENCHMARK_IDENTITY_CONFLICT');
  if(!prior||compareExactRankedFractions(a.overall,prior.overall as RankedOutcomeAggregate['overall'])>0){
    await tx.execute(sql`INSERT INTO oid_ranked_best_result(benchmark_version,agent_id,run_id,updated_at) VALUES(${a.benchmarkVersion},${input.agentId},${input.runId},${input.finishedAt})
      ON CONFLICT(benchmark_version,agent_id) DO UPDATE SET run_id=EXCLUDED.run_id,updated_at=EXCLUDED.updated_at`);
  }
  const sequence=await rows<{next:string|number}>(tx,sql`SELECT COALESCE(MAX(sequence),0)+1 AS next FROM oid_run_event WHERE run_id=${input.runId}`);
  await tx.execute(sql`INSERT INTO oid_run_event(id,run_id,sequence,source,event_type,payload_hash,payload_json,created_at) VALUES(${randomUUID()},${input.runId},
    ${sequence[0]!.next},'coordinator','run.ranked_eligible',${handoffHash},${canonicalTaskJson(body)}::jsonb,${input.finishedAt})`);
  return{handoffHash,aggregateHash};
}