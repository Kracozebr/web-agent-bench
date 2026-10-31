import { sql } from 'drizzle-orm';
import { randomUUID } from 'node:crypto';
import type { OwnerDatabase } from './db.js';
import { HttpError } from './http-error.js';
import { canonicalTaskJson,sha256CanonicalTaskJson } from './task-release.js';
import { recordTaskActionReceipt } from './task-action-service.js';
import type { SafeTaskActionEvidence,TaskActionEvidenceSink } from './bef-task-executor.js';

type Transaction=Parameters<Parameters<OwnerDatabase['transaction']>[0]>[0];
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HASH=/^[0-9a-f]{64}$/i;
const PATH=/^(?![A-Za-z]:)(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/-]{1,512}$/;
interface FenceTarget {runId:string;agentId:string;taskIndex:number;preparationId:string;generationId:string|null;fenceEvidenceHash:string}
type PendingAction={id:string;run_id:string;task_index:number;task_id:string;owner_id:string;agent_id:string;access_generation:number;
 grant_owner_id:string;grant_agent_id:string;grant_access_generation:number;environment_id:string;action_sequence:string;
 operation_id:string;payload_hash:string;action_kind:SafeTaskActionEvidence['actionKind'];command_json:unknown;
 outbox_status:'pending'|'delivered';transaction_hash:string|null};
function object(value:unknown):Record<string,unknown>|null {
 if(typeof value==='string'){try{value=JSON.parse(value)}catch{return null}}
 return value!==null&&typeof value==='object'&&!Array.isArray(value)?value as Record<string,unknown>:null;
}
function resultRows<T>(value:unknown):T[]{if(!Array.isArray(value))throw Error('post_fence_query_unavailable');return value as T[];}
function failure():never{throw new HttpError(409,'POST_FENCE_ACTION_PROOF_UNAVAILABLE','The original task fence/action scope cannot be verified');}

/**
 * AICODE-NOTE: Cancellation must finish admitted receipts after its exact generation fence.
 * Pending outbox means no dispatch claim committed; delivered ambiguity remains unknown.
 * This function never sends a participant command, attributes platform failure or refunds funds.
 */
export async function finalizeFencedTaskActionReceipts(
 deps:{db:OwnerDatabase;evidenceSink?:TaskActionEvidenceSink},input:FenceTarget,
):Promise<{rejected:number;unknown:number}> {
 if(!UUID.test(input.runId)||!UUID.test(input.agentId)||!UUID.test(input.preparationId)||
  (input.generationId!==null&&!UUID.test(input.generationId))||!Number.isSafeInteger(input.taskIndex)||input.taskIndex<0||input.taskIndex>11||
  !HASH.test(input.fenceEvidenceHash))failure();
 return deps.db.transaction(async(tx)=>{
  const ownerRows=resultRows<{owner_id:string}>(await tx.execute(sql`SELECT owner_id FROM oid_benchmark_run
   WHERE id=${input.runId} AND agent_id=${input.agentId}`));
  const owner=ownerRows[0]?.owner_id;if(!owner)failure();
  const owners=resultRows<{id:string}>(await tx.execute(sql`SELECT id FROM oid_owner WHERE id=${owner} FOR UPDATE`));
  if(owners.length!==1)failure();
  const agents=resultRows<{id:string}>(await tx.execute(sql`SELECT id FROM oid_agent
   WHERE id=${input.agentId} AND owner_id=${owner} FOR NO KEY UPDATE`));
  if(agents.length!==1)failure();
  const runs=resultRows<{id:string;status:string;access_generation:number;task_ids:string[];manifest_hash:string;release_identity:string}>(
   await tx.execute(sql`SELECT id,status,access_generation,task_ids,manifest_hash,release_identity FROM oid_benchmark_run
    WHERE id=${input.runId} AND owner_id=${owner} AND agent_id=${input.agentId} FOR UPDATE`));
  const run=runs[0];if(!run||!['cancellation_requested','cancelled','unknown'].includes(run.status))failure();
  const tasks=resultRows<{task_id:string}>(await tx.execute(sql`SELECT task_id FROM oid_run_task
   WHERE run_id=${input.runId} AND task_index=${input.taskIndex} FOR UPDATE`));
  const task=tasks[0];if(!task||task.task_id!==run.task_ids[input.taskIndex])failure();
  const proofs=resultRows<{lease_id:string;environment_id:string;task_id:string;release_identity:string;manifest_hash:string;
   environment_manifest_sha256:string;application_source_hash:string;state:string;fence_evidence:unknown;
   observation_status:string;generation_id:string|null}>(await tx.execute(sql`SELECT i.lease_id,i.environment_id,i.task_id,
    i.release_identity,i.manifest_hash,i.environment_manifest_sha256,i.application_source_hash,l.state,l.fence_evidence,
    o.status AS observation_status,o.generation_id FROM oid_task_preparation_intent i
    JOIN oid_task_environment_lease l ON l.preparation_id=i.preparation_id AND l.lease_id=i.lease_id
    JOIN LATERAL (SELECT status,generation_id FROM oid_task_preparation_observation
      WHERE preparation_id=i.preparation_id ORDER BY revision DESC LIMIT 1) o ON true
    WHERE i.preparation_id=${input.preparationId} AND i.run_id=${input.runId} AND i.task_index=${input.taskIndex}`));
  const proof=proofs[0];const fence=object(proof?.fence_evidence),reference=object(fence?.evidence);
  if(proofs.length!==1||!proof||proof.state!=='fenced'||proof.observation_status!=='fenced'||proof.generation_id!==input.generationId||
   proof.task_id!==task.task_id||proof.release_identity!==run.release_identity||proof.manifest_hash!==run.manifest_hash||
   !fence||fence.confirmed!==true||fence.preparationId!==input.preparationId||fence.leaseId!==proof.lease_id||
   fence.environmentId!==proof.environment_id||fence.generationId!==input.generationId||!reference||
   reference.sha256!==input.fenceEvidenceHash||typeof reference.path!=='string'||!PATH.test(reference.path)||
   reference.boundary!=='actual_tool_http_x402_local_evm_application_store')failure();
  const actions=resultRows<PendingAction>(await tx.execute(sql`SELECT a.id,a.run_id,a.task_index,a.task_id,a.owner_id,a.agent_id,
   a.access_generation,a.environment_id,a.action_sequence::text AS action_sequence,a.operation_id,a.payload_hash,a.action_kind,a.command_json,
   g.owner_id AS grant_owner_id,g.agent_id AS grant_agent_id,g.access_generation AS grant_access_generation,
   o.status AS outbox_status,r.transaction_hash FROM oid_run_task_action a
   JOIN oid_agent_access_grant g ON g.id=a.grant_id
   JOIN oid_run_task_action_outbox o ON o.action_id=a.id JOIN oid_run_task_action_receipt r ON r.action_id=a.id
   WHERE a.run_id=${input.runId} AND a.task_index=${input.taskIndex} AND r.receipt_status='pending'
   ORDER BY a.action_sequence FOR UPDATE OF a,o,r`));
  if(actions.length&&!deps.evidenceSink)throw new HttpError(503,'POST_FENCE_ACTION_EVIDENCE_UNAVAILABLE','Action evidence storage is required before cancellation can finalize');
  // Reuse the one authoritative receipt writer inside these same locks/transaction, not a nested commit.
  const sameTransactionDb={execute:(query:Parameters<Transaction['execute']>[0])=>tx.execute(query),
   transaction:async(callback:(transaction:Transaction)=>Promise<unknown>)=>callback(tx)} as unknown as OwnerDatabase;
  let rejected=0,unknown=0;
  for(const action of actions){
   const command=object(action.command_json);
   if(!command||command.kind!==action.action_kind||action.owner_id!==owner||action.agent_id!==input.agentId||action.access_generation!==run.access_generation||
    action.grant_owner_id!==owner||action.grant_agent_id!==input.agentId||action.grant_access_generation!==action.access_generation||
    action.task_id!==task.task_id||action.environment_id!==proof.environment_id||
    sha256CanonicalTaskJson({runId:action.run_id,taskIndex:action.task_index,command})!==action.payload_hash)failure();
   const neverDispatched=action.outbox_status==='pending';
   const status=neverDispatched?'rejected_before_execution' as const:'unknown' as const;
   const evidence:SafeTaskActionEvidence&{fenceConfirmation:Record<string,unknown>}={
    schema:'bef-task-action-observation-v1',actionId:action.id,runId:input.runId,taskIndex:input.taskIndex,
    actionSequence:action.action_sequence,ownerOperationId:action.operation_id,actionKind:action.action_kind,
    commandSha256:action.payload_hash,environmentId:proof.environment_id,generationId:input.generationId,
    manifestSha256:proof.environment_manifest_sha256,applicationSourceSha256:proof.application_source_hash,
    idempotencyKey:`task-action-${action.id}`,status,
    reasonCode:neverDispatched?'cancelled_before_dispatch_after_exact_fence':'cancelled_after_dispatch_effect_unknown',
    ...(action.transaction_hash?{transactionHash:action.transaction_hash}:{}),
    fenceConfirmation:{preparationId:input.preparationId,leaseId:proof.lease_id,generationId:input.generationId,
     evidencePath:reference.path,evidenceHash:input.fenceEvidenceHash,priorOutboxStatus:action.outbox_status},
   };
   const artifact=await deps.evidenceSink!.write(evidence);
   if(!PATH.test(artifact.path)||!HASH.test(artifact.sha256))failure();
   // Retain pending outbox as the original no-dispatch marker; terminal receipt prevents any replay.
   await recordTaskActionReceipt({db:sameTransactionDb},{actionId:action.id,status,evidenceHash:artifact.sha256,evidencePath:artifact.path,
    ...(action.transaction_hash?{transactionHash:action.transaction_hash}:{})});
   const payload={actionId:action.id,taskIndex:input.taskIndex,receiptStatus:status,priorOutboxStatus:action.outbox_status,
    preparationId:input.preparationId,generationId:input.generationId,fenceEvidenceHash:input.fenceEvidenceHash,evidenceHash:artifact.sha256};
   await tx.execute(sql`INSERT INTO oid_run_event(id,run_id,sequence,source,event_type,payload_hash,payload_json)
    SELECT ${randomUUID()},${input.runId},COALESCE(MAX(sequence),0)+1,'executor',
    ${neverDispatched?'task.action.fenced_before_dispatch':'task.action.fenced_effect_unknown'},
    ${sha256CanonicalTaskJson(payload)},${canonicalTaskJson(payload)}::jsonb FROM oid_run_event WHERE run_id=${input.runId}`);
   if(neverDispatched)rejected++;else unknown++;
  }
  return {rejected,unknown};
 });
}
