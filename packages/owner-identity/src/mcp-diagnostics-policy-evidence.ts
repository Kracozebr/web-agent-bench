import {createHash} from 'node:crypto';
import {sql} from 'drizzle-orm';
import type {OwnerDatabase} from './db.js';
import type {DiagnosticEvidence} from './mcp-diagnostics-contract.js';
import type {DiagnosticPrincipal} from './mcp-diagnostics-service.js';
import {reportFirst} from './report-db.js';
import {TaskActionCommandSchema} from './task-action-service.js';
import {canonicalTaskJson} from './task-release.js';

const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const OP=/^[A-Za-z0-9_-]{12,128}$/;
const HEX=/^[a-f0-9]{64}$/;
const digest=(value:unknown)=>createHash('sha256').update(canonicalTaskJson(value)).digest('hex');
const object=(value:unknown):Record<string,unknown>=>value!==null&&typeof value==='object'&&!Array.isArray(value)?value as Record<string,unknown>:{};
interface BoundRun {case_id:string;run_id:string;owner_id:string;agent_id:string;connection_id:string;mode:'training'|'ranked';access_generation:number;policy_revision:number;run_policy_revision:number;training:boolean;ranked:boolean;run_deadline:Date|string|null;database_now:Date|string}
interface PriorAction {id:string;run_id:string;task_index:number;owner_id:string;agent_id:string;command_json:unknown;payload_hash:string;task_id:string}
interface ClosedTask {task_index:number;task_id:string;accepted_action_sequence:string;action_cutoff_sequence:string|null;closure_id:string|null;closure_reason:string|null;closure_status:string;closure_row_id:string|null;closure_row_reason:string|null;closure_row_cutoff:string|null;closure_payload_hash:string|null;task_deadline_elapsed:boolean;run_deadline_elapsed:boolean;closure_after_task_deadline:boolean|null;closure_after_run_deadline:boolean|null}
export interface DiagnosticPolicyEvidenceInput {principal:DiagnosticPrincipal;caseId?:string;tool:string;errorCode:string;arguments:unknown}

// AICODE-NOTE: These are post-response read-only causal checks, not a second
// authorization path or an HTTP-status classifier. Raw arguments remain only
// in RAM. Missing, changed or contradictory state yields no positive attribution.
export async function deriveDiagnosticPolicyEvidence(deps:{db:OwnerDatabase},input:DiagnosticPolicyEvidenceInput):Promise<DiagnosticEvidence|undefined>{
 const {principal:p,caseId,tool,errorCode}=input,args=object(input.arguments);
 if(!caseId||![caseId,p.ownerId,p.agentId,p.connectionId].every(value=>typeof value==='string'&&UUID.test(value))||
  typeof args.runId!=='string'||!UUID.test(args.runId)||
  !['IDEMPOTENCY_CONFLICT','TASK_CLOSED','TASK_DEADLINE','MODE_NOT_ALLOWED'].includes(errorCode)||
  !['runs.task_action','runs.finish_task','runs.current_task','runs.task_action_status'].includes(tool))return;
 if(errorCode!=='MODE_NOT_ALLOWED'&&tool!=='runs.task_action')return;
 return deps.db.transaction(async tx=>{
  const run=reportFirst<BoundRun>(await tx.execute(sql`SELECT c.id AS case_id,r.id AS run_id,c.owner_id,c.agent_id,c.connection_id,r.mode,r.access_generation,
    policy.revision AS policy_revision,r.agent_policy_revision AS run_policy_revision,policy.training,policy.ranked,r.overall_deadline AS run_deadline,clock_timestamp() AS database_now
   FROM oid_mcp_diagnostic_case c JOIN oid_benchmark_run r ON r.intent_id=c.intent_id AND r.owner_id=c.owner_id AND r.agent_id=c.agent_id
   JOIN oid_agent a ON a.id=c.agent_id AND a.owner_id=c.owner_id JOIN oid_owner o ON o.id=c.owner_id
   JOIN oid_agent_policy policy ON policy.agent_id=a.id
   JOIN oid_agent_access_grant g ON g.id=c.connection_id AND g.owner_id=c.owner_id AND g.agent_id=c.agent_id
   WHERE c.id=${caseId}::uuid AND c.owner_id=${p.ownerId}::uuid AND c.agent_id=${p.agentId}::uuid AND c.connection_id=${p.connectionId}::uuid
    AND r.id=${args.runId}::uuid AND a.access_generation=r.access_generation AND g.access_generation=a.access_generation
    AND a.access_revoked_at IS NULL AND g.revoked_at IS NULL AND g.role='agent' AND g.expires_at>clock_timestamp() AND o.admission_status='admitted'`));
  if(!run)return;
  const enabled=run.mode==='training'?run.training:run.ranked;
  if(errorCode==='MODE_NOT_ALLOWED'){
   if(enabled||!Number.isSafeInteger(run.policy_revision)||run.policy_revision<1)return;
   // Hash only independently selected retained policy/generation/run identities.
   return {independentlyVerified:true,policyMatched:true,evidenceIds:[run.case_id,run.run_id,digest({ownerId:run.owner_id,agentId:run.agent_id,connectionId:run.connection_id,runId:run.run_id,mode:run.mode,accessGeneration:run.access_generation,policyRevision:run.policy_revision,training:run.training,ranked:run.ranked})]};
  }
  if(!enabled||!Number.isInteger(args.taskIndex)||Number(args.taskIndex)<0||Number(args.taskIndex)>11||typeof args.operationId!=='string'||!OP.test(args.operationId))return;
  const fence=reportFirst<{fenced:boolean}>(await tx.execute(sql`SELECT EXISTS(SELECT 1 FROM oid_run_mode_cancellation_outbox
   WHERE owner_id=${p.ownerId}::uuid AND agent_id=${p.agentId}::uuid AND mode=${run.mode} AND policy_revision>${run.run_policy_revision}) AS fenced`));
  if(fence?.fenced)return;
  if(errorCode==='IDEMPOTENCY_CONFLICT'){
   const command=TaskActionCommandSchema.safeParse(args.command);if(!command.success)return;
   const prior=reportFirst<PriorAction>(await tx.execute(sql`SELECT id,run_id,task_index,owner_id,agent_id,command_json,payload_hash,task_id
    FROM oid_run_task_action WHERE run_id=${run.run_id}::uuid AND operation_id=${args.operationId}
     AND owner_id=${p.ownerId}::uuid AND agent_id=${p.agentId}::uuid`));
   if(!prior||!UUID.test(prior.id)||!HEX.test(prior.payload_hash))return;
   const original=TaskActionCommandSchema.safeParse(prior.command_json);if(!original.success)return;
   const originalHash=digest({runId:prior.run_id,taskIndex:prior.task_index,command:original.data});
   const requestedHash=digest({runId:run.run_id,taskIndex:args.taskIndex,command:command.data});
   if(originalHash!==prior.payload_hash||prior.task_index===args.taskIndex&&prior.payload_hash===requestedHash)return;
   return {independentlyVerified:true,policyMatched:true,evidenceIds:[run.case_id,run.run_id,prior.id,prior.payload_hash]};
  }
  const priorIdentity=reportFirst(await tx.execute(sql`SELECT id FROM oid_run_task_action WHERE run_id=${run.run_id}::uuid AND operation_id=${args.operationId}
   UNION ALL SELECT id FROM oid_run_task_closure WHERE run_id=${run.run_id}::uuid AND operation_id=${args.operationId}`));
  if(priorIdentity)return;
  const competing=reportFirst<{recovering:boolean;unresolved:boolean}>(await tx.execute(sql`SELECT
   EXISTS(SELECT 1 FROM oid_run_platform_recovery WHERE run_id=${run.run_id}::uuid AND status IN ('recovering','unknown','exhausted')) AS recovering,
   EXISTS(SELECT 1 FROM oid_run_task_action a JOIN oid_run_task_action_receipt r ON r.action_id=a.id WHERE a.run_id=${run.run_id}::uuid AND a.task_index=${args.taskIndex} AND r.receipt_status='unknown') AS unresolved`));
  if(competing?.recovering||competing?.unresolved)return;
  const task=reportFirst<ClosedTask>(await tx.execute(sql`SELECT t.task_index,t.task_id,t.accepted_action_sequence::text,t.action_cutoff_sequence::text,t.closure_id,t.closure_reason,t.closure_status,
    c.id AS closure_row_id,c.reason AS closure_row_reason,c.action_cutoff_sequence::text AS closure_row_cutoff,c.payload_hash AS closure_payload_hash,
    t.deadline_at IS NOT NULL AND clock_timestamp()>=t.deadline_at AS task_deadline_elapsed,
    r.overall_deadline IS NOT NULL AND clock_timestamp()>=r.overall_deadline AS run_deadline_elapsed,
    c.requested_at>=t.deadline_at AS closure_after_task_deadline,c.requested_at>=r.overall_deadline AS closure_after_run_deadline
   FROM oid_run_task t JOIN oid_benchmark_run r ON r.id=t.run_id LEFT JOIN oid_run_task_closure c ON c.id=t.closure_id AND c.run_id=t.run_id AND c.task_index=t.task_index AND c.owner_id=${p.ownerId}::uuid AND c.agent_id=${p.agentId}::uuid
   WHERE t.run_id=${run.run_id}::uuid AND t.task_index=${args.taskIndex}`));
  if(!task||!task.closure_id||!UUID.test(task.closure_id)||task.closure_row_id!==task.closure_id||
   !['closing','closed','unknown'].includes(task.closure_status)||task.closure_reason!==task.closure_row_reason||
   task.action_cutoff_sequence===null||task.action_cutoff_sequence!==task.closure_row_cutoff||
   !/^\d+$/.test(task.accepted_action_sequence)||!/^\d+$/.test(task.action_cutoff_sequence)||BigInt(task.action_cutoff_sequence)>BigInt(task.accepted_action_sequence)||
   !task.closure_payload_hash||!HEX.test(task.closure_payload_hash))return;
  if(errorCode==='TASK_DEADLINE'){
   if(!['task_deadline','run_deadline'].includes(task.closure_row_reason??''))return;
   if(task.closure_row_reason==='run_deadline'?(task.run_deadline_elapsed!==true||task.closure_after_run_deadline!==true):(task.task_deadline_elapsed!==true||task.closure_after_task_deadline!==true))return;
  }
  return {independentlyVerified:true,policyMatched:true,evidenceIds:[run.case_id,run.run_id,task.closure_id,task.closure_payload_hash]};
 },{accessMode:'read only',isolationLevel:'repeatable read'});
}
