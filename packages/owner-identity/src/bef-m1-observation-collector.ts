/**
 * Run-bound M1 payment and delivery evidence collection. This returns only an
 * unsealed candidate; it never dispatches actions, grades, or changes BEF state.
 *
 * AICODE-NOTE: EIP-3009 calldata contains signed authorization material. The
 * collector hashes transaction input and complete RPC replies in memory, but
 * persists only public transaction metadata and decoded participant Transfer
 * projections. Unknown or contradictory payment/delivery evidence stays unknown.
 */
import { createHash } from 'node:crypto';
import { lstat, open, realpath } from 'node:fs/promises';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import { sql } from 'drizzle-orm';
import { keccak256 } from 'viem';
import { readOnlyToolResponseMatches } from './bef-task-executor.js';
import type { OwnerDatabase } from './db.js';
import { TaskActionCommandSchema } from './task-action-service.js';
import type { TaskActionCommand } from './task-action-service.js';
import type { PersistedTaskObservations, TaskEvidenceBinding } from './task-evaluator.js';
import {
  canonicalTaskJson, sha256CanonicalTaskJson, type EvidenceReference, type TaskCase, type TaskReleaseQuerySource,
} from './task-release.js';
import type { TaskObservationBundleCandidate } from './task-observation-store.js';
import { projectM1PacketObservations, validateM1CapturePacket, type M1CaptureAction, type M1CapturePacket } from './task-m1-capture-packet.js';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HASH = /^[0-9a-f]{64}$/i;
const TX = /^0x[0-9a-f]{64}$/i;
const ADDRESS = /^0x[0-9a-f]{40}$/i;
const HEX_QUANTITY = /^0x(?:0|[1-9a-f][0-9a-f]*)$/i;
const HEX_WORD = /^0x[0-9a-f]{64}$/i;
const TRANSFER_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
const BALANCE_OF = '0x70a08231';
const ALLOWANCE = '0xdd62ed3e';
const EVIDENCE_BOUNDARY = 'actual_tool_http_x402_local_evm_application_store' as const;
const ROOT = 'artifacts/runs/owner-identity-bef-task-coordinator/';
const ACTION_ROOT = `${ROOT}action/`;
const PREPARATION_ROOT = `${ROOT}preparation/`;
const OBSERVATION_ROOT = `${ROOT}observation/`;
const MAX_ACTIONS = 256;
const MAX_ROWS = 2048;
const MAX_BLOCKS = 256;
const MAX_EVIDENCE_BYTES = 256 * 1024;
// Retrieved content is base64 encoded inside the action evidence JSON. Keep
// bounded headroom for the executor's 1 MiB content ceiling plus JSON.
const MAX_ACTION_EVIDENCE_BYTES = 2 * 1024 * 1024;
const MAX_MANIFEST_BYTES = 256 * 1024;
const MAX_RESOURCE_BYTES = 2 * 1024 * 1024;
const MAX_RPC_BYTES = 4 * 1024 * 1024;
const MAX_PACKET_BYTES = 8 * 1024 * 1024;
const SECRET_KEYS = new Set(['privatekey','privkey','seedphrase','mnemonic','secret','clientsecret','bearer','bearertoken','accesstoken',
  'refreshtoken','providertoken','paymenttoken','token','apitoken','apikey','authorization','walletmaterial','walletsecret',
  'signature','signedpayload','paymentpayload','paymentauthorization','paymentauth','paymentproof','xpayment','xpaymentsignature',
  'xpaymentpayload','xpaymentauthorization','x402authorization','x402signature','x402payload','x402proof','password','dsn','databaseurl']);
const SECRET_VALUE_FIELDS = new Set(['input','data','calldata','rawtransaction','rawtx','paymentpayload','authorization','signature','v','r','s']);

type Json = Record<string, unknown>;
type OwnerTx = Parameters<Parameters<OwnerDatabase['transaction']>[0]>[0];
type ReadQuery = (statement: string, parameters?: readonly unknown[]) => Promise<unknown>;
type Row = Record<string, unknown>;

export interface BefM1ReadOnlyPostgresPort {
  environmentId: string;
  withRepeatableRead<T>(callback: (query: ReadQuery) => Promise<T>): Promise<T>;
}
export interface BefM1ReadOnlyRpcPort { environmentId: string; request(method: string, params: readonly unknown[]): Promise<unknown> }
export interface BefM1EvidenceSink { write(packet: M1CapturePacket): Promise<EvidenceReference> }
export interface BefM1ObservationCollectorDependencies {
  db: OwnerDatabase;
  taskReleaseSource: TaskReleaseQuerySource;
  repositoryRoot: string;
  postgresByEnvironment: Readonly<Record<string, BefM1ReadOnlyPostgresPort>>;
  rpcByEnvironment: Readonly<Record<string, BefM1ReadOnlyRpcPort>>;
  evidenceSink: BefM1EvidenceSink;
}

export type BefM1UnavailableCode =
  | 'invalid_target' | 'unsupported_task' | 'owner_cutoff_unavailable' | 'owner_cutoff_mismatch' | 'reconciliation_pending'
  | 'action_evidence_unavailable' | 'preparation_unavailable' | 'release_binding_mismatch' | 'source_not_configured'
  | 'observer_role_invalid' | 'observer_census_unavailable' | 'observer_census_changed' | 'rpc_identity_mismatch'
  | 'rpc_observation_unavailable' | 'rpc_interval_too_large' | 'rpc_mapping_incomplete' | 'baseline_mismatch'
  | 'state_effect_detected' | 'capture_evidence_unavailable';
export type BefM1CollectionResult =
  | { status: 'unavailable'; reasonCode: BefM1UnavailableCode }
  | { status: 'candidate'; candidate: TaskObservationBundleCandidate; evidence: EvidenceReference;
      classification: 'run_bound_observations_candidate_not_grade' };

class Unavailable extends Error {
  constructor(readonly reasonCode: BefM1UnavailableCode) { super(reasonCode); }
}
function unavailable(reasonCode: BefM1UnavailableCode): BefM1CollectionResult { return { status: 'unavailable', reasonCode }; }
function isRecord(value: unknown): value is Json { return Boolean(value && typeof value === 'object' && !Array.isArray(value)); }
function isRows(value: unknown): value is Row[] { return Array.isArray(value) && value.every(isRecord); }
function parseJson(value: unknown, code: BefM1UnavailableCode): unknown {
  if (typeof value !== 'string') return value;
  try { return JSON.parse(value) as unknown; } catch { throw new Unavailable(code); }
}
function safeRows(value: unknown, code: BefM1UnavailableCode): Row[] {
  if (isRows(value)) return value;
  if (isRecord(value) && isRows(value.rows)) return value.rows;
  throw new Unavailable(code);
}
async function ownerRows<T extends Row>(tx: OwnerTx, statement: ReturnType<typeof sql>): Promise<T[]> {
  return safeRows(await tx.execute(statement), 'owner_cutoff_unavailable') as T[];
}
function sequence(value: unknown): number | null {
  try { const n = BigInt(value as string | number | bigint); return n >= 0n && n <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(n) : null; }
  catch { return null; }
}
function normalizeHash(value: unknown): string | null { return typeof value === 'string' && TX.test(value) ? value.toLowerCase() : null; }
function normalizeAddress(value: unknown): string | null { return typeof value === 'string' && ADDRESS.test(value) ? value.toLowerCase() : null; }
function quantity(value: unknown): bigint | null {
  if (typeof value !== 'string' || !HEX_QUANTITY.test(value)) return null;
  try { return BigInt(value); } catch { return null; }
}
function decimal(value: unknown): bigint | null {
  if (typeof value !== 'string' && typeof value !== 'number' && typeof value !== 'bigint') return null;
  try { const n = BigInt(value); return n >= 0n ? n : null; } catch { return null; }
}
function asDate(value: unknown): string | null {
  const date = value instanceof Date ? value : typeof value === 'string' ? new Date(value) : null;
  return date && Number.isFinite(date.getTime()) ? date.toISOString() : null;
}
function hashJson(value: unknown): string { return sha256CanonicalTaskJson(value).toLowerCase(); }
function hashString(value: string): string { return createHash('sha256').update(value, 'utf8').digest('hex'); }
function hasSecret(value: unknown, seen = new Set<object>()): boolean {
  if (value === null || typeof value !== 'object') return false;
  if (seen.has(value)) return true;
  seen.add(value);
  const found = Array.isArray(value) ? value.some((item) => hasSecret(item, seen)) : Object.entries(value as Json).some(([key, child]) => {
    const normalized = key.toLowerCase().replace(/[^a-z]/g, '');
    return SECRET_KEYS.has(normalized) || SECRET_VALUE_FIELDS.has(normalized) || hasSecret(child, seen);
  });
  seen.delete(value); return found;
}
function evidenceRef(value: unknown): EvidenceReference | null {
  if (!isRecord(value) || Object.keys(value).sort().join(',') !== 'boundary,path,sha256' || value.boundary !== EVIDENCE_BOUNDARY ||
      typeof value.path !== 'string' || !HASH.test(String(value.sha256)) || value.path.includes('\\') || value.path.includes('\0') ||
      !/^(?![A-Za-z]:)(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/-]{1,512}$/.test(value.path)) return null;
  return { path: value.path, sha256: String(value.sha256).toLowerCase(), boundary: EVIDENCE_BOUNDARY };
}
async function readEvidence(rootPath: string, ref: EvidenceReference, prefix: string, code: BefM1UnavailableCode,
  max = MAX_EVIDENCE_BYTES): Promise<Buffer> {
  if (!ref.path.startsWith(prefix) || ref.path.includes('\\') || ref.path.includes('\0') || isAbsolute(ref.path) ||
      ref.path.split('/').some((part) => !part || part === '.' || part === '..')) throw new Unavailable(code);
  const root = await realpath(rootPath).catch(() => { throw new Unavailable(code); });
  const candidate = resolve(root, ...ref.path.split('/'));
  const actual = await realpath(candidate).catch(() => { throw new Unavailable(code); });
  const rel = relative(root, actual);
  if (!rel || rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel) || !rel.split(sep).join('/').startsWith(prefix)) throw new Unavailable(code);
  const handle = await open(actual, 'r').catch(() => { throw new Unavailable(code); });
  try {
    const before = await handle.stat({ bigint: true }); const linkBefore = await lstat(actual, { bigint: true });
    if (!before.isFile() || !linkBefore.isFile() || before.dev !== linkBefore.dev || before.ino !== linkBefore.ino || before.size < 1n || before.size > BigInt(max)) {
      throw new Unavailable(code);
    }
    const buffer = Buffer.alloc(max + 1); let offset = 0;
    while (offset < buffer.length) { const result = await handle.read(buffer, offset, buffer.length - offset, null); if (!result.bytesRead) break; offset += result.bytesRead; }
    const after = await handle.stat({ bigint: true }); const linkAfter = await lstat(actual, { bigint: true });
    if (offset < 1 || offset > max || BigInt(offset) !== before.size || before.dev !== after.dev || before.ino !== after.ino ||
        before.size !== after.size || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs ||
        linkAfter.dev !== after.dev || linkAfter.ino !== after.ino) throw new Unavailable(code);
    const bytes = buffer.subarray(0, offset);
    if (createHash('sha256').update(bytes).digest('hex') !== ref.sha256) throw new Unavailable(code);
    return bytes;
  } catch (error) { if (error instanceof Unavailable) throw error; throw new Unavailable(code); }
  finally { await handle.close().catch(() => undefined); }
}
function parseSafe(bytes: Buffer, code: BefM1UnavailableCode): Json {
  let parsed: unknown; try { parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as unknown; } catch { throw new Unavailable(code); }
  if (!isRecord(parsed) || hasSecret(parsed)) throw new Unavailable(code);
  return parsed;
}

type PrepRow = {
  preparation_id:string; claim_id:string; lease_id:string; environment_id:string; release_identity:string; manifest_hash:string; task_id:string;
  case_id:string; case_hash:string; initial_state_sha256:string; execution_identity_hash:string; environment_manifest_sha256:string;
  application_source_hash:string; created_at:Date|string; lease_state:string; observation_status:string; generation_id:string|null;
  participant_id:string|null; payer_address:string|null; baseline_state_sha256:string|null; fixture_evidence:unknown; baseline_evidence:unknown;
};
type ActionRow = {
  id:string; run_id:string; task_index:number; owner_id:string; agent_id:string; task_id:string; environment_id:string;
  action_sequence:string|number; operation_id:string; payload_hash:string; action_kind:string; command_json:unknown;
  receipt_revision:number; receipt_status:string; evidence_hash:string|null; evidence_path:string|null; transaction_hash:string|null;
  history_revision:number|null; history_status:string|null; history_evidence_hash:string|null; history_evidence_path:string|null; history_transaction_hash:string|null;
};
type RunRow = { owner_id:string; agent_id:string; mode:string; task_ids:unknown; release_identity:string; manifest_hash:string; task_id:string;
  closure_status:string; closure_id:string|null; closure_operation_id:string|null; closure_payload_hash:string|null; closure_reason:string|null;
  action_cutoff_sequence:string|number|null; reconciled_action_sequence:string|number };
type Census = { generation:Json; operations:Json[]; selectedExecutions:Json[]; selectedEvents:Json[]; payments:Json[]; deliveries:Json[];
  costs:Json[]; denials:Json[]; x402Observations:Json[]; rpcObservations:Json[]; evidenceArtifacts:Json[] };
type M1LoadedAction = { row:ActionRow; sequence:number; command:Extract<TaskActionCommand,{kind:'inspect_catalog'|'inspect_offer'|'pay'|'retrieve'}>;
  evidence:Json; ref:EvidenceReference; response:Json|null; protocol:Json|null };
type RpcCheckpoint = { blockNumber:string; blockHash:string; parentHash:string; balances:Array<{account:string;assetId:string;amountUnits:string}>;
  allowances:Array<{owner:string;tokenAssetId:string;spender:string;amountUnits:string}>; participantTransactionCount:string };
type IdentityAsset = ManifestData['assets'][number];
type RpcBlock = { number:string; hash:string; parentHash:string; transactionCount:number };

const MANIFEST_REL = 'infrastructure/benchmark-environment/manifest.json';
async function readPinnedFile(rootPath:string, relativePath:string, max:number, code:BefM1UnavailableCode):Promise<Buffer> {
  const root=await realpath(rootPath).catch(()=>{throw new Unavailable(code)});
  const candidate=resolve(root,relativePath);
  const actual=await realpath(candidate).catch(()=>{throw new Unavailable(code)});
  const rel=relative(root,actual);
  if(!rel||rel==='..'||rel.startsWith(`..${sep}`)||isAbsolute(rel))throw new Unavailable(code);
  const handle=await open(actual,'r').catch(()=>{throw new Unavailable(code)});
  try {
    const before=await handle.stat({bigint:true});const linkBefore=await lstat(actual,{bigint:true});
    if(!before.isFile()||!linkBefore.isFile()||before.dev!==linkBefore.dev||before.ino!==linkBefore.ino||before.size<1n||before.size>BigInt(max))throw new Unavailable(code);
    const bytes=Buffer.alloc(max+1);let offset=0;
    while(offset<bytes.length){const read=await handle.read(bytes,offset,bytes.length-offset,null);if(!read.bytesRead)break;offset+=read.bytesRead;}
    const after=await handle.stat({bigint:true});const linkAfter=await lstat(actual,{bigint:true});
    if(offset<1||offset>max||BigInt(offset)!==before.size||before.dev!==after.dev||before.ino!==after.ino||before.size!==after.size||
       before.mtimeNs!==after.mtimeNs||before.ctimeNs!==after.ctimeNs||linkAfter.dev!==after.dev||linkAfter.ino!==after.ino)throw new Unavailable(code);
    return bytes.subarray(0,offset);
  }catch(error){if(error instanceof Unavailable)throw error;throw new Unavailable(code)}finally{await handle.close().catch(()=>undefined)}
}
function publicPins(prep:PrepRow,runId:string,taskIndex:number):string {
  const createdAt=asDate(prep.created_at);if(!createdAt)throw new Unavailable('preparation_unavailable');
  return hashJson({preparationId:prep.preparation_id,runId,taskIndex,claimId:prep.claim_id,leaseId:prep.lease_id,environmentId:prep.environment_id,
    releaseIdentity:prep.release_identity,manifestHash:prep.manifest_hash,taskId:prep.task_id,caseId:prep.case_id,caseHash:prep.case_hash,
    initialStateSha256:prep.initial_state_sha256,executionIdentityHash:prep.execution_identity_hash,
    environmentManifestSha256:prep.environment_manifest_sha256,applicationSourceHash:prep.application_source_hash,createdAt});
}
function addressRef(value:string,participant:string):string {
  const resolved=value==='participant'?participant:normalizeAddress(value);if(!resolved)throw new Unavailable('release_binding_mismatch');return resolved;
}
function stateProjection(state:Extract<TaskCase,{taskId:'M1'}>['initialState']|RpcCheckpoint):Json {
  const balances=state.balances.map((item)=>({...item})).sort((a,b)=>`${a.account.toLowerCase()}|${a.assetId}`.localeCompare(`${b.account.toLowerCase()}|${b.assetId}`));
  const allowances=state.allowances.map((item)=>({...item})).sort((a,b)=>`${a.owner.toLowerCase()}|${a.tokenAssetId}|${a.spender.toLowerCase()}`.localeCompare(`${b.owner.toLowerCase()}|${b.tokenAssetId}|${b.spender.toLowerCase()}`));
  return {balances,allowances,deliveredComponentIds:'deliveredComponentIds' in state?[...state.deliveredComponentIds].sort():[],
    fulfilledObligationIds:'fulfilledObligationIds' in state?[...state.fulfilledObligationIds].sort():[]};
}
function validateSession(row:Row,privileges:Row[]):Json {
  const required=['bef_environment','bef_generation','bef_operation','bef_selected_execution','bef_selected_execution_event','bef_payment','bef_delivery',
    'bef_transaction_cost','bef_denial','bef_x402_observation','bef_rpc_observation','bef_evidence_artifact'];
  const byName=new Map(privileges.map((item)=>[String(item.table_name),item]));
  if(row.current_user!=='bef_observer'||row.session_user!=='bef_observer'||row.transaction_read_only!=='on'||row.transaction_isolation!=='repeatable read'||
    row.rolsuper!==false||row.rolbypassrls!==false||row.schema_create!==false||typeof row.database_name!=='string'||required.some((name)=>{
      const item=byName.get(name);return !item||item.can_select!==true||item.can_insert!==false||item.can_update!==false||item.can_delete!==false||item.can_truncate!==false;
    }))throw new Unavailable('observer_role_invalid');
  return {currentUser:'bef_observer',sessionUser:'bef_observer',databaseName:row.database_name,transactionReadOnly:'on',superuser:false,bypassRls:false};
}
function valueSafe(v:unknown):unknown { if(v instanceof Date)return v.toISOString();if(typeof v==='bigint')return v.toString();if(Array.isArray(v))return v.map(valueSafe);if(isRecord(v))return Object.fromEntries(Object.entries(v).map(([k,x])=>[k,valueSafe(x)]));return v; }
function project(row:Row,keys:readonly string[]):Json { const result:Json={};for(const key of keys)result[key]=valueSafe(row[key]);return result; }

async function captureCensus(port:BefM1ReadOnlyPostgresPort,envId:string,generationId:string):Promise<{session:Json;census:Census}> {
  try{return await port.withRepeatableRead(async(query)=>{
    const sessionRows=safeRows(await query(`SELECT current_user AS current_user,session_user AS session_user,current_database() AS database_name,
      current_setting('transaction_read_only') AS transaction_read_only,current_setting('transaction_isolation') AS transaction_isolation,
      (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) AS rolsuper,(SELECT rolbypassrls FROM pg_roles WHERE rolname=current_user) AS rolbypassrls,
      has_schema_privilege(current_user,'public','CREATE') AS schema_create`),'observer_census_unavailable');
    const privs=safeRows(await query(`SELECT table_name,has_table_privilege(current_user,'public.'||table_name,'SELECT') AS can_select,
      has_table_privilege(current_user,'public.'||table_name,'INSERT') AS can_insert,has_table_privilege(current_user,'public.'||table_name,'UPDATE') AS can_update,
      has_table_privilege(current_user,'public.'||table_name,'DELETE') AS can_delete,has_table_privilege(current_user,'public.'||table_name,'TRUNCATE') AS can_truncate
      FROM unnest(ARRAY['bef_environment','bef_generation','bef_operation','bef_selected_execution','bef_selected_execution_event','bef_payment','bef_delivery',
      'bef_transaction_cost','bef_denial','bef_x402_observation','bef_rpc_observation','bef_evidence_artifact']) AS table_name`),'observer_census_unavailable');
    if(sessionRows.length!==1)throw new Unavailable('observer_role_invalid');const session=validateSession(sessionRows[0]!,privs);
    const gen=safeRows(await query(`SELECT g.generation_id::text,g.env_id,g.participant_id,g.payer_address,trim(g.manifest_sha256) manifest_sha256,g.status,g.resource_variant,
      g.fixture_transaction_hash,g.fixture_block_hash,g.fixture_token_delta_units::text,g.fixture_native_balance_wei::text,g.expires_at::text,g.fenced_at::text,
      e.chain_id::text,e.node_identity,trim(e.manifest_sha256) environment_manifest_sha256 FROM public.bef_generation g JOIN public.bef_environment e ON e.env_id=g.env_id
      WHERE g.env_id=$1 AND g.generation_id=$2::uuid`,[envId,generationId]),'observer_census_unavailable');
    if(gen.length!==1)throw new Unavailable('observer_census_unavailable');
    const ops=safeRows(await query(`SELECT o.operation_id::text,o.env_id,o.generation_id::text,o.participant_id,o.idempotency_key_sha256,trim(o.request_sha256) request_sha256,
      o.operation_kind,o.status,o.receipt_status,o.transaction_hash,trim(o.response_sha256) response_sha256,o.started_at::text,o.completed_at::text,
      o.selected_offer_id,o.selected_amount_units::text,o.selected_resource_id,trim(o.selected_resource_sha256) selected_resource_sha256,o.payment_response_mode
      FROM public.bef_operation o WHERE o.env_id=$1 AND o.generation_id=$2::uuid ORDER BY o.started_at,o.operation_id LIMIT ${MAX_ROWS+1}`,[envId,generationId]),'observer_census_unavailable');
    const opIds=ops.map((x)=>String(x.operation_id));
    const selected=safeRows(await query(`SELECT operation_id::text,env_id,generation_id::text,action_kind,transaction_hash,outcome FROM public.bef_selected_execution
      WHERE env_id=$1 AND generation_id=$2::uuid ORDER BY created_at,operation_id LIMIT ${MAX_ROWS+1}`,[envId,generationId]),'observer_census_unavailable');
    const events=safeRows(await query(`SELECT event_sequence::text,event_id::text,operation_id::text,env_id,generation_id::text,event_kind,transaction_hash,created_at::text
      FROM public.bef_selected_execution_event WHERE env_id=$1 AND generation_id=$2::uuid ORDER BY event_sequence LIMIT ${MAX_ROWS+1}`,[envId,generationId]),'observer_census_unavailable');
    const payments=safeRows(await query(`SELECT payment_id::text,operation_id::text,env_id,generation_id::text,payer_address,network,asset_address,amount_units::text,facilitator_address,
      transaction_hash,receipt_status,token_delta_units::text,observed_at::text,payer_balance_before::text,payer_balance_after::text,
      facilitator_balance_before::text,facilitator_balance_after::text FROM public.bef_payment WHERE env_id=$1 AND generation_id=$2::uuid ORDER BY observed_at,payment_id LIMIT ${MAX_ROWS+1}`,
      [envId,generationId]),'observer_census_unavailable');
    const deliveries=safeRows(await query(`SELECT d.delivery_id::text,d.operation_id::text,o.env_id,o.generation_id::text,d.resource_id,trim(d.content_sha256) content_sha256,
      d.content_bytes::text,d.delivered_at::text FROM public.bef_delivery d JOIN public.bef_operation o ON o.operation_id=d.operation_id
      WHERE o.env_id=$1 AND o.generation_id=$2::uuid ORDER BY d.delivered_at,d.delivery_id LIMIT ${MAX_ROWS+1}`,[envId,generationId]),'observer_census_unavailable');
    const costs=safeRows(await query(`SELECT c.operation_id::text,c.env_id,c.generation_id::text,c.transaction_hash,c.payer_address,c.payer_role,c.receipt_status,
      c.transaction_from,c.receipt_from,c.receipt_block_number::text,c.receipt_block_hash,c.gas_used::text,c.effective_gas_price_wei::text,c.gas_cost_wei::text,
      c.modeled_gas_fee_usdc_units::text,c.manifest_sha256,c.created_at::text FROM public.bef_transaction_cost c WHERE c.env_id=$1 AND c.generation_id=$2::uuid
      ORDER BY c.transaction_hash LIMIT ${MAX_ROWS+1}`,[envId,generationId]),'observer_census_unavailable');
    const denials=safeRows(await query(`SELECT denial_id::text,env_id,generation_id::text,operation_id::text,route,reason_code,request_sha256,protected_state_sha256,created_at::text
      FROM public.bef_denial WHERE generation_id=$1::uuid ORDER BY created_at,denial_id LIMIT ${MAX_ROWS+1}`,[generationId]),'observer_census_unavailable');
    const x402=safeRows(await query(`SELECT observation_id::text,env_id,generation_id::text,operation_id::text,variant_id,phase,request_sha256,
      safe_request->'paymentRequirements' AS payment_requirements,safe_request->'paymentPayload'->>'x402Version' AS x402_version,
      response_sha256,outcome,transaction_hash,observed_at::text FROM public.bef_x402_observation
      WHERE env_id=$1 AND generation_id=$2::uuid ORDER BY observed_at,observation_id LIMIT ${MAX_ROWS+1}`,[envId,generationId]),'observer_census_unavailable');
    const rpc=opIds.length?safeRows(await query(`SELECT observation_id::text,operation_id::text,boundary,method,params_sha256,result_sha256,forwarded,
      response_status,source_block_hash,created_at::text FROM public.bef_rpc_observation WHERE operation_id=ANY($1::uuid[]) ORDER BY created_at,observation_id LIMIT ${MAX_ROWS+1}`,
      [opIds]),'observer_census_unavailable'):[];
    const artifacts=safeRows(await query(`SELECT artifact_id::text,operation_id::text,generation_id::text,relative_path,sha256,boundary,content_type,created_at::text
      FROM public.bef_evidence_artifact WHERE generation_id=$1::uuid OR operation_id=ANY($2::uuid[]) ORDER BY created_at,artifact_id LIMIT ${MAX_ROWS+1}`,
      [generationId,opIds]),'observer_census_unavailable');
    if([ops,selected,events,payments,deliveries,costs,denials,x402,rpc,artifacts].some((list)=>list.length>MAX_ROWS))throw new Unavailable('observer_census_unavailable');
    const census:Census={generation:project(gen[0]!,['generation_id','env_id','participant_id','payer_address','manifest_sha256','status','resource_variant','fixture_transaction_hash',
        'fixture_block_hash','fixture_token_delta_units','fixture_native_balance_wei','expires_at','fenced_at','chain_id','node_identity','environment_manifest_sha256']),
      operations:ops.map((r)=>project(r,['operation_id','env_id','generation_id','participant_id','idempotency_key_sha256','request_sha256','operation_kind','status','receipt_status',
        'transaction_hash','response_sha256','started_at','completed_at','selected_offer_id','selected_amount_units','selected_resource_id','selected_resource_sha256','payment_response_mode'])),
      selectedExecutions:selected.map((r)=>project(r,['operation_id','env_id','generation_id','action_kind','transaction_hash','outcome'])),
      selectedEvents:events.map((r)=>project(r,['event_sequence','event_id','operation_id','env_id','generation_id','event_kind','transaction_hash','created_at'])),
      payments:payments.map((r)=>project(r,['payment_id','operation_id','env_id','generation_id','payer_address','network','asset_address','amount_units','facilitator_address','transaction_hash',
        'receipt_status','token_delta_units','observed_at','payer_balance_before','payer_balance_after','facilitator_balance_before','facilitator_balance_after'])),
      deliveries:deliveries.map((r)=>project(r,['delivery_id','operation_id','env_id','generation_id','resource_id','content_sha256','content_bytes','delivered_at'])),
      costs:costs.map((r)=>project(r,['operation_id','env_id','generation_id','transaction_hash','payer_address','payer_role','receipt_status','transaction_from','receipt_from','receipt_block_number',
        'receipt_block_hash','gas_used','effective_gas_price_wei','gas_cost_wei','modeled_gas_fee_usdc_units','manifest_sha256','created_at'])),
      denials:denials.map((r)=>project(r,['denial_id','env_id','generation_id','operation_id','route','reason_code','request_sha256','protected_state_sha256','created_at'])),
      x402Observations:x402.map((r)=>{const req=parseJson(r.payment_requirements,'observer_census_unavailable');if(!isRecord(req)||hasSecret(req))throw new Unavailable('observer_census_unavailable');
        const extra=isRecord(req.extra)?req.extra:{};const safeReq={scheme:req.scheme,network:req.network,asset:req.asset,amount:req.amount,payTo:req.payTo,
          maxTimeoutSeconds:String(req.maxTimeoutSeconds),extra:{assetTransferMethod:extra.assetTransferMethod,paymentFlow:extra.paymentFlow,name:extra.name,version:extra.version}};
        const row=project(r,['observation_id','env_id','generation_id','operation_id','variant_id','phase','request_sha256','x402_version','response_sha256','outcome','transaction_hash','observed_at']);
        return {...row,requirements:safeReq};}),
      rpcObservations:rpc.map((r)=>project(r,['observation_id','operation_id','boundary','method','params_sha256','result_sha256','forwarded','response_status','source_block_hash','created_at'])),
      evidenceArtifacts:artifacts.map((r)=>project(r,['artifact_id','operation_id','generation_id','relative_path','sha256','boundary','content_type','created_at']))};
    if(hasSecret(census)||Buffer.byteLength(canonicalTaskJson(census),'utf8')>MAX_PACKET_BYTES)throw new Unavailable('observer_census_unavailable');
    return {session,census};
  });}catch(error){if(error instanceof Unavailable)throw error;throw new Unavailable('observer_census_unavailable')}
}

type PreparedEvidence={fixture:EvidenceReference;baseline:EvidenceReference;blockNumber:bigint;blockHash:string};
async function loadPreparedEvidence(root:string,prep:PrepRow,runId:string,index:number,taskCase:Extract<TaskCase,{taskId:'M1'}>):Promise<PreparedEvidence>{
  const fixture=evidenceRef(prep.fixture_evidence),baseline=evidenceRef(prep.baseline_evidence);
  if(!fixture||!baseline||fixture.path===baseline.path||fixture.sha256===baseline.sha256)throw new Unavailable('preparation_unavailable');
  const [fixtureBytes,baselineBytes]=await Promise.all([readEvidence(root,fixture,PREPARATION_ROOT,'preparation_unavailable'),readEvidence(root,baseline,PREPARATION_ROOT,'preparation_unavailable')]);
  const f=parseSafe(fixtureBytes,'preparation_unavailable'),b=parseSafe(baselineBytes,'preparation_unavailable'),pins=publicPins(prep,runId,index);
  for(const [doc,kind] of [[f,'fixture'],[b,'baseline']] as const){
    if(doc.schemaVersion!=='owner-bef-task-preparation-evidence/v1'||doc.kind!==kind||doc.preparationId!==prep.preparation_id||
      doc.environmentId!==prep.environment_id||doc.publicPinsSha256!==pins||!isRecord(doc.evidence))throw new Unavailable('preparation_unavailable');
  }
  const fixtureEvidence=f.evidence as Json;const health=fixtureEvidence.environmentHealth;const status=fixtureEvidence.publicStatus;
  if(!isRecord(health)||health.boundary!=='private_fork'||health.environmentId!==prep.environment_id||
    String(health.environmentManifestSha256).toLowerCase()!==prep.environment_manifest_sha256.toLowerCase()||
    String(health.applicationSourceSha256).toLowerCase()!==prep.application_source_hash.toLowerCase()||
    !isRecord(status)||status.schemaVersion!=='bef-public-preparation-status/v1'||status.envId!==prep.environment_id||
    status.preparationId!==prep.preparation_id||status.status!=='ready'||status.generationId!==prep.generation_id)
    throw new Unavailable('preparation_unavailable');
  const evidence=b.evidence as Json;const state=evidence.state;
  if(!isRecord(state)||state.sameBlock!==true||!isRecord(state.projection)||!Array.isArray(state.reads)||
    evidence.stateSha256!==taskCase.initialState.stateSha256.toLowerCase()||evidence.expectedStateSha256!==taskCase.initialState.stateSha256.toLowerCase()||
    prep.baseline_state_sha256?.toLowerCase()!==taskCase.initialState.stateSha256.toLowerCase()||
    canonicalTaskJson(state.projection)!==canonicalTaskJson(stateProjection(taskCase.initialState))||
    hashJson(state.projection)!==taskCase.initialState.stateSha256.toLowerCase())throw new Unavailable('baseline_mismatch');
  const blockNumber=quantity(state.blockNumber),blockHash=normalizeHash(state.blockHash);
  if(blockNumber===null||!blockHash)throw new Unavailable('preparation_unavailable');
  return {fixture,baseline,blockNumber,blockHash};
}

type ManifestData={raw:Buffer;json:Json;resource:Json;resourceBytes:Buffer;resourcePin:Json;assets:Array<{assetId:string;kind:string;chainId:number;address:string|null;codeHash:string|null;decimals:number}>};
async function loadManifest(root:string,prep:PrepRow,taskCase:Extract<TaskCase,{taskId:'M1'}>,release:Awaited<ReturnType<TaskReleaseQuerySource['getValidatedReleaseRecord']>>):Promise<ManifestData>{
  const raw=await readPinnedFile(root,MANIFEST_REL,MAX_MANIFEST_BYTES,'release_binding_mismatch');
  const rawSha=createHash('sha256').update(raw).digest('hex');
  if(rawSha!==prep.environment_manifest_sha256.toLowerCase()||rawSha!==release!.manifest.executionIdentity.environmentManifestSha256.toLowerCase())throw new Unavailable('release_binding_mismatch');
  let parsed:unknown;try{parsed=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw)) as unknown}catch{throw new Unavailable('release_binding_mismatch')}
  if(!isRecord(parsed)||parsed.schemaVersion!=='bef-runtime-manifest/v1'||!isRecord(parsed.x402)||!Array.isArray(parsed.x402.catalog)||!isRecord(parsed.contracts))throw new Unavailable('release_binding_mismatch');
  const x=parsed.x402 as Json;const matches=(x.catalog as unknown[]).filter((item)=>isRecord(item)&&item.resourceId===taskCase.objective.component.resourceId);
  if(matches.length!==1)throw new Unavailable('release_binding_mismatch');
  const manifestResource=matches[0] as Json;
  if(typeof manifestResource.resourcePath!=='string'||typeof manifestResource.resourceSha256!=='string'||!HASH.test(manifestResource.resourceSha256)||
      manifestResource.contentType!=='application/json'||!isRecord(manifestResource.provenance)||!Array.isArray(manifestResource.offers))throw new Unavailable('release_binding_mismatch');
  const resourcePath=manifestResource.resourcePath;
  if(resourcePath.startsWith('/')||resourcePath.includes('\\')||resourcePath.split('/').some((p)=>!p||p==='.'||p==='..'))throw new Unavailable('release_binding_mismatch');
  const resourceBytes=await readPinnedFile(root,resourcePath,MAX_RESOURCE_BYTES,'release_binding_mismatch');
  if(createHash('sha256').update(resourceBytes).digest('hex')!==manifestResource.resourceSha256.toLowerCase())throw new Unavailable('release_binding_mismatch');
  let resource:unknown;try{resource=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(resourceBytes)) as unknown}catch{throw new Unavailable('release_binding_mismatch')}
  if(!isRecord(resource)||resource.resourceId!==manifestResource.resourceId||resource.schema!==manifestResource.schema)throw new Unavailable('release_binding_mismatch');
  const payment=taskCase.objective.paymentRequirements;
  const assets=release!.manifest.executionIdentity.assets;
  const usdc=assets.find((item)=>item.assetId===payment.assetId);
  if(!usdc||usdc.kind!=='erc20'||!normalizeAddress(usdc.address)||usdc.chainId!==release!.manifest.executionIdentity.localChainId||
      payment.assetId!=='USDC'||payment.resourceId!==manifestResource.resourceId)throw new Unavailable('release_binding_mismatch');
  // The task's complete requirements are authoritative for evaluator identity; the original raw
  // environment manifest independently pins the network/token/scheme/method.
  if(x.scheme!=='exact'||x.assetTransferMethod!=='eip3009'||x.network!==payment.network||String(x.asset).toLowerCase()!==usdc.address!.toLowerCase())
    throw new Unavailable('release_binding_mismatch');
  const offers=(manifestResource.offers as unknown[]).map((item)=>{if(!isRecord(item)||typeof item.id!=='string'||typeof item.amount!=='string')throw new Unavailable('release_binding_mismatch');return {id:item.id,amount:item.amount}});
  const resourcePin={resourceId:String(manifestResource.resourceId),resourceSha256:String(manifestResource.resourceSha256).toLowerCase(),contentType:'application/json',offers,
    paymentPolicy:{scheme:String(x.scheme),network:String(x.network),asset:String(x.asset).toLowerCase(),assetTransferMethod:String(x.assetTransferMethod),
      eip712Domain:isRecord(x.eip712Domain)?x.eip712Domain:{name:'',version:''}}};
  const execAssets=assets.map((asset)=>({assetId:asset.assetId,kind:asset.kind,chainId:asset.chainId,address:asset.address,codeHash:asset.codeHash,decimals:asset.decimals}));
  return {raw,json:parsed,resource:resource as Json,resourceBytes,resourcePin,assets:execAssets};
}

function actionPayloadHash(runId:string,index:number,command:TaskActionCommand):string{return hashJson({runId,taskIndex:index,command});}
function parsePaymentProtocol(value:unknown):Json|null{return isRecord(value)?value:null}
const ACTION_EVIDENCE_KEYS=new Set(['schema','actionId','runId','taskIndex','actionSequence','ownerOperationId','actionKind','commandSha256','environmentId','generationId',
  'manifestSha256','applicationSourceSha256','idempotencyKey','status','reasonCode','requestStartedAt','requestFinishedAt','httpStatus','befOperationId','transactionHash',
  'outcome','receiptStatus','rawResponseSha256','participantToolResponse','receiptGasUsed','receiptEffectiveGasPriceWei','paymentProtocol','environmentHealth']);

async function loadM1Actions(root:string,run:RunRow,prep:PrepRow,runId:string,index:number,cutoff:number,rows:ActionRow[],taskCase:Extract<TaskCase,{taskId:'M1'}>,
  resourcePin:Json):Promise<M1LoadedAction[]>{
  if(cutoff>MAX_ACTIONS||rows.length!==cutoff)throw new Unavailable('owner_cutoff_mismatch');
  const actions:M1LoadedAction[]=[];const byId=new Map<string,M1LoadedAction>();
  for(let i=0;i<rows.length;i++){
    const row=rows[i]!;const seq=sequence(row.action_sequence);const ref=evidenceRef(row.evidence_path&&row.evidence_hash?{path:row.evidence_path,sha256:String(row.evidence_hash).toLowerCase(),boundary:EVIDENCE_BOUNDARY}:null);
    if(seq!==i+1||!UUID.test(row.id)||row.id!==row.id.toLowerCase()||row.run_id!==runId||row.task_index!==index||row.owner_id!==run.owner_id||row.agent_id!==run.agent_id||
      row.task_id!=='M1'||row.environment_id!==prep.environment_id||!ref||!HASH.test(row.payload_hash)||!HASH.test(row.evidence_hash??'')||
      row.history_revision!==row.receipt_revision||row.history_status!==row.receipt_status||row.history_evidence_hash!==row.evidence_hash||
      row.history_evidence_path!==row.evidence_path||(row.history_transaction_hash?.toLowerCase()??null)!==(row.transaction_hash?.toLowerCase()??null))throw new Unavailable('action_evidence_unavailable');
    const parsed=TaskActionCommandSchema.safeParse(parseJson(row.command_json,'action_evidence_unavailable'));
    if(!parsed.success||!['inspect_catalog','inspect_offer','pay','retrieve'].includes(parsed.data.kind)||actionPayloadHash(runId,index,parsed.data)!==row.payload_hash.toLowerCase())throw new Unavailable('action_evidence_unavailable');
    const command=parsed.data as M1LoadedAction['command'];
    const evidence=parseSafe(await readEvidence(root,ref,ACTION_ROOT,'action_evidence_unavailable',MAX_ACTION_EVIDENCE_BYTES),'action_evidence_unavailable');
    if(Object.keys(evidence).some((key)=>!ACTION_EVIDENCE_KEYS.has(key))||evidence.schema!=='bef-task-action-observation-v1'||evidence.actionId!==row.id||evidence.runId!==runId||
      evidence.taskIndex!==index||String(evidence.actionSequence)!==String(seq)||evidence.ownerOperationId!==row.operation_id||evidence.actionKind!==command.kind||
      evidence.commandSha256!==row.payload_hash.toLowerCase()||evidence.environmentId!==prep.environment_id||evidence.generationId!==prep.generation_id||
      evidence.manifestSha256!==prep.environment_manifest_sha256.toLowerCase()||evidence.applicationSourceSha256!==prep.application_source_hash.toLowerCase()||
      evidence.idempotencyKey!==`task-action-${row.id}`)throw new Unavailable('action_evidence_unavailable');
    const status=row.receipt_status;const response=isRecord(evidence.participantToolResponse)?evidence.participantToolResponse:null;
    const protocol=parsePaymentProtocol(evidence.paymentProtocol);const befOperationId=typeof evidence.befOperationId==='string'&&UUID.test(evidence.befOperationId)?evidence.befOperationId.toLowerCase():null;
    const tx=normalizeHash(evidence.transactionHash);
    if(status==='unknown'||!['observed','rejected_before_execution'].includes(status)||evidence.status!==status||
      (status==='observed'&&(!response||typeof evidence.rawResponseSha256!=='string'||!HASH.test(evidence.rawResponseSha256)))||
      (status==='rejected_before_execution'&&(response!==null||tx!==null||row.transaction_hash!==null||
        typeof evidence.reasonCode!=='string'||evidence.reasonCode.length<1||evidence.reasonCode.length>128||
        (evidence.rawResponseSha256!==undefined&&(typeof evidence.rawResponseSha256!=='string'||!HASH.test(evidence.rawResponseSha256)))||
        (protocol!==null&&command.kind!=='pay'))))throw new Unavailable('action_evidence_unavailable');
    if(status==='observed'){
      if(command.kind==='inspect_catalog'||command.kind==='inspect_offer'){
        if(!response||!readOnlyToolResponseMatches(command,response)||protocol!==null)throw new Unavailable('action_evidence_unavailable');
      }else if(command.kind==='pay'){
        if(!response||!protocol||response.operationId!==befOperationId||response.status!=='payment_confirmed'||!isRecord(response.payment)||
          response.deliveryHandle!==befOperationId||protocol.schema!=='bef-x402-split-payment-observation-v1'||protocol.befOperationId!==befOperationId||
          protocol.resourceId!==command.resourceId||protocol.offerId!==command.offerId||!tx||tx!==normalizeHash(response.payment.transactionHash)||
          response.payment.receiptStatus!=='success')throw new Unavailable('action_evidence_unavailable');
      }else{
        if(!response||!protocol||!befOperationId||response.operationId!==befOperationId||protocol.schema!=='bef-x402-retrieve-observation-v1'||
          protocol.payOperationId!==befOperationId||protocol.deliveryMatchesPinnedResource!==true||!isRecord(response)||response.contentType!=='application/json')throw new Unavailable('action_evidence_unavailable');
      }
      if(command.kind==='inspect_catalog'&&befOperationId!==null&&response?.operationId!==befOperationId)throw new Unavailable('action_evidence_unavailable');
      if(command.kind==='inspect_offer'&&(!befOperationId||response?.operationId!==befOperationId))throw new Unavailable('action_evidence_unavailable');
    }else if(command.kind==='pay'&&protocol!==null&&
      (protocol.schema!=='bef-x402-split-payment-observation-v1'||!isRecord(protocol.readHandle)||
        !['task_split_pay_pinned_context_unavailable','task_split_pay_challenge_unavailable','task_split_pay_challenge_invalid',
          'task_split_pay_challenge_scope_mismatch','task_split_pay_authorization_invalid'].includes(String(evidence.reasonCode))||
        (protocol.befOperationId!==undefined&&protocol.befOperationId!==befOperationId)))
      throw new Unavailable('action_evidence_unavailable');
    if((command.kind==='inspect_catalog'||command.kind==='inspect_offer'||command.kind==='retrieve')&&row.transaction_hash!==null)throw new Unavailable('action_evidence_unavailable');
    if((status==='observed'&&command.kind!=='inspect_catalog'&&!befOperationId)|| (command.kind==='pay'&&row.transaction_hash?.toLowerCase()!==tx) ||
      (command.kind!=='pay'&&row.transaction_hash!==null))throw new Unavailable('action_evidence_unavailable');
    const action:M1LoadedAction={row,sequence:seq,command,evidence,ref,response,protocol};
    actions.push(action);byId.set(row.id,action);
  }
  const reads=new Map<string,{action:M1LoadedAction;handle:Json}>();
  for(const action of actions){
    if(action.command.kind==='inspect_catalog'||action.command.kind==='inspect_offer'){
      if(action.row.receipt_status!=='observed'||!action.response)continue;
      const handle=action.response.readHandle;
      if(isRecord(handle)&&typeof handle.operationId==='string')reads.set(action.row.id,{action,handle});
    }
    if(action.command.kind==='pay'){
      if(action.row.receipt_status==='rejected_before_execution'&&action.protocol===null)continue;
      const read=byId.get(action.command.offerReadActionId);const prior=read&&reads.get(read.row.id);
      if(!prior||prior.action.sequence>=action.sequence||read?.command.kind!=='inspect_catalog'&&read?.command.kind!=='inspect_offer'||!action.protocol||
        canonicalTaskJson((action.protocol as Json).readHandle)!==canonicalTaskJson(prior.handle))throw new Unavailable('action_evidence_unavailable');
      const pp=action.protocol;const accepted=pp.acceptedTerms;const offerId=action.command.offerId;
      if(pp.resourceId!==action.command.resourceId||pp.offerId!==offerId||!isRecord(accepted)||typeof pp.resourceSha256!=='string'||!HASH.test(pp.resourceSha256))
        throw new Unavailable('action_evidence_unavailable');
    }
    if(action.command.kind==='retrieve'){
      if(action.row.receipt_status==='rejected_before_execution')continue;
      const prior=byId.get(action.command.payActionId);
      if(!prior||prior.command.kind!=='pay'||prior.sequence>=action.sequence||prior.row.receipt_status!=='observed'||
        action.row.receipt_status!=='observed'||action.evidence.befOperationId!==prior.evidence.befOperationId||
        action.response?.operationId!==prior.evidence.befOperationId||action.protocol?.payOperationId!==prior.evidence.befOperationId)
        throw new Unavailable('action_evidence_unavailable');
    }
  }
  return actions;
}

class RpcRecorder {
  readonly responseHashes:Array<{method:string;paramsSha256:string;resultSha256:string}>=[];
  constructor(private readonly port:BefM1ReadOnlyRpcPort){}
  async request(method:string,params:readonly unknown[]):Promise<unknown>{
    if(!['eth_chainId','eth_blockNumber','eth_getBlockByNumber','eth_getTransactionByHash','eth_getTransactionReceipt','eth_getBalance','eth_call','eth_getCode','eth_getTransactionCount','eth_getLogs'].includes(method))
      throw new Unavailable('rpc_observation_unavailable');
    let result:unknown;try{result=await this.port.request(method,params)}catch{throw new Unavailable('rpc_observation_unavailable')}
    try{if(Buffer.byteLength(canonicalTaskJson(result),'utf8')>MAX_RPC_BYTES)throw new Unavailable('rpc_observation_unavailable');}
    catch(error){if(error instanceof Unavailable)throw error;throw new Unavailable('rpc_observation_unavailable')}
    this.responseHashes.push({method,paramsSha256:hashJson(params),resultSha256:hashJson(result)});
    return result;
  }
}
function paddedAddress(address:string):string{return address.slice(2).toLowerCase().padStart(64,'0')}
function blockHeader(value:unknown,expected?:bigint):{number:bigint;hash:string;parentHash:string;transactions?:unknown[]}{
  if(!isRecord(value))throw new Unavailable('rpc_observation_unavailable');
  const number=quantity(value.number),hash=normalizeHash(value.hash),parentHash=normalizeHash(value.parentHash);
  if(number===null||!hash||!parentHash||(expected!==undefined&&number!==expected))throw new Unavailable('rpc_observation_unavailable');
  if(value.transactions!==undefined&&(!Array.isArray(value.transactions)||value.transactions.length>10000))throw new Unavailable('rpc_observation_unavailable');
  return {number,hash,parentHash,...(Array.isArray(value.transactions)?{transactions:value.transactions}:{})};
}
function encodeBalanceOf(address:string):string{return `${BALANCE_OF}${paddedAddress(address)}`}
function encodeAllowance(owner:string,spender:string):string{return `${ALLOWANCE}${paddedAddress(owner)}${paddedAddress(spender)}`}
function addressFromRef(value:string,participant:string):string{const out=value==='participant'?participant:normalizeAddress(value);if(!out)throw new Unavailable('release_binding_mismatch');return out}
function assetMap(assets:ManifestData['assets'],localChainId:number):Map<string,{assetId:string;kind:string;chainId:number;address:string|null;codeHash:string|null;decimals:number}>{
  const map=new Map<string,{assetId:string;kind:string;chainId:number;address:string|null;codeHash:string|null;decimals:number}>();
  for(const asset of assets){if(map.has(asset.assetId)||asset.chainId!==localChainId)throw new Unavailable('release_binding_mismatch');map.set(asset.assetId,asset)}
  return map;
}
async function verifyCode(rpc:RpcRecorder,identity:ManifestData['assets'],contracts:Array<{address:string;codeHash:string}>,chain:number,block:bigint):Promise<void>{
  const expected=new Map<string,string>();
  for(const asset of identity){if(asset.kind!=='erc20')continue;const addr=normalizeAddress(asset.address);if(!addr||!asset.codeHash||!HASH.test(asset.codeHash))throw new Unavailable('release_binding_mismatch');expected.set(addr,asset.codeHash.toLowerCase())}
  for(const contract of contracts){const addr=normalizeAddress(contract.address);if(!addr||!HASH.test(contract.codeHash))throw new Unavailable('release_binding_mismatch');
    const prior=expected.get(addr);if(prior&&prior!==contract.codeHash.toLowerCase())throw new Unavailable('release_binding_mismatch');expected.set(addr,contract.codeHash.toLowerCase())}
  for(const [address,hash] of expected){const code=await rpc.request('eth_getCode',[address,`0x${block.toString(16)}`]);
    if(typeof code!=='string'||!/^0x(?:[0-9a-f]{2})+$/i.test(code)||keccak256(code as `0x${string}`).slice(2).toLowerCase()!==hash)throw new Unavailable('rpc_identity_mismatch')}
  if(!Number.isSafeInteger(chain)||chain<1)throw new Unavailable('rpc_identity_mismatch');
}
async function readCheckpoint(rpc:RpcRecorder,taskCase:Extract<TaskCase,{taskId:'M1'}>,assets:ManifestData['assets'],identityAssets:Map<string,IdentityAsset>,
  participant:string,block:bigint):Promise<RpcCheckpoint>{
  const tag=`0x${block.toString(16)}`;const header=blockHeader(await rpc.request('eth_getBlockByNumber',[tag,false]),block);const balances:RpcCheckpoint['balances']=[];
  // Include every identity asset for the participant, plus every exact case balance key. The task-state hash
  // below is computed over the sealed key set; extra asset reads remain in the public checkpoint for audit.
  const balanceKeys=new Map<string,{account:string;assetId:string}>();
  for(const item of taskCase.initialState.balances)balanceKeys.set(`${addressFromRef(item.account,participant)}|${item.assetId}`,{account:item.account,assetId:item.assetId});
  for(const asset of assets)balanceKeys.set(`${participant}|${asset.assetId}`,{account:'participant',assetId:asset.assetId});
  for(const item of balanceKeys.values()){
    const account=addressFromRef(item.account,participant);const asset=identityAssets.get(item.assetId);if(!asset)throw new Unavailable('release_binding_mismatch');
    let amount:bigint|null=null;
    if(asset.kind==='native'&&asset.address===null)amount=quantity(await rpc.request('eth_getBalance',[account,tag]));
    else if(asset.kind==='erc20'&&normalizeAddress(asset.address)){
      const word=await rpc.request('eth_call',[{to:asset.address,data:encodeBalanceOf(account)},tag]);
      if(typeof word==='string'&&HEX_WORD.test(word))amount=BigInt(word);
    }
    if(amount===null)throw new Unavailable('rpc_observation_unavailable');balances.push({account:item.account,assetId:item.assetId,amountUnits:amount.toString()});
  }
  const allowances:RpcCheckpoint['allowances']=[];
  for(const item of taskCase.initialState.allowances){const asset=identityAssets.get(item.tokenAssetId),owner=addressFromRef(item.owner,participant),spender=normalizeAddress(item.spender);
    if(!asset||asset.kind!=='erc20'||!normalizeAddress(asset.address)||!spender)throw new Unavailable('release_binding_mismatch');
    const word=await rpc.request('eth_call',[{to:asset.address,data:encodeAllowance(owner,spender)},tag]);
    if(typeof word!=='string'||!HEX_WORD.test(word))throw new Unavailable('rpc_observation_unavailable');allowances.push({owner:item.owner,tokenAssetId:item.tokenAssetId,spender:item.spender,amountUnits:BigInt(word).toString()});
  }
  return {blockNumber:block.toString(),blockHash:header.hash,parentHash:header.parentHash,
    balances:balances.sort((a,b)=>`${a.account.toLowerCase()}|${a.assetId}`.localeCompare(`${b.account.toLowerCase()}|${b.assetId}`)),
    allowances:allowances.sort((a,b)=>`${a.owner.toLowerCase()}|${a.tokenAssetId}|${a.spender.toLowerCase()}`.localeCompare(`${b.owner.toLowerCase()}|${b.tokenAssetId}|${b.spender.toLowerCase()}`)),
    participantTransactionCount:'0'};
}
function caseCheckpointProjection(checkpoint:RpcCheckpoint,taskCase:Extract<TaskCase,{taskId:'M1'}>):Json{
  const keys=new Set(taskCase.initialState.balances.map((item)=>`${item.account.toLowerCase()}|${item.assetId}`));
  const allowances=new Set(taskCase.initialState.allowances.map((item)=>`${item.owner.toLowerCase()}|${item.tokenAssetId}|${item.spender.toLowerCase()}`));
  return {balances:checkpoint.balances.filter((item)=>keys.has(`${item.account.toLowerCase()}|${item.assetId}`)).sort((a,b)=>`${a.account.toLowerCase()}|${a.assetId}`.localeCompare(`${b.account.toLowerCase()}|${b.assetId}`)),
    allowances:checkpoint.allowances.filter((item)=>allowances.has(`${item.owner.toLowerCase()}|${item.tokenAssetId}|${item.spender.toLowerCase()}`))
      .sort((a,b)=>`${a.owner.toLowerCase()}|${a.tokenAssetId}|${a.spender.toLowerCase()}`.localeCompare(`${b.owner.toLowerCase()}|${b.tokenAssetId}|${b.spender.toLowerCase()}`)),
    deliveredComponentIds:[...taskCase.initialState.deliveredComponentIds].sort(),fulfilledObligationIds:[...taskCase.initialState.fulfilledObligationIds].sort()};
}
type Interval={blocks:RpcBlock[];transactions:Map<string,Json>;participantLogQueryCount:number;transferLogs:Json[]};
function decodeTransferLog(value:unknown,tokenAddress:string,assetId:string,participant:string):Json{
  if(!isRecord(value)||!Array.isArray(value.topics)||value.topics.length!==3||value.topics[0]?.toLowerCase()!==TRANSFER_TOPIC||typeof value.data!=='string'||!HEX_WORD.test(value.data))
    throw new Unavailable('rpc_observation_unavailable');
  const fromTopic=String(value.topics[1]),toTopic=String(value.topics[2]);
  if(!/^0x[0-9a-f]{64}$/i.test(fromTopic)||!/^0x[0-9a-f]{64}$/i.test(toTopic))throw new Unavailable('rpc_observation_unavailable');
  const from=normalizeAddress(`0x${fromTopic.slice(-40)}`),to=normalizeAddress(`0x${toTopic.slice(-40)}`),transactionHash=normalizeHash(value.transactionHash),blockHash=normalizeHash(value.blockHash);
  const blockNumber=quantity(value.blockNumber),logIndex=quantity(value.logIndex),address=normalizeAddress(value.address);
  if(!from||!to||!transactionHash||!blockHash||blockNumber===null||logIndex===null||address!==tokenAddress||value.removed===true||
    (from!==participant&&to!==participant))throw new Unavailable('rpc_observation_unavailable');
  return {assetId,tokenAddress,transactionHash,blockNumber:blockNumber.toString(),blockHash,logIndex:logIndex.toString(),from,to,amountUnits:BigInt(value.data).toString()};
}
async function readInterval(rpc:RpcRecorder,assets:ManifestData['assets'],baseline:RpcCheckpoint,final:RpcCheckpoint,participant:string):Promise<Interval>{
  const from=BigInt(baseline.blockNumber),to=BigInt(final.blockNumber);if(to<from||to-from>BigInt(MAX_BLOCKS))throw new Unavailable('rpc_interval_too_large');
  const blocks:RpcBlock[]=[];const transactions=new Map<string,Json>();let parent=baseline.blockHash;
  for(let number=from+1n;number<=to;number++){
    const raw=await rpc.request('eth_getBlockByNumber',[`0x${number.toString(16)}`,true]);const header=blockHeader(raw,number);
    if(header.parentHash!==parent||!header.transactions)throw new Unavailable('rpc_mapping_incomplete');
    for(const value of header.transactions){
      if(!isRecord(value))throw new Unavailable('rpc_observation_unavailable');const hash=normalizeHash(value.hash),sender=normalizeAddress(value.from),recipient=value.to===null?null:normalizeAddress(value.to);
      if(!hash||!sender||(value.to!==null&&!recipient)||typeof value.input!=='string'||quantity(value.nonce)===null||quantity(value.value)===null||
        quantity(value.blockNumber)!==number||normalizeHash(value.blockHash)!==header.hash)throw new Unavailable('rpc_observation_unavailable');
      if(sender===participant)throw new Unavailable('state_effect_detected');transactions.set(hash,value);
    }
    blocks.push({number:number.toString(),hash:header.hash,parentHash:header.parentHash,transactionCount:header.transactions.length});parent=header.hash;
  }
  if(to>from&&parent!==final.blockHash)throw new Unavailable('rpc_mapping_incomplete');
  const transferLogs:Json[]=[];let participantLogQueryCount=0;const tokens=assets.filter((a)=>a.kind==='erc20').map((a)=>({id:a.assetId,address:normalizeAddress(a.address)}))
    .filter((a):a is {id:string;address:string}=>Boolean(a.address));
  const dedupe=new Map<string,Json>();
  if(to>from){for(const token of tokens){for(const topics of [[TRANSFER_TOPIC,`0x${paddedAddress(participant)}`],[TRANSFER_TOPIC,null,`0x${paddedAddress(participant)}`]] as const){
    const logs=await rpc.request('eth_getLogs',[{address:token.address,fromBlock:`0x${(from+1n).toString(16)}`,toBlock:`0x${to.toString(16)}`,topics}]);participantLogQueryCount++;
    if(!Array.isArray(logs)||logs.length>MAX_ROWS)throw new Unavailable('rpc_observation_unavailable');
    for(const value of logs){const decoded=decodeTransferLog(value,token.address,token.id,participant);const key=`${decoded.transactionHash}|${decoded.logIndex}|${decoded.assetId}`;
      const prior=dedupe.get(key);if(prior&&canonicalTaskJson(prior)!==canonicalTaskJson(decoded))throw new Unavailable('rpc_mapping_incomplete');dedupe.set(key,decoded);}
  }}}
  transferLogs.push(...dedupe.values());transferLogs.sort((a,b)=>BigInt(String(a.blockNumber))<BigInt(String(b.blockNumber))?-1:BigInt(String(a.blockNumber))>BigInt(String(b.blockNumber))?1:
    BigInt(String(a.logIndex))<BigInt(String(b.logIndex))?-1:BigInt(String(a.logIndex))>BigInt(String(b.logIndex))?1:String(a.transactionHash).localeCompare(String(b.transactionHash)));
  if(transferLogs.length>MAX_ROWS)throw new Unavailable('rpc_observation_unavailable');
  const headerByNumber=new Map([[baseline.blockNumber,baseline.blockHash],...blocks.map((b)=>[b.number,b.hash] as [string,string]),[final.blockNumber,final.blockHash]]);
  for(const log of transferLogs)if(headerByNumber.get(String(log.blockNumber))!==log.blockHash||!transactions.has(String(log.transactionHash)))throw new Unavailable('rpc_mapping_incomplete');
  return {blocks,transactions,participantLogQueryCount,transferLogs};
}

function expectedReadRequestHash(action:M1LoadedAction,_environmentId:string):string{
  const request=action.command.kind==='inspect_catalog'?{method:'GET',path:'/catalog'}:action.command.kind==='inspect_offer'?
    {method:'GET',path:'/offer',resourceId:action.command.resourceId}:null;
  return request?hashString(JSON.stringify(request)):'';
}
function expectedPaymentRequirements(row:Json,op:Json,resourcePin:Json):Json{
  const manifestOffers=(resourcePin.offers as Array<{id:string;amount:string}>);const offer=manifestOffers.find((candidate)=>candidate.id===op.selected_offer_id);
  if(!offer||String(op.selected_amount_units)!==offer.amount||op.selected_resource_id!==resourcePin.resourceId||op.selected_resource_sha256!==resourcePin.resourceSha256)
    throw new Unavailable('rpc_mapping_incomplete');
  const pin=resourcePin.paymentPolicy as Json;
  const challenge=row.requirements as Json;const extra=challenge.extra as Json;
  if(String(row.x402_version)!=='2'||challenge.scheme!==pin.scheme||challenge.network!==pin.network||String(challenge.asset).toLowerCase()!==String(pin.asset).toLowerCase()||
    String(challenge.amount)!==offer.amount||!normalizeAddress(challenge.payTo)||extra.assetTransferMethod!==pin.assetTransferMethod||extra.paymentFlow!=='authorization'||
    extra.name!==(pin.eip712Domain as Json).name||extra.version!==(pin.eip712Domain as Json).version)throw new Unavailable('rpc_mapping_incomplete');
  return {scheme:String(challenge.scheme),network:String(challenge.network),asset:String(challenge.asset).toLowerCase(),amount:String(challenge.amount),payTo:String(challenge.payTo).toLowerCase(),
    maxTimeoutSeconds:String(challenge.maxTimeoutSeconds),x402_version:String(row.x402_version),
    extra:{assetTransferMethod:String(extra.assetTransferMethod),paymentFlow:String(extra.paymentFlow),name:String(extra.name),version:String(extra.version)}};
}
function expectedPayRequestHash(action:M1LoadedAction):string{
  const p=action.protocol;if(!p||action.command.kind!=='pay')return '';
  const body={resourceId:action.command.resourceId,offerId:action.command.offerId,readHandle:p.readHandle,acceptedTerms:p.acceptedTerms};
  return hashString(JSON.stringify({method:'POST',path:'/tools/'+String(action.evidence.environmentId)+'/pay',body}));
}
export function validateM1OperationCensus(census:Census,actions:M1LoadedAction[],envId:string,generationId:string,participantId:string,resourcePin:Json):void{
  if(census.selectedExecutions.length||census.selectedEvents.length||census.denials.length)throw new Unavailable('rpc_mapping_incomplete');
  const byId=new Map(census.operations.map((op)=>[String(op.operation_id).toLowerCase(),op]));const consumed=new Set<string>();
  for(const action of actions){
    const expectedIdempotency=hashString(`task-action-${action.row.id}`);
    if(action.row.receipt_status==='rejected_before_execution'){
      const matchingByKey=census.operations.filter((op)=>String(op.idempotency_key_sha256).toLowerCase()===expectedIdempotency);
      if(matchingByKey.length>1)throw new Unavailable('rpc_mapping_incomplete');
      if(action.command.kind==='pay'&&action.protocol!==null){
        const protocol=action.protocol;
        const recordedId=action.evidence.befOperationId===undefined?null:String(action.evidence.befOperationId).toLowerCase();
        const protocolId=typeof protocol.befOperationId==='string'?protocol.befOperationId.toLowerCase():null;
        if(recordedId!==protocolId)throw new Unavailable('rpc_mapping_incomplete');
        const operation=recordedId?byId.get(recordedId):matchingByKey[0];
        if(recordedId&&!operation||operation&&matchingByKey[0]&&operation.operation_id!==matchingByKey[0]!.operation_id)
          throw new Unavailable('rpc_mapping_incomplete');
        if(operation){
          const id=String(operation.operation_id).toLowerCase();
          if(operation.env_id!==envId||operation.generation_id!==generationId||operation.participant_id!==participantId||
            String(operation.idempotency_key_sha256).toLowerCase()!==expectedIdempotency||operation.operation_kind!=='purchase'||
            !['awaiting_payment','rejected'].includes(String(operation.status))||operation.receipt_status!=='not_submitted'||operation.transaction_hash!==null||
            operation.payment_response_mode!=='deferred_delivery'||operation.selected_offer_id!==action.command.offerId||
            operation.selected_resource_id!==action.command.resourceId||String(operation.selected_resource_sha256).toLowerCase()!==String(protocol.resourceSha256).toLowerCase()||
            String(operation.selected_amount_units)!==String(protocol.amountUnits)||String(operation.request_sha256).toLowerCase()!==expectedPayRequestHash(action)||
            census.payments.some((row)=>String(row.operation_id).toLowerCase()===id)||census.deliveries.some((row)=>String(row.operation_id).toLowerCase()===id)||
            census.costs.some((row)=>String(row.operation_id).toLowerCase()===id)||census.x402Observations.some((row)=>String(row.operation_id).toLowerCase()===id))
            throw new Unavailable('rpc_mapping_incomplete');
          const responseHash=action.evidence.rawResponseSha256;
          if(operation.response_sha256!==null&&(!responseHash||String(operation.response_sha256).toLowerCase()!==String(responseHash).toLowerCase()))
            throw new Unavailable('rpc_mapping_incomplete');
          consumed.add(id);
        }
      }else if(matchingByKey.length!==0||action.evidence.befOperationId!==undefined){
        throw new Unavailable('rpc_mapping_incomplete');
      }
      continue;
    }
    if(action.row.receipt_status!=='observed'||!action.evidence.befOperationId)continue;
    const id=String(action.evidence.befOperationId).toLowerCase();const operation=byId.get(id);
    if(!operation){if(action.command.kind==='inspect_catalog'&&action.response?.operationId===undefined)continue;throw new Unavailable('rpc_mapping_incomplete');}
    if(operation.env_id!==envId||operation.generation_id!==generationId||operation.participant_id!==participantId||
      String(operation.idempotency_key_sha256).toLowerCase()!==expectedIdempotency||String(operation.operation_id).toLowerCase()!==id)
      throw new Unavailable('rpc_mapping_incomplete');
    if(action.command.kind==='inspect_catalog'||action.command.kind==='inspect_offer'){
      if(consumed.has(id)||operation.operation_kind!==(action.command.kind==='inspect_catalog'?'catalog':'offer')||operation.status!=='accepted'||
        operation.receipt_status!=='not_submitted'||operation.transaction_hash!==null||String(operation.request_sha256).toLowerCase()!==expectedReadRequestHash(action,envId)||
        !action.response||String(operation.response_sha256).toLowerCase()!==String(action.evidence.rawResponseSha256).toLowerCase())throw new Unavailable('rpc_mapping_incomplete');
      consumed.add(id);
    }else if(action.command.kind==='pay'){
      if(consumed.has(id)||operation.operation_kind!=='purchase'||!['settled','delivered'].includes(String(operation.status))||operation.receipt_status!=='success'||
        operation.payment_response_mode!=='deferred_delivery'||operation.transaction_hash!==action.evidence.transactionHash||
        String(operation.response_sha256).toLowerCase()!==String(action.evidence.rawResponseSha256).toLowerCase()||
        operation.selected_offer_id!==action.command.offerId||operation.selected_resource_id!==action.command.resourceId||
        String(operation.selected_resource_sha256).toLowerCase()!==String(action.protocol?.resourceSha256).toLowerCase()||
        String(operation.selected_amount_units)!==String(action.protocol?.amountUnits)||String(operation.request_sha256).toLowerCase()!==expectedPayRequestHash(action))
        throw new Unavailable('rpc_mapping_incomplete');
      const payCommand=action.command.kind==='pay'?action.command:null;
      if(!payCommand||payCommand.resourceId!==resourcePin.resourceId||!Array.isArray(resourcePin.offers)||!resourcePin.offers.some((o)=>isRecord(o)&&o.id===payCommand.offerId))
        throw new Unavailable('action_evidence_unavailable');
      const body=action.response;const pp=action.protocol!;
      if(!body||!isRecord(body.payment)||body.payment.amount!==String(pp.amountUnits)||String(body.payment.asset).toLowerCase()!==String(pp.asset).toLowerCase()||
        body.payment.network!==pp.network||String(body.payment.payTo).toLowerCase()!==String((pp.acceptedTerms as Json).payTo).toLowerCase()||
        pp.resourceSha256!==resourcePin.resourceSha256||pp.befOperationId!==id)throw new Unavailable('rpc_mapping_incomplete');
      consumed.add(id);
    }
  }
  for(const action of actions)if(action.command.kind==='retrieve'&&action.row.receipt_status==='observed'){
    if(!action.evidence.befOperationId||!byId.has(String(action.evidence.befOperationId).toLowerCase()))throw new Unavailable('rpc_mapping_incomplete');
    consumed.add(String(action.evidence.befOperationId).toLowerCase());
  }
  if(consumed.size!==byId.size)throw new Unavailable('rpc_mapping_incomplete');
  const payActions=actions.filter((a)=>a.command.kind==='pay'&&a.row.receipt_status==='observed');
  const allX402=census.x402Observations;
  if(allX402.length!==payActions.length*2)throw new Unavailable('rpc_mapping_incomplete');
  const paymentRows=census.payments;const expectedOps=new Set(payActions.map((a)=>String(a.evidence.befOperationId).toLowerCase()));
  if(paymentRows.length!==payActions.length||census.deliveries.some((d)=>!expectedOps.has(String(d.operation_id).toLowerCase())))throw new Unavailable('rpc_mapping_incomplete');
  for(const action of payActions){const opId=String(action.evidence.befOperationId).toLowerCase();const op=byId.get(opId)!;
    const observations=allX402.filter((x)=>String(x.operation_id).toLowerCase()===opId);
    const verify=observations.filter((x)=>x.phase==='verify'),settle=observations.filter((x)=>x.phase==='settle');
    if(observations.length!==2||verify.length!==1||settle.length!==1||verify[0]!.outcome!=='success'||settle[0]!.outcome!=='success'||
      verify[0]!.variant_id!=='baseline'||settle[0]!.variant_id!=='baseline'||settle[0]!.transaction_hash!==op.transaction_hash||
      canonicalTaskJson(verify[0]!.requirements)!==canonicalTaskJson(settle[0]!.requirements))throw new Unavailable('rpc_mapping_incomplete');
    const requirement=expectedPaymentRequirements(verify[0]!,op,resourcePin);const protocol=action.protocol!;const accepted=protocol.acceptedTerms as Json;
    const requirementExtra=requirement.extra as Json;
    if(accepted.scheme!==requirement.scheme||accepted.network!==requirement.network||String(accepted.asset).toLowerCase()!==requirement.asset||accepted.amount!==requirement.amount||
      String(accepted.payTo).toLowerCase()!==requirement.payTo||accepted.transferMethod!==requirementExtra.assetTransferMethod)
      throw new Unavailable('rpc_mapping_incomplete');
  }
}

function transferTopicAddress(value:unknown):string|null{
  if(typeof value!=='string'||!/^0x[0-9a-f]{64}$/i.test(value))return null;return normalizeAddress(`0x${value.slice(-40)}`);
}
function paymentRowsByOperation(census:Census):Map<string,Json>{
  const map=new Map<string,Json>();for(const row of census.payments){const id=String(row.operation_id).toLowerCase();if(map.has(id))throw new Unavailable('rpc_mapping_incomplete');map.set(id,row)}return map;
}
async function makePaymentProofs(rpc:RpcRecorder,interval:Interval,census:Census,actions:M1LoadedAction[],participant:string,assets:ManifestData['assets'],
  envManifestHash:string):Promise<Json[]>{
  const paymentByOp=paymentRowsByOperation(census);const costsByTx=new Map<string,Json>();
  for(const cost of census.costs){const tx=normalizeHash(cost.transaction_hash);if(!tx||costsByTx.has(tx))throw new Unavailable('rpc_mapping_incomplete');costsByTx.set(tx,cost)}
  const payActions=actions.filter((a)=>a.command.kind==='pay'&&a.row.receipt_status==='observed');
  if(paymentByOp.size!==payActions.length||costsByTx.size!==paymentByOp.size)throw new Unavailable('rpc_mapping_incomplete');
  const assetByAddress=new Map<string,string>();for(const asset of assets)if(asset.kind==='erc20'&&normalizeAddress(asset.address))assetByAddress.set(normalizeAddress(asset.address)!,asset.assetId);
  const globalLogs=new Map<string,Json[]>();for(const log of interval.transferLogs){const key=String(log.transactionHash).toLowerCase();const list=globalLogs.get(key)??[];list.push(log);globalLogs.set(key,list)}
  const proofs:Json[]=[];
  for(const action of payActions){const operationId=String(action.evidence.befOperationId).toLowerCase();const payment=paymentByOp.get(operationId);
    if(!payment)throw new Unavailable('rpc_mapping_incomplete');const txHash=normalizeHash(payment.transaction_hash);if(!txHash||txHash!==normalizeHash(action.evidence.transactionHash)||
      txHash!==normalizeHash(action.response?.payment&&isRecord(action.response.payment)?action.response.payment.transactionHash:null))throw new Unavailable('rpc_mapping_incomplete');
    const transaction=interval.transactions.get(txHash);if(!transaction)throw new Unavailable('rpc_mapping_incomplete');
    const txFrom=normalizeAddress(transaction.from),txTo=transaction.to===null?null:normalizeAddress(transaction.to),token=normalizeAddress(payment.asset_address),facilitator=normalizeAddress(payment.facilitator_address),payer=normalizeAddress(payment.payer_address);
    const txBlock=quantity(transaction.blockNumber),txBlockHash=normalizeHash(transaction.blockHash),nonce=quantity(transaction.nonce),value=quantity(transaction.value);
    if(!txFrom||!txTo||!token||!facilitator||!payer||txBlock===null||!txBlockHash||nonce===null||value===null||typeof transaction.input!=='string'||
      !HASH.test(createHash('sha256').update(transaction.input,'utf8').digest('hex'))||txFrom!==facilitator||txTo!==token||value!==0n||payment.receipt_status!=='success'||
      String(payment.network)!==String((action.protocol as Json).network)||String(payment.amount_units)!==String((action.protocol as Json).amountUnits)||
      normalizeAddress(payment.payer_address)!==participant||normalizeAddress((action.protocol as Json).asset)!==token||payment.token_delta_units!==payment.amount_units||
      decimal(payment.payer_balance_before)===null||decimal(payment.payer_balance_after)===null||BigInt(String(payment.payer_balance_before))-BigInt(String(payment.payer_balance_after))!==BigInt(String(payment.amount_units))||
      decimal(payment.facilitator_balance_before)===null||decimal(payment.facilitator_balance_after)===null||
      BigInt(String(payment.facilitator_balance_after))-BigInt(String(payment.facilitator_balance_before))!==BigInt(String(payment.amount_units)))throw new Unavailable('rpc_mapping_incomplete');
    const receiptRaw=await rpc.request('eth_getTransactionReceipt',[txHash]);if(!isRecord(receiptRaw)||!Array.isArray(receiptRaw.logs)||receiptRaw.logs.length>MAX_ROWS)throw new Unavailable('rpc_observation_unavailable');
    const receiptHash=normalizeHash(receiptRaw.transactionHash),receiptBlock=quantity(receiptRaw.blockNumber),receiptBlockHash=normalizeHash(receiptRaw.blockHash),receiptIndex=quantity(receiptRaw.transactionIndex),
      receiptFrom=normalizeAddress(receiptRaw.from),receiptTo=receiptRaw.to===null?null:normalizeAddress(receiptRaw.to),receiptStatus=quantity(receiptRaw.status),gasUsed=quantity(receiptRaw.gasUsed),effectiveGasPrice=quantity(receiptRaw.effectiveGasPrice);
    if(receiptHash!==txHash||receiptBlock===null||receiptBlock!==txBlock||receiptBlockHash!==txBlockHash||receiptIndex===null||receiptFrom!==txFrom||receiptTo!==txTo||
      receiptStatus!==1n||gasUsed===null||effectiveGasPrice===null||gasUsed===0n||effectiveGasPrice===0n)throw new Unavailable('rpc_observation_unavailable');
    const cost=costsByTx.get(txHash);if(!cost||cost.operation_id!==operationId||cost.payer_role!=='facilitator'||normalizeAddress(cost.payer_address)!==txFrom||
      normalizeAddress(cost.transaction_from)!==txFrom||normalizeAddress(cost.receipt_from)!==receiptFrom||cost.receipt_status!=='success'||
      String(cost.receipt_block_number)!==receiptBlock.toString()||normalizeHash(cost.receipt_block_hash)!==receiptBlockHash||
      String(cost.gas_used)!==gasUsed.toString()||String(cost.effective_gas_price_wei)!==effectiveGasPrice.toString()||String(cost.gas_cost_wei)!==(gasUsed*effectiveGasPrice).toString()||
      String(cost.manifest_sha256).toLowerCase()!==envManifestHash||decimal(cost.modeled_gas_fee_usdc_units)===null)throw new Unavailable('rpc_mapping_incomplete');
    const relatedLogs=globalLogs.get(txHash)??[];const matching=relatedLogs.filter((log)=>log.assetId==='USDC'&&log.from===participant&&log.to===facilitator&&String(log.amountUnits)===String(payment.amount_units));
    if(matching.length!==1)throw new Unavailable('rpc_mapping_incomplete');
    const receiptTransfers:Json[]=[];
    for(const rawLog of receiptRaw.logs){if(!isRecord(rawLog))throw new Unavailable('rpc_observation_unavailable');const address=normalizeAddress(rawLog.address);const assetId=address?assetByAddress.get(address):undefined;
      if(!assetId||!Array.isArray(rawLog.topics)||rawLog.topics[0]?.toLowerCase()!==TRANSFER_TOPIC)continue;
      const from=transferTopicAddress(rawLog.topics[1]),to=transferTopicAddress(rawLog.topics[2]);if(!from||!to)throw new Unavailable('rpc_observation_unavailable');
      if(from===participant||to===participant){const projected=decodeTransferLog({...rawLog,transactionHash:txHash,blockNumber:receiptBlock,blockHash:receiptBlockHash},address!,assetId,participant);
        receiptTransfers.push(projected);}
    }
    const expectedLogs=relatedLogs.filter((log)=>String(log.transactionHash).toLowerCase()===txHash);
    const normalizeLogs=(list:Json[])=>list.map((x)=>({assetId:x.assetId,tokenAddress:x.tokenAddress,transactionHash:x.transactionHash,blockNumber:x.blockNumber,blockHash:x.blockHash,
      logIndex:x.logIndex,from:x.from,to:x.to,amountUnits:x.amountUnits})).sort((a,b)=>`${a.logIndex}|${a.assetId}`.localeCompare(`${b.logIndex}|${b.assetId}`));
    if(canonicalTaskJson(normalizeLogs(receiptTransfers))!==canonicalTaskJson(normalizeLogs(expectedLogs)))throw new Unavailable('rpc_mapping_incomplete');
    const proof={operationId,paymentId:String(payment.payment_id).toLowerCase(),transactionHash:txHash,
      transaction:{hash:txHash,from:txFrom,to:txTo,value:value.toString(),nonce:nonce.toString(),blockNumber:txBlock.toString(),blockHash:txBlockHash,
        inputSha256:createHash('sha256').update(transaction.input,'utf8').digest('hex')},
      receipt:{transactionHash:txHash,transactionIndex:receiptIndex.toString(),blockNumber:receiptBlock.toString(),blockHash:receiptBlockHash,from:receiptFrom,to:receiptTo,
        status:'success',gasUsed:gasUsed.toString(),effectiveGasPrice:effectiveGasPrice.toString(),logsSha256:hashJson(receiptRaw.logs)}};
    proofs.push(proof);
  }
  return proofs;
}

function paymentQuoteMatches(item:Json,pin:Json,offer:Json):boolean{
  const payment=item.payment;if(!isRecord(payment))return false;const policy=pin.paymentPolicy as Json;
  return payment.scheme===policy.scheme&&payment.network===policy.network&&String(payment.asset).toLowerCase()===String(policy.asset).toLowerCase()&&
    payment.amount===offer.amount&&normalizeAddress(payment.payTo)!==null&&payment.transferMethod===policy.assetTransferMethod;
}
function validateManifestReadActions(actions:M1LoadedAction[],manifest:ManifestData,taskCase:Extract<TaskCase,{taskId:'M1'}>):void{
  const x402=manifest.json.x402 as Json;const catalog=x402.catalog as Json[];const byResource=new Map(catalog.map((item)=>[String(item.resourceId),item]));
  for(const action of actions){if(action.row.receipt_status!=='observed'||!action.response)continue;
    if(action.command.kind==='inspect_catalog'){
      const body=action.response;if(body.freeInspection!==true||body.deliveryState!=='not_delivered'||!Array.isArray(body.catalog))throw new Unavailable('action_evidence_unavailable');
      const actual=body.catalog as unknown[];if(actual.length!==catalog.length)throw new Unavailable('action_evidence_unavailable');
      for(const entryValue of actual){if(!isRecord(entryValue))throw new Unavailable('action_evidence_unavailable');const def=byResource.get(String(entryValue.resourceId));
        const expectedOffers=def&&Array.isArray(def.offers)?def.offers as Json[]:null;
        if(!def||!expectedOffers||entryValue.resourceSha256!==def.resourceSha256||entryValue.contentType!==def.contentType||entryValue.schema!==def.schema||
          !Array.isArray(entryValue.offers)||entryValue.offers.length!==expectedOffers.length)
          throw new Unavailable('action_evidence_unavailable');
        for(const offerValue of entryValue.offers){if(!isRecord(offerValue))throw new Unavailable('action_evidence_unavailable');
          const expected=expectedOffers.find((item)=>item.id===offerValue.id);if(!expected||!paymentQuoteMatches(offerValue,manifest.resourcePin,expected))throw new Unavailable('action_evidence_unavailable');}
      }
    }
    if(action.command.kind==='inspect_offer'){
      const def=byResource.get(action.command.resourceId),body=action.response;const expectedOffers=def&&Array.isArray(def.offers)?def.offers as Json[]:null;
      if(!def||!expectedOffers||body.resourceSha256!==def.resourceSha256||body.contentType!==def.contentType||
        (body.schema!==undefined&&body.schema!==def.schema)||(body.provenance!==undefined&&canonicalTaskJson(body.provenance)!==canonicalTaskJson(def.provenance))||body.freeInspection!==true||body.deliveryState!=='not_delivered'||
        !Array.isArray(body.offers)||body.offers.length!==expectedOffers.length)throw new Unavailable('action_evidence_unavailable');
      for(const offerValue of body.offers){if(!isRecord(offerValue))throw new Unavailable('action_evidence_unavailable');
        const expected=expectedOffers.find((item)=>item.id===offerValue.id);if(!expected||!paymentQuoteMatches(offerValue,manifest.resourcePin,expected))throw new Unavailable('action_evidence_unavailable');}
    }
    if(action.command.kind==='retrieve'){
      const body=action.response!;const bytesText=body.contentBytes;
      if(body.resourceId!==taskCase.objective.component.resourceId||body.contentType!==manifest.resourcePin.contentType||
        body.contentHash!==manifest.resourcePin.resourceSha256||typeof bytesText!=='string'||!isRecord(body.content))throw new Unavailable('action_evidence_unavailable');
      const bytes=Buffer.from(bytesText,'base64');
      if(bytes.toString('base64')!==bytesText||bytes.length<1||bytes.length>MAX_RESOURCE_BYTES||createHash('sha256').update(bytes).digest('hex')!==String(body.contentHash).toLowerCase())
        throw new Unavailable('action_evidence_unavailable');
      let decoded:unknown;try{decoded=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes)) as unknown}catch{throw new Unavailable('action_evidence_unavailable')}
      if(!isRecord(decoded)||canonicalTaskJson(decoded)!==canonicalTaskJson(body.content)||canonicalTaskJson(decoded)!==canonicalTaskJson(manifest.resource))
        throw new Unavailable('action_evidence_unavailable');
      const definition=byResource.get(String(body.resourceId));const source=definition&&isRecord(definition.provenance)?definition.provenance.classification:null;
      if(typeof source!=='string'||!taskCase.objective.component.sourceIds.includes(source)||!taskCase.objective.component.validator.permittedProvenance.includes(source))
        throw new Unavailable('action_evidence_unavailable');
    }
  }
}

function checkCheckpointEffects(taskCase:Extract<TaskCase,{taskId:'M1'}>,baseline:RpcCheckpoint,final:RpcCheckpoint,logs:Json[],participant:string):void{
  const initialByKey=new Map(taskCase.initialState.balances.map((item)=>[`${addressFromRef(item.account,participant)}|${item.assetId}`,BigInt(item.amountUnits)]));
  const beforeByKey=new Map(baseline.balances.map((item)=>[`${addressFromRef(item.account,participant)}|${item.assetId}`,BigInt(item.amountUnits)]));
  const afterByKey=new Map(final.balances.map((item)=>[`${addressFromRef(item.account,participant)}|${item.assetId}`,BigInt(item.amountUnits)]));
  for(const [key,expected] of initialByKey){if(beforeByKey.get(key)!==expected)throw new Unavailable('baseline_mismatch');}
  const changed=new Map<string,bigint>();for(const log of logs){const asset=String(log.assetId),amount=BigInt(String(log.amountUnits));
    const from=String(log.from),to=String(log.to);for(const [account,delta] of [[from,-amount],[to,amount]] as const){const key=`${account.toLowerCase()}|${asset}`;changed.set(key,(changed.get(key)??0n)+delta);}}
  for(const [key,before] of beforeByKey){const expected=before+(changed.get(key)??0n);const after=afterByKey.get(key);
    if(after===undefined||after!==expected)throw new Unavailable('state_effect_detected');}
  for(const [key,after] of afterByKey)if(!beforeByKey.has(key)&&after!==0n)throw new Unavailable('state_effect_detected');
  for(const item of taskCase.initialState.allowances){const key=`${item.owner.toLowerCase()}|${item.tokenAssetId}|${item.spender.toLowerCase()}`;
    const before=baseline.allowances.find((a)=>`${a.owner.toLowerCase()}|${a.tokenAssetId}|${a.spender.toLowerCase()}`===key);
    const after=final.allowances.find((a)=>`${a.owner.toLowerCase()}|${a.tokenAssetId}|${a.spender.toLowerCase()}`===key);
    if(!before||!after||before.amountUnits!==after.amountUnits||before.amountUnits!==item.amountUnits)throw new Unavailable('state_effect_detected');}
}

type ClosedM1RunRow = RunRow & {status:string;cancellation_reason:string|null;task_status:string;started_at:Date|string|null};
type ClosureProofRow = {id:string;operation_id:string|null;payload_hash:string;reason:string;answer_json:unknown;action_cutoff_sequence:string|number;owner_id:string;agent_id:string};

async function collectLocked(deps:BefM1ObservationCollectorDependencies,target:{runId:string;taskIndex:number},tx:OwnerTx):Promise<BefM1CollectionResult>{
  const owners=await ownerRows<{owner_id:string;agent_id:string}>(tx,sql`SELECT owner_id,agent_id FROM oid_benchmark_run WHERE id=${target.runId}`);
  const owner=owners[0];if(!owner)return unavailable('owner_cutoff_unavailable');
  await tx.execute(sql`SELECT id FROM oid_owner WHERE id=${owner.owner_id} FOR NO KEY UPDATE`);
  await tx.execute(sql`SELECT id FROM oid_agent WHERE id=${owner.agent_id} AND owner_id=${owner.owner_id} FOR NO KEY UPDATE`);
  const runs=await ownerRows<ClosedM1RunRow>(tx,sql`SELECT r.owner_id,r.agent_id,r.mode,r.task_ids,r.release_identity,r.manifest_hash,r.status,r.cancellation_reason,
      t.task_id,t.status AS task_status,t.started_at,t.closure_status,t.closure_id,t.closure_operation_id,t.closure_payload_hash,t.closure_reason,
      t.action_cutoff_sequence::text AS action_cutoff_sequence,t.reconciled_action_sequence::text AS reconciled_action_sequence
    FROM oid_benchmark_run r JOIN oid_run_task t ON t.run_id=r.id
    WHERE r.id=${target.runId} AND r.owner_id=${owner.owner_id} AND r.agent_id=${owner.agent_id} AND t.task_index=${target.taskIndex} FOR UPDATE OF r,t`);
  const run=runs[0];if(!run)return unavailable('owner_cutoff_unavailable');
  let taskIds:unknown=run.task_ids;if(typeof taskIds==='string')taskIds=parseJson(taskIds,'owner_cutoff_mismatch');
  if(run.mode!=='training'||run.status!=='running'||run.cancellation_reason!==null||run.task_id!=='M1'||!Array.isArray(taskIds)||taskIds[target.taskIndex]!=='M1')
    return unavailable('unsupported_task');
  if(!run.started_at||run.task_status!=='running'||run.closure_status!=='closed'||!run.closure_id||run.action_cutoff_sequence===null)
    return unavailable('owner_cutoff_unavailable');
  const actionCutoff=sequence(run.action_cutoff_sequence),reconciled=sequence(run.reconciled_action_sequence);
  if(actionCutoff===null||reconciled===null||reconciled<actionCutoff)return unavailable('reconciliation_pending');
  if(actionCutoff>MAX_ACTIONS)return unavailable('owner_cutoff_mismatch');
  const closures=await ownerRows<ClosureProofRow>(tx,sql`SELECT id,operation_id,payload_hash,reason,answer_json,action_cutoff_sequence::text AS action_cutoff_sequence,owner_id,agent_id
    FROM oid_run_task_closure WHERE id=${run.closure_id} AND run_id=${target.runId} AND task_index=${target.taskIndex} FOR KEY SHARE`);
  const closure=closures[0];if(!closure||closure.owner_id!==run.owner_id||closure.agent_id!==run.agent_id||sequence(closure.action_cutoff_sequence)!==actionCutoff||
      closure.operation_id!==run.closure_operation_id||closure.payload_hash!==run.closure_payload_hash||closure.reason!==run.closure_reason||run.closure_reason===null)
    return unavailable('owner_cutoff_mismatch');
  const closureAnswer=parseJson(closure.answer_json,'owner_cutoff_mismatch');if(closureAnswer!==null)return unavailable('owner_cutoff_mismatch');

  const prepRows=await ownerRows<PrepRow>(tx,sql`SELECT i.preparation_id::text,i.claim_id::text,i.lease_id::text,i.environment_id,i.release_identity,i.manifest_hash,
      i.task_id,i.case_id,i.case_hash,i.initial_state_sha256,i.execution_identity_hash,i.environment_manifest_sha256,i.application_source_hash,i.created_at,
      l.state AS lease_state,o.status AS observation_status,o.generation_id::text,o.participant_id,o.payer_address,o.baseline_state_sha256,o.fixture_evidence,o.baseline_evidence
    FROM oid_task_preparation_intent i JOIN oid_task_environment_lease l ON l.preparation_id=i.preparation_id AND l.lease_id=i.lease_id
    JOIN LATERAL (SELECT status,generation_id,participant_id,payer_address,baseline_state_sha256,fixture_evidence,baseline_evidence
      FROM oid_task_preparation_observation WHERE preparation_id=i.preparation_id ORDER BY revision DESC LIMIT 1) o ON true
    WHERE i.run_id=${target.runId} AND i.task_index=${target.taskIndex} FOR UPDATE OF i,l`);
  const prep=prepRows[0];const participant=prep?normalizeAddress(prep.payer_address):null;
  if(prepRows.length!==1||!prep||prep.lease_state!=='leased'||prep.observation_status!=='ready'||!prep.generation_id||!prep.participant_id||!participant||
      prep.task_id!=='M1'||prep.release_identity!==run.release_identity||prep.manifest_hash!==run.manifest_hash||
      prep.baseline_state_sha256?.toLowerCase()!==prep.initial_state_sha256.toLowerCase())return unavailable('preparation_unavailable');
  const bindings=await ownerRows<{env_id:string;generation_id:string;manifest_hash:string;application_source_hash:string;participant_id:string;payer_address:string}>(tx,
    sql`SELECT env_id,generation_id::text,manifest_hash,application_source_hash,participant_id,payer_address FROM oid_task_execution_binding
      WHERE run_id=${target.runId} AND task_index=${target.taskIndex} FOR KEY SHARE`);
  const execution=bindings[0];if(bindings.length!==1||!execution||execution.env_id!==prep.environment_id||execution.generation_id!==prep.generation_id||
      execution.manifest_hash?.toLowerCase()!==prep.environment_manifest_sha256.toLowerCase()||
      execution.application_source_hash?.toLowerCase()!==prep.application_source_hash.toLowerCase()||execution.participant_id!==prep.participant_id||
      normalizeAddress(execution.payer_address)!==participant)return unavailable('preparation_unavailable');
  const release=await deps.taskReleaseSource.getValidatedReleaseRecord(run.release_identity,run.manifest_hash,tx);
  if(!release||release.releaseIdentity!==run.release_identity||release.manifestHash!==run.manifest_hash||
      release.manifest.releaseIdentity!==run.release_identity||release.manifest.manifestHash!==run.manifest_hash)return unavailable('release_binding_mismatch');
  const rawCase=release.manifest.cases.training.find((item)=>item.taskId==='M1');
  if(!rawCase||rawCase.caseId!==prep.case_id||rawCase.caseHash!==prep.case_hash||rawCase.executionIdentityHash!==prep.execution_identity_hash||
      rawCase.initialState.stateSha256.toLowerCase()!==prep.initial_state_sha256.toLowerCase()||rawCase.executionIdentityHash!==release.manifest.executionIdentityHash)
    return unavailable('release_binding_mismatch');
  const taskCase=rawCase as Extract<TaskCase,{taskId:'M1'}>;
  const binding:TaskEvidenceBinding={ownerId:run.owner_id,agentId:run.agent_id,runId:target.runId,environmentId:prep.environment_id,
    releaseIdentity:run.release_identity,manifestHash:run.manifest_hash,caseId:taskCase.caseId,caseHash:taskCase.caseHash,rubricHash:taskCase.rubricHash,taskId:'M1'};
  const actionRows=await ownerRows<ActionRow>(tx,sql`SELECT a.id::text,a.run_id::text,a.task_index,a.owner_id::text,a.agent_id::text,a.task_id,a.environment_id,
      a.action_sequence::text,a.operation_id,a.payload_hash,a.action_kind,a.command_json,r.receipt_revision,r.receipt_status,r.evidence_hash,r.evidence_path,r.transaction_hash,
      h.revision AS history_revision,h.receipt_status AS history_status,h.evidence_hash AS history_evidence_hash,h.evidence_path AS history_evidence_path,
      h.transaction_hash AS history_transaction_hash FROM oid_run_task_action a JOIN oid_run_task_action_receipt r ON r.action_id=a.id
    LEFT JOIN LATERAL (SELECT revision,receipt_status,evidence_hash,evidence_path,transaction_hash FROM oid_run_task_action_reconciliation
      WHERE action_id=a.id ORDER BY revision DESC LIMIT 1) h ON true
    WHERE a.run_id=${target.runId} AND a.task_index=${target.taskIndex} ORDER BY a.action_sequence FOR UPDATE OF a,r`);
  const postgres=deps.postgresByEnvironment[prep.environment_id],rpcPort=deps.rpcByEnvironment[prep.environment_id];
  if(!postgres||!rpcPort||postgres.environmentId!==prep.environment_id||rpcPort.environmentId!==prep.environment_id)return unavailable('source_not_configured');
  let manifest:ManifestData,prepared:PreparedEvidence;
  try{[manifest,prepared]=await Promise.all([loadManifest(deps.repositoryRoot,prep,taskCase,release),loadPreparedEvidence(deps.repositoryRoot,prep,target.runId,target.taskIndex,taskCase)]);}
  catch(error){if(error instanceof Unavailable)return unavailable(error.reasonCode);return unavailable('preparation_unavailable');}
  let actions:M1LoadedAction[];
  try{actions=await loadM1Actions(deps.repositoryRoot,run,prep,target.runId,target.taskIndex,actionCutoff,actionRows,taskCase,manifest.resourcePin);
    validateManifestReadActions(actions,manifest,taskCase);}
  catch(error){if(error instanceof Unavailable)return unavailable(error.reasonCode);return unavailable('action_evidence_unavailable');}
  const censusBefore=await captureCensus(postgres,prep.environment_id,prep.generation_id);
  const generation=censusBefore.census.generation;const local=isRecord(manifest.json.local)?manifest.json.local:null;
  const identity=release.manifest.executionIdentity;
  if(!participant||generation.env_id!==prep.environment_id||generation.generation_id!==prep.generation_id||generation.participant_id!==prep.participant_id||
      normalizeAddress(String(generation.payer_address))!==participant||String(generation.chain_id)!==String(identity.localChainId)||generation.status!=='active'||
      generation.resource_variant!=='canonical'||String(generation.manifest_sha256).toLowerCase()!==prep.environment_manifest_sha256.toLowerCase()||
      String(generation.environment_manifest_sha256).toLowerCase()!==prep.environment_manifest_sha256.toLowerCase()||!local||generation.node_identity!==local.identity)
    return unavailable('rpc_mapping_incomplete');
  let packetActions:M1CaptureAction[];
  try{packetActions=actions.map((action)=>({actionId:action.row.id,actionSequence:action.sequence,ownerOperationId:action.row.operation_id,
      actionKind:action.command.kind,commandSha256:action.row.payload_hash.toLowerCase(),receiptStatus:action.row.receipt_status as M1CaptureAction['receiptStatus'],
      actionEvidence:action.ref,befOperationId:action.evidence.befOperationId as string|null,transactionHash:normalizeHash(action.evidence.transactionHash),
      rawResponseSha256:typeof action.evidence.rawResponseSha256==='string'?action.evidence.rawResponseSha256.toLowerCase():null,
      participantToolResponse:action.response,paymentProtocol:action.protocol}));
    validateM1OperationCensus(censusBefore.census,actions,prep.environment_id,prep.generation_id,prep.participant_id,manifest.resourcePin);
  }catch(error){if(error instanceof Unavailable)return unavailable(error.reasonCode);return unavailable('rpc_mapping_incomplete');}
  const rpc=new RpcRecorder(rpcPort);let localChainId:bigint;let baseline:RpcCheckpoint;let final:RpcCheckpoint;let interval:Interval;
  try{
    const chainId=quantity(await rpc.request('eth_chainId',[]));if(chainId===null||chainId!==BigInt(identity.localChainId))return unavailable('rpc_identity_mismatch');
    localChainId=chainId;const identityAssets=assetMap(manifest.assets,Number(chainId));
    baseline=await readCheckpoint(rpc,taskCase,manifest.assets,identityAssets,participant,prepared.blockNumber);
    await verifyCode(rpc,manifest.assets,identity.contracts,Number(chainId),prepared.blockNumber);
    if(baseline.blockHash!==prepared.blockHash||canonicalTaskJson(caseCheckpointProjection(baseline,taskCase))!==canonicalTaskJson(stateProjection(taskCase.initialState)))
      return unavailable('baseline_mismatch');
    const initialNonce=quantity(await rpc.request('eth_getTransactionCount',[participant,`0x${prepared.blockNumber.toString(16)}`]));
    if(initialNonce===null)return unavailable('rpc_observation_unavailable');baseline.participantTransactionCount=initialNonce.toString();
    const head=quantity(await rpc.request('eth_blockNumber',[]));if(head===null||head<prepared.blockNumber)return unavailable('rpc_observation_unavailable');
    final=await readCheckpoint(rpc,taskCase,manifest.assets,identityAssets,participant,head);
    await verifyCode(rpc,manifest.assets,identity.contracts,Number(chainId),head);
    const finalNonce=quantity(await rpc.request('eth_getTransactionCount',[participant,`0x${head.toString(16)}`]));
    if(finalNonce===null)return unavailable('rpc_observation_unavailable');final.participantTransactionCount=finalNonce.toString();
    interval=await readInterval(rpc,manifest.assets,baseline,final,participant);
    const baselineAgain=blockHeader(await rpc.request('eth_getBlockByNumber',[`0x${prepared.blockNumber.toString(16)}`,false]),prepared.blockNumber);
    const finalAgain=blockHeader(await rpc.request('eth_getBlockByNumber',[`0x${head.toString(16)}`,false]),head);
    if(baselineAgain.hash!==baseline.blockHash||finalAgain.hash!==final.blockHash)return unavailable('rpc_mapping_incomplete');
    checkCheckpointEffects(taskCase,baseline,final,interval.transferLogs,participant);
  }catch(error){if(error instanceof Unavailable)return unavailable(error.reasonCode);return unavailable('rpc_observation_unavailable');}
  let paymentProofs:Json[];
  try{paymentProofs=await makePaymentProofs(rpc,interval,censusBefore.census,actions,participant,manifest.assets,prep.environment_manifest_sha256.toLowerCase());}
  catch(error){if(error instanceof Unavailable)return unavailable(error.reasonCode);return unavailable('rpc_observation_unavailable');}
  const censusAfter=await captureCensus(postgres,prep.environment_id,prep.generation_id);
  if(censusBefore.session.databaseName!==censusAfter.session.databaseName||canonicalTaskJson(censusBefore.census)!==canonicalTaskJson(censusAfter.census)||
      String(censusAfter.census.generation.status)!=='active')return unavailable('observer_census_changed');
  const packetValue={schemaVersion:'bts-m1-run-observation-capture/v1' as const,classification:'run_bound_observations_candidate_not_grade' as const,binding,
    closure:{closureId:closure.id,actionCutoffSequence:actionCutoff,reconciledActionSequence:reconciled,reason:closure.reason,operationId:closure.operation_id,
      payloadHash:closure.payload_hash,answer:closureAnswer},
    execution:{preparationId:prep.preparation_id,leaseId:prep.lease_id,generationId:prep.generation_id,environmentId:prep.environment_id,
      environmentManifestHash:prep.environment_manifest_sha256.toLowerCase(),applicationSourceHash:prep.application_source_hash.toLowerCase(),
      executionIdentityHash:prep.execution_identity_hash.toLowerCase(),initialStateSha256:prep.initial_state_sha256.toLowerCase()},
    preparation:{fixtureEvidence:prepared.fixture,baselineEvidence:prepared.baseline,baselineBlockNumber:prepared.blockNumber.toString(),baselineBlockHash:prepared.blockHash},
    ownerActions:packetActions,bef:{session:censusBefore.session,before:censusBefore.census,after:censusAfter.census,
      censusSha256:hashJson(censusBefore.census),resourcePin:manifest.resourcePin,
      environmentManifest:{encoding:'base64' as const,bytes:manifest.raw.toString('base64'),sha256:prep.environment_manifest_sha256.toLowerCase()}},
    rpc:{localChainId:localChainId.toString(),baseline,final,intervalBlocks:interval.blocks,participantLogQueryCount:interval.participantLogQueryCount,
      responseHashes:rpc.responseHashes,paymentProofs,participantTransferLogs:interval.transferLogs}};
  let packet:M1CapturePacket;
  try{packet=validateM1CapturePacket(packetValue);}catch{return unavailable('capture_evidence_unavailable');}
  if(hasSecret(packet)||Buffer.byteLength(canonicalTaskJson(packet),'utf8')>MAX_PACKET_BYTES)return unavailable('capture_evidence_unavailable');
  let evidence:EvidenceReference|null=null;try{evidence=evidenceRef(await deps.evidenceSink.write(packet));}catch{return unavailable('capture_evidence_unavailable');}
  if(!evidence||!evidence.path.startsWith(OBSERVATION_ROOT))return unavailable('capture_evidence_unavailable');
  let projection:ReturnType<typeof projectM1PacketObservations>;
  try{projection=projectM1PacketObservations(packet,{taskCase,binding,taskIndex:target.taskIndex,closureId:closure.id,captureEvidence:evidence,
      assets:manifest.assets.map((asset)=>({assetId:asset.assetId,address:asset.address,kind:asset.kind as 'native'|'erc20',chainId:asset.chainId}))});}
  catch{return unavailable('rpc_mapping_incomplete');}
  const sequenceNumbers=[...projection.transfers,...projection.payments,...projection.stateMutations,...projection.deliveries,...projection.expenses].map((item)=>item.sequence);
  const observationCutoff=sequenceNumbers.length?Math.max(...sequenceNumbers):0;
  const observations:PersistedTaskObservations={schemaVersion:'bts-task-observations/v1',binding,coveredThroughSequence:observationCutoff,captureEvidence:evidence,
    coverage:projection.coverage,transfers:projection.transfers,payments:projection.payments,stateMutations:projection.stateMutations,finalStates:[],
    allowanceChanges:[],allowanceUses:[],answers:[],selections:[],deliveries:projection.deliveries,trades:[],conversions:[],expenses:projection.expenses};
  const candidate:TaskObservationBundleCandidate={schemaVersion:'bts-task-observation-bundle-candidate/v1',observationCutoffSequence:observationCutoff,
    cutoffStatus:'authoritative',cutoffEvidence:evidence,observations};
  return {status:'candidate',candidate,evidence,classification:'run_bound_observations_candidate_not_grade'};
}

/** Collects a closed M1 training task into an unsealed candidate; no action dispatch, grading, or BEF writes occur here. */
export async function collectBefM1TaskObservationCandidate(deps:BefM1ObservationCollectorDependencies,target:{runId:string;taskIndex:number}):Promise<BefM1CollectionResult>{
  if(!UUID.test(target.runId)||!Number.isSafeInteger(target.taskIndex)||target.taskIndex<0||target.taskIndex>11)return unavailable('invalid_target');
  try{return await deps.db.transaction(async(tx)=>collectLocked(deps,target,tx));}
  catch(error){if(error instanceof Unavailable)return unavailable(error.reasonCode);return unavailable('owner_cutoff_unavailable');}
}






