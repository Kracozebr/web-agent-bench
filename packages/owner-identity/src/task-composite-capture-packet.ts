import type {ChainCapturePacket} from './task-chain-capture-packet.js';
import type {PaidDataCapturePacket} from './task-paid-data-capture-packet.js';
/** Composite evidence retains each child's original sequence and raw evidence reference. */
import {canonicalTaskJson,type EvidenceReference} from './task-release.js';
import type {PersistedTaskObservations,TaskEvidenceBinding,ObservationDomain} from './task-evaluator.js';
import type {TaskObservationBundleCandidate} from './task-observation-store.js';
export type CompositeObservationBoundary={actionCutoffSequence:number;observationCutoffSequence:number;baselineBlockNumber:string;baselineBlockHash:string;finalBlockNumber:string;finalBlockHash:string};
export type CompositeCapturePacket={schemaVersion:'bts-composite-run-observation-capture/v1';classification:'run_bound_observations_candidate_not_grade';
 binding:TaskEvidenceBinding;execution:Record<string,unknown>;closure:Record<string,unknown>;
 children:{paid:{evidence:EvidenceReference;boundary:CompositeObservationBoundary};chain:{evidence:EvidenceReference;boundary:CompositeObservationBoundary}}};
const BOUNDARY='actual_tool_http_x402_local_evm_application_store';
function fail():never{throw new Error('composite_observation_proof_invalid');}
function rec(v:unknown):v is Record<string,unknown>{return !!v&&typeof v==='object'&&!Array.isArray(v);}
const same=(a:unknown,b:unknown)=>canonicalTaskJson(a)===canonicalTaskJson(b);
function ref(v:unknown):v is EvidenceReference{return rec(v)&&Object.keys(v).sort().join(',')==='boundary,path,sha256'&&v.boundary===BOUNDARY&&
 typeof v.sha256==='string'&&/^[0-9a-f]{64}$/.test(v.sha256)&&typeof v.path==='string'&&
 /^artifacts\/runs\/owner-identity-bef-task-coordinator\/observation\/[A-Za-z0-9._/-]+$/.test(v.path)&&!v.path.split('/').some(s=>s==='.'||s==='..'||!s);}
function boundary(v:unknown):v is CompositeObservationBoundary{if(!rec(v)||Object.keys(v).sort().join(',')!=='actionCutoffSequence,baselineBlockHash,baselineBlockNumber,finalBlockHash,finalBlockNumber,observationCutoffSequence')return false;
 return ['actionCutoffSequence','observationCutoffSequence'].every(k=>Number.isSafeInteger(v[k])&&Number(v[k])>=0)&&
 ['baselineBlockNumber','finalBlockNumber'].every(k=>typeof v[k]==='string'&&/^(0|[1-9][0-9]*)$/.test(v[k] as string))&&
 ['baselineBlockHash','finalBlockHash'].every(k=>typeof v[k]==='string'&&/^0x[0-9a-f]{64}$/i.test(v[k] as string));}
export function validateCompositeCapturePacket(v:unknown):CompositeCapturePacket{
 if(!rec(v)||Object.keys(v).sort().join(',')!=='binding,children,classification,closure,execution,schemaVersion'||v.schemaVersion!=='bts-composite-run-observation-capture/v1'||
 v.classification!=='run_bound_observations_candidate_not_grade'||!rec(v.binding)||!['H3','U1'].includes(String(v.binding.taskId))||!rec(v.execution)||!rec(v.closure)||!rec(v.children)||
 Object.keys(v.children).sort().join(',')!=='chain,paid')fail();
 for(const child of Object.values(v.children)){if(!rec(child)||Object.keys(child).sort().join(',')!=='boundary,evidence'||!ref(child.evidence)||!boundary(child.boundary))fail();}
 const binding=v.binding,execution=v.execution;
 const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,hash=/^[0-9a-f]{64}$/;
 if(Object.keys(v.binding).sort().join(',')!=='agentId,caseHash,caseId,environmentId,manifestHash,ownerId,releaseIdentity,rubricHash,runId,taskId'||
 !['runId','ownerId','agentId'].every(k=>typeof binding[k]==='string'&&uuid.test(binding[k] as string))||
 !['caseHash','manifestHash','rubricHash'].every(k=>typeof binding[k]==='string'&&hash.test(binding[k] as string))||
 !['caseId','environmentId','releaseIdentity'].every(k=>typeof binding[k]==='string'&&/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/.test(binding[k] as string)))fail();
 if(Object.keys(v.execution).sort().join(',')!=='applicationSourceHash,environmentId,environmentManifestHash,executionIdentityHash,generationId,initialStateSha256,leaseId,preparationId'||
 v.execution.environmentId!==v.binding.environmentId||!['preparationId','leaseId','generationId'].every(k=>typeof execution[k]==='string'&&uuid.test(execution[k] as string))||
 !['applicationSourceHash','environmentManifestHash','executionIdentityHash','initialStateSha256'].every(k=>typeof execution[k]==='string'&&hash.test(execution[k] as string)))fail();
 if(Object.keys(v.closure).sort().join(',')!=='actionCutoffSequence,closureId,operationId,payloadHash,reason,reconciledActionSequence'||
 typeof v.closure.closureId!=='string'||!uuid.test(v.closure.closureId)||!(v.closure.operationId===null||typeof v.closure.operationId==='string'&&/^[A-Za-z0-9_-]{12,128}$/.test(v.closure.operationId))||
 typeof v.closure.payloadHash!=='string'||!hash.test(v.closure.payloadHash)||!['agent_finish','task_deadline','run_deadline'].includes(String(v.closure.reason)))fail();
 const p=v as unknown as CompositeCapturePacket,a=p.children.paid.boundary,b=p.children.chain.boundary;
 if(p.children.paid.evidence.path===p.children.chain.evidence.path||
 ['actionCutoffSequence','baselineBlockNumber','baselineBlockHash','finalBlockNumber','finalBlockHash'].some(k=>a[k as keyof typeof a]!==b[k as keyof typeof b])||
 p.closure.actionCutoffSequence!==a.actionCutoffSequence||p.closure.reconciledActionSequence!==a.actionCutoffSequence)fail();
 return structuredClone(p);
}
export function parseCompositeCapturePacket(bytes:Uint8Array):CompositeCapturePacket{if(bytes.length===0||bytes.length>32768)fail();return validateCompositeCapturePacket(JSON.parse(Buffer.from(bytes).toString('utf8')));}
/** Both children must already have been independently reprojected from their retained raw packet. */
export function composeTaskObservationCandidates(packetValue:unknown,paid:TaskObservationBundleCandidate,chain:TaskObservationBundleCandidate,root:EvidenceReference):TaskObservationBundleCandidate{
 const packet=validateCompositeCapturePacket(packetValue);if(!ref(root))fail();
 for(const [key,child] of [['paid',paid],['chain',chain]] as const){const obs=child.observations,pin=packet.children[key];
  if(child.schemaVersion!=='bts-task-observation-bundle-candidate/v1'||child.cutoffStatus!=='authoritative'||!obs||
   !same(obs.binding,packet.binding)||!same(child.cutoffEvidence,pin.evidence)||!same(obs.captureEvidence,pin.evidence)||
   obs.coveredThroughSequence!==pin.boundary.observationCutoffSequence||child.observationCutoffSequence!==pin.boundary.observationCutoffSequence)fail();
 }
 const p=paid.observations!,c=chain.observations!,cutoff=Math.max(p.coveredThroughSequence,c.coveredThroughSequence);
 // AICODE-NOTE: Paid facts own payments/delivery; chain owns final balances/allowances/routes. Never infer missing child coverage.
 const coverage:PersistedTaskObservations['coverage']={...c.coverage};
 for(const domain of ['payments','deliveries'] as ObservationDomain[])coverage[domain]=p.coverage[domain]??'incomplete';
 for(const domain of ['transfers','expenses','stateMutations'] as ObservationDomain[]){coverage[domain]=[p.coverage[domain],c.coverage[domain]].every(s=>s==='complete')?'complete':
  [p.coverage[domain],c.coverage[domain]].includes('contradictory')?'contradictory':'incomplete';}
 if(c.finalStates.length!==1||c.finalStates[0]!.sequence!==cutoff)fail();
 const expenses=[...p.expenses,...c.expenses];const expenseKeys=expenses.map(e=>e.component+':'+e.transactionHash);
 if(new Set(expenseKeys).size!==expenseKeys.length)fail();
 const observations:PersistedTaskObservations={schemaVersion:'bts-task-observations/v1',binding:packet.binding,coveredThroughSequence:cutoff,captureEvidence:root,coverage,
  transfers:[...p.transfers,...c.transfers],payments:p.payments,stateMutations:[...p.stateMutations,...c.stateMutations],finalStates:c.finalStates,
  allowanceChanges:c.allowanceChanges,allowanceUses:c.allowanceUses,answers:[...p.answers,...c.answers],selections:[...p.selections,...c.selections],
  deliveries:p.deliveries,trades:c.trades,conversions:c.conversions,expenses};
 const ids=new Set<string>();for(const list of Object.values(observations)){if(!Array.isArray(list))continue;for(const item of list){
  if(!rec(item)||typeof item.observationId!=='string'||ids.has(item.observationId)||!Number.isSafeInteger(item.sequence)||Number(item.sequence)>cutoff||
   !same(item.binding,packet.binding)||![packet.children.paid.evidence,packet.children.chain.evidence].some(e=>same(e,item.evidence)))fail();ids.add(item.observationId);
 }}
 return{schemaVersion:'bts-task-observation-bundle-candidate/v1',observationCutoffSequence:cutoff,cutoffStatus:'authoritative',cutoffEvidence:root,observations:structuredClone(observations)};
}
/** Cross-child identity checks supplement each child's own strict parser and independent raw-file hashing. */
export function verifyCompositeCaptureChildren(packetValue:unknown,paid:PaidDataCapturePacket,chain:ChainCapturePacket):void{
 const root=validateCompositeCapturePacket(packetValue);
 if(!same(root.binding,paid.binding)||!same(root.binding,chain.binding)||!same(root.execution,paid.execution)||!same(root.execution,chain.execution)||
  !same(root.closure,paid.closure)||chain.closure.closureId!==paid.closure.closureId||chain.closure.actionCutoffSequence!==paid.closure.actionCutoffSequence||
  chain.closure.reconciledActionSequence!==paid.closure.reconciledActionSequence)fail();
 const p=root.children.paid.boundary,c=root.children.chain.boundary;
 if(p.baselineBlockNumber!==paid.rpc.baselineBlock.number||p.baselineBlockHash!==paid.rpc.baselineBlock.hash||p.finalBlockNumber!==paid.rpc.finalBlock.number||p.finalBlockHash!==paid.rpc.finalBlock.hash||
 c.baselineBlockNumber!==chain.rpc.baseline.blockNumber||c.baselineBlockHash!==chain.rpc.baseline.blockHash||c.finalBlockNumber!==chain.rpc.final.blockNumber||c.finalBlockHash!==chain.rpc.final.blockHash)fail();
 if(chain.externalActions.length!==paid.ownerActions.length)fail();
 for(let i=0;i<paid.ownerActions.length;i++){const a=paid.ownerActions[i]!,b=chain.externalActions[i]!;
  for(const key of ['actionId','actionSequence','ownerOperationId','actionKind','commandSha256','receiptStatus','actionEvidence','befOperationId','transactionHash'] as const)
   if(!same(a[key],b[key]))fail();
 }
 const paidHashes=new Set<string>();
 for(const effect of paid.rpc.paymentEffects){const tx=effect.transaction,receipt=effect.receipt;
  if(!rec(tx)||!rec(receipt)||typeof effect.transactionHash!=='string'||paidHashes.has(effect.transactionHash.toLowerCase()))fail();
  paidHashes.add(effect.transactionHash.toLowerCase());
  const found=chain.rpc.transactions.filter(t=>t.hash.toLowerCase()===effect.transactionHash!.toString().toLowerCase());if(found.length!==1)fail();const match=found[0]!;
  const hashProof=match as unknown as Record<string,unknown>;
  if(hashProof.inputSha256!==tx.inputSha256||hashProof.receiptLogsSha256!==receipt.logsSha256||hashProof.input!==null)fail();
  if(match.hash!==tx.hash||match.from!==tx.from||match.to!==tx.to||match.nonce!==tx.nonce||match.valueWei!==tx.value||match.blockNumber!==tx.blockNumber||match.blockHash!==tx.blockHash||
   match.hash!==receipt.transactionHash||match.transactionIndex!==receipt.transactionIndex||match.blockNumber!==receipt.blockNumber||match.blockHash!==receipt.blockHash||
   match.status!==receipt.status||match.gasUsed!==receipt.gasUsed||match.effectiveGasPriceWei!==receipt.effectiveGasPriceWei)fail();
 }
 const observedPays=paid.ownerActions.filter(a=>['pay','purchase'].includes(a.actionKind)&&a.receiptStatus==='observed').map(a=>a.transactionHash?.toLowerCase());
 if(observedPays.some(h=>!h||!paidHashes.has(h))||new Set(observedPays).size!==paidHashes.size)fail();
}