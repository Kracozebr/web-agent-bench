import {collectBefChainTaskObservationCandidate,type BefChainObservationCollectorDependencies} from './bef-chain-observation-collector.js';
import {collectBefPaidDataObservationCandidate} from './bef-paid-data-observation-collector.js';
import {validateTaskChainCapturePacket} from './task-chain-capture-packet.js';
import {validatePaidDataCapturePacket} from './task-paid-data-capture-packet.js';
import {composeTaskObservationCandidates,validateCompositeCapturePacket,verifyCompositeCaptureChildren,type CompositeCapturePacket} from './task-composite-capture-packet.js';
import {canonicalTaskJson,type EvidenceReference} from './task-release.js';
import type {TaskObservationBundleCandidate} from './task-observation-store.js';
const same=(a:unknown,b:unknown)=>canonicalTaskJson(a)===canonicalTaskJson(b);
const unavailable=(reasonCode:string)=>({status:'unavailable' as const,reasonCode});
function candidate(value:unknown):value is TaskObservationBundleCandidate{return !!value&&typeof value==='object'&&
 (value as {schemaVersion?:unknown}).schemaVersion==='bts-task-observation-bundle-candidate/v1';}
/** No actor execution or grade writes. Each child retains its own bounded observer snapshot and evidence file. */
export async function collectBefCompositeObservationCandidate(deps:Omit<BefChainObservationCollectorDependencies,'evidenceSink'>&{evidenceSink:{write(packet:unknown):Promise<EvidenceReference>}},target:{runId:string;taskIndex:number}){
 try{
  let chainPacketValue:unknown,paidPacketValue:unknown;
  const paid=await collectBefPaidDataObservationCandidate({...deps,evidenceSink:{async write(packet){paidPacketValue=packet;return deps.evidenceSink.write(packet);}}},target);
  if(paid.status!=='candidate'||!candidate(paid.candidate))return unavailable(paid.status==='unavailable'?paid.reasonCode:'paid_typed_observations_unavailable');
  const chain=await collectBefChainTaskObservationCandidate({...deps,evidenceSink:{async write(packet){chainPacketValue=packet;return deps.evidenceSink.write(packet);}}},target);
  if(chain.status!=='candidate')return unavailable(chain.reasonCode);
  const paidPacket=validatePaidDataCapturePacket(paidPacketValue),chainPacket=validateTaskChainCapturePacket(chainPacketValue);
  if(!['H3','U1'].includes(chainPacket.taskId)||!same(paidPacket.binding,chainPacket.binding)||!same(paidPacket.execution,chainPacket.execution)||
   paidPacket.closure.closureId!==chainPacket.closure.closureId||paidPacket.closure.actionCutoffSequence!==chainPacket.closure.actionCutoffSequence||
   paidPacket.closure.reconciledActionSequence!==chainPacket.closure.reconciledActionSequence)return unavailable('composite_binding_mismatch');
  const paidBoundary={actionCutoffSequence:paidPacket.closure.actionCutoffSequence,observationCutoffSequence:paid.candidate.observationCutoffSequence,
   baselineBlockNumber:paidPacket.rpc.baselineBlock.number,baselineBlockHash:paidPacket.rpc.baselineBlock.hash,
   finalBlockNumber:paidPacket.rpc.finalBlock.number,finalBlockHash:paidPacket.rpc.finalBlock.hash};
  const packet:CompositeCapturePacket=validateCompositeCapturePacket({schemaVersion:'bts-composite-run-observation-capture/v1',
   classification:'run_bound_observations_candidate_not_grade',binding:chainPacket.binding,execution:chainPacket.execution,closure:paidPacket.closure,
   children:{paid:{evidence:paid.evidence,boundary:paidBoundary},chain:{evidence:chain.evidence,boundary:chain.boundary}}});
  verifyCompositeCaptureChildren(packet,paidPacket,chainPacket);
  // Validate composition before retaining the root. Child captures remain evidence even if this check fails.
  const provisional:EvidenceReference={path:'artifacts/runs/owner-identity-bef-task-coordinator/observation/composite-preflight.json',sha256:'0'.repeat(64),boundary:'actual_tool_http_x402_local_evm_application_store'};
  composeTaskObservationCandidates(packet,paid.candidate,chain.candidate,provisional);
  const evidence=await deps.evidenceSink.write(packet),merged=composeTaskObservationCandidates(packet,paid.candidate,chain.candidate,evidence);
  return{status:'candidate' as const,candidate:merged,evidence,packet,classification:'run_bound_observations_candidate_not_grade' as const};
 }catch{return unavailable('composite_observation_unavailable');}
}