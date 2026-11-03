import { createHash } from 'node:crypto';
import { lstat, open, realpath } from 'node:fs/promises';
import { resolve } from 'node:path';
import { collectBefPaidFamilyObservationCandidate } from './bef-paid-data-observation-collector.js';
import { collectBefChainFamilyObservationCandidate, type BefChainObservationCollectorDependencies } from './bef-chain-observation-collector.js';
import { composeAdmittedActionObservationCandidates, projectAdmittedActionFamilyCandidates,
  validateAdmittedActionsCapturePacket, AdmittedActionsCaptureError,
  type AdmittedActionsCapturePacket } from './task-admitted-actions-capture-packet.js';
import { canonicalTaskJson, type EvidenceReference } from './task-release.js';
import { PaidFamilyEffectProofUnavailable } from './paid-family-effect-proof.js';

const BOUNDARY='actual_tool_http_x402_local_evm_application_store' as const;
const ROOT='artifacts/runs/owner-identity-bef-task-coordinator/observation/';
type Dependencies=Omit<BefChainObservationCollectorDependencies,'evidenceSink'>&{
  evidenceSink:{write(packet:unknown):Promise<EvidenceReference>};
};
const unavailable=(reasonCode:string)=>({status:'unavailable' as const,reasonCode});
const same=(a:unknown,b:unknown)=>canonicalTaskJson(a)===canonicalTaskJson(b);

/** Read the single pinned public runtime manifest without an unbounded allocation or symlink. */
async function manifestBytes(repositoryRoot:string,expectedHash:string):Promise<Uint8Array>{
  const root=await realpath(repositoryRoot),path=resolve(root,'infrastructure/benchmark-environment/manifest.json');
  if(await realpath(path)!==path)throw new Error('ADMITTED_MANIFEST_UNAVAILABLE');
  const beforePath=await lstat(path,{bigint:true});
  if(!beforePath.isFile()||beforePath.isSymbolicLink())throw new Error('ADMITTED_MANIFEST_UNAVAILABLE');
  const handle=await open(path,'r');
  try{
    const before=await handle.stat({bigint:true});
    if(before.size<1n||before.size>262144n||before.dev!==beforePath.dev||before.ino!==beforePath.ino)
      throw new Error('ADMITTED_MANIFEST_UNAVAILABLE');
    const buffer=Buffer.alloc(262145);let size=0;
    for(;;){const part=await handle.read(buffer,size,buffer.length-size,size);size+=part.bytesRead;if(!part.bytesRead||size===buffer.length)break;}
    const after=await handle.stat({bigint:true}),afterPath=await lstat(path,{bigint:true});
    if(size!==Number(before.size)||before.dev!==after.dev||before.ino!==after.ino||before.size!==after.size||
      before.mtimeNs!==after.mtimeNs||before.ctimeNs!==after.ctimeNs||afterPath.dev!==after.dev||afterPath.ino!==after.ino||
      afterPath.size!==after.size||afterPath.mtimeNs!==after.mtimeNs||afterPath.ctimeNs!==after.ctimeNs||
      !afterPath.isFile()||afterPath.isSymbolicLink()||createHash('sha256').update(buffer.subarray(0,size)).digest('hex')!==expectedHash)
      throw new Error('ADMITTED_MANIFEST_UNAVAILABLE');
    return buffer.subarray(0,size);
  }finally{await handle.close();}
}

/**
 * AICODE-NOTE: Neither child can establish whole-task completeness on its own.
 * Every admitted action is joined to the same cutoff and both independently read
 * effect families before the unchanged rubric receives any observations.
 */
export async function collectBefAdmittedActionsObservationCandidate(deps:Dependencies,target:{runId:string;taskIndex:number}){
  try{
    const paid=await collectBefPaidFamilyObservationCandidate(deps,target);
    if(paid.status!=='candidate')return unavailable('paid_family_'+paid.reasonCode);
    const chain=await collectBefChainFamilyObservationCandidate(deps,target);
    if(chain.status!=='candidate')return unavailable('chain_family_'+chain.reasonCode);
    if(!paid.census||!paid.taskCase||!chain.census||!chain.packet||
      !same(paid.census,chain.census))return unavailable('admitted_action_census_changed');
    const census=paid.census;
    const release=await deps.taskReleaseSource.getValidatedReleaseRecord(census.binding.releaseIdentity,census.binding.manifestHash);
    if(!release||release.manifest.executionIdentityHash!==census.execution.executionIdentityHash)
      return unavailable('admitted_release_binding_mismatch');
    const environmentManifest=await manifestBytes(deps.repositoryRoot,release.manifest.executionIdentity.environmentManifestSha256);
    const packet:AdmittedActionsCapturePacket=validateAdmittedActionsCapturePacket({
      schemaVersion:'bts-admitted-actions-observation-capture/v1',classification:'run_bound_observations_candidate_not_grade',
      binding:census.binding,taskIndex:census.taskIndex,execution:census.execution,closure:census.closure,
      closureAnswer:paid.closureAnswer,
      census:{schemaVersion:'bts-admitted-action-census-reference/v1',entries:census.entries.map(({document,...entry})=>entry)},
      children:{paid:{evidence:paid.evidence,boundary:paid.boundary},chain:{evidence:chain.evidence,boundary:chain.boundary}}
    });
    const options={taskCase:paid.taskCase,paidPacket:paid.packet,chainPacket:chain.packet,census,
      localChainId:release.manifest.executionIdentity.localChainId,executionIdentity:release.manifest.executionIdentity,
      environmentManifest,ethValuation:release.manifest.costPolicy.ethValuation};
    const children=projectAdmittedActionFamilyCandidates(packet,options);
    const provisional:EvidenceReference={path:ROOT+'admitted-preflight.json',sha256:'0'.repeat(64),boundary:BOUNDARY};
    composeAdmittedActionObservationCandidates(packet,children.paid,children.chain,provisional,options);
    const evidence=await deps.evidenceSink.write(packet);
    if(evidence.boundary!==BOUNDARY||!evidence.path.startsWith(ROOT)||!/^[0-9a-f]{64}$/.test(evidence.sha256))
      return unavailable('admitted_capture_evidence_unavailable');
    const candidate=composeAdmittedActionObservationCandidates(packet,children.paid,children.chain,evidence,options);
    return {status:'candidate' as const,classification:'run_bound_observations_candidate_not_grade' as const,
      candidate,evidence,packet};
  }catch(error){
    if(error instanceof PaidFamilyEffectProofUnavailable)return unavailable(error.reasonCode);
    if(error instanceof AdmittedActionsCaptureError)return unavailable(error.code.toLowerCase());
    if(error instanceof Error&&error.message==='PAID_FAMILY_EFFECTS_UNVERIFIED')return unavailable('paid_family_effects_unverified');
    if(error instanceof Error&&error.message==='ADMITTED_MANIFEST_UNAVAILABLE')return unavailable('admitted_manifest_unavailable');
    return unavailable('admitted_family_observation_unavailable');
  }
}
