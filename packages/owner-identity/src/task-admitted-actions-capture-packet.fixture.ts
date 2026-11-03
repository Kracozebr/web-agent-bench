import { createHash } from 'node:crypto';
import { makeZeroActionChainFamilyCaptureFixture } from './task-chain-family-capture-packet.fixture.js';
import {makeRejectedSwapFamilyFixture} from './task-rejected-swap-proof.fixture.js';
import type {AdmittedActionRow} from './bef-admitted-action-census.js';
import { canonicalTaskJson, sha256CanonicalTaskJson, type EvidenceReference } from './task-release.js';
import { validateAdmittedActionCensus } from './bef-admitted-action-census.js';
import { projectAdmittedActionFamilyCandidates, type AdmittedActionsCapturePacket } from './task-admitted-actions-capture-packet.js';
import type { PaidDataCapturePacket } from './task-paid-data-capture-packet.js';

// AICODE-NOTE: Complete synthetic codec fixture for strict replay tests. It does not qualify
// a physical environment, a native model or an actual benchmark outcome.
export async function makeAdmittedActionsCaptureFixture(options:{rejectedSwap?:boolean}={}) {
  const rejection=options.rejectedSwap?makeRejectedSwapFamilyFixture():undefined;
  const chainFixture = rejection??makeZeroActionChainFamilyCaptureFixture();
  const chain = chainFixture.packet, { taskCase, context } = chainFixture;
  const closure = { ...chain.closure, reason: 'agent_finish' as const, operationId: 'unit_actual_finish_operation',
    payloadHash: sha256CanonicalTaskJson({ action: 'task_finish', runId: chain.binding.runId, taskIndex: 0, answer: null }) };
  const generation = { ...(chain.bef.before.generation as Record<string, unknown>), resource_variant: 'canonical' };
  const before = { generation, operations: [], payments: [], deliveries: [], costs: [], x402Observations: [] };
  const paid: PaidDataCapturePacket = { schemaVersion: 'bts-paid-family-observation-capture/v1',
    classification: 'run_bound_observations_candidate_not_grade', binding: chain.binding, execution: chain.execution, closure,
    preparation: { fixtureEvidence: chain.preparation.fixtureEvidence, baselineEvidence: chain.preparation.baselineEvidence,
      baselineBlockNumber: chain.preparation.baselineBlockNumber, baselineBlockHash: chain.preparation.baselineBlockHash },
    manifest: { sha256: chain.execution.environmentManifestHash, paymentPolicy: {}, catalog: [], componentReferences: [] },
    ownerActions: [], bef: { session: chain.bef.session, before, after: structuredClone(before), censusSha256: sha256CanonicalTaskJson(before) },
    rpc: { localChainId: chain.rpc.localChainId, baselineBlock: { number: chain.rpc.baseline.blockNumber, hash: chain.rpc.baseline.blockHash },
      finalBlock: { number: chain.rpc.final.blockNumber, hash: chain.rpc.final.blockHash }, paymentEffects: [] },
    coverage: { actionCutoffSequence: closure.actionCutoffSequence, observationCutoffSequence: 0, ownerActionCount: closure.actionCutoffSequence, paidActionCount: 0,
      befPaymentCount: 0, deliveryCount: 0, costCount: 0, rpcPaymentProofCount: 0, status: 'observed' } };
  const bytes = (value: unknown) => Buffer.from(canonicalTaskJson(value));
  const evidence = (name: string, value: unknown): EvidenceReference => ({
    path: 'artifacts/runs/owner-identity-bef-task-coordinator/observation/' + name + '.json',
    sha256: createHash('sha256').update(bytes(value)).digest('hex'), boundary: 'actual_tool_http_x402_local_evm_application_store' });
  const actionRows:AdmittedActionRow[]=[],actionDocuments=new Map<string,Buffer>();
  if(rejection){const a=rejection.action,d=rejection.document,raw=bytes(d),sha256=createHash('sha256').update(raw).digest('hex');a.actionEvidence.sha256=sha256;actionDocuments.set(a.actionEvidence.path,raw);
    actionRows.push({id:a.actionId,run_id:chain.binding.runId,task_index:0,owner_id:chain.binding.ownerId,agent_id:chain.binding.agentId,task_id:chain.binding.taskId,environment_id:chain.binding.environmentId,action_sequence:1,operation_id:a.ownerOperationId,payload_hash:a.commandSha256,action_kind:'swap',command_json:a.command,receipt_revision:1,receipt_status:a.receiptStatus,evidence_hash:sha256,evidence_path:a.actionEvidence.path,transaction_hash:null,history_revision:1,history_status:a.receiptStatus,history_evidence_hash:sha256,history_evidence_path:a.actionEvidence.path,history_transaction_hash:null,tool_response_json:null,tool_response_hash:null,history_tool_response_json:null,history_tool_response_hash:null});}
  const census = await validateAdmittedActionCensus({ binding: chain.binding, taskIndex: 0, execution: chain.execution,
    closure, rows: actionRows, readActionEvidence: async ref => {const raw=actionDocuments.get(ref.path);if(!raw)throw new Error('unexpected action read');return raw;} });
  const chainRef = evidence('generic-chain-fixture', chain), paidRef = evidence('generic-paid-fixture', paid);
  const packet: AdmittedActionsCapturePacket = { schemaVersion: 'bts-admitted-actions-observation-capture/v1',
    classification: 'run_bound_observations_candidate_not_grade', binding: chain.binding, taskIndex: 0,
    execution: chain.execution, closure, closureAnswer: null,
    census: { schemaVersion: 'bts-admitted-action-census-reference/v1', entries: census.entries.map(({document:_document,...entry})=>entry) },
    children: { paid: { evidence: paidRef, boundary: { actionCutoffSequence: closure.actionCutoffSequence, observationCutoffSequence: 0,
      baselineBlockNumber: chain.rpc.baseline.blockNumber, baselineBlockHash: chain.rpc.baseline.blockHash,
      finalBlockNumber: chain.rpc.final.blockNumber, finalBlockHash: chain.rpc.final.blockHash } },
      chain: { evidence: chainRef, boundary: { actionCutoffSequence: closure.actionCutoffSequence, observationCutoffSequence: 1,
        baselineBlockNumber: chain.rpc.baseline.blockNumber, baselineBlockHash: chain.rpc.baseline.blockHash,
        finalBlockNumber: chain.rpc.final.blockNumber, finalBlockHash: chain.rpc.final.blockHash } } } };
  const projectionOptions = { ...context, taskCase, paidPacket: paid, chainPacket: chain, census, localChainId: context.executionIdentity.localChainId };
  const projected = projectAdmittedActionFamilyCandidates(packet, projectionOptions);
  // Preserve the actual strict projector's cutoff rather than inventing its value.
  packet.children.chain.boundary.observationCutoffSequence = projected.chain.observationCutoffSequence;
  packet.children.paid.boundary.observationCutoffSequence = projected.paid.observationCutoffSequence;
  const root = evidence('generic-root-fixture', packet);
  return { packet, paid, chain, census, taskCase, context, options:projectionOptions, projected, root,actionRows,
    files: new Map([[paidRef.path, bytes(paid)], [chainRef.path, bytes(chain)], [root.path, bytes(packet)],...actionDocuments]) };
}
