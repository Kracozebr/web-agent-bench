import assert from 'node:assert/strict';
import test from 'node:test';
import { validPaidDataCapturePacket, fixtureRetrievedResponse } from './task-paid-data-capture-packet.fixture.js';
import { validatePaidDataCapturePacket, validatePaidFamilyCapturePacket, parsePaidFamilyCapturePacket,
  projectPaidDataObservationBundle } from './task-paid-data-capture-packet.js';
import type { TaskCase } from './task-release.js';
import type { TaskEvidenceBinding } from './task-evaluator.js';

test('paid-family evidence retains every real task identity while the legacy parser stays restricted', () => {
  for (const taskId of ['S1','S2','S3','S4','M1','M2','M3','M4','H1','H2','H3','U1'] as const) {
    const packet=validPaidDataCapturePacket();
    packet.schemaVersion='bts-paid-family-observation-capture/v1';packet.binding.taskId=taskId;
    assert.equal(validatePaidFamilyCapturePacket(packet).binding.taskId,taskId);
    assert.equal(parsePaidFamilyCapturePacket(Buffer.from(JSON.stringify(packet))).binding.taskId,taskId);
    assert.throws(()=>validatePaidDataCapturePacket(packet));
    if (!['M1','M2','H1','H3','U1'].includes(taskId)) {
      packet.schemaVersion='bts-paid-data-run-observation-capture/v1';
      assert.throws(()=>validatePaidDataCapturePacket(packet));
    }
  }
});

test('paid-family projection cannot claim global effects complete even with observed paid receipts', () => {
  const packet=validPaidDataCapturePacket();packet.schemaVersion='bts-paid-family-observation-capture/v1';
  // Identity/projection fixture only. Independent chain and environment gates remain separate.
  const taskCase={taskId:'H1',caseId:packet.binding.caseId,caseHash:packet.binding.caseHash,
    objective:{requiredComponents:packet.manifest.componentReferences.map(component=>({...component,
      sourceIds:['public-benchmark-fixture'],validator:{}}))}} as unknown as TaskCase;
  const candidate=projectPaidDataObservationBundle(packet,{taskCase,binding:packet.binding as TaskEvidenceBinding,
    captureEvidence:{path:'artifacts/runs/owner-identity-bef-task-coordinator/observation/paid-family-fixture.json',
      sha256:'a'.repeat(64),boundary:'actual_tool_http_x402_local_evm_application_store'},
    assets:[{assetId:'USDC',kind:'erc20',chainId:8453,address:'0x'+'2'.repeat(40)}],
    actionResponses:new Map(packet.ownerActions.filter(action=>action.actionKind==='retrieve')
      .map(action=>[action.actionId,fixtureRetrievedResponse]))});
  assert.ok(candidate.observations!.payments.length>0);
  for (const domain of ['transfers','stateMutations','expenses','balances','allowances','trades','conversions'] as const)
    assert.equal(candidate.observations!.coverage[domain],'incomplete',domain);
});

test('a missing paid action cannot be hidden by retaining the application coverage count', () => {
  const packet=validPaidDataCapturePacket();packet.schemaVersion='bts-paid-family-observation-capture/v1';
  packet.ownerActions.pop();
  assert.throws(()=>validatePaidFamilyCapturePacket(packet));
});

test('family schema rejects unknown task identities and secret-bearing additions', () => {
  const packet=validPaidDataCapturePacket();packet.schemaVersion='bts-paid-family-observation-capture/v1';
  assert.throws(()=>validatePaidFamilyCapturePacket({...packet,binding:{...packet.binding,taskId:'S99'}}));
  assert.throws(()=>validatePaidFamilyCapturePacket({...packet,authorization:'synthetic-canary-never-an-actual-credential'}));
});

test('a fully verified off-goal delivery stays visible to the unchanged rubric in a family capture',()=>{
  const legacy=validPaidDataCapturePacket(),family=structuredClone(legacy);
  family.schemaVersion='bts-paid-family-observation-capture/v1';
  const taskCase={taskId:'H1',caseId:legacy.binding.caseId,caseHash:legacy.binding.caseHash,
    objective:{requiredComponents:legacy.manifest.componentReferences.map(component=>({...component,
      sourceIds:['public-benchmark-fixture'],validator:{}}))}} as unknown as TaskCase;
  const context={taskCase,binding:legacy.binding as TaskEvidenceBinding,
    captureEvidence:{path:'artifacts/runs/owner-identity-bef-task-coordinator/observation/off-goal-family-fixture.json',
      sha256:'b'.repeat(64),boundary:'actual_tool_http_x402_local_evm_application_store' as const},
    assets:[{assetId:'USDC',kind:'erc20' as const,chainId:8453,address:'0x'+'2'.repeat(40)}],
    actionResponses:new Map(legacy.ownerActions.filter(action=>action.actionKind==='retrieve')
      .map(action=>[action.actionId,fixtureRetrievedResponse]))};
  assert.equal(projectPaidDataObservationBundle(legacy,context).observations!.deliveries.length,0);
  const projected=projectPaidDataObservationBundle(family,context).observations!;
  assert.equal(projected.deliveries.length,2);
  assert.ok(projected.deliveries.every(delivery=>delivery.resourceId==='resource-market-snapshot'&&
    delivery.componentId==='observed-resource:resource-market-snapshot'));
  const invalid=structuredClone(context);
  invalid.actionResponses.clear();
  assert.notEqual(projectPaidDataObservationBundle(family,invalid).observations!.coverage.deliveries,'complete');
});
