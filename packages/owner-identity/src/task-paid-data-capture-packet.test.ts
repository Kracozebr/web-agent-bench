import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { canonicalTaskJson, sha256CanonicalTaskJson, type TaskCase } from './task-release.js';
import { PaidDataCapturePacketError, parsePaidDataCapturePacket, projectPaidDataCaptureCandidate, projectPaidDataObservationBundle,
  validatePaidDataCapturePacket, validatePaidDataCapturePacketPins } from './task-paid-data-capture-packet.js';
import { fixturePayload, fixtureRetrievedResponse, paymentOperationIds, validPaidDataCapturePacket } from './task-paid-data-capture-packet.fixture.js';
import {projectPaidDataPaymentProtocol} from './bef-paid-data-observation-collector.js';

const hash=(value:Uint8Array|string)=>createHash('sha256').update(value).digest('hex');

test('actual collector protocol projection retains modern pay and retrieve identities through H1 packet projection',()=>{
 const {packet,context}=closedUnrequestedSecondPayment('H1');
 const signer=`0x${'a'.repeat(40)}`,payee=`0x${'3'.repeat(40)}`;
 for(const action of packet.ownerActions){
  const old=action.paymentProtocol;
  if(!old)continue;
  const legacy=projectPaidDataPaymentProtocol(old);
  assert.deepEqual(projectPaidDataPaymentProtocol({...old,facilitatorAddress:signer}),legacy);
  action.paymentProtocol=projectPaidDataPaymentProtocol({...old,paymentRecipient:payee,...(action.actionKind==='pay'?{facilitatorAddress:signer}:{})});
  assert.equal(action.paymentProtocol!.paymentRecipient,payee);
 }
 const census=packet.bef.after as Record<string,any>;
 for(const payment of census.payments){payment.payment_recipient=payee;payment.facilitator_address=signer;}
 validatePaidDataCapturePacket(packet);
 const candidate=projectPaidDataObservationBundle(packet,context);
 assert.equal(candidate.observations!.payments.length,2);
 assert.ok(candidate.observations!.payments.every(p=>p.status==='settled'&&p.requirements.recipient===payee));
 assert.ok(candidate.observations!.stateMutations.every(m=>!m.key.startsWith(signer)));
 const bad=structuredClone(packet),pay=bad.ownerActions.find(a=>a.actionKind==='pay')!;
 pay.paymentProtocol=projectPaidDataPaymentProtocol({...pay.paymentProtocol,paymentRecipient:null});
 assert.equal(pay.paymentProtocol!.paymentRecipient,null);
 assert.throws(()=>validatePaidDataCapturePacket(bad),PaidDataCapturePacketError);
});

function closedUnrequestedSecondPayment(taskId: 'M1'|'M2'|'H1'|'H3'|'U1' = 'H1') {
  const packet=validPaidDataCapturePacket();
  packet.binding.taskId=taskId;
  packet.ownerActions=packet.ownerActions.filter((action)=>!(action.actionKind==='retrieve'&&action.befOperationId===paymentOperationIds.second));
  packet.closure.actionCutoffSequence=4;packet.closure.reconciledActionSequence=4;packet.closure.reason='task_deadline';
  const after=packet.bef.after as Record<string,any>;
  for(const row of after.x402Observations)Object.assign(row,{env_id:packet.execution.environmentId,generation_id:packet.execution.generationId});
  after.deliveries=after.deliveries.filter((delivery:Record<string,unknown>)=>delivery.operation_id!==paymentOperationIds.second);
  after.operations.find((operation:Record<string,unknown>)=>operation.operation_id===paymentOperationIds.second).status='settled';
  for(const effect of packet.rpc.paymentEffects)(effect.receipt as Record<string,unknown>).status='success';
  const component={componentId:taskId==='M2'?'stream':'market-reference',resourceId:'resource-market-snapshot'};
  packet.manifest.componentReferences=[{...component}];
  const objective=taskId==='M1'?{component}:taskId==='H3'?{referenceComponent:component,routeObjective:{referenceField:'priceBand'}}:
    taskId==='M2'?{catalog:[{offerId:'stream',resourceId:component.resourceId}]}:{requiredComponents:[component]};
  const taskCase={...h1Case(packet),taskId,objective} as unknown as TaskCase;
  const refresh=()=>{
    packet.bef.before=structuredClone(packet.bef.after);packet.bef.censusSha256=sha256CanonicalTaskJson(packet.bef.after);
    packet.coverage={...packet.coverage,actionCutoffSequence:packet.closure.actionCutoffSequence,
      ownerActionCount:packet.closure.actionCutoffSequence,paidActionCount:packet.ownerActions.length,
      deliveryCount:(packet.bef.after.deliveries as unknown[]).length,
      rpcPaymentProofCount:packet.rpc.paymentEffects.filter((effect)=>effect.verification==='observed').length};
  };
  refresh();
  const context={taskCase,binding:packet.binding as unknown as import('./task-evaluator.js').TaskEvidenceBinding,
    captureEvidence:{path:'artifacts/runs/owner-identity-bef-task-coordinator/observation/paid-absence.json',sha256:'c'.repeat(64),
      boundary:'actual_tool_http_x402_local_evm_application_store' as const},
    assets:[{assetId:'USDC',kind:'erc20' as const,chainId:8453,address:'0x'+'2'.repeat(40)}],
    actionResponses:new Map<string,Record<string,unknown>>(packet.ownerActions.filter((action)=>action.actionKind==='retrieve').map((action)=>[action.actionId,fixtureRetrievedResponse]))};
  if(taskCase.taskId==='H3'){
    const decoded={resourceId:component.resourceId,schema:'web-agent-bench/market-state-brief/v1',content:{priceBand:'medium'}};
    const bytes=Buffer.from(JSON.stringify(decoded)),contentHash=hash(bytes);
    Object.assign(packet.manifest.catalog.find((resource)=>resource.resourceId===component.resourceId)!,
      {schema:decoded.schema,resourceSha256:contentHash,payloadSha256:contentHash,payloadByteCount:bytes.length});
    for(const operation of after.operations)operation.selected_resource_sha256=contentHash;
    for(const delivery of after.deliveries){delivery.content_sha256=contentHash;delivery.byte_count=String(bytes.length);}
    const response={resourceId:component.resourceId,contentType:'application/json',contentHash,contentBytes:bytes.toString('base64'),content:decoded};
    for(const action of packet.ownerActions.filter((item)=>item.actionKind==='retrieve')){
      Object.assign(action.retrievedContent!,{resourceSchema:decoded.schema,contentSha256:contentHash,byteCount:bytes.length});
      Object.assign(action.safeResponse!,{contentHash});context.actionResponses.set(action.actionId,response);
    }
    Object.assign(taskCase.objective.referenceComponent,{validator:{validatorVersion:'bef-route-delivery-validator/v1',
      payloadSchemaVersion:'bef-route-delivery/v1',additionalProperties:false,requiredFields:[{name:'resourceId',type:'string'},
        {name:'contentType',type:'string'},{name:'contentHash',type:'sha256'},{name:'contentBytes',type:'string'},{name:'priceBand',type:'string'}]}});
    refresh();
  }
  return {packet,context,refresh};
}

test('every shared paid task proves absence per payment without confusing another operation retrieval',()=>{
  for(const taskId of ['M1','M2','H1','H3','U1'] as const){
    const {packet,context}=closedUnrequestedSecondPayment(taskId);
    const candidate=projectPaidDataObservationBundle(packet,context);
    const payments=candidate.observations!.payments;
    assert.equal(payments.length,2);
    assert.equal(payments[0]!.deliveryRequestAbsence,undefined,'delivered first payment needs no negative fact');
    const proof=payments[1]!.deliveryRequestAbsence;
    assert.ok(proof,taskId+' must prove the second payment was never retrieved');
    assert.deepEqual(proof,{schemaVersion:'bts-delivery-request-absence/v1',status:'not_admitted_at_cutoff',
      paymentAttemptId:payments[1]!.paymentAttemptId,paymentActionSequence:4,acceptedActionCutoffSequence:4,
      authority:{closureId:packet.closure.closureId,preparationId:packet.execution.preparationId,
        leaseId:packet.execution.leaseId,generationId:packet.execution.generationId},captureEvidence:context.captureEvidence});
    assert.equal(candidate.observations!.deliveries.length,1,'unrelated successful retrieval is retained');
  }
});

test('shared paid absence rejects unverified census, payment provenance, receipt and cutoff facts',()=>{
  const variants=['hash','before','generation','observer','isolation','partial','unknown','contradictory','receipt','effect','payment-id','payment-generation',
    'transaction','source-action','cost','existing-delivery','duplicate-payment','cutoff'] as const;
  for(const variant of variants){
    const {packet,context,refresh}=closedUnrequestedSecondPayment();
    const after=packet.bef.after as Record<string,any>,effect=packet.rpc.paymentEffects[1]!;
    if(variant==='generation')after.generation.generation_id='00000000-0000-4000-8000-000000000000';
    if(variant==='observer')packet.bef.session.currentUser='unverified-observer';
    if(variant==='isolation')packet.bef.session.transactionIsolation='read committed';
    if(variant==='partial'||variant==='unknown'||variant==='contradictory')packet.coverage.status=variant;
    if(variant==='receipt')delete effect.receipt;
    if(variant==='effect')effect.verification='partial';
    if(variant==='payment-id')effect.paymentId='foreign-payment';
    if(variant==='payment-generation')after.payments[1].generation_id='00000000-0000-4000-8000-000000000000';
    if(variant==='transaction')(effect.transaction as Record<string,unknown>).hash='0x'+'f'.repeat(64);
    if(variant==='source-action')effect.sourceOwnerActionIds=['00000000-0000-4000-8000-000000000000'];
    if(variant==='cost')after.costs[1].transaction_hash='0x'+'f'.repeat(64);
    if(variant==='existing-delivery')after.deliveries.push({...after.deliveries[0],operation_id:paymentOperationIds.second});
    if(variant==='duplicate-payment')after.payments.push(structuredClone(after.payments[1]));
    refresh();
    if(variant==='duplicate-payment')packet.coverage.befPaymentCount++;
    if(variant==='hash')packet.bef.censusSha256='0'.repeat(64);
    if(variant==='before')packet.bef.before={...packet.bef.before,unexpected:'changed'};
    if(variant==='cutoff')packet.closure.actionCutoffSequence=3;
    if(variant==='cutoff')assert.throws(()=>projectPaidDataObservationBundle(packet,context),PaidDataCapturePacketError);
    else assert.equal(projectPaidDataObservationBundle(packet,context).observations!.payments.some((payment)=>payment.deliveryRequestAbsence!==undefined),false,variant);
  }
});

test('admitted same-operation retrieval never becomes known absence, including rejected or unlinked retrievals',()=>{
  for(const kind of ['observed','rejected','unlinked','conflicting','pending','unknown'] as const){
    const {packet,context,refresh}=closedUnrequestedSecondPayment();
    const retrieve=structuredClone(validPaidDataCapturePacket().ownerActions[4]!);
    if(kind!=='observed'){
      retrieve.receiptStatus='rejected_before_execution';retrieve.safeResponse=null;retrieve.retrievedContent=null;
      retrieve.rawResponseSha256=null;
    }
    if(kind==='unlinked'){retrieve.befOperationId=null;retrieve.paymentProtocol=null;}
    if(kind==='conflicting')retrieve.paymentProtocol={payOperationId:paymentOperationIds.first};
    if(kind==='pending'||kind==='unknown')(retrieve as unknown as {receiptStatus:string}).receiptStatus=kind;
    packet.ownerActions.push(retrieve);packet.closure.actionCutoffSequence=5;packet.closure.reconciledActionSequence=5;refresh();
    if(kind==='pending'||kind==='unknown')assert.throws(()=>projectPaidDataObservationBundle(packet,context),PaidDataCapturePacketError);
    else assert.equal(projectPaidDataObservationBundle(packet,context).observations!.payments[1]!.deliveryRequestAbsence,undefined,kind);
  }
});

test('legacy shared paid projection preserves exact facts and hash when optional absence proof is suppressed',()=>{
  for(const taskId of ['M1','M2','H1','H3','U1'] as const){
    const {packet,context}=closedUnrequestedSecondPayment(taskId);
    const current=projectPaidDataObservationBundle(packet,context);
    const legacy=projectPaidDataObservationBundle(packet,{...context,preserveLegacyDeliveryObservations:true});
    assert.ok(current.observations!.payments[1]!.deliveryRequestAbsence);
    delete current.observations!.payments[1]!.deliveryRequestAbsence;
    assert.equal(canonicalTaskJson(current),canonicalTaskJson(legacy));
    assert.equal(sha256CanonicalTaskJson(current),sha256CanonicalTaskJson(legacy));
  }
});

test('paid-data packet round-trips with all public catalog offers and secret-free payment projections',()=>{
  const packet=validPaidDataCapturePacket(),bytes=Buffer.from(canonicalTaskJson(packet),'utf8');
  assert.deepEqual(validatePaidDataCapturePacket(packet),packet);
  assert.deepEqual(parsePaidDataCapturePacket(bytes),packet);
  assert.equal(hash(bytes),hash(Buffer.from(canonicalTaskJson(parsePaidDataCapturePacket(bytes)),'utf8')));
  assert.equal(packet.manifest.catalog.length,2);
  assert.equal(packet.manifest.catalog.reduce((n,resource)=>n+((resource.offers as unknown[]).length),0),3);
  const serialized=JSON.stringify(packet);
  assert.equal(serialized.includes('contentBytes'),false);
  assert.equal(serialized.includes('"signature"'),false);
  assert.equal(serialized.includes('"calldata"'),false);
});

test('candidate keeps every payment, including resources outside the case component map',()=>{
  const packet=validPaidDataCapturePacket();
  const candidate=projectPaidDataCaptureCandidate(packet,h1Case(packet));
  assert.deepEqual(candidate.resources.map((resource)=>resource.resourceId),['resource-required-risk','resource-market-snapshot']);
  assert.deepEqual(candidate.componentReferences.map((component)=>component.componentId),['risk-reference']);
  assert.equal(candidate.payments.length,2);
  const operationMap=new Map((packet.bef.after.operations as Array<Record<string,unknown>>).map((operation)=>[String(operation.operation_id),operation]));
  const observedResources=candidate.payments.map((payment)=>operationMap.get(String(payment.operation_id))?.selected_resource_id);
  assert.deepEqual(observedResources,['resource-market-snapshot','resource-market-snapshot']);
  assert.ok(observedResources.every((resourceId)=>!candidate.componentReferences.some((component)=>component.resourceId===resourceId)));
  assert.deepEqual(candidate.rpcPaymentEffects.map((effect)=>effect.verification),['observed','observed']);
  assert.deepEqual(candidate.boundary,{
    actionCutoffSequence:5,observationCutoffSequence:5,baselineBlockNumber:'100',baselineBlockHash:packet.rpc.baselineBlock.hash,
    finalBlockNumber:'105',finalBlockHash:packet.rpc.finalBlock.hash,
  });
  assert.equal(candidate.coverage.status,'observed');
  assert.equal('trades' in candidate,false);
  assert.equal('conversions' in candidate,false);
});

test('multi-purchase and repeated retrieval preserve separate owner operations and one delivery identity per BEF operation',()=>{
  const packet=validPaidDataCapturePacket();
  const actions=packet.ownerActions;
  assert.equal(actions.length,5);
  const payA=actions[0]!,retrieveA=actions[1]!,retryRetrieveA=actions[2]!,payB=actions[3]!,retrieveB=actions[4]!;
  assert.notEqual(payA.ownerOperationId,retrieveA.ownerOperationId);
  assert.equal(payA.befOperationId,retrieveA.befOperationId);
  assert.equal(retrieveA.befOperationId,retryRetrieveA.befOperationId);
  assert.notEqual(retrieveA.ownerOperationId,retryRetrieveA.ownerOperationId);
  assert.notEqual(payA.befOperationId,payB.befOperationId);
  assert.equal(retrieveB.befOperationId,payB.befOperationId);
  const deliveryA=packet.bef.after.deliveries as Array<Record<string,unknown>>;
  assert.equal(deliveryA.filter((delivery)=>delivery.operation_id===paymentOperationIds.first).length,1);
  assert.equal(deliveryA.filter((delivery)=>delivery.operation_id===paymentOperationIds.second).length,1);
  assert.equal(retrieveA.retrievedContent?.contentSha256,fixturePayload.contentHash);
  assert.equal(retrieveA.retrievedContent?.payloadSchemaVersion,'bef-delivery-envelope/v1');
  assert.equal(retrieveA.retrievedContent?.resourceSchema,'market-snapshot/v4');
  assert.notEqual(retrieveA.retrievedContent?.payloadSchemaVersion,retrieveA.retrievedContent?.resourceSchema);
});

test('packet rejects raw signed input while retaining only transaction and log hashes',()=>{
  const packet=validPaidDataCapturePacket() as unknown as Record<string,any>;
  packet.rpc.paymentEffects[0].transaction.input='0xdeadbeef';
  assert.throws(()=>validatePaidDataCapturePacket(packet),(error:unknown)=>
    error instanceof PaidDataCapturePacketError&&error.code==='PAID_DATA_PACKET_SECRET_FIELD');
  const safe=validPaidDataCapturePacket();
  assert.match(String(safe.rpc.paymentEffects[0]?.transaction && (safe.rpc.paymentEffects[0]!.transaction as Record<string,unknown>).inputSha256),/^[0-9a-f]{64}$/);
  assert.match(String(safe.rpc.paymentEffects[0]?.receipt && (safe.rpc.paymentEffects[0]!.receipt as Record<string,unknown>).logsSha256),/^[0-9a-f]{64}$/);
});

test('packet rejects duplicate or out-of-cutoff paid owner action identities and inconsistent action census counts',()=>{
  const duplicateId=validPaidDataCapturePacket() as unknown as Record<string,any>;
  duplicateId.ownerActions[1].actionId=duplicateId.ownerActions[0].actionId;
  assert.throws(()=>validatePaidDataCapturePacket(duplicateId),(error:unknown)=>error instanceof PaidDataCapturePacketError&&error.code==='PAID_DATA_PACKET_INVALID');
  const duplicateOwnerOperation=validPaidDataCapturePacket() as unknown as Record<string,any>;
  duplicateOwnerOperation.ownerActions[1].ownerOperationId=duplicateOwnerOperation.ownerActions[0].ownerOperationId;
  assert.throws(()=>validatePaidDataCapturePacket(duplicateOwnerOperation),(error:unknown)=>error instanceof PaidDataCapturePacketError&&error.code==='PAID_DATA_PACKET_INVALID');
  const duplicateSequence=validPaidDataCapturePacket() as unknown as Record<string,any>;
  duplicateSequence.ownerActions[1].actionSequence=duplicateSequence.ownerActions[0].actionSequence;
  assert.throws(()=>validatePaidDataCapturePacket(duplicateSequence),(error:unknown)=>error instanceof PaidDataCapturePacketError&&error.code==='PAID_DATA_PACKET_INVALID');
  const outsideCutoff=validPaidDataCapturePacket() as unknown as Record<string,any>;
  outsideCutoff.ownerActions[4].actionSequence=6;
  assert.throws(()=>validatePaidDataCapturePacket(outsideCutoff),(error:unknown)=>error instanceof PaidDataCapturePacketError&&error.code==='PAID_DATA_PACKET_INVALID');
  const wrongCounts=validPaidDataCapturePacket() as unknown as Record<string,any>;
  wrongCounts.coverage.paidActionCount--;
  assert.throws(()=>validatePaidDataCapturePacket(wrongCounts),(error:unknown)=>error instanceof PaidDataCapturePacketError&&error.code==='PAID_DATA_PACKET_INVALID');
  const wrongCutoff=validPaidDataCapturePacket() as unknown as Record<string,any>;
  wrongCutoff.coverage.actionCutoffSequence--;
  assert.throws(()=>validatePaidDataCapturePacket(wrongCutoff),(error:unknown)=>error instanceof PaidDataCapturePacketError&&error.code==='PAID_DATA_PACKET_INVALID');
  const wrongOwnerCount=validPaidDataCapturePacket() as unknown as Record<string,any>;
  wrongOwnerCount.coverage.ownerActionCount--;
  assert.throws(()=>validatePaidDataCapturePacket(wrongOwnerCount),(error:unknown)=>error instanceof PaidDataCapturePacketError&&error.code==='PAID_DATA_PACKET_INVALID');
  const wrongCensus=validPaidDataCapturePacket() as unknown as Record<string,any>;
  wrongCensus.coverage.deliveryCount++;
  assert.throws(()=>validatePaidDataCapturePacket(wrongCensus),(error:unknown)=>error instanceof PaidDataCapturePacketError&&error.code==='PAID_DATA_PACKET_INVALID');
});

test('paid packet chain identity and preparation baseline are rebound to the validated release interval',()=>{
  const packet=validPaidDataCapturePacket();
  assert.equal(validatePaidDataCapturePacketPins(packet,8453),packet);
  assert.throws(()=>validatePaidDataCapturePacketPins({...packet,rpc:{...packet.rpc,localChainId:'1'}},8453),
    (error:unknown)=>error instanceof PaidDataCapturePacketError&&error.code==='PAID_DATA_PACKET_INVALID');
  assert.throws(()=>validatePaidDataCapturePacketPins({...packet,preparation:{...packet.preparation,baselineBlockNumber:'99'}},8453),
    (error:unknown)=>error instanceof PaidDataCapturePacketError&&error.code==='PAID_DATA_PACKET_INVALID');
  assert.throws(()=>validatePaidDataCapturePacketPins({...packet,preparation:{...packet.preparation,baselineBlockHash:'0x'+'f'.repeat(64)}},8453),
    (error:unknown)=>error instanceof PaidDataCapturePacketError&&error.code==='PAID_DATA_PACKET_INVALID');
});

test('projection requires the exact immutable case identity and keeps the delivery envelope version distinct',()=>{
  const packet=validPaidDataCapturePacket(),projected=projectPaidDataCaptureCandidate(packet,h1Case(packet));
  assert.throws(()=>projectPaidDataCaptureCandidate(packet,{...h1Case(packet),caseHash:'0'.repeat(64)} as TaskCase),
    (error:unknown)=>error instanceof PaidDataCapturePacketError&&error.code==='PAID_DATA_PACKET_INVALID');
  assert.equal(projected.resources[1]?.schema,'market-snapshot/v4');
  assert.equal(projected.actions[1]?.retrievedContent?.payloadSchemaVersion,'bef-delivery-envelope/v1');
});
const h1Case=(packet=validPaidDataCapturePacket()):TaskCase=>({
  taskId:'H1',caseId:String(packet.binding.caseId),caseHash:String(packet.binding.caseHash),objective:{requiredComponents:packet.manifest.componentReferences.map((component)=>({
    ...component,sourceIds:['public-benchmark-fixture'],validator:{}}))},
} as unknown as TaskCase);

test('M2 keeps complete paid-data observations bound to the immutable task case',()=>{
  const packet=validPaidDataCapturePacket();
  packet.binding.taskId='M2';packet.binding.caseId='fixture-m2-case';packet.binding.caseHash='a'.repeat(64);
  const catalog:Array<{offerId:string;resourceId:string}> = [];
  for(const resource of packet.manifest.catalog){
    const offers=Array.isArray(resource.offers)?resource.offers:[];
    for(const value of offers){
      if(!value||typeof value!=='object'||Array.isArray(value))continue;
      const offer=value as Record<string,unknown>;
      if(typeof offer.id==='string'&&typeof resource.resourceId==='string')catalog.push({offerId:offer.id,resourceId:resource.resourceId});
    }
  }
  packet.manifest.componentReferences=catalog.map((offer)=>({componentId:offer.offerId,resourceId:offer.resourceId}));
  const taskCase={taskId:'M2',caseId:packet.binding.caseId,caseHash:packet.binding.caseHash,objective:{catalog}} as unknown as TaskCase;
  const candidate=projectPaidDataCaptureCandidate(packet,taskCase);
  assert.equal(candidate.binding.taskId,'M2');
  assert.equal(candidate.resources.length,2);
  assert.equal(candidate.payments.length,2);
  assert.equal(candidate.componentReferences.length,catalog.length);
  assert.equal(candidate.coverage.status,'observed');
});
test('paid-data typed candidate projects the actual delivery envelope and preserves child observation sequencing',()=>{
  const packet=validPaidDataCapturePacket();
  packet.manifest.componentReferences=[{componentId:'market-reference',resourceId:'resource-market-snapshot'}];
  const taskCase={...h1Case(packet),objective:{requiredComponents:[{componentId:'market-reference',resourceId:'resource-market-snapshot',
    sourceIds:['public-benchmark-fixture'],validator:{}}]}} as unknown as TaskCase;
  const captureEvidence={path:'artifacts/runs/owner-identity-bef-task-coordinator/observation/paid.json',sha256:'c'.repeat(64),
    boundary:'actual_tool_http_x402_local_evm_application_store' as const};
  const actionResponses=new Map(packet.ownerActions.filter((action)=>action.actionKind==='retrieve').map((action)=>[action.actionId,fixtureRetrievedResponse]));
  const candidate=projectPaidDataObservationBundle(packet,{taskCase,binding:packet.binding as unknown as import('./task-evaluator.js').TaskEvidenceBinding,
    captureEvidence,assets:[{assetId:'USDC',kind:'erc20',chainId:8453,address:'0x'+'2'.repeat(40)}],actionResponses});
  assert.equal(candidate.observationCutoffSequence,5);
  assert.equal(candidate.observations?.payments.length,2);
  assert.equal(candidate.observations?.transfers.length,2);
  assert.equal(candidate.observations?.deliveries.length,2);
  assert.equal(candidate.observations?.expenses.length,0);
  assert.equal(candidate.observations?.deliveries[0]?.payloadSchemaVersion,'bef-delivery-envelope/v1');
  assert.equal((candidate.observations?.deliveries[0]?.payload as Record<string,unknown>).contentBytes,fixtureRetrievedResponse.contentBytes);
  assert.deepEqual(Object.keys(candidate.observations?.deliveries[0]?.payload ?? {}).sort(),['contentBytes','contentHash','contentType','resourceId']);
  assert.deepEqual(candidate.observations?.coverage,{transfers:'complete',payments:'complete',stateMutations:'complete',deliveries:'complete',expenses:'complete'});
});

test('H3 typed delivery adds only the route field decoded from its hash-bound public resource',()=>{
  const packet=validPaidDataCapturePacket();
  packet.binding.taskId='H3';
  const resourceId='resource-market-snapshot',resourceSchema='web-agent-bench/market-state-brief/v1';
  const decodedResource={resourceId,schema:resourceSchema,content:{routeCode:'alternative'}};
  const contentBytes=Buffer.from(JSON.stringify(decodedResource),'utf8'),contentHash=hash(contentBytes);
  const resource=packet.manifest.catalog.find((item)=>item.resourceId===resourceId)!;
  Object.assign(resource,{schema:resourceSchema,dataType:'market-state-brief',resourceSha256:contentHash,payloadSha256:contentHash,
    payloadByteCount:contentBytes.length,payloadTopLevelFields:Object.keys(decodedResource).sort()});
  packet.manifest.componentReferences=[{componentId:'market-route-reference',resourceId}];
  for(const operation of packet.bef.after.operations as Array<Record<string,unknown>>)
    if(operation.selected_resource_id===resourceId)operation.selected_resource_sha256=contentHash;
  for(const delivery of packet.bef.after.deliveries as Array<Record<string,unknown>>){
    delivery.content_sha256=contentHash;delivery.byte_count=String(contentBytes.length);
  }
  for(const action of packet.ownerActions.filter((item)=>item.actionKind==='retrieve')){
    action.retrievedContent!.payloadSchemaVersion='bef-delivery-envelope/v1';
    action.retrievedContent!.resourceSchema=resourceSchema;
    action.retrievedContent!.contentSha256=contentHash;
    action.retrievedContent!.byteCount=contentBytes.length;
    action.safeResponse={...action.safeResponse!,resourceId,contentType:'application/json',contentHash};
  }
  const response={resourceId,contentType:'application/json',contentHash,contentBytes:contentBytes.toString('base64'),content:decodedResource};
  const validator={validatorVersion:'bef-route-delivery-validator/v1',payloadSchemaVersion:'bef-route-delivery/v1',
    requiredFields:[{name:'resourceId',type:'string'},{name:'contentType',type:'string'},{name:'contentHash',type:'sha256'},
      {name:'contentBytes',type:'string'},{name:'routeCode',type:'string'}],additionalProperties:false,predicates:[],
    permittedProvenance:['public-benchmark-fixture']};
  const taskCase={...h1Case(packet),taskId:'H3',objective:{referenceComponent:{componentId:'market-route-reference',resourceId,
    sourceIds:['public-benchmark-fixture'],validator},routeObjective:{referenceField:'routeCode',allowedRouteIds:['alternative-route'],
    expectedRouteByValue:[{value:'alternative',routeId:'alternative-route'}]},inputAssetId:'USDC',exactInputUnits:'100000',
    permittedRoutes:[],minimumOutputUnits:'1',nativeReserveWei:'1',combinedExpenseBudgetUsdcUnits:'1'}} as unknown as TaskCase;
  const captureEvidence={path:'artifacts/runs/owner-identity-bef-task-coordinator/observation/h3-route.json',sha256:'e'.repeat(64),
    boundary:'actual_tool_http_x402_local_evm_application_store' as const};
  const actionResponses=new Map(packet.ownerActions.filter((action)=>action.actionKind==='retrieve')
    .map((action)=>[action.actionId,response] as const));
  const candidate=projectPaidDataObservationBundle(packet,{taskCase,binding:packet.binding as unknown as import('./task-evaluator.js').TaskEvidenceBinding,
    captureEvidence,assets:[{assetId:'USDC',kind:'erc20',chainId:8453,address:'0x'+'2'.repeat(40)}],actionResponses});
  assert.equal(candidate.observations?.deliveries.length,2);
  const delivery=candidate.observations!.deliveries[0]!;
  const expectedPayload={resourceId,contentType:'application/json',contentHash,contentBytes:response.contentBytes,routeCode:'alternative'};
  assert.equal(delivery.payloadSchemaVersion,'bef-route-delivery/v1');
  assert.deepEqual(delivery.payload,expectedPayload);
  assert.equal(delivery.payloadSha256,hash(canonicalTaskJson(expectedPayload)));
  assert.deepEqual(candidate.observations?.coverage.deliveries,'complete');

  const missingPacket=structuredClone(packet),missingResource={resourceId,schema:resourceSchema,content:{}};
  const missingBytes=Buffer.from(JSON.stringify(missingResource),'utf8'),missingHash=hash(missingBytes);
  const missingCatalog=missingPacket.manifest.catalog.find((item)=>item.resourceId===resourceId)!;
  Object.assign(missingCatalog,{resourceSha256:missingHash,payloadSha256:missingHash,payloadByteCount:missingBytes.length,
    payloadTopLevelFields:Object.keys(missingResource).sort()});
  for(const operation of missingPacket.bef.after.operations as Array<Record<string,unknown>>)
    if(operation.selected_resource_id===resourceId)operation.selected_resource_sha256=missingHash;
  for(const item of missingPacket.bef.after.deliveries as Array<Record<string,unknown>>){
    item.content_sha256=missingHash;item.byte_count=String(missingBytes.length);
  }
  for(const action of missingPacket.ownerActions.filter((item)=>item.actionKind==='retrieve')){
    action.retrievedContent!.contentSha256=missingHash;action.retrievedContent!.byteCount=missingBytes.length;
    action.safeResponse={...action.safeResponse!,resourceId,contentType:'application/json',contentHash:missingHash};
  }
  const missingResponse={resourceId,contentType:'application/json',contentHash:missingHash,contentBytes:missingBytes.toString('base64'),content:missingResource};
  const missingResponses=new Map(missingPacket.ownerActions.filter((action)=>action.actionKind==='retrieve')
    .map((action)=>[action.actionId,missingResponse] as const));
  const missingCandidate=projectPaidDataObservationBundle(missingPacket,{taskCase,binding:missingPacket.binding as unknown as import('./task-evaluator.js').TaskEvidenceBinding,
    captureEvidence,assets:[{assetId:'USDC',kind:'erc20',chainId:8453,address:'0x'+'2'.repeat(40)}],actionResponses:missingResponses});
  assert.equal(missingCandidate.observations?.deliveries.length,0);
  assert.equal(missingCandidate.observations?.coverage.deliveries,'incomplete');
});

test('paid-only H3 and U1 candidates leave chain trade and conversion coverage incomplete',()=>{
  for(const taskId of ['H3','U1'] as const){
    const packet=validPaidDataCapturePacket();packet.binding.taskId=taskId;
    const components=packet.manifest.componentReferences.map((component)=>({...component,sourceIds:['public-benchmark-fixture'],validator:{}}));
    const objective=taskId==='H3'?{referenceComponent:components[0]}:{requiredComponents:components};
    const taskCase={...h1Case(packet),taskId,objective} as unknown as TaskCase;
    const candidate=projectPaidDataObservationBundle(packet,{taskCase,binding:packet.binding as unknown as import('./task-evaluator.js').TaskEvidenceBinding,
      captureEvidence:{path:'artifacts/runs/owner-identity-bef-task-coordinator/observation/composite.json',sha256:'d'.repeat(64),
        boundary:'actual_tool_http_x402_local_evm_application_store'},assets:[],actionResponses:new Map()});
    assert.equal(candidate.observations?.coverage.trades,'incomplete');
    assert.equal(candidate.observations?.coverage.conversions,'incomplete');
  }
});
