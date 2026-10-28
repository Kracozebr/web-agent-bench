import { createHash } from 'node:crypto';
import type { EvidenceReference } from './task-release.js';
import type { PaidDataCapturePacket } from './task-paid-data-capture-packet.js';

const hash=(value:string)=>createHash('sha256').update(value).digest('hex');
const uuid=(n:number)=>'20000000-0000-4000-8000-'+String(n).padStart(12,'0');
const tx=(ch:string)=>'0x'+ch.repeat(64);
const address=(ch:string)=>'0x'+ch.repeat(40);
const boundary='actual_tool_http_x402_local_evm_application_store' as const;
const evidence=(type:'action'|'preparation',n:number):EvidenceReference=>({
  path:'artifacts/runs/owner-identity-bef-task-coordinator/'+type+'/'+uuid(n)+'.json',
  sha256:hash('evidence-'+n),boundary,
});
const payA=uuid(31),payB=uuid(32),payActionA=uuid(1),payActionB=uuid(4);
const deliveredPayload={resourceId:'resource-market-snapshot',schema:'market-snapshot/v4',priceBand:'medium'};
const contentBytes=Buffer.from(JSON.stringify(deliveredPayload),'utf8');
const contentSha256=hash(contentBytes.toString('utf8'));
const op=(operationId:string,resourceId:string,offerId:string,amount:string,rawHash:string)=>({
  operation_id:operationId,env_id:'bef-paid-fixture',generation_id:uuid(8),participant_id:uuid(9),
  idempotency_key_sha256:hash('task-action-'+(operationId===payA?payActionA:payActionB)),
  request_sha256:hash('request-'+operationId),operation_kind:'purchase',status:'delivered',receipt_status:'success',
  transaction_hash:tx(operationId===payA?'a':'b'),response_sha256:rawHash,selected_offer_id:offerId,selected_amount_units:amount,
  selected_resource_id:resourceId,selected_resource_sha256:contentSha256,payment_response_mode:'deferred_delivery',
});
const payment=(operationId:string,letter:string,amount:string)=>({
  payment_id:uuid(letter==='a'?41:42),operation_id:operationId,env_id:'bef-paid-fixture',generation_id:uuid(8),
  payer_address:address('1'),network:'eip155:8453',asset_address:address('2'),amount_units:amount,facilitator_address:address('3'),
  transaction_hash:tx(letter),receipt_status:'success',token_delta_units:amount,observed_at:'2026-10-28T09:00:00.000Z',
  payer_balance_before:'900000',payer_balance_after:String(900000-Number(amount)),facilitator_balance_before:'0',
  facilitator_balance_after:amount,
});
const delivery=(operationId:string,id:number)=>({delivery_id:uuid(id),operation_id:operationId,env_id:'bef-paid-fixture',
  generation_id:uuid(8),resource_id:'resource-market-snapshot',content_sha256:contentSha256,byte_count:String(contentBytes.length),
  delivered_at:'2026-10-28T09:00:02.000Z'});
const cost=(operationId:string,letter:string)=>({operation_id:operationId,env_id:'bef-paid-fixture',generation_id:uuid(8),
  transaction_hash:tx(letter),payer_address:address('3'),payer_role:'facilitator',receipt_status:'success',transaction_from:address('3'),
  receipt_from:address('3'),receipt_block_number:'102',receipt_block_hash:tx('c'),gas_used:'50000',
  effective_gas_price_wei:'1000000000',gas_cost_wei:'50000000000000',modeled_gas_fee_usdc_units:'1',
  manifest_sha256:hash('manifest'),created_at:'2026-10-28T09:00:01.000Z'});
function ownerAction(n:number,kind:'pay'|'retrieve',operationId:string,ownerOperationId:string,rawHash:string){
  const common={
    actionId:uuid(n),actionSequence:n,ownerOperationId,actionKind:kind,commandSha256:hash('command-'+n),
    receiptStatus:'observed' as const,actionEvidence:evidence('action',n),befOperationId:operationId,
    transactionHash:kind==='pay'?tx(operationId===payA?'a':'b'):null,rawResponseSha256:rawHash,
    safeResponse:kind==='pay'?{operationId,status:'payment_confirmed',deliveryHandle:operationId,
      payment:{transactionHash:tx(operationId===payA?'a':'b'),receiptStatus:'success',amount:'125000',asset:address('2'),
        network:'eip155:8453',payTo:address('3')}}:
      {operationId,resourceId:'resource-market-snapshot',contentType:'application/json',contentHash:contentSha256,deliveryId:operationId===payA?uuid(51):uuid(52)},
    paymentProtocol:kind==='pay'?{schema:'bef-x402-split-payment-observation-v1',befOperationId:operationId,
      resourceId:'resource-market-snapshot',offerId:'stream',amountUnits:'125000',network:'eip155:8453',asset:address('2'),
      readHandle:{kind:'offer',operationId:uuid(19)},acceptedTerms:{amount:'125000',payTo:address('3')}}:
      {schema:'bef-x402-retrieve-observation-v1',payOperationId:operationId,deliveryMatchesPinnedResource:true},
    retrievedContent:kind==='retrieve'?{payloadSchemaVersion:'bef-delivery-envelope/v1',resourceSchema:'market-snapshot/v4',
      resourceId:'resource-market-snapshot',contentType:'application/json',contentSha256,byteCount:contentBytes.length,validJson:true}:null,
  };
  return common;
}
const generation={generation_id:uuid(8),env_id:'bef-paid-fixture',participant_id:uuid(9),payer_address:address('1'),
  manifest_sha256:hash('manifest'),status:'active',resource_variant:'canonical',chain_id:'8453',node_identity:'local-fixture',
  environment_manifest_sha256:hash('manifest')};
const operations=[op(payA,'resource-market-snapshot','stream','125000',hash('pay-response-a')),
  op(payB,'resource-market-snapshot','stream','125000',hash('pay-response-b'))];
const payments=[payment(payA,'a','125000'),payment(payB,'b','125000')];
const deliveries=[delivery(payA,51),delivery(payB,52)];
const costs=[cost(payA,'a'),cost(payB,'b')];
const census={generation,operations,payments,deliveries,costs,x402Observations:[
  {operation_id:payA,phase:'challenge',x402_version:'2',requirements:{scheme:'exact',network:'eip155:8453',asset:address('2'),
    amount:'125000',payTo:address('3'),maxTimeoutSeconds:'60',extra:{assetTransferMethod:'eip3009',paymentFlow:'authorization',
      name:'USD Coin',version:'2'}}},
  {operation_id:payB,phase:'challenge',x402_version:'2',requirements:{scheme:'exact',network:'eip155:8453',asset:address('2'),
    amount:'125000',payTo:address('3'),maxTimeoutSeconds:'60',extra:{assetTransferMethod:'eip3009',paymentFlow:'authorization',
      name:'USD Coin',version:'2'}}},
]};
export function validPaidDataCapturePacket():PaidDataCapturePacket{
  return {
    schemaVersion:'bts-paid-data-run-observation-capture/v1',classification:'run_bound_observations_candidate_not_grade',
    binding:{ownerId:uuid(1),agentId:uuid(2),runId:uuid(3),environmentId:'bef-paid-fixture',releaseIdentity:'fixture-release',
      manifestHash:hash('release'),caseId:'fixture-h1-case',caseHash:hash('case'),rubricHash:hash('rubric'),taskId:'H1'},
    closure:{closureId:uuid(4),actionCutoffSequence:5,reconciledActionSequence:5,reason:'agent_finish',operationId:null,payloadHash:hash('closure')},
    execution:{preparationId:uuid(5),leaseId:uuid(6),generationId:uuid(8),environmentId:'bef-paid-fixture',
      environmentManifestHash:hash('manifest'),applicationSourceHash:hash('application'),executionIdentityHash:hash('execution'),
      initialStateSha256:hash('initial')},
    preparation:{fixtureEvidence:evidence('preparation',10),baselineEvidence:evidence('preparation',11),
      baselineBlockNumber:'100',baselineBlockHash:tx('d')},
    manifest:{sha256:hash('manifest'),paymentPolicy:{scheme:'exact',network:'eip155:8453',asset:address('2'),
        assetTransferMethod:'eip3009',eip712Domain:{name:'USD Coin',version:'2'}},
      catalog:[
        {resourceId:'resource-required-risk',resourceSha256:hash('risk-payload'),contentType:'application/json',
          schema:'risk-policy/v2',dataType:'risk-policy',provenance:{classification:'public-benchmark-fixture'},
          offers:[{id:'basic',amount:'100000'},{id:'premium',amount:'250000'}],
          payloadSha256:hash('risk-payload'),payloadByteCount:98,payloadTopLevelFields:['resourceId','schema','riskBand']},
        {resourceId:'resource-market-snapshot',resourceSha256:contentSha256,contentType:'application/json',
          schema:'market-snapshot/v4',dataType:'market-snapshot',provenance:{classification:'public-benchmark-fixture'},
          offers:[{id:'stream',amount:'125000'}],payloadSha256:contentSha256,payloadByteCount:contentBytes.length,
          payloadTopLevelFields:['priceBand','resourceId','schema']},
      ],
      componentReferences:[{componentId:'risk-reference',resourceId:'resource-required-risk'}],
    },
    ownerActions:[
      ownerAction(1,'pay',payA,'owner-operation-pay-a',hash('pay-response-a')),
      ownerAction(2,'retrieve',payA,'owner-operation-retrieve-a',hash('retrieve-response-a')),
      ownerAction(3,'retrieve',payA,'owner-operation-retrieve-again-a',hash('retrieve-response-again-a')),
      ownerAction(4,'pay',payB,'owner-operation-pay-b',hash('pay-response-b')),
      ownerAction(5,'retrieve',payB,'owner-operation-retrieve-b',hash('retrieve-response-b')),
    ],
    bef:{session:{currentUser:'bef_observer',sessionUser:'bef_observer',databaseName:'bef_fixture',transactionReadOnly:'on',
        transactionIsolation:'repeatable read',superuser:false,bypassRls:false},
      before:structuredClone({...census,operations:[],payments:[],deliveries:[],costs:[],x402Observations:[]}),
      after:structuredClone(census),censusSha256:hash('census')},
    rpc:{localChainId:'8453',baselineBlock:{number:'100',hash:tx('d')},finalBlock:{number:'105',hash:tx('e')},
      paymentEffects:[
        {operationId:payA,paymentId:uuid(41),transactionHash:tx('a'),sourceOwnerActionIds:[uuid(1)],verification:'observed',
          transaction:{hash:tx('a'),inputSha256:hash('input')},receipt:{transactionHash:tx('a'),logsSha256:hash('logs')},
          decodedTransfers:[{assetId:'USDC',tokenAddress:address('2'),transactionHash:tx('a'),blockNumber:'102',blockHash:tx('c'),logIndex:'0',from:address('1'),to:address('3'),amountUnits:'125000'}]},
        {operationId:payB,paymentId:uuid(42),transactionHash:tx('b'),sourceOwnerActionIds:[uuid(4)],verification:'observed',
          transaction:{hash:tx('b'),inputSha256:hash('input-b')},receipt:{transactionHash:tx('b'),logsSha256:hash('logs-b')},
          decodedTransfers:[{assetId:'USDC',tokenAddress:address('2'),transactionHash:tx('b'),blockNumber:'103',blockHash:tx('e'),logIndex:'0',from:address('1'),to:address('3'),amountUnits:'125000'}]},
      ]},
    coverage:{actionCutoffSequence:5,observationCutoffSequence:5,ownerActionCount:5,paidActionCount:5,befPaymentCount:2,
      deliveryCount:2,costCount:2,rpcPaymentProofCount:2,status:'observed'},
  };
}
export const paymentOperationIds={first:payA,second:payB};
export const fixturePayload={resourceId:'resource-market-snapshot',contentType:'application/json',contentHash:contentSha256,byteCount:contentBytes.length,deliveryEnvelopeSchemaVersion:'bef-delivery-envelope/v1',resourceSchema:'market-snapshot/v4'};

export const fixtureRetrievedResponse={resourceId:'resource-market-snapshot',contentType:'application/json',contentHash:contentSha256,contentBytes:contentBytes.toString('base64'),content:deliveredPayload};
