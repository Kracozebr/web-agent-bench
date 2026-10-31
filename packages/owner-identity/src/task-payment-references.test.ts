import test from 'node:test';
import assert from 'node:assert/strict';
import { resolveTaskPaymentReference } from './task-payment-references.js';
import { sha256CanonicalTaskJson } from './task-release.js';

const terms = { scheme:'exact', network:'eip155:8453', asset:'0x'+'1'.repeat(40), amount:'100000',
  payTo:'0x'+'2'.repeat(40), transferMethod:'eip3009' };
const identity = {name:'USD Coin',version:'2',paymentFlow:'authorization'};
const operationId='00000000-0000-4000-8000-000000000001';
function fixture(payment:unknown,kind:'offer'|'catalog'='offer') {
  const resource={resourceId:'resource',payment,offers:[{id:'canonical',payment}]};
  const body={operationId,readHandle:{kind,operationId},freeInspection:true,deliveryState:'not_delivered',
    ...(kind==='offer'?resource:{catalog:[{resourceId:'resource',offers:resource.offers}]})};
  const row={action_kind:kind==='offer'?'inspect_offer':'inspect_catalog',command_json:{kind:'inspect_offer',resourceId:'resource'},
    receipt_status:'observed',tool_response_json:body,tool_response_hash:sha256CanonicalTaskJson(body),transaction_hash:null};
  const tx={execute:async()=>[row]};
  const target={runId:'00000000-0000-4000-8000-000000000002',taskIndex:0,environmentId:'env',
    command:{kind:'pay' as const,resourceId:'resource',offerId:'canonical',offerReadActionId:'00000000-0000-4000-8000-000000000003'}};
  return {body,row,run:()=>resolveTaskPaymentReference(tx as never,target)};
}

test('payment reference accepts exact legacy or complete public identity and projects only six consent terms',async()=>{
  for(const kind of ['offer','catalog'] as const)for(const payment of [terms,{...terms,...identity}]){
    const input=fixture(payment,kind),hash=input.row.tool_response_hash;
    assert.deepEqual(await input.run(),{kind:'pay',readHandle:{kind,operationId},acceptedTerms:terms});
    assert.equal(input.row.tool_response_hash,hash,'retained raw reference hash must not be rewritten');
    assert.deepEqual(input.row.tool_response_json,input.body);
  }
});

test('payment reference rejects partial malformed unknown or conflicting public identity',async()=>{
  const variants:Record<string,unknown>[]=[{...terms,name:identity.name}, {...terms,...identity,version:null},
    {...terms,...identity,name:'bad\nname'}, {...terms,...identity,version:''},
    {...terms,...identity,paymentFlow:'foreign-flow'}, {...terms,...identity,signature:'not accepted'},
    {...terms,...identity,extra:'not accepted'}];
  for(const key of ['name','version','paymentFlow']){const payment:Record<string,unknown>={...terms,...identity};delete payment[key];variants.push(payment);}
  for(const payment of variants)await assert.rejects(fixture(payment).run(),{code:'TASK_PAYMENT_OFFER_NOT_INSPECTED'});
  for(const rootPayment of [terms,{...terms,...identity,name:'foreign-domain'},{...terms,...identity,version:'99'}]){
    const input=fixture({...terms,...identity});
    assert.ok('payment' in input.body);
    input.body.payment=rootPayment;
    input.row.tool_response_hash=sha256CanonicalTaskJson(input.body);
    await assert.rejects(input.run(),{code:'TASK_PAYMENT_OFFER_NOT_INSPECTED'});
  }
});

test('payment reference verifies the original raw response hash before interpreting added public metadata',async()=>{
  const input=fixture({...terms,...identity});
  assert.ok('offers' in input.body);
  const payment=input.body.offers[0]!.payment;
  assert.ok(payment && typeof payment === 'object');
  Object.assign(payment,{name:'changed-after-capture'});
  await assert.rejects(input.run(),{code:'TASK_PAYMENT_REFERENCE_UNAVAILABLE'});
});
