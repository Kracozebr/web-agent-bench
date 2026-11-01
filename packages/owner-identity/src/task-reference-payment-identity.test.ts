import test from 'node:test';
import assert from 'node:assert/strict';
import {referencePaymentIdentityMatches as matches} from './task-reference-payment-identity.js';
const payee='0x1111111111111111111111111111111111111111';
const signer='0x2222222222222222222222222222222222222222';
test('reference payment separates independently bound gas signer from public payee',()=>{
  const row={facilitator_address:signer,payment_recipient:payee};
  assert.equal(matches(row,payee,signer,{settlementSignerAddress:signer}),true);
  assert.equal(matches(row,payee,payee),false);
  assert.equal(matches(row,signer,signer),false);
  assert.equal(matches(row,payee,signer,{settlementSignerAddress:payee}),false);
  for(const payment_recipient of [undefined,'',false,123,'0x'+'0'.repeat(40)])assert.equal(matches({...row,payment_recipient},payee,signer),false);
});
test('old raw rows preserve exact signer-as-payee interpretation',()=>{
  assert.equal(matches({facilitator_address:signer},signer,signer),true);
  assert.equal(matches({facilitator_address:signer,payment_recipient:null},signer,signer),true);
  assert.equal(matches({facilitator_address:signer},payee,signer),false);
});
