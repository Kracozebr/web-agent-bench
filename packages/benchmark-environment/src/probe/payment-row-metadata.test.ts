import assert from 'node:assert/strict';
import test from 'node:test';
import {capturePaymentMetadata} from './payment-row-metadata.js';
test('independent snapshot keeps the observed modern payee separate from gas signer',()=>{
 const observed={facilitator_address:'0x'+'2'.repeat(40),payment_recipient:'0x'+'1'.repeat(40),transaction_hash:null};
 assert.deepEqual(capturePaymentMetadata(observed),observed);
 assert.notEqual(capturePaymentMetadata(observed).payment_recipient,capturePaymentMetadata(observed).facilitator_address);
});
test('legacy raw snapshot omits only the new NULL metadata without rewriting other NULL observations',()=>{
 const old={facilitator_address:'0x'+'2'.repeat(40),transaction_hash:null};
 const migrated={...old,payment_recipient:null};
 assert.deepEqual(capturePaymentMetadata(migrated),old);
 assert.equal(migrated.payment_recipient,null);
 assert.deepEqual(capturePaymentMetadata(old),old);
 for(const malformed of ['',false,123,undefined])assert.equal(Object.hasOwn(capturePaymentMetadata({...old,payment_recipient:malformed}),'payment_recipient'),true);
});
