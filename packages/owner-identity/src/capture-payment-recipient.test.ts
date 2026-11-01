import assert from 'node:assert/strict';
import test from 'node:test';
import {capturePaymentRecipient} from './capture-payment-recipient.js';
const signer=`0x${'1'.repeat(40)}`,payee=`0x${'2'.repeat(40)}`;
test('public capture identities distinguish canonical recipient from gas signer and preserve absent/null legacy decoding',()=>{
 assert.equal(capturePaymentRecipient({facilitatorAddress:signer},{facilitator_address:signer}),signer);
 assert.equal(capturePaymentRecipient({facilitatorAddress:signer},{facilitator_address:signer,payment_recipient:null}),signer);
 assert.equal(capturePaymentRecipient({}, {facilitator_address:signer}),signer);
 const protocol={facilitatorAddress:signer,paymentRecipient:payee},row={facilitator_address:signer,payment_recipient:payee};
 assert.equal(capturePaymentRecipient(protocol,row),payee);
 for(const bad of [null,undefined,'',12,'not-address'])assert.throws(()=>capturePaymentRecipient({...protocol,paymentRecipient:bad},row));
 for(const bad of [null,undefined,'',signer])assert.throws(()=>capturePaymentRecipient(protocol,{...row,payment_recipient:bad}));
 assert.throws(()=>capturePaymentRecipient({...protocol,facilitatorAddress:payee},row));
 assert.throws(()=>capturePaymentRecipient({facilitatorAddress:signer},row));
 const zero=`0x${'0'.repeat(40)}`;
 assert.throws(()=>capturePaymentRecipient({...protocol,paymentRecipient:zero},{...row,payment_recipient:zero}));
 assert.throws(()=>capturePaymentRecipient({...protocol,facilitatorAddress:zero},{...row,facilitator_address:zero}));
});
