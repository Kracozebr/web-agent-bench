import assert from 'node:assert/strict';
import test from 'node:test';
import { parsePaymentRecipient, paymentRecipient, verifyPaymentRecipient, durablePaymentRecipient, retainedPaymentActors } from './payment-recipient.js';
const payee = '0x1111111111111111111111111111111111111111' as const;
const firstSigner = '0x2222222222222222222222222222222222222222' as const;
const restartedSigner = '0x3333333333333333333333333333333333333333' as const;
test('public payee remains pinned when the ephemeral transaction signer changes after restart', () => {
  for (const address of [firstSigner, restartedSigner]) {
    const observed = verifyPaymentRecipient(payee, { address, paymentRecipient: payee });
    assert.equal(paymentRecipient({ facilitatorAddress: address, paymentRecipient: observed }), payee);
    assert.notEqual(observed, address);
  }
});
test('mismatched, absent or signer-substituted advertised payee fails closed', () => {
  for (const advertised of [undefined, firstSigner, restartedSigner]) {
    assert.throws(() => verifyPaymentRecipient(payee, { address: firstSigner, paymentRecipient: advertised }));
  }
  assert.throws(() => verifyPaymentRecipient(undefined, { address: firstSigner, paymentRecipient: payee }));
  for (const malformed of [null, 123, '', false]) assert.throws(() => verifyPaymentRecipient(undefined, {address:firstSigner,paymentRecipient:malformed}));
  assert.throws(() => verifyPaymentRecipient(undefined, {address:'not-an-address'}));
  for (const value of ['0x'+'0'.repeat(40), 'not-an-address', payee+'\n']) assert.throws(() => parsePaymentRecipient(value));
});
test('legacy unset profile retains its historical signer-as-payee behavior', () => {
  assert.equal(parsePaymentRecipient(''), undefined);
  assert.equal(paymentRecipient({facilitatorAddress:firstSigner}),firstSigner);
  assert.equal(verifyPaymentRecipient(undefined,{address:firstSigner}),firstSigner);
});
test('retained delivery binds public payee to original requirements independently of gas signer', () => {
  const proof={facilitator_address:firstSigner,payment_recipient:payee,original_requirements_pay_to:payee};
  assert.equal(durablePaymentRecipient(proof),payee);
  assert.equal(durablePaymentRecipient({...proof,facilitator_address:restartedSigner}),payee);
  assert.equal(durablePaymentRecipient({...proof,original_requirements_pay_to:firstSigner}),null);
  for(const payment_recipient of [undefined,'',false,123,'0x'+'0'.repeat(40),firstSigner])assert.equal(durablePaymentRecipient({...proof,payment_recipient}),null);
  assert.equal(durablePaymentRecipient({facilitator_address:firstSigner,original_requirements_pay_to:firstSigner}),firstSigner);
  assert.equal(durablePaymentRecipient({facilitator_address:firstSigner,payment_recipient:null,original_requirements_pay_to:firstSigner}),firstSigner);
  assert.equal(durablePaymentRecipient({facilitator_address:firstSigner,original_requirements_pay_to:payee}),null);
});

test('original receipt recovery retains independent nonzero signer and payee roles',()=>{
 assert.deepEqual(retainedPaymentActors({facilitator_address:firstSigner,payment_recipient:payee}),{signer:firstSigner,payee});
 assert.deepEqual(retainedPaymentActors({facilitator_address:firstSigner,payment_recipient:null}),{signer:firstSigner,payee:firstSigner});
 for(const bad of [undefined,null,'',false,123,'0x'+'0'.repeat(40)]){
  assert.equal(retainedPaymentActors({facilitator_address:bad,payment_recipient:payee}),null);
  if(bad!==null)assert.equal(retainedPaymentActors({facilitator_address:firstSigner,payment_recipient:bad}),null);
 }
});
