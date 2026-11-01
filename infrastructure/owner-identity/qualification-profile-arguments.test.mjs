import test from 'node:test';
import assert from 'node:assert/strict';
import {parseQualificationArguments} from './qualify-source-refresh.mjs';
const args=['--execute','--application-sha256','1'.repeat(64),'--probe-sha256','2'.repeat(64),'--manifest-sha256','3'.repeat(64)];

test('schema admission is opt-in and cannot alter the legacy qualification arguments',()=>{
  const original={execute:true,application:'1'.repeat(64),probe:'2'.repeat(64),manifest:'3'.repeat(64)};
  assert.deepEqual(parseQualificationArguments(args),original);
  assert.deepEqual(parseQualificationArguments([...args,'--restart-payment-identity']),{...original,restartPaymentIdentity:true});
  assert.deepEqual(parseQualificationArguments([...args,'--restart-payment-identity','--reconcile-u1-native-gas']),{...original,restartPaymentIdentity:true,reconcileU1NativeGas:true});
  assert.deepEqual(parseQualificationArguments([...args,'--restart-payment-identity','--reconcile-native-gas']),{...original,restartPaymentIdentity:true,reconcileNativeGas:true});
  assert.deepEqual(parseQualificationArguments(['--plan']),{execute:false});
});

test('unknown, repeated or misplaced admission flags fail before qualification starts',()=>{
  for(const invalid of [[...args,'--allow-migrations'],[...args,'--reconcile-u1-native-gas'],[...args,'--reconcile-u1-native-gas','--restart-payment-identity'],[...args,'--restart-payment-identity','--reconcile-u1-native-gas','--reconcile-u1-native-gas'],[...args,'--restart-payment-identity','--restart-payment-identity'],['--restart-payment-identity',...args],['--plan','--restart-payment-identity']]){
    assert.throws(()=>parseQualificationArguments(invalid),/qualification_usage/);
  }
  assert.throws(()=>parseQualificationArguments([...args,'--restart-payment-identity','--reconcile-u1-native-gas','--reconcile-native-gas']),/qualification_usage/);
  assert.throws(()=>parseQualificationArguments([...args,'--reconcile-native-gas']),/qualification_usage/);
});
