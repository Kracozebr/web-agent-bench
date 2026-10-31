import assert from 'node:assert/strict';
import test from 'node:test';
import { referenceRecipientOption, validateTransferRecipient } from './task-transfer-recipient.js';
import { parseDifficultyV2Arguments } from './task-difficulty-v2-main.js';
import { captureSelectedUsdcTransfer } from './task-transfer-capture.js';
import type { ProbeContext } from './runner.js';

const target = '0x'+'2'.repeat(40), fixed = '0x'+'3'.repeat(40);
test('S1 public fixture pin accepts either mode; omitted pin keeps legacy generation',()=>{
  for(const mode of ['ranked','training'])assert.equal(referenceRecipientOption('S1',mode,target),target);
  assert.equal(referenceRecipientOption('S1','ranked'),undefined);
  assert.equal(referenceRecipientOption('M1','training'),undefined);
  for(const id of ['S2','S3','S4','M1','M2','M3','M4','H1','H2','H3','U1'])assert.throws(()=>referenceRecipientOption(id,'ranked',target),/scope_invalid/);
  for(const bad of ['0x'+'0'.repeat(40),'bad','0x123','0x'+'g'.repeat(40)])assert.throws(()=>referenceRecipientOption('S1','ranked',bad),/recipient_invalid/);
  assert.throws(()=>referenceRecipientOption('S1','other',target),/scope_invalid/);
  assert.throws(()=>validateTransferRecipient(target,[],target),/collides_with_payer/);
  assert.throws(()=>validateTransferRecipient(target,[target]),/collides_with_contract/);
});

test('CLI pin validation happens before any runtime/reset/generation boundary',()=>{
  const base=['--task-id','S1','--mode','ranked','--env-id','bef-env-a','--evidence-dir','/tmp/test'];
  assert.equal(parseDifficultyV2Arguments([...base,'--recipient',target]).recipient,target);
  assert.equal(parseDifficultyV2Arguments(base).recipient,undefined);
  assert.throws(()=>parseDifficultyV2Arguments([...base,'--recipient','bad']));
  assert.throws(()=>parseDifficultyV2Arguments([...base,'--recipient',target,'--recipient',target]));
  assert.throws(()=>parseDifficultyV2Arguments(base.map(x=>x==='S1'?'M1':x).concat(['--recipient',target])));
});

test('capture rejects invalid/fixed pins before reset and pinned target needs no recipient key',async()=>{
  let calls=0;
  const context={runtime:{manifest:{funding:{maxUsdcUnitsPerGeneration:'1000000'},contracts:{pool:{address:fixed}}}},
    capability:{reset:{route:'POST /internal/admin/environments/{envId}/reset'}},env:{envId:'bef-env-a',apiBaseUrl:'http://127.0.0.1:1',adminKey:'synthetic'},
    secretValues:[],transport:{async request(){calls++;throw Error('isolated_reset_boundary');}}} as unknown as ProbeContext;
  for(const pin of ['bad',fixed])await assert.rejects(captureSelectedUsdcTransfer(context,'100000',pin),/recipient_/);
  assert.equal(calls,0);
  await assert.rejects(captureSelectedUsdcTransfer(context,'100000',target),/isolated_reset_boundary/);
  assert.equal(calls,1);assert.equal(context.secretValues.length,1,'only the payer signer is generated for an explicit recipient');
  context.secretValues.length=0;
  await assert.rejects(captureSelectedUsdcTransfer(context,'100000'),/isolated_reset_boundary/);
  assert.equal(context.secretValues.length,2,'legacy default still generates payer and recipient signers');
});
