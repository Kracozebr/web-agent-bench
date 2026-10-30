import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { getAddress } from 'viem';
import test from 'node:test';
import { collectBefChainTaskObservationCandidate } from './bef-chain-observation-collector.js';
import { makeChainCaptureCompositeFixture, makeChainCaptureFixture, prependChainInspectionFixture, makeRejectedChainCaptureFixture } from './task-chain-capture-packet.fixture.js';
import { ChainCapturePacketError, projectTaskChainCapturePacket, validateTaskChainCapturePacket } from './task-chain-capture-packet.js';
import { canonicalTaskJson } from './task-release.js';

type Fixture=ReturnType<typeof makeChainCaptureFixture>|ReturnType<typeof makeChainCaptureCompositeFixture>;
function projection(fixture:Fixture){
 validateTaskChainCapturePacket(fixture.packet,fixture.taskCase);
 const evidence={path:'artifacts/runs/owner-identity-bef-task-coordinator/observation/capture.json',sha256:'a'.repeat(64),
  boundary:'actual_tool_http_x402_local_evm_application_store' as const};
 return projectTaskChainCapturePacket(fixture.packet,{binding:fixture.binding,taskCase:fixture.taskCase,evidence,ethValuation:fixture.ethValuation});
}
function project(taskId:'M3'|'M4'|'H2'|'H3'|'U1'){
 const fixture=taskId==='H3'||taskId==='U1'?makeChainCaptureCompositeFixture(taskId):makeChainCaptureFixture(taskId);
 return {...fixture,observations:projection(fixture)};
}

test('rejected-transfer source request retains the producer checksum token before RPC address normalization',()=>{
 const fixture=makeRejectedChainCaptureFixture('H2'),token='0x833589fcd6edb6e08f4c7c32d4f71b54bda02913';
 fixture.packet.rpc.assets.find((asset)=>asset.assetId==='USDC')!.address=token;
 const census=fixture.packet.bef.before as Record<string,unknown>,proof=(census.rejectedChainOperations as Record<string,unknown>[])[0]!;
 const operation=proof.operation as Record<string,unknown>,event=(proof.selectedEvents as Record<string,unknown>[])[0]!;
 const command=fixture.packet.rejectedChainActions![0]!.command;
 const request=(address:string)=>createHash('sha256').update(canonicalTaskJson({method:'POST',path:'/tools/transfer',action:{...command,token:address}})).digest('hex');
 function bindRequest(hash:string){
  operation.requestSha256=hash;(event.eventPayload as Record<string,unknown>).requestSha256=hash;
  event.eventJsonSha256=createHash('sha256').update(canonicalTaskJson(event.eventPayload)).digest('hex');
  fixture.packet.bef.after=structuredClone(census);fixture.packet.bef.censusSha256=createHash('sha256').update(canonicalTaskJson(census)).digest('hex');
 }
 bindRequest(request(getAddress(token)));
 assert.doesNotThrow(()=>projection(fixture));
 bindRequest(request(token));
 assert.throws(()=>projection(fixture),ChainCapturePacketError);
});

for(const taskId of ['M3','M4','H2'] as const){
 test(`${taskId} retains a source-proven rejected transfer without projecting effects or losing the immutable cutoff`,()=>{
  const fixture=makeRejectedChainCaptureFixture(taskId),observations=projection(fixture);
  assert.equal(fixture.packet.closure.actionCutoffSequence,1);
  assert.equal(fixture.packet.rejectedChainActions!.length,1);
  for(const domain of ['transfers','allowanceChanges','allowanceUses','trades','conversions','expenses'] as const)assert.deepEqual(observations[domain],[]);
  assert.equal(observations.finalStates.length,1);
  assert.deepEqual(fixture.packet.rpc.baseline,fixture.packet.rpc.final);
  const mixed=makeRejectedChainCaptureFixture(taskId,true),base=projection(makeChainCaptureFixture(taskId)),projected=projection(mixed);
  for(const domain of ['transfers','allowanceChanges','allowanceUses','trades','conversions','expenses'] as const){
   assert.equal(projected[domain].length,base[domain].length);
   assert.ok(projected[domain].every((value)=>value.actionSequence>1));
  }
 });
 test(`${taskId} rejects incomplete, contradictory or rebound rejected-transfer source proof`,()=>{
  for(const [domain,key,value] of [['operation','status','settlement_unknown'],['operation','receiptStatus','unknown'],['operation','transactionHash','0x'+'f'.repeat(64)],
   ['operation','responseSha256','f'.repeat(64)],['operation','requestSha256','f'.repeat(64)],['operation','idempotencyKeySha256','f'.repeat(64)],
   ['operation','participantId','other-participant'],['operation','generationId','10000000-0000-4000-8000-000000000fff'],
   ['selectedExecution','prestate',{}],['selectedExecution','transactionIntent',{}],['selectedExecution','measurement',{}],
   ['selectedExecution','outcome','settlement_unknown'],['selectedExecution','reasonCode','different-reason']] as const){
   const fixture=makeRejectedChainCaptureFixture(taskId),census=fixture.packet.bef.before as Record<string,unknown>;
   const proof=(census.rejectedChainOperations as Record<string,unknown>[])[0]!;
   (proof[domain] as Record<string,unknown>)[key]=value;
   fixture.packet.bef.after=structuredClone(census);fixture.packet.bef.censusSha256=createHash('sha256').update(canonicalTaskJson(census)).digest('hex');
   assert.throws(()=>projection(fixture),ChainCapturePacketError,`${domain}.${key}`);
  }
  for(const variant of ['missing','extra','altered-event','cost','missing-cutoff','command','missing-baseline'] as const){
   const fixture=makeRejectedChainCaptureFixture(taskId),census=fixture.packet.bef.before as Record<string,unknown>;
   const proof=(census.rejectedChainOperations as Record<string,unknown>[])[0]!;
   if(variant==='missing')census.rejectedChainOperations=[];
   if(variant==='extra')(census.rejectedChainOperations as unknown[]).push(structuredClone(proof));
   if(variant==='altered-event')(proof.selectedEvents as Record<string,unknown>[])[1]!.eventKind='original_tx_hash_bound';
   if(variant==='cost')proof.costsCount=1;
   if(variant==='missing-cutoff')fixture.packet.closure.actionCutoffSequence=0;
   if(variant==='command')fixture.packet.rejectedChainActions![0]!.command.amountUnits='999';
   if(variant==='missing-baseline')fixture.packet.rpc.baseline.blockHash='0x'+'f'.repeat(64);
   fixture.packet.bef.after=structuredClone(census);fixture.packet.bef.censusSha256=createHash('sha256').update(canonicalTaskJson(census)).digest('hex');
   assert.throws(()=>projection(fixture),ChainCapturePacketError,variant);
  }
  for(const variant of ['event-id-collision','event-sequence-collision','operation-collision','state-change','nonce-change','unsafe-observer'] as const){
   const fixture=makeRejectedChainCaptureFixture(taskId,variant.includes('collision')),census=fixture.packet.bef.before as Record<string,unknown>;
   const proof=(census.rejectedChainOperations as Record<string,unknown>[])[0]!,events=proof.selectedEvents as Record<string,unknown>[];
   const observed=(census.selectedEvents as Record<string,unknown>[])[0];
   if(variant==='event-id-collision')events[0]!.eventId=observed!.eventId;
   if(variant==='event-sequence-collision')events[0]!.eventSequence=observed!.eventSequence;
   if(variant==='operation-collision')fixture.packet.rejectedChainActions![0]!.befOperationId=fixture.packet.ownerActions[0]!.befOperationId;
   if(variant==='state-change')fixture.packet.rpc.final.balances[0]!.amountUnits='777';
   if(variant==='nonce-change')fixture.packet.rpc.final.participantTransactionCount='1';
   if(variant==='unsafe-observer')fixture.packet.bef.session.superuser=true;
   fixture.packet.bef.after=structuredClone(census);fixture.packet.bef.censusSha256=createHash('sha256').update(canonicalTaskJson(census)).digest('hex');
   assert.throws(()=>projection(fixture),ChainCapturePacketError,variant);
  }
 });
 test(`${taskId} retains the full neutral inspection prefix without adding chain or economic effects`,()=>{
  const base=makeChainCaptureFixture(taskId),fixture=prependChainInspectionFixture(base);
  const before=projection(base),after=projection(fixture);
  assert.equal(fixture.packet.externalActions.length,2);
  assert.equal(fixture.packet.closure.actionCutoffSequence,base.packet.closure.actionCutoffSequence+2);
  for(const key of ['transfers','allowanceChanges','allowanceUses','trades','conversions','expenses'] as const){
   assert.equal(after[key].length,before[key].length);
   assert.ok(after[key].every((row)=>row.actionSequence>=3));
  }
  const census=fixture.packet.bef.before as Record<string,unknown>,baseCensus=base.packet.bef.before as Record<string,unknown>;
  assert.equal((census.inspectionOperations as unknown[]).length,2);
  for(const key of ['operations','costs','selectedExecutions','selectedEvents','paymentsCount','deliveriesCount'])assert.deepEqual(census[key],baseCensus[key]);
  assert.deepEqual(fixture.packet.rpc,base.packet.rpc);
 });
 test(`${taskId} rejects paid/retrieve actions and effectful or unobserved inspection prefix`,()=>{
  for(const kind of ['purchase','pay','retrieve'] as const){
   const fixture=prependChainInspectionFixture(makeChainCaptureFixture(taskId));
   fixture.packet.externalActions[0]!.actionKind=kind;
   assert.throws(()=>projection(fixture),ChainCapturePacketError);
  }
  const effectful=prependChainInspectionFixture(makeChainCaptureFixture(taskId));
  effectful.packet.externalActions[0]!.transactionHash='0x'+'f'.repeat(64);
  assert.throws(()=>projection(effectful),ChainCapturePacketError);
  const rejected=prependChainInspectionFixture(makeChainCaptureFixture(taskId));
  rejected.packet.externalActions[0]!.receiptStatus='rejected_before_execution';
  assert.throws(()=>projection(rejected),ChainCapturePacketError);
 });
 test(`${taskId} requires independently source-bound GET operations for every neutral inspection`,()=>{
  for(const [key,value] of [['operationId','10000000-0000-4000-8000-000000000fff'],['requestSha256','f'.repeat(64)],
   ['responseSha256','f'.repeat(64)],['idempotencyKeySha256','f'.repeat(64)],['participantId','other-participant'],
   ['transactionHash','0x'+'f'.repeat(64)],['receiptStatus','success'],['status','settled'],['costsCount',1],
   ['selectedExecutionsCount',1],['selectedEventsCount',1]] as const){
   const fixture=prependChainInspectionFixture(makeChainCaptureFixture(taskId)),census=fixture.packet.bef.before as Record<string,unknown>;
   (census.inspectionOperations as Record<string,unknown>[])[0]![key]=value;
   fixture.packet.bef.after=structuredClone(census);
   fixture.packet.bef.censusSha256=createHash('sha256').update(canonicalTaskJson(census)).digest('hex');
   assert.throws(()=>projection(fixture),ChainCapturePacketError,key);
  }
  const missing=prependChainInspectionFixture(makeChainCaptureFixture(taskId)),census=missing.packet.bef.before as Record<string,unknown>;
  census.inspectionOperations=[];missing.packet.bef.after=structuredClone(census);
  missing.packet.bef.censusSha256=createHash('sha256').update(canonicalTaskJson(census)).digest('hex');
  assert.throws(()=>projection(missing),ChainCapturePacketError);
 });
}

test('M3 binds the USDC swap receipt, pool swap, WETH unwrap, final native balance and separate gas/DEX costs',()=>{
 const {observations}=project('M3');
 assert.equal(observations.trades.length,1);
 assert.deepEqual({routeId:observations.trades[0]!.routeId,input:observations.trades[0]!.inputAmountUnits,
  output:observations.trades[0]!.outputAmountUnits,inputAsset:observations.trades[0]!.inputAssetId,outputAsset:observations.trades[0]!.outputAssetId},
  {routeId:'route-usdc-weth',input:'200000',output:'1250000',inputAsset:'USDC',outputAsset:'WETH'});
 assert.deepEqual(observations.conversions.map((row)=>[row.conversion,row.inputAmountUnits,row.outputAmountUnits]),[['unwrap','1250000','1250000']]);
 assert.equal(observations.finalStates[0]!.balances.find((row)=>row.assetId==='ETH')?.amountUnits,'1000000000001249400');
 assert.equal(observations.expenses.filter((row)=>row.component==='participant_gas').length,3);
 assert.equal(observations.expenses.find((row)=>row.component==='verified_dex_fee')?.usdcUnits,'600');
});

test('M4 binds wrap, allowance history/use, WETH swap, final zero allowance and valued DEX cost',()=>{
 const {observations}=project('M4');
 assert.deepEqual(observations.conversions.map((row)=>[row.conversion,row.inputAmountUnits,row.outputAmountUnits]),[['wrap','100000000000000','100000000000000']]);
 assert.equal(observations.trades[0]?.inputAssetId,'WETH');
 assert.equal(observations.trades[0]?.inputAmountUnits,'100000000000000');
 assert.equal(observations.trades[0]?.outputAmountUnits,'2000');
 assert.equal(observations.allowanceChanges[0]?.amountBeforeUnits,'0');
 assert.equal(observations.allowanceChanges[0]?.amountAfterUnits,'100000000000000');
 assert.equal(observations.allowanceUses[0]?.amountUnits,'100000000000000');
 assert.equal(observations.finalStates[0]!.allowances[0]?.amountUnits,'0');
 assert.equal(observations.expenses.find((row)=>row.component==='verified_dex_fee')?.usdcUnits,'717');
 assert.equal(observations.expenses.filter((row)=>row.component==='participant_gas').length,3);
});

test('H2 preserves two participant payout receipts and recipient balances with nonzero baselines',()=>{
 const {observations}=project('H2');
 assert.deepEqual(observations.transfers.map((row)=>[row.to,row.amountUnits,row.operation]),[
  ['0x00000000000000000000000000000000000000a2','1000','payout'],
  ['0x00000000000000000000000000000000000000a3','2000','payout'],
 ]);
 assert.equal(observations.finalStates[0]!.balances.find((row)=>row.account==='0x00000000000000000000000000000000000000a2')?.amountUnits,'1007');
 assert.equal(observations.finalStates[0]!.balances.find((row)=>row.account==='0x00000000000000000000000000000000000000a3')?.amountUnits,'2008');
 assert.equal(observations.expenses.filter((row)=>row.component==='participant_gas').length,2);
 assert.equal(observations.expenses.some((row)=>row.component==='verified_dex_fee'),false);
});

test('H3 keeps facilitator x402 receipt in the chain census while projecting only the task swap and its own costs',()=>{
 const fixture=makeChainCaptureCompositeFixture('H3'),{observations}=project('H3');
 const payment=fixture.packet.rpc.transactions.find((tx)=>tx.hash===fixture.packet.externalActions.find((action)=>action.actionKind==='pay')!.transactionHash)!;
 assert.equal(payment.from,'0x00000000000000000000000000000000000000a4');
 assert.equal(payment.input,null,'external EIP-3009 calldata is never retained');
 assert.match(payment.inputSha256,/^[0-9a-f]{64}$/i);
 assert.match(payment.receiptLogsSha256,/^[0-9a-f]{64}$/i);
 assert.equal(fixture.packet.rpc.final.participantTransactionCount,'3');
 const paymentOperations=(fixture.packet.bef.before as Record<string, unknown>)['externalPaymentOperations'];
 assert.ok(Array.isArray(paymentOperations));
 assert.equal(paymentOperations.length,1);
 assert.equal(observations.trades.length,1);
 assert.equal(observations.transfers.some((row)=>row.transactionHash===payment.hash),false);
 assert.equal(observations.finalStates[0]!.balances.find((row)=>row.account==='participant'&&row.assetId==='USDC')?.amountUnits,'799500');
 assert.equal(observations.expenses.filter((row)=>row.component==='participant_gas').length,3);
 assert.equal(observations.expenses.filter((row)=>row.component==='verified_dex_fee').length,1);
});

test('H3 and U1 final snapshots follow the shared owner cutoff without changing chain action sequences',()=>{
 for(const taskId of ['H3','U1'] as const){
  const fixture=makeChainCaptureCompositeFixture(taskId),{observations}=project(taskId);
  assert.ok(observations.finalStates[0]!.sequence>fixture.packet.closure.actionCutoffSequence);
  assert.deepEqual(observations.trades.map((row)=>row.actionSequence),fixture.packet.ownerActions
   .filter((action)=>action.actionKind==='swap').map((action)=>action.actionSequence));
 }
});

test('U1 chain projection captures scoped allowance history, final balances and chain gas separately from paid receipts',()=>{
 const fixture=makeChainCaptureCompositeFixture('U1'),{observations}=project('U1');
 const trade=observations.trades[0]!,route=fixture.packet.rpc.routes.find((item)=>item.routeId===trade.routeId)!;
 const swapOutput=observations.transfers.filter((item)=>item.transactionHash===trade.transactionHash&&item.from===route.pool&&
  item.assetId===trade.outputAssetId);
 assert.equal(observations.coverage.allowances,'complete');
 assert.equal(observations.trades.length,1);
 assert.equal(swapOutput.length,1);
 assert.deepEqual([swapOutput[0]!.to,swapOutput[0]!.amountUnits,swapOutput[0]!.operation],
  ['participant',trade.outputAmountUnits,'other']);
 assert.equal(observations.allowanceChanges.length,1);
 assert.equal(observations.allowanceUses.length,1);
 assert.equal(observations.finalStates[0]!.allowances[0]?.amountUnits,'0');
 assert.equal(observations.finalStates[0]!.balances.find((row)=>row.account==='participant'&&row.assetId==='USDC')?.amountUnits,'1000500');
 assert.equal(observations.expenses.filter((row)=>row.component==='participant_gas').length,3);
 assert.equal(observations.transfers.some((row)=>row.transactionHash===fixture.packet.externalActions.find((action)=>action.actionKind==='pay')!.transactionHash),false);
});

test('U1 rejects missing or altered pool-output receipt transfers',()=>{
 const fixture=makeChainCaptureCompositeFixture('U1'),swap=fixture.packet.ownerActions.find((action)=>action.actionKind==='swap')!;
 const route=fixture.packet.rpc.routes.find((item)=>item.tokenInAssetId===swap.command.inputAssetId&&
  item.tokenOutAssetId===swap.command.outputAssetId&&item.feeTier===Number(swap.command.feeTier??500))!;
 const isOutput=(log:Record<string,unknown>)=>{
  const topics=Array.isArray(log.topics)?log.topics.map(String):[];
  return String(log.transactionHash).toLowerCase()===swap.transactionHash.toLowerCase()&&
   String(log.address).toLowerCase()===route.tokenOut.toLowerCase()&&
   topics[1]?.toLowerCase().endsWith(route.pool.slice(2).toLowerCase())===true&&
   topics[2]?.toLowerCase().endsWith(fixture.packet.rpc.participant.slice(2).toLowerCase())===true;
 };
 const missing=structuredClone(fixture),missingIndex=missing.packet.rpc.transferLogs.findIndex(isOutput);
 assert.ok(missingIndex>=0);
 missing.packet.rpc.transferLogs.splice(missingIndex,1);
 assert.throws(()=>projection(missing),ChainCapturePacketError);

 const altered=structuredClone(fixture),alteredLog=altered.packet.rpc.transferLogs.find(isOutput)!;
 const actualAmount=BigInt(String(alteredLog.data));
 alteredLog.data='0x'+(actualAmount+1n).toString(16).padStart(64,'0');
 const transaction=altered.packet.rpc.transactions.find((item)=>item.hash.toLowerCase()===swap.transactionHash.toLowerCase())!;
  const transactionLog=transaction.logs.find((item)=>isOutput(item))!;
 transactionLog.data=alteredLog.data;
 transaction.receiptLogsSha256=createHash('sha256').update(canonicalTaskJson(transaction.logs)).digest('hex');
 assert.throws(()=>projection(altered),ChainCapturePacketError);
});

test('H3 rejects an unbound facilitator payment hash and a missing external receipt from its pinned block',()=>{
 const fixture=makeChainCaptureCompositeFixture('H3');
 const wrongHash=structuredClone(fixture.packet);
 wrongHash.externalActions.find((action)=>action.actionKind==='pay')!.transactionHash='0x'+'f'.repeat(64);
 assert.throws(()=>validateTaskChainCapturePacket(wrongHash,fixture.taskCase),ChainCapturePacketError);
 const omitted=structuredClone(fixture.packet);
 omitted.rpc.intervalBlocks.at(-1)!.externalTransactions=[];
 assert.throws(()=>validateTaskChainCapturePacket(omitted,fixture.taskCase),ChainCapturePacketError);
 const rawPaymentInput=structuredClone(fixture.packet);
 rawPaymentInput.rpc.transactions.find((tx)=>tx.hash===fixture.packet.externalActions.find((action)=>action.actionKind==='pay')!.transactionHash)!.input='0x1234';
 assert.throws(()=>validateTaskChainCapturePacket(rawPaymentInput,fixture.taskCase),ChainCapturePacketError);
 const changedActionInput=makeChainCaptureFixture('M3');
 changedActionInput.packet.rpc.transactions[0]!.inputSha256='f'.repeat(64);
 assert.throws(()=>validateTaskChainCapturePacket(changedActionInput.packet,changedActionInput.taskCase),ChainCapturePacketError);
});

test('packet rejects action-to-operation rebinding and RPC log fields that disagree with the original receipt',()=>{
 const fixture=makeChainCaptureFixture('M3');
 const wrongAction=structuredClone(fixture.packet);
 wrongAction.ownerActions[1]!.transactionHash=wrongAction.ownerActions[0]!.transactionHash;
 assert.throws(()=>validateTaskChainCapturePacket(wrongAction,fixture.taskCase),ChainCapturePacketError);
 const wrongLog=structuredClone(fixture.packet);
 const selectedSwap=wrongLog.rpc.swapLogs[0]!;
 selectedSwap.rpcBlockNumber='0x999';
 assert.throws(()=>validateTaskChainCapturePacket(wrongLog,fixture.taskCase),ChainCapturePacketError);
});

test('packet rejects a detached pool receipt, altered WETH conversion, and changed payout recipient',()=>{
 const swap=makeChainCaptureFixture('M3');
 swap.packet.rpc.transactions.find((tx)=>tx.hash===swap.packet.ownerActions.find((action)=>action.actionKind==='swap')!.transactionHash)!.logs[1]!.address='0x00000000000000000000000000000000000000ff';
 assert.throws(()=>projection(swap),ChainCapturePacketError);

 const conversion=makeChainCaptureFixture('M4');
 conversion.packet.rpc.transactions.find((tx)=>tx.hash===conversion.packet.ownerActions[0]!.transactionHash)!.logs[0]!.data='0x'+'0'.repeat(63)+'1';
 assert.throws(()=>projection(conversion),ChainCapturePacketError);

 const payout=makeChainCaptureFixture('H2');
 const payoutTopics=payout.packet.rpc.transferLogs[0]!.topics as string[];
 payoutTopics[2]='0x00000000000000000000000000000000000000000000000000000000000000ff';
 assert.throws(()=>projection(payout),ChainCapturePacketError);
});

test('packet rejects source-measurement receipt gas that differs from cost and RPC receipts',()=>{
 const fixture=makeChainCaptureFixture('M3');
 const before=fixture.packet.bef.before as Record<string,unknown>;
 const selected=before.selectedExecutions as Record<string,unknown>[];
 const measurement=selected[0]!.measurement as Record<string,unknown>;
 const receipt=measurement.receipt as Record<string,unknown>;
 receipt.gasUsed='101';
 receipt.gasCostWei='202';
 assert.throws(()=>projection(fixture),ChainCapturePacketError);

 const wrongPrice=makeChainCaptureFixture('M3');
 const wrongBefore=wrongPrice.packet.bef.before as Record<string,unknown>;
 const wrongSelected=wrongBefore.selectedExecutions as Record<string,unknown>[];
 const wrongMeasurement=wrongSelected[0]!.measurement as Record<string,unknown>;
 const wrongReceipt=wrongMeasurement.receipt as Record<string,unknown>;
 wrongReceipt.effectiveGasPriceWei='3';
 wrongReceipt.gasCostWei='300';
 assert.throws(()=>projection(wrongPrice),ChainCapturePacketError);
});

test('chain census requires the original BEF event JSON hash on every selected event',()=>{
 const fixture=makeChainCaptureFixture('M3');
 const before=fixture.packet.bef.before as Record<string,unknown>;
 const events=before.selectedEvents as Record<string,unknown>[];
 assert.ok(events.length>0);
 assert.ok(events.every((event)=>typeof event.eventJsonSha256==='string'&&/^[0-9a-f]{64}$/i.test(event.eventJsonSha256)));
 assert.doesNotThrow(()=>validateTaskChainCapturePacket(fixture.packet,fixture.taskCase));

 const missing=structuredClone(fixture.packet);
 const missingBefore=missing.bef.before as Record<string,unknown>;
 const missingEvents=missingBefore.selectedEvents as Record<string,unknown>[];
 delete missingEvents[0]!.eventJsonSha256;
 missing.bef.after=structuredClone(missing.bef.before);
 missing.bef.censusSha256=createHash('sha256').update(canonicalTaskJson(missing.bef.before)).digest('hex');
 assert.throws(()=>validateTaskChainCapturePacket(missing,fixture.taskCase),ChainCapturePacketError);

 const malformed=structuredClone(fixture.packet);
 const malformedBefore=malformed.bef.before as Record<string,unknown>;
 const malformedEvents=malformedBefore.selectedEvents as Record<string,unknown>[];
 malformedEvents[0]!.eventJsonSha256='not-a-sha256';
 malformed.bef.after=structuredClone(malformed.bef.before);
 malformed.bef.censusSha256=createHash('sha256').update(canonicalTaskJson(malformed.bef.before)).digest('hex');
 assert.throws(()=>validateTaskChainCapturePacket(malformed,fixture.taskCase),ChainCapturePacketError);
});

test('invalid collector targets return before opening the owner database transaction',async()=>{
 let transactions=0;
 const deps={db:{transaction:async()=>{transactions++;throw new Error('must-not-run')}}} as never;
 const result=await collectBefChainTaskObservationCandidate(deps,{runId:'not-a-uuid',taskIndex:0});
 assert.deepEqual(result,{status:'unavailable',reasonCode:'invalid_target'});
 assert.equal(transactions,0);
});
