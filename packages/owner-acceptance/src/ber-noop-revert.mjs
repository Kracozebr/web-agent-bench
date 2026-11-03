/** Finite reference-SDK negative control. Actor observations are not independent acceptance. */
import {createHash} from 'node:crypto';
export const PROFILE='NOOP_REVERT_D';
export const FLAGS=Object.freeze({'--ber-noop-revert-training':'training','--ber-noop-revert-ranked':'ranked'});
export const W=1000000000000n,MAX_UINT256=(1n<<256n)-1n;
const TRAINING=['S1','M1','H1'],RANKED=['S1','S2','S3','S4','M1','M2','M3','M4','H1','H2','H3','U1'];
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i,ADDRESS=/^0x[a-f0-9]{40}$/i,HASH=/^0x[a-f0-9]{64}$/i;
const FIELDS=['blockNumber','payerNativeWei','payerWethUnits','payerUsdcUnits','recipientWethUnits','recipientUsdcUnits','wethRouterAllowance','usdcRouterAllowance','poolWethUnits','poolUsdcUnits','poolLiquidity','poolSqrtPriceX96'];
const APPROVAL='0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925',DEPOSIT='0xe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c';
const need=(value,code)=>{if(!value)throw Object.assign(new Error(code),{code});};
const object=v=>v&&typeof v==='object'&&!Array.isArray(v),canonical=v=>JSON.stringify(v,(_,x)=>object(x)?Object.fromEntries(Object.keys(x).sort().map(k=>[k,x[k]])):x),sha=v=>createHash('sha256').update(canonical(v)).digest('hex');
const units=v=>{need(typeof v==='string'&&/^(0|[1-9][0-9]{0,77})$/.test(v)&&BigInt(v)<=MAX_UINT256,'BER_D_UNITS_INVALID');return BigInt(v);};
const address=v=>{need(typeof v==='string'&&ADDRESS.test(v),'BER_D_ADDRESS_INVALID');return v.toLowerCase();};
const exact=(v,keys)=>object(v)&&Object.keys(v).sort().join(',')===[...keys].sort().join(',');
const word=v=>BigInt(v).toString(16).padStart(64,'0'),addressWord=v=>address(v).slice(2).padStart(64,'0');
const snapshot=v=>{need(exact(v,FIELDS),'BER_D_SNAPSHOT_INCOMPLETE');for(const key of FIELDS)units(v[key]);return v;};
export function validateNoopRevertScope(taskIds,task){
 const expected=task?.mode==='training'?TRAINING:task?.mode==='ranked'?RANKED:null;
 need(expected&&canonical(taskIds)===canonical(expected)&&expected[task.taskIndex]===task.taskId&&UUID.test(task.runId??'')&&task.participantToolProtocol==='separate_payment_delivery_v2','BER_D_FULL_IMMUTABLE_SCOPE_REQUIRED');
 const asset=id=>{const a=task.execution?.assets?.find(a=>a.assetId===id);need(a?.kind==='erc20'&&a.chainId===task.execution.localChainId,'BER_D_TECHNICAL_ASSET_UNAVAILABLE');return address(a.address);};
 const router=task.execution?.contracts?.find(c=>c.contractId==='swapRouter02');need(router,'BER_D_TECHNICAL_ROUTER_UNAVAILABLE');
 return {weth:asset('WETH'),usdc:asset('USDC'),router:address(router.address)};
}

export async function executeFixedNoopRevert({taskIds,task,admitAndObserve,now=Date.now}){
 const scope=validateNoopRevertScope(taskIds,task),deadline=Math.min(Date.parse(task.deadlineAt),Date.parse(task.overallDeadline));
 need(Number.isFinite(deadline)&&typeof admitAndObserve==='function','BER_D_EXECUTION_SEAM_INVALID');
 const proof={schemaVersion:'ber-controlled-noop-revert-actor/v1',profile:PROFILE,nativeAgent:false,negativeControlOnly:true,positiveCoverageCredit:false,independentProof:'not_run',runId:task.runId,taskId:task.taskId,taskIndex:task.taskIndex,issuedTaskSha256:sha(task),steps:[]};
 const identities={operations:new Set(),actions:new Set(),transactions:new Set(),bef:new Set()};let previous,participant;
 const step=async(command,label,expectedOutcome)=>{
  need(deadline-now()>12000,'BER_D_DISPATCH_HEADROOM_EXHAUSTED');const record={label,command:structuredClone(command)};proof.steps.push(record);
  const {admission:a,receipt:r}=await admitAndObserve(command);
  need(a&&UUID.test(a.operationId??'')&&UUID.test(a.actionId??'')&&a.runId===task.runId&&a.taskIndex===task.taskIndex&&canonical(a.command)===canonical(command),'BER_D_ADMISSION_IDENTITY_CHANGED');
  record.original={operationId:a.operationId,actionId:a.actionId,...(HASH.test(r?.transactionHash??'')?{transactionHash:r.transactionHash}:{})};
  need(r?.status==='observed'&&r.runId===task.runId&&r.taskIndex===task.taskIndex&&r.taskId===task.taskId&&r.actionId===a.actionId&&String(r.actionSequence)===String(proof.steps.length)&&Number.isSafeInteger(r.receiptRevision)&&r.receiptRevision>0&&HASH.test(r.transactionHash??''),'BER_D_ACTUAL_RECEIPT_REQUIRED');
  for(const [set,id]of [[identities.operations,a.operationId],[identities.actions,a.actionId],[identities.transactions,r.transactionHash.toLowerCase()]]){need(!set.has(id),'BER_D_ORIGINAL_ID_REUSED');set.add(id);}
  const m=r.toolResponse,tx=m?.transaction,receipt=m?.receipt,before=snapshot(m?.before),after=snapshot(m?.after),selected=m?.selectedAction;
  need(m?.outcome===expectedOutcome&&receipt?.status===expectedOutcome&&UUID.test(m.operationId??'')&&!identities.bef.has(m.operationId),'BER_D_ACTUAL_OUTCOME_UNCONFIRMED');identities.bef.add(m.operationId);
  need(tx?.hash===r.transactionHash&&receipt.transactionHash===r.transactionHash&&tx.chainId===task.execution.localChainId&&address(tx.from)===address(receipt.from)&&tx.gasLimit===command.gasLimit,'BER_D_TRANSACTION_IDENTITY_CHANGED');
  participant??=address(tx.from);need(address(tx.from)===participant,'BER_D_PARTICIPANT_CHANGED');
  const to=command.kind==='swap'?scope.router:scope.weth,value=command.kind==='wrap'?W:0n;
  const calldata=command.kind==='wrap'?'0xd0e30db0':command.kind==='approve'?'0x095ea7b3'+addressWord(scope.router)+word(W):'0x04e45aaf'+addressWord(scope.weth)+addressWord(scope.usdc)+word(500n)+addressWord(participant)+word(W)+word(MAX_UINT256)+word(0n);
  need(address(tx.to)===to&&address(receipt.to)===to&&units(tx.valueWei)===value&&tx.input?.toLowerCase()===calldata,'BER_D_CHOSEN_TRANSACTION_CHANGED');
  const selectedMatches=command.kind==='wrap'?exact(selected,['kind','amountWei','gasLimit'])&&selected.kind==='wrap'&&selected.amountWei===String(W):command.kind==='approve'?exact(selected,['kind','tokenAssetId','token','spender','amountUnits','gasLimit'])&&selected.kind==='approve'&&selected.tokenAssetId==='WETH'&&address(selected.token)===scope.weth&&address(selected.spender)===scope.router&&selected.amountUnits===String(W):exact(selected,['kind','route','router','inputAssetId','outputAssetId','tokenIn','tokenOut','fee','amountInUnits','amountOutMinimumUnits','recipient','gasLimit'])&&selected.kind==='swap'&&selected.route==='uniswap-v3-exactInputSingle'&&address(selected.router)===scope.router&&selected.inputAssetId==='WETH'&&selected.outputAssetId==='USDC'&&address(selected.tokenIn)===scope.weth&&address(selected.tokenOut)===scope.usdc&&selected.fee===500&&selected.amountInUnits===String(W)&&selected.amountOutMinimumUnits===String(MAX_UINT256)&&address(selected.recipient)===participant;
  need(selectedMatches&&selected.gasLimit===command.gasLimit,'BER_D_SELECTED_ACTION_CHANGED');
  need(HASH.test(receipt.blockHash??'')&&tx.blockHash===receipt.blockHash&&tx.blockNumber===receipt.blockNumber&&after.blockNumber===receipt.blockNumber&&units(after.blockNumber)===units(before.blockNumber)+1n&&tx.transactionIndex==='0','BER_D_BLOCK_BINDING_CHANGED');
  if(previous)need(canonical(before)===canonical(previous.after)&&units(tx.nonce)===units(previous.nonce)+1n,'BER_D_STATE_CONTINUITY_CHANGED');
  const gas=units(receipt.gasUsed)*units(receipt.effectiveGasPrice);need(units(receipt.gasUsed)>0n&&units(receipt.gasUsed)<=units(command.gasLimit)&&units(receipt.gasCostWei)===gas&&units(before.payerNativeWei)-units(after.payerNativeWei)===gas+value,'BER_D_UNEXPLAINED_NATIVE_OR_GAS');
  const changed=new Set(['blockNumber','payerNativeWei']);
  if(command.kind==='wrap'){changed.add('payerWethUnits');changed.add('recipientWethUnits');need(units(after.payerWethUnits)-units(before.payerWethUnits)===W&&units(after.recipientWethUnits)-units(before.recipientWethUnits)===W,'BER_D_OWN_WRAP_UNCONFIRMED');}
  if(command.kind==='approve'){changed.add('wethRouterAllowance');need(units(after.wethRouterAllowance)===W,'BER_D_APPROVAL_UNCONFIRMED');if(label==='noop_approval')need(before.wethRouterAllowance===after.wethRouterAllowance,'BER_D_NOOP_NOT_OBSERVED');}
  for(const field of FIELDS)if(!changed.has(field))need(before[field]===after[field],'BER_D_UNEXPLAINED_STATE_EFFECT');
  need(Array.isArray(receipt.logs),'BER_D_LOGS_MISSING');
  if(command.kind==='swap')need(receipt.logs.length===0&&m.fee?.principalAsset==='WETH'&&m.fee.selectedPrincipalUnits===String(W)&&m.fee.principalUnits==='0','BER_D_MINED_REVERT_NOT_PROVEN');
  else {need(receipt.logs.length===1,'BER_D_LOGS_CONTRADICTORY');const log=receipt.logs[0],topics=command.kind==='approve'?[APPROVAL,'0x'+addressWord(participant),'0x'+addressWord(scope.router)]:[DEPOSIT,'0x'+addressWord(participant)];need(address(log.address)===scope.weth&&canonical(log.topics.map(x=>x.toLowerCase()))===canonical(topics)&&log.data?.toLowerCase()==='0x'+word(W)&&log.transactionHash===r.transactionHash&&log.blockHash===receipt.blockHash&&log.blockNumber===receipt.blockNumber&&log.transactionIndex==='0'&&log.logIndex==='0'&&log.removed===false,'BER_D_EVENT_IDENTITY_CHANGED');}
  need(typeof r.evidencePath==='string'&&r.evidencePath.length<=512&&/^artifacts\/runs\/[A-Za-z0-9._/-]+$/.test(r.evidencePath)&&!r.evidencePath.split('/').some(x=>!x||x==='.'||x==='..')&&/^[a-f0-9]{64}$/i.test(r.evidenceHash??''),'BER_D_EVIDENCE_REFERENCE_MISSING');
  Object.assign(record.original,{befOperationId:m.operationId,receiptRevision:r.receiptRevision,actionSequence:r.actionSequence});record.evidence={path:r.evidencePath,sha256:r.evidenceHash};record.measurementSha256=sha(m);record.beforeSha256=sha(before);record.afterSha256=sha(after);record.allowanceBefore=before.wethRouterAllowance;record.allowanceAfter=after.wethRouterAllowance;record.receiptStatus=receipt.status;record.gasWei=String(gas);previous={after,nonce:tx.nonce};return participant;
 };
 try{
  // AICODE-NOTE: This bootstrap is identical on every task; the second approval is
  // a real no-op without inspecting or adapting to hidden initial allowance/stock.
  const payer=await step({kind:'wrap',amountWei:String(W),gasLimit:'100000'},'declared_wrap','success');
  const approve={kind:'approve',tokenAssetId:'WETH',amountUnits:String(W),gasLimit:'100000'};
  await step(approve,'declared_approval','success');await step(approve,'noop_approval','success');
  await step({kind:'swap',inputAssetId:'WETH',outputAssetId:'USDC',feeTier:500,amountInUnits:String(W),amountOutMinimumUnits:String(MAX_UINT256),recipient:payer,gasLimit:'300000'},'mined_revert','reverted');
  return proof;
 }catch(error){proof.blocker={code:/^BER_D_[A-Z_]+$/.test(error?.code??'')?error.code:'BER_D_UNRESOLVED_ORIGINAL_ACTION'};throw Object.assign(new Error(proof.blocker.code),{code:proof.blocker.code,negativeControlProof:proof});}
}
