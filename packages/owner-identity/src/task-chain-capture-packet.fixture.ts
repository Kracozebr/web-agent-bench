import { createHash } from 'node:crypto';
import { canonicalTaskJson, type EvidenceReference } from './task-release.js';
import type { ChainCaptureExternalAction, ChainCapturePacket, ChainJson, ChainTaskCase } from './task-chain-capture-packet.js';

const BOUNDARY='actual_tool_http_x402_local_evm_application_store' as const;
export const CHAIN_ADDRESSES={
 participant:'0x00000000000000000000000000000000000000a1',
 recipientA:'0x00000000000000000000000000000000000000a2',
 recipientB:'0x00000000000000000000000000000000000000a3',
 weth:'0x0000000000000000000000000000000000000001',
 usdc:'0x0000000000000000000000000000000000000002',
 router:'0x0000000000000000000000000000000000000003',
 pool:'0x0000000000000000000000000000000000000004',
 facilitator:'0x00000000000000000000000000000000000000a4',
} as const;
const sha=(value:string)=>createHash('sha256').update(value).digest('hex');
const word=(value:bigint)=>value.toString(16).padStart(64,'0');
const signed=(value:bigint)=>word(value<0n?(1n<<256n)+value:value);
const topicAddress=(value:string)=>`0x${value.slice(2).toLowerCase().padStart(64,'0')}`;
const id=(value:number)=>`10000000-0000-4000-8000-${value.toString(16).padStart(12,'0')}`;
const hash=(value:string)=>`0x${sha(value)}`;
const evidence=(path:string,seed:string):EvidenceReference=>({path,sha256:sha(seed),boundary:BOUNDARY});

type Command=Record<string,unknown>&{kind:'approve'|'transfer'|'wrap'|'unwrap'|'swap'};
type Scenario={taskId:ChainCapturePacket['taskId'];taskCase:ChainTaskCase;packet:ChainCapturePacket;binding:ChainCapturePacket['binding'];ethValuation:{numerator:string;denominator:string}};

export function makeRejectedChainCaptureFixture(taskId:'M3'|'M4'|'H2',withObserved=false){
 const fixture=makeChainCaptureFixture(taskId),packet=fixture.packet;
 packet.bef.session={currentUser:'bef_observer',sessionUser:'bef_observer',databaseName:'bef',transactionReadOnly:'on',transactionIsolation:'repeatable read',superuser:false,bypassRls:false};
 if(!withObserved){
  packet.ownerActions=[];
  packet.rpc.final=structuredClone(packet.rpc.baseline);packet.rpc.intervalBlocks=[];packet.rpc.transactions=[];
  packet.rpc.transferLogs=[];packet.rpc.approvalLogs=[];packet.rpc.swapLogs=[];packet.rpc.wethLogs=[];
  const census=packet.bef.before as ChainJson;
  for(const key of ['operations','selectedExecutions','selectedEvents','costs'])census[key]=[];
  census.counts={operations:'0',externalPaymentOperations:'0',selectedExecutions:'0',selectedEvents:'0',costs:'0'};
  packet.closure.actionCutoffSequence=0;packet.closure.reconciledActionSequence=0;
 }
 packet.ownerActions.forEach((action)=>{action.actionSequence++;});
 const command={kind:'transfer' as const,amountUnits:'1000',recipient:CHAIN_ADDRESSES.recipientA,gasLimit:'100000'};
 const actionId=id(300),operationId=id(301),commandSha256=sha(canonicalTaskJson({runId:packet.binding.runId,taskIndex:0,command}));
 const actionEvidence=evidence(`artifacts/runs/owner-identity-bef-task-coordinator/action/${actionId}.json`,'rejected-chain-child');
 packet.rejectedChainActions=[{actionId,actionSequence:1,ownerOperationId:'owner-rejected-transfer-1',actionKind:'transfer',commandSha256,command,
  receiptStatus:'rejected_before_execution',reasonCode:'platform_recovery_original_operation_terminal',actionEvidence,befOperationId:operationId,transactionHash:null}];
 const census=packet.bef.before as ChainJson,generation=census.generation as ChainJson;
 const requestSha256=sha(canonicalTaskJson({method:'POST',path:'/tools/transfer',action:{...command,token:CHAIN_ADDRESSES.usdc}}));
 const payloads=[{actionKind:'transfer',selectedAction:command,requestSha256},{reasonCode:'execution_observation_unknown'}];
 census.rejectedChainOperations=[{operation:{operationId,environmentId:packet.binding.environmentId,generationId:packet.execution.generationId,
  participantId:generation.participant_id,idempotencyKeySha256:sha(`task-action-${actionId}`),requestSha256,actionKind:'transfer',status:'rejected',
  receiptStatus:'not_submitted',transactionHash:null,responseSha256:null,startedAt:'2026-10-30T00:00:00Z',completedAt:'2026-10-30T00:00:01Z'},
  selectedExecution:{operationId,environmentId:packet.binding.environmentId,generationId:packet.execution.generationId,actionKind:'transfer',selectedAction:command,
   prestate:null,transactionIntent:null,measurement:null,transactionHash:null,outcome:'rejected',reasonCode:'execution_observation_unknown',completedAt:'2026-10-30T00:00:01Z'},
  selectedEvents:payloads.map((eventPayload,index)=>({eventId:id(302+index),eventSequence:String(1000+index),operationId,
   eventKind:index===0?'selected_action_bound':'rejected_before_broadcast',eventJsonSha256:sha(canonicalTaskJson(eventPayload)),transactionHash:null,eventPayload})),costsCount:0}];
 packet.closure.actionCutoffSequence++;packet.closure.reconciledActionSequence++;
 packet.bef.after=structuredClone(census);packet.bef.censusSha256=sha(canonicalTaskJson(census));
 const rejectedActionDocument={schema:'bef-task-action-observation-v1',actionId,runId:packet.binding.runId,taskIndex:0,actionSequence:'1',
  ownerOperationId:'owner-rejected-transfer-1',actionKind:'transfer',commandSha256,environmentId:packet.binding.environmentId,generationId:packet.execution.generationId,
  manifestSha256:packet.execution.environmentManifestHash,applicationSourceSha256:packet.execution.applicationSourceHash,idempotencyKey:`task-action-${actionId}`,
  status:'rejected_before_execution',reasonCode:'platform_recovery_original_operation_terminal',befOperationId:operationId};
 return {...fixture,rejectedActionDocument};
}

export function prependChainInspectionFixture(fixture:Scenario):Scenario{
 const copy=structuredClone(fixture),packet=copy.packet;
 packet.ownerActions.forEach((action)=>{action.actionSequence+=2;});
 packet.externalActions=['inspect_catalog','inspect_offer'].map((kind,index)=>({
  actionId:id(200+index),actionSequence:index+1,ownerOperationId:`owner-inspection-${index}`,
  actionKind:kind as 'inspect_catalog'|'inspect_offer',commandSha256:sha(`inspection-${index}`),receiptStatus:'observed',
  actionEvidence:evidence(`artifacts/runs/owner-identity-bef-task-coordinator/action/${id(200+index)}.json`,`inspection-${index}`),
  befOperationId:id(210+index),transactionHash:null,
  inspection:{command:kind==='inspect_catalog'?{kind}:{kind,resourceId:'resource-a'},rawResponseSha256:sha(`inspection-response-${index}`)},
 }));
 const census=packet.bef.before as ChainJson,generation=census.generation as ChainJson;
 census.inspectionOperations=packet.externalActions.map((action)=>({operationId:action.befOperationId,environmentId:packet.binding.environmentId,
  generationId:packet.execution.generationId,participantId:generation.participant_id,
  idempotencyKeySha256:sha(`task-action-${action.actionId}`),
  requestSha256:sha(JSON.stringify(action.actionKind==='inspect_catalog'?{method:'GET',path:'/catalog'}:{method:'GET',path:'/offer',resourceId:'resource-a'})),
  actionKind:action.actionKind==='inspect_catalog'?'catalog':'offer',status:'accepted',receiptStatus:'not_submitted',transactionHash:null,
  responseSha256:action.inspection!.rawResponseSha256,startedAt:'2026-10-30T00:00:00Z',completedAt:'2026-10-30T00:00:01Z',
  selectedExecutionsCount:0,selectedEventsCount:0,costsCount:0}));
 packet.bef.after=structuredClone(census);packet.bef.censusSha256=sha(canonicalTaskJson(census));
 packet.closure.actionCutoffSequence+=2;packet.closure.reconciledActionSequence+=2;
 return copy;
}

function selected(command:Command):ChainJson{
 if(command.kind==='approve')return {kind:command.kind,tokenAssetId:command.tokenAssetId,amountUnits:command.amountUnits,gasLimit:command.gasLimit};
 if(command.kind==='transfer')return {kind:command.kind,amountUnits:command.amountUnits,recipient:command.recipient,gasLimit:command.gasLimit};
 if(command.kind==='wrap'||command.kind==='unwrap')return {kind:command.kind,amountWei:command.amountWei,gasLimit:command.gasLimit};
 return {kind:command.kind,inputAssetId:command.inputAssetId,outputAssetId:command.outputAssetId,feeTier:command.feeTier,
  amountInUnits:command.amountInUnits,amountOutMinimumUnits:command.amountOutMinimumUnits,recipient:command.recipient,gasLimit:command.gasLimit};
}
function txInput(command:Command,route?:{tokenIn:string;tokenOut:string;router:string;feeTier:number}):string{
 if(command.kind==='approve')return `0x095ea7b3${topicAddress(CHAIN_ADDRESSES.router).slice(2)}${word(BigInt(String(command.amountUnits)))}`;
 if(command.kind==='transfer')return `0xa9059cbb${topicAddress(String(command.recipient)).slice(2)}${word(BigInt(String(command.amountUnits)))}`;
 if(command.kind==='wrap')return '0xd0e30db0';
 if(command.kind==='unwrap')return `0x2e1a7d4d${word(BigInt(String(command.amountWei)))}`;
 if(!route)throw new Error('fixture_route_missing');
 return `0x04e45aaf${topicAddress(route.tokenIn).slice(2)}${topicAddress(route.tokenOut).slice(2)}${word(BigInt(route.feeTier))}`+
  `${topicAddress(String(command.recipient)).slice(2)}${word(BigInt(String(command.amountInUnits)))}`+
  `${word(BigInt(String(command.amountOutMinimumUnits)))}${word(0n)}`;
}
function rawLog(address:string,topics:string[],data:string,blockNumber:number,blockHash:string,transactionHash:string,logIndex:number):ChainJson{
 return {address:address.toLowerCase(),topics:topics.map((x)=>x.toLowerCase()),data:data.toLowerCase(),blockNumber:String(blockNumber),blockHash,
  transactionHash,transactionIndex:'0',logIndex:String(logIndex),removed:false,rpcBlockNumber:`0x${blockNumber.toString(16)}`,
  rpcTransactionIndex:'0x0',rpcLogIndex:`0x${logIndex.toString(16)}`};
}
function hasTopic(log:ChainJson,topic:string):boolean{return Array.isArray(log.topics)&&log.topics[0]===topic}
function actionLogs(command:Command,txHash:string,blockNumber:number,blockHash:string,route?:{tokenIn:string;tokenOut:string;router:string;feeTier:number},
 unwrapAmount='0'):ChainJson[]{
 const p=CHAIN_ADDRESSES.participant,router=CHAIN_ADDRESSES.router,pool=CHAIN_ADDRESSES.pool;
 if(command.kind==='approve')return [rawLog(command.tokenAssetId==='USDC'?CHAIN_ADDRESSES.usdc:CHAIN_ADDRESSES.weth,
  ['0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925',topicAddress(p),topicAddress(router)],
  `0x${word(BigInt(String(command.amountUnits)))}`,blockNumber,blockHash,txHash,0)];
 if(command.kind==='transfer')return [rawLog(CHAIN_ADDRESSES.usdc,
  ['0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',topicAddress(p),topicAddress(String(command.recipient))],
  `0x${word(BigInt(String(command.amountUnits)))}`,blockNumber,blockHash,txHash,0)];
 if(command.kind==='wrap')return [rawLog(CHAIN_ADDRESSES.weth,
  ['0xe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c',topicAddress(p)],
  `0x${word(BigInt(String(command.amountWei)))}`,blockNumber,blockHash,txHash,0)];
 if(command.kind==='unwrap')return [rawLog(CHAIN_ADDRESSES.weth,
  ['0x7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65',topicAddress(p)],
  `0x${word(BigInt(String(command.amountWei)))}`,blockNumber,blockHash,txHash,0)];
 if(!route)throw new Error('fixture_route_missing');
 const input=BigInt(String(command.amountInUnits)),output=BigInt(unwrapAmount);
 const amount0=route.tokenIn.toLowerCase()<route.tokenOut.toLowerCase()?input:-output;
 const amount1=route.tokenIn.toLowerCase()<route.tokenOut.toLowerCase()?-output:input;
 return [
  rawLog(route.tokenIn,['0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',topicAddress(p),topicAddress(router)],`0x${word(input)}`,blockNumber,blockHash,txHash,0),
  rawLog(CHAIN_ADDRESSES.pool,['0xc42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67',topicAddress(router),topicAddress(p)],
   `0x${signed(amount0)}${signed(amount1)}${word(1n)}${word(1n)}${signed(0n)}`,blockNumber,blockHash,txHash,1),
  rawLog(route.tokenOut,['0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',topicAddress(pool),topicAddress(p)],`0x${word(output)}`,blockNumber,blockHash,txHash,2),
 ];
}

export function makeChainCaptureFixture(taskId:'M3'|'M4'|'H2'):Scenario{
 const participant=CHAIN_ADDRESSES.participant,router=CHAIN_ADDRESSES.router,pool=CHAIN_ADDRESSES.pool;
 const route=taskId==='M3'?{routeId:'route-usdc-weth',tokenInAssetId:'USDC',tokenOutAssetId:'WETH',tokenIn:CHAIN_ADDRESSES.usdc,tokenOut:CHAIN_ADDRESSES.weth,feeTier:3000}:
  taskId==='M4'?{routeId:'route-weth-usdc',tokenInAssetId:'WETH',tokenOutAssetId:'USDC',tokenIn:CHAIN_ADDRESSES.weth,tokenOut:CHAIN_ADDRESSES.usdc,feeTier:3000}:null;
 const commands:Command[]=taskId==='M3'?[{kind:'approve',tokenAssetId:'USDC',amountUnits:'200000',gasLimit:'100000'},
  {kind:'swap',inputAssetId:'USDC',outputAssetId:'WETH',feeTier:3000,amountInUnits:'200000',amountOutMinimumUnits:'1000000',recipient:participant,gasLimit:'150000'},
  {kind:'unwrap',amountWei:'1250000',gasLimit:'100000'}]:taskId==='M4'?[{kind:'wrap',amountWei:'100000000000000',gasLimit:'100000'},
  {kind:'approve',tokenAssetId:'WETH',amountUnits:'100000000000000',gasLimit:'100000'},
  {kind:'swap',inputAssetId:'WETH',outputAssetId:'USDC',feeTier:3000,amountInUnits:'100000000000000',amountOutMinimumUnits:'2000',recipient:participant,gasLimit:'150000'}]:
  [{kind:'transfer',amountUnits:'1000',recipient:CHAIN_ADDRESSES.recipientA,gasLimit:'100000'},
   {kind:'transfer',amountUnits:'2000',recipient:CHAIN_ADDRESSES.recipientB,gasLimit:'100000'}];
 const feeRoute=route?{...route,router,pool}:null;
 const caseBalances=taskId==='H2'?[{account:'participant',assetId:'USDC',amountUnits:'10000'},
  {account:CHAIN_ADDRESSES.recipientA,assetId:'USDC',amountUnits:'7'},{account:CHAIN_ADDRESSES.recipientB,assetId:'USDC',amountUnits:'8'},
  {account:'participant',assetId:'ETH',amountUnits:'1000000000000000000'}]:taskId==='M3'?
  [{account:'participant',assetId:'USDC',amountUnits:'1000000'},{account:'participant',assetId:'WETH',amountUnits:'0'},
   {account:'participant',assetId:'ETH',amountUnits:'1000000000000000000'}]:
  [{account:'participant',assetId:'WETH',amountUnits:'0'},{account:'participant',assetId:'USDC',amountUnits:'1000000'},
   {account:'participant',assetId:'ETH',amountUnits:'1000000000000000000'}];
 const caseAllowances=route?[{owner:'participant',tokenAssetId:route.tokenInAssetId,spender:router,amountUnits:'0'}]:[];
 const objective:Record<string,unknown>=taskId==='H2'?{permittedConversions:[],obligations:[
  {obligationId:'payout-a',recipient:CHAIN_ADDRESSES.recipientA,assetId:'USDC',exactAmountUnits:'1000'},
  {obligationId:'payout-b',recipient:CHAIN_ADDRESSES.recipientB,assetId:'USDC',exactAmountUnits:'2000'}]}:
  {permittedRoutes:[{routeId:route!.routeId,routeType:'uniswap_v3_exact_input_single',tokenInAssetId:route!.tokenInAssetId,
   tokenOutAssetId:route!.tokenOutAssetId,routerContractId:'swapRouter02',poolContractId:'pool3000',feeTier:3000}]};
 const caseId=`case-${taskId.toLowerCase()}`,caseHash=sha(`case-${taskId}`),rubricHash=sha(`rubric-${taskId}`),executionIdentityHash=sha('identity'),initialStateSha256=sha('initial');
 const taskCase={taskId,caseId,caseHash,rubricHash,executionIdentityHash,initialState:{stateSha256:initialStateSha256,balances:caseBalances,allowances:caseAllowances,
  deliveredComponentIds:[],fulfilledObligationIds:[]},objective} as unknown as ChainTaskCase;
 const binding={ownerId:id(1),agentId:id(2),runId:id(3),environmentId:'bef-local-74btsbrl',releaseIdentity:'local-fork-v1',manifestHash:sha('manifest'),
  caseId,caseHash,rubricHash,taskId};
 const generationId=id(4),environmentId='bef-local-74btsbrl',manifestSha=sha('environment-manifest'),participantId=id(5);
 const assets:ChainCapturePacket['rpc']['assets']=[
  {assetId:'ETH',kind:'native',address:null,codeHash:null},{assetId:'WETH',kind:'erc20',address:CHAIN_ADDRESSES.weth,codeHash:sha('weth-code')},
  {assetId:'USDC',kind:'erc20',address:CHAIN_ADDRESSES.usdc,codeHash:sha('usdc-code')}];
 const contracts=[{contractId:'swapRouter02',address:router,codeHash:sha('router-code')},{contractId:'pool3000',address:pool,codeHash:sha('pool-code')}];
 const routes:ChainCapturePacket['rpc']['routes']=feeRoute?[{routeId:feeRoute.routeId,tokenInAssetId:feeRoute.tokenInAssetId,tokenOutAssetId:feeRoute.tokenOutAssetId,
  router,pool,tokenIn:feeRoute.tokenIn,tokenOut:feeRoute.tokenOut,feeTier:feeRoute.feeTier}]:[];
 const baselineBlockHash=hash('block-100'),baselineParent=hash('block-99');
 const initialCount='0';
 const baselineBalances=caseBalances.map((row)=>({...row}));
 const finalBalances=baselineBalances.map((row)=>({...row}));
 const allowance=route?{owner:'participant',tokenAssetId:route.tokenInAssetId,spender:router,amountUnits:'0'}:null;
 const baselineAllowances=allowance?[{...allowance}]:[],finalAllowances=allowance?[{...allowance}]:[];
 if(taskId==='M3'){
  finalBalances.find((x)=>x.assetId==='USDC')!.amountUnits='800000';finalBalances.find((x)=>x.assetId==='ETH')!.amountUnits='1000000000001249400';
 }else if(taskId==='M4'){
  finalBalances.find((x)=>x.assetId==='USDC')!.amountUnits='1002000';finalBalances.find((x)=>x.assetId==='ETH')!.amountUnits='999899999999999400';
 }else{
   finalBalances.find((x)=>x.account==='participant'&&x.assetId==='USDC')!.amountUnits='7000';
  finalBalances.find((x)=>x.account===CHAIN_ADDRESSES.recipientA)!.amountUnits='1007';
  finalBalances.find((x)=>x.account===CHAIN_ADDRESSES.recipientB)!.amountUnits='2008';
  finalBalances.find((x)=>x.assetId==='ETH')!.amountUnits='999999999999999600';
 }
 const actions:ChainCapturePacket['ownerActions']=[];const operations:ChainJson[]=[],selectedExecutions:ChainJson[]=[],selectedEvents:ChainJson[]=[],costs:ChainJson[]=[],transactions:ChainCapturePacket['rpc']['transactions']=[];
 const intervalBlocks:ChainCapturePacket['rpc']['intervalBlocks']=[];let parent=baselineBlockHash;
 for(let index=0;index<commands.length;index++){
  const command=commands[index]!,actionId=id(10+index),ownerOp=`owner-operation-${taskId}-${index}`,befOp=id(30+index),blockNumber=101+index,blockHash=hash(`block-${blockNumber}`),
   transactionHash=hash(`transaction-${taskId}-${index}`),actionSelected=selected(command),requestSha=sha(`request-${taskId}-${index}`);
  const actionRouteValue=command.kind==='swap'&&feeRoute?{tokenIn:feeRoute.tokenIn,tokenOut:feeRoute.tokenOut,router,pool,feeTier:feeRoute.feeTier}:undefined;
  const logs=actionLogs(command,transactionHash,blockNumber,blockHash,actionRouteValue,command.kind==='unwrap'?String(command.amountWei):command.kind==='swap'?(taskId==='M3'?'1250000':'2000'):'0');
  const to=command.kind==='approve'?command.tokenAssetId==='USDC'?CHAIN_ADDRESSES.usdc:CHAIN_ADDRESSES.weth:
   command.kind==='transfer'?CHAIN_ADDRESSES.usdc:command.kind==='wrap'||command.kind==='unwrap'?CHAIN_ADDRESSES.weth:router;
  const valueWei=command.kind==='wrap'?String(command.amountWei):'0';const input=txInput(command,actionRouteValue);
  const tx={hash:transactionHash,from:participant,to,nonce:String(index),input,inputSha256:sha(input),receiptLogsSha256:sha(canonicalTaskJson(logs)),valueWei,gasLimit:String(command.gasLimit),blockNumber:String(blockNumber),blockHash,
   transactionIndex:'0',chainId:'31337',status:'success' as const,gasUsed:'100',effectiveGasPriceWei:'2',gasCostWei:'200',logs};
  const measurementRaw={measurement:taskId+'-'+index,receipt:{transactionHash,status:tx.status,gasUsed:tx.gasUsed,
   effectiveGasPrice:tx.effectiveGasPriceWei}};
  const measurementSha=sha(canonicalTaskJson(measurementRaw));
  transactions.push(tx);intervalBlocks.push({number:String(blockNumber),hash:blockHash,parentHash:parent,transactionCount:1,participantTransactions:[transactionHash],externalTransactions:[]});parent=blockHash;
  actions.push({actionId,actionSequence:index+1,ownerOperationId:ownerOp,actionKind:command.kind,commandSha256:sha(`command-${taskId}-${index}`),
   command:command as ChainJson,selectedAction:actionSelected,approvalSpender:command.kind==='approve'?router:null,
   actionEvidence:evidence(`artifacts/runs/owner-identity-bef-task-coordinator/action/${actionId}.json`,`action-${index}`),
   befOperationId:befOp,transactionHash});
  operations.push({operationId:befOp,environmentId,generationId,participantId,idempotencyKeySha256:sha(`task-action-${actionId}`),requestSha256:requestSha,
   actionKind:command.kind,status:'settled',receiptStatus:'success',transactionHash,responseSha256:sha(`response-${index}`),startedAt:`2026-10-28T00:00:0${index}.000Z`,completedAt:`2026-10-28T00:00:0${index+1}.000Z`});
  const intent={hash:transactionHash,type:'eip1559',chainId:31337,blockHash:null,blockNumber:null,transactionIndex:null,from:participant,to,nonce:String(index),input,valueWei,
   gasLimit:String(command.gasLimit),maxFeePerGasWei:'3',maxPriorityFeePerGasWei:'1'};
  selectedExecutions.push({operationId:befOp,environmentId,generationId,actionKind:command.kind,selectedAction:actionSelected,prestate:{blockNumber:String(blockNumber-1)},
   transactionIntent:intent,measurement:{measurementSha256:measurementSha,receipt:{transactionHash,status:tx.status,gasUsed:tx.gasUsed,
     effectiveGasPriceWei:tx.effectiveGasPriceWei,gasCostWei:tx.gasCostWei}},transactionHash,outcome:'success',reasonCode:null,completedAt:`2026-10-28T00:00:0${index+1}.000Z`});
  const payloads:[string,string|null,ChainJson][]=[['selected_action_bound',null,{actionKind:command.kind,requestSha256:requestSha,selectedAction:actionSelected}],
   ['prestate_observed',null,{prestate:{blockNumber:String(blockNumber-1)}}],['original_tx_hash_bound',transactionHash,{requestSha256:requestSha,transactionHash,transactionIntent:intent}],
   ['receipt_finalized',transactionHash,{outcome:'success',measurementSha256:measurementSha}]];
  for(let j=0;j<payloads.length;j++){
   const [eventKind,eventTx,eventPayload]=payloads[j]!;
   selectedEvents.push({eventId:id(100+index*4+j),eventSequence:String(index*4+j+1),operationId:befOp,eventKind,
    eventJsonSha256:sha(canonicalTaskJson(eventPayload)),transactionHash:eventTx,eventPayload});
  }
  const principal=command.kind==='wrap'?['ETH',String(command.amountWei)]:command.kind==='unwrap'?['WETH',String(command.amountWei)]:
   command.kind==='swap'?[String(command.inputAssetId),String(command.amountInUnits)]:command.kind==='transfer'?['USDC',String(command.amountUnits)]:[null,'0'];
  const blockParent=intervalBlocks[index]!.parentHash;
  costs.push({operationId:befOp,environmentId,generationId,transactionHash,payerAddress:participant,payerRole:'participant',receiptStatus:'success',transactionFrom:participant,
   receiptFrom:participant,receiptBlockNumber:String(blockNumber),receiptBlockHash:blockHash,receiptBlockParentHash:blockParent,gasUsed:'100',effectiveGasPriceWei:'2',gasCostWei:'200',
   modeledGasFeeUsdcUnits:'1',manifestSha256:manifestSha,selectedPrincipalAsset:principal[0],selectedPrincipalUnits:principal[1],observedPrincipalUnits:principal[1]});
 }
 const census:CensusFixture={generation:{generation_id:generationId,env_id:environmentId,participant_id:participantId,payer_address:participant,manifest_sha256:manifestSha,
   status:'active',chain_id:'31337',environment_manifest_sha256:manifestSha},operations,inspectionOperations:[],externalPaymentOperations:[],selectedExecutions,selectedEvents,costs,paymentsCount:'0',deliveriesCount:'0',
  counts:{operations:String(operations.length),externalPaymentOperations:'0',selectedExecutions:String(selectedExecutions.length),selectedEvents:String(selectedEvents.length),costs:String(costs.length)}};
 const finalBlock=Number(intervalBlocks.at(-1)?.number??100),finalHash=intervalBlocks.at(-1)?.hash??baselineBlockHash;
 const baseCheckpoint={blockNumber:'100',blockHash:baselineBlockHash,parentHash:baselineParent,balances:baselineBalances,allowances:baselineAllowances,participantTransactionCount:initialCount};
 const finalCheckpoint={blockNumber:String(finalBlock),blockHash:finalHash,parentHash:intervalBlocks.at(-1)?.parentHash??baselineParent,balances:finalBalances,allowances:finalAllowances,
  participantTransactionCount:String(commands.length)};
 const packet:ChainCapturePacket={schemaVersion:'bts-chain-task-observation-capture/v1',classification:'run_bound_observations_candidate_not_grade',taskId,binding,
  closure:{closureId:id(6),actionCutoffSequence:commands.length,reconciledActionSequence:commands.length},
  execution:{preparationId:id(7),leaseId:id(8),generationId,environmentId,environmentManifestHash:manifestSha,applicationSourceHash:sha('source'),
   executionIdentityHash,initialStateSha256},
  preparation:{fixtureEvidence:evidence('artifacts/runs/owner-identity-bef-task-coordinator/preparation/fixture.json','fixture'),
   baselineEvidence:evidence('artifacts/runs/owner-identity-bef-task-coordinator/preparation/baseline.json','baseline'),baselineBlockNumber:'100',baselineBlockHash},
  ownerActions:actions,externalActions:[],bef:{session:{currentUser:'bef_observer',transactionReadOnly:'on'},before:census,after:structuredClone(census),censusSha256:sha(canonicalTaskJson(census))},
  rpc:{localChainId:'31337',participant,assets,contracts,routes,identityCodeHashes:[...assets.filter((x)=>x.address).map((x)=>({address:x.address!,expectedCodeHash:x.codeHash!,observedCodeHash:x.codeHash!})),
   ...contracts.map((x)=>({address:x.address,expectedCodeHash:x.codeHash,observedCodeHash:x.codeHash}))],baseline:baseCheckpoint,final:finalCheckpoint,intervalBlocks,transactions,
   transferLogs:transactions.flatMap((x)=>x.logs.filter((log)=>hasTopic(log,TRANSFER))),approvalLogs:transactions.flatMap((x)=>x.logs.filter((log)=>hasTopic(log,APPROVAL))),
   swapLogs:transactions.flatMap((x)=>x.logs.filter((log)=>hasTopic(log,SWAP))),wethLogs:transactions.flatMap((x)=>x.logs.filter((log)=>hasTopic(log,DEPOSIT)||hasTopic(log,WITHDRAWAL))),
   responseHashes:[]}};
 return {taskId,taskCase,packet,binding,ethValuation:{numerator:'2390',denominator:'1000000000000'}};
}

export function makeChainCaptureCompositeFixture(taskId:'H3'|'U1'):Scenario{
 const base=makeChainCaptureFixture(taskId==='H3'?'M3':'M4'),packet=structuredClone(base.packet);
 const route=packet.rpc.routes[0]!;
 const permittedRoute={routeId:route.routeId,routeType:'uniswap_v3_exact_input_single',tokenInAssetId:route.tokenInAssetId,
  tokenOutAssetId:route.tokenOutAssetId,routerContractId:'swapRouter02',poolContractId:'pool3000',feeTier:route.feeTier};
 const component={componentId:'reference-market',resourceId:'market-reference',validator:{validatorVersion:'validator-v1',payloadSchemaVersion:'schema-v1',
  requiredFields:[{name:'route',type:'string'}],additionalProperties:false,predicates:[{op:'one_of',field:'route',values:['base']}],permittedProvenance:['oracle-a']},
  sourceIds:['oracle-a']};
 const objective:Record<string,unknown>=taskId==='H3'?{referenceComponent:component,
  routeObjective:{referenceField:'route',allowedRouteIds:[route.routeId],expectedRouteByValue:[{value:'base',routeId:route.routeId}]},
  inputAssetId:'USDC',exactInputUnits:'200000',permittedRoutes:[permittedRoute],minimumOutputUnits:'1000000',nativeReserveWei:'100000000000000000',
  combinedExpenseBudgetUsdcUnits:'10000'}:{requiredComponents:[component],permittedSources:['oracle-a'],permittedRoutes:[permittedRoute],
  allocationAssets:[{assetId:'WETH',usdcBaseUnitsPerAssetBaseUnit:{numerator:'1',denominator:'1'},targetShareBps:5000,toleranceBps:500}],
  payoutObligations:[{obligationId:'payout-a',recipient:CHAIN_ADDRESSES.recipientA,assetId:'USDC',exactAmountUnits:'1000'},
   {obligationId:'payout-b',recipient:CHAIN_ADDRESSES.recipientB,assetId:'USDC',exactAmountUnits:'2000'}],
  temporarySpenderScope:[{owner:'participant',tokenAssetId:'WETH',spender:CHAIN_ADDRESSES.router}],nativeReserveWei:'100000000000000000',
  expenseBudgetUsdcUnits:'10000',duplicatePurchaseIdentity:'resource-identity'};
 const taskCase={...base.taskCase,taskId,objective} as unknown as ChainTaskCase;
 const binding={...base.binding,taskId};
 packet.taskId=taskId;packet.binding=binding;
 delete (packet.bef.before as ChainJson).inspectionOperations;
 packet.ownerActions.forEach((action,index)=>{action.actionSequence=(taskId==='H3'?[4,6,7]:[5,6,7])[index]!;});
 const externalPaymentId=id(taskId==='H3'?70:71),paymentHash=hash(`payment-${taskId}`);
 const externalActions:ChainCaptureExternalAction[]=[
  {actionId:id(taskId==='H3'?72:75),actionSequence:1,ownerOperationId:`owner-read-${taskId}-catalog`,actionKind:'inspect_catalog',
   commandSha256:sha(`read-${taskId}-catalog`),receiptStatus:'observed',actionEvidence:evidence(`artifacts/runs/owner-identity-bef-task-coordinator/action/${id(taskId==='H3'?72:75)}.json`,`read-${taskId}-catalog`),
   befOperationId:id(taskId==='H3'?76:79),transactionHash:null},
  {actionId:id(taskId==='H3'?73:77),actionSequence:2,ownerOperationId:`owner-read-${taskId}-offer`,actionKind:'inspect_offer',
   commandSha256:sha(`read-${taskId}-offer`),receiptStatus:'observed',actionEvidence:evidence(`artifacts/runs/owner-identity-bef-task-coordinator/action/${id(taskId==='H3'?73:77)}.json`,`read-${taskId}-offer`),
   befOperationId:id(taskId==='H3'?78:80),transactionHash:null},
  {actionId:id(taskId==='H3'?74:78),actionSequence:3,ownerOperationId:`owner-pay-${taskId}-1`,actionKind:'pay',commandSha256:sha(`pay-${taskId}`),
   receiptStatus:'observed',actionEvidence:evidence(`artifacts/runs/owner-identity-bef-task-coordinator/action/${id(taskId==='H3'?74:78)}.json`,`pay-${taskId}`),
   befOperationId:externalPaymentId,transactionHash:paymentHash},
  {actionId:id(taskId==='H3'?79:81),actionSequence:taskId==='H3'?5:4,ownerOperationId:`owner-retrieve-${taskId}-1`,actionKind:'retrieve',
   commandSha256:sha(`retrieve-${taskId}`),receiptStatus:'observed',actionEvidence:evidence(`artifacts/runs/owner-identity-bef-task-coordinator/action/${id(taskId==='H3'?79:81)}.json`,
    `retrieve-${taskId}`),befOperationId:externalPaymentId,transactionHash:null},
 ];
 packet.externalActions=externalActions;
 packet.closure.actionCutoffSequence=7;packet.closure.reconciledActionSequence=7;
 const last=packet.rpc.intervalBlocks.at(-1)!;
 const paymentBlockNumber=BigInt(last.number)+1n,paymentBlockHash=hash(`block-${taskId}-payment`),paymentAmount=taskId==='H3'?'500':'1500';
 const paymentLog=rawLog(CHAIN_ADDRESSES.usdc,[TRANSFER,topicAddress(CHAIN_ADDRESSES.participant),topicAddress(CHAIN_ADDRESSES.facilitator)],
  `0x${word(BigInt(paymentAmount))}`,Number(paymentBlockNumber),paymentBlockHash,paymentHash,0);
 const paymentInput='0x';
 const paymentTransaction={hash:paymentHash,from:CHAIN_ADDRESSES.facilitator,to:CHAIN_ADDRESSES.usdc,nonce:'0',input:null,inputSha256:sha(paymentInput),receiptLogsSha256:sha(canonicalTaskJson([paymentLog])),valueWei:'0',gasLimit:'150000',
  blockNumber:paymentBlockNumber.toString(),blockHash:paymentBlockHash,transactionIndex:'0',chainId:'31337',status:'success' as const,gasUsed:'200',
  effectiveGasPriceWei:'2',gasCostWei:'400',logs:[paymentLog]};
 packet.rpc.transactions.push(paymentTransaction);
 packet.rpc.intervalBlocks.push({number:paymentBlockNumber.toString(),hash:paymentBlockHash,parentHash:last.hash,transactionCount:1,
  participantTransactions:[],externalTransactions:[paymentHash]});
 packet.rpc.transferLogs.push(paymentLog);
 packet.rpc.final.blockNumber=paymentBlockNumber.toString();packet.rpc.final.blockHash=paymentBlockHash;packet.rpc.final.parentHash=last.hash;
 const usdcFinal=packet.rpc.final.balances.find((row)=>row.account==='participant'&&row.assetId==='USDC');
 if(usdcFinal)usdcFinal.amountUnits=(BigInt(usdcFinal.amountUnits)-BigInt(paymentAmount)).toString();
 const census=packet.bef.before;
 census.externalPaymentOperations=[{operationId:externalPaymentId,status:'delivered',receiptStatus:'success',transactionHash:paymentHash}];
 census.paymentsCount='1';census.deliveriesCount='1';
 const counts=census.counts as ChainJson;counts.externalPaymentOperations='1';
 packet.bef.after=structuredClone(census);packet.bef.censusSha256=sha(canonicalTaskJson(census));
 return {taskId,taskCase,packet,binding,ethValuation:base.ethValuation};
}
type CensusFixture={generation:ChainJson;operations:ChainJson[];inspectionOperations:ChainJson[];externalPaymentOperations:ChainJson[];selectedExecutions:ChainJson[];selectedEvents:ChainJson[];costs:ChainJson[];
 paymentsCount:string;deliveriesCount:string;counts:ChainJson};
const TRANSFER='0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
const APPROVAL='0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925';
const SWAP='0xc42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67';
const DEPOSIT='0xe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c';
const WITHDRAWAL='0x7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65';
