import {createHash} from 'node:crypto';
import {makeChainCaptureFixture} from './task-chain-capture-packet.fixture.js';
import {deriveChainFamilyScope} from './task-chain-family-scope.js';
import {canonicalTaskJson,type TaskCase,type TaskReleaseManifest} from './task-release.js';

// AICODE-NOTE: Synthetic codec regression fixture; never physical or native acceptance.
const hash=(value:string)=>createHash('sha256').update(value).digest('hex');
export function makeChainFamilyCaptureFixture(taskId:'S1'|'M4'='S1'){
  const f=makeChainCaptureFixture('M4'),packet=f.packet;
  const usdc=packet.rpc.assets.find(a=>a.assetId==='USDC')!,weth=packet.rpc.assets.find(a=>a.assetId==='WETH')!,router=packet.rpc.contracts.find(c=>c.contractId==='swapRouter02')!,pool=packet.rpc.contracts.find(c=>c.contractId==='pool3000')!;
  const manifest={schemaVersion:'bef-runtime-manifest/v1',contracts:{usdc:{address:usdc.address,proxyCodeHash:usdc.codeHash},weth:{address:weth.address,codeHash:weth.codeHash},swapRouter02:{address:router.address,codeHash:router.codeHash},pool3000:{address:pool.address,codeHash:pool.codeHash,token0:weth.address,token1:usdc.address,fee:3000}}};
  const bytes=Buffer.from(JSON.stringify(manifest)),manifestSha=hash(bytes.toString());
  const taskCase:TaskCase=taskId==='M4'?f.taskCase:{...f.taskCase,taskId:'S1',objective:{tokenAssetId:'USDC',recipient:'0x00000000000000000000000000000000000000a2',exactPrincipalUnits:'1000',nativeReserveWei:'10000'}} as TaskCase;
  packet.schemaVersion='bts-chain-family-observation-capture/v1';packet.taskId=taskId;packet.binding.taskId=taskId;
  packet.execution.environmentManifestHash=manifestSha;
  const identity={environmentManifestSha256:manifestSha,localChainId:31337,assets:packet.rpc.assets,contracts:packet.rpc.contracts} as TaskReleaseManifest['executionIdentity'];
  packet.technicalScope=deriveChainFamilyScope(bytes,identity,taskCase);packet.rpc.routes=packet.technicalScope.routes;
  for(const census of [packet.bef.before,packet.bef.after]){
    delete census.inspectionOperations;(census.generation as Record<string,unknown>).manifest_sha256=manifestSha;(census.generation as Record<string,unknown>).environment_manifest_sha256=manifestSha;
    for(const cost of census.costs as Record<string,unknown>[])cost.manifestSha256=manifestSha;
  }
  packet.bef.censusSha256=hash(canonicalTaskJson(packet.bef.before));
  packet.bef.session={currentUser:'bef_observer',sessionUser:'bef_observer',databaseName:'unit_fixture',transactionReadOnly:'on',transactionIsolation:'repeatable read',superuser:false,bypassRls:false};
  const states=[{ETH:'1000000000000000000',WETH:'0',USDC:'1000000'},{ETH:'999899999999999800',WETH:'100000000000000',USDC:'1000000'},{ETH:'999899999999999600',WETH:'100000000000000',USDC:'1000000'},{ETH:'999899999999999400',WETH:'0',USDC:'1002000'}];
  packet.rpc.balanceHistory=packet.ownerActions.map((action,index)=>{const tx=packet.rpc.transactions[index]!,block=packet.rpc.intervalBlocks[index]!;return {family:'chain',actionId:action.actionId,actionSequence:action.actionSequence,transactionHash:tx.hash,blockNumber:tx.blockNumber,blockHash:tx.blockHash,parentBlockNumber:String(BigInt(tx.blockNumber)-1n),parentBlockHash:block.parentHash,balances:packet.rpc.assets.map(asset=>({account:'participant',assetId:asset.assetId,beforeValue:states[index]![asset.assetId as 'ETH'|'USDC'|'WETH'],afterValue:states[index+1]![asset.assetId as 'ETH'|'USDC'|'WETH']}))};});
  const evidence={path:'artifacts/runs/owner-identity-bef-task-coordinator/observation/family-unit.json',sha256:'a'.repeat(64),boundary:'actual_tool_http_x402_local_evm_application_store' as const};
  return {packet,taskCase,context:{binding:packet.binding,taskCase,evidence,ethValuation:f.ethValuation,executionIdentity:identity,environmentManifest:bytes}};
}

export function makeZeroActionChainFamilyCaptureFixture(){
 const f=makeChainFamilyCaptureFixture('S1'),p=f.packet;p.ownerActions=[];p.externalActions=[];p.closure.actionCutoffSequence=0;p.closure.reconciledActionSequence=0;
 for(const c of [p.bef.before,p.bef.after]){c.operations=[];c.externalPaymentOperations=[];c.selectedExecutions=[];c.selectedEvents=[];c.costs=[];c.paymentsCount='0';c.deliveriesCount='0';c.counts={operations:'0',externalPaymentOperations:'0',selectedExecutions:'0',selectedEvents:'0',costs:'0'};}
 p.bef.censusSha256=hash(canonicalTaskJson(p.bef.before));p.rpc.final=structuredClone(p.rpc.baseline);p.rpc.intervalBlocks=[];p.rpc.transactions=[];p.rpc.transferLogs=[];p.rpc.approvalLogs=[];p.rpc.swapLogs=[];p.rpc.wethLogs=[];p.rpc.balanceHistory=[];return f;
}
