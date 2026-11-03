/** Technical chain identity for observations, independent of a task's goal whitelist. */
import {createHash} from 'node:crypto';
import type {TaskCase,TaskReleaseManifest} from './task-release.js';

type Identity=TaskReleaseManifest['executionIdentity'];
type Json=Record<string,unknown>;
export type ChainFamilyRoute={routeId:string;tokenInAssetId:string;tokenOutAssetId:string;router:string;pool:string;tokenIn:string;tokenOut:string;feeTier:number};
export type ChainFamilyScope={manifest:{path:'infrastructure/benchmark-environment/manifest.json';sha256:string};routes:ChainFamilyRoute[]};
const ADDRESS=/^0x[0-9a-f]{40}$/i,HASH=/^(?:0x)?[0-9a-f]{64}$/i;
const rec=(value:unknown):value is Json=>!!value&&typeof value==='object'&&!Array.isArray(value);
const address=(value:unknown)=>typeof value==='string'&&ADDRESS.test(value)?value.toLowerCase():null;
const digest=(value:unknown)=>typeof value==='string'&&HASH.test(value)?value.replace(/^0x/,'').toLowerCase():null;
function need(value:unknown):asserts value{if(!value)throw new Error('chain_family_scope_unavailable');}

export function chainGoalRoutes(taskCase:TaskCase){
  if(taskCase.taskId==='H2')return taskCase.objective.permittedConversions;
  if(['M3','M4','H3','U1'].includes(taskCase.taskId))return (taskCase as Extract<TaskCase,{taskId:'M3'|'M4'|'H3'|'U1'}>).objective.permittedRoutes;
  return [];
}

export function deriveChainFamilyScope(bytes:Uint8Array,identity:Identity,taskCase:TaskCase):ChainFamilyScope{
  need(bytes.byteLength>0&&bytes.byteLength<=256*1024);
  const sha256=createHash('sha256').update(bytes).digest('hex');need(sha256===identity.environmentManifestSha256.toLowerCase());
  let manifest:unknown;try{manifest=JSON.parse(Buffer.from(bytes).toString('utf8'));}catch{need(false);}
  need(rec(manifest)&&manifest.schemaVersion==='bef-runtime-manifest/v1'&&rec(manifest.contracts));
  const contracts=(manifest as Json).contracts as Json,router=contracts.swapRouter02;
  need(rec(router)&&address(router.address)&&digest(router.codeHash));
  const routerAddress=address((router as Json).address)!;
  need(identity.contracts.some(c=>address(c.address)===routerAddress&&digest(c.codeHash)===digest((router as Json).codeHash)));
  const assets=new Map(identity.assets.filter(a=>a.kind==='erc20'&&a.address).map(a=>[address(a.address)!,a]));
  for(const name of ['usdc','weth']){
    const pin=contracts[name];need(rec(pin)&&address(pin.address));const asset=assets.get(address((pin as Json).address)!);
    need(asset&&asset.assetId===(name==='usdc'?'USDC':'WETH')&&digest(asset.codeHash)===digest(name==='usdc'?(pin as Json).proxyCodeHash:(pin as Json).codeHash));
  }
  const routes:ChainFamilyRoute[]=[],seen=new Set<string>();
  for(const value of Object.values(contracts)){
    if(!rec(value)||value.token0===undefined&&value.token1===undefined&&value.fee===undefined)continue;
    const pool=address(value.address),token0=address(value.token0),token1=address(value.token1),fee=value.fee;
    need(pool&&token0&&token1&&token0!==token1&&Number.isSafeInteger(fee)&&Number(fee)>0&&Number(fee)<=0xffffff&&digest(value.codeHash));
    need(identity.contracts.some(c=>address(c.address)===pool&&digest(c.codeHash)===digest(value.codeHash)));
    const left=assets.get(token0!),right=assets.get(token1!);need(left&&right);
    for(const [input,output] of [[left,right],[right,left]] as const){
      const key=pool+'|'+input.assetId+'|'+output.assetId+'|'+fee;need(!seen.has(key));seen.add(key);
      // AICODE-NOTE: Goal route IDs annotate actual technical routes; they never authorize observation.
      const goal=chainGoalRoutes(taskCase).filter(r=>r.tokenInAssetId===input.assetId&&r.tokenOutAssetId===output.assetId&&r.feeTier===fee&&
        identity.contracts.some(c=>c.contractId===r.routerContractId&&address(c.address)===routerAddress)&&
        identity.contracts.some(c=>c.contractId===r.poolContractId&&address(c.address)===pool)).sort((a,b)=>a.routeId.localeCompare(b.routeId,'en'))[0];
      const routeId=goal?.routeId??`technical-${pool!.slice(2)}-${input.assetId}-${output.assetId}-${fee}`;need(routeId.length<=128);
      routes.push({routeId,tokenInAssetId:input.assetId,tokenOutAssetId:output.assetId,router:routerAddress,pool:pool!,tokenIn:address(input.address)!,tokenOut:address(output.address)!,feeTier:Number(fee)});
    }
  }
  need(routes.length>0&&routes.length<=128);
  return {manifest:{path:'infrastructure/benchmark-environment/manifest.json',sha256},routes};
}
