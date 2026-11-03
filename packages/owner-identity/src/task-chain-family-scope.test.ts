import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {deriveChainFamilyScope} from './task-chain-family-scope.js';
import type {TaskCase,TaskReleaseManifest} from './task-release.js';

const a=(char:string)=>'0x'+char.repeat(40),h=(char:string)=>char.repeat(64);
function fixture(){
  const manifest={schemaVersion:'bef-runtime-manifest/v1',contracts:{usdc:{address:a('1'),proxyCodeHash:'0x'+h('a')},weth:{address:a('2'),codeHash:'0x'+h('b')},swapRouter02:{address:a('3'),codeHash:'0x'+h('c')},pool:{address:a('4'),codeHash:'0x'+h('d'),token0:a('2'),token1:a('1'),fee:500},pool3000:{address:a('5'),codeHash:'0x'+h('e'),token0:a('2'),token1:a('1'),fee:3000}}};
  const bytes=Buffer.from(JSON.stringify(manifest)),identity={environmentManifestSha256:createHash('sha256').update(bytes).digest('hex'),assets:[{assetId:'USDC',kind:'erc20',address:a('1'),codeHash:h('a')},{assetId:'WETH',kind:'erc20',address:a('2'),codeHash:h('b')}],contracts:[{contractId:'router',address:a('3'),codeHash:h('c')},{contractId:'pool500',address:a('4'),codeHash:h('d')},{contractId:'pool3000',address:a('5'),codeHash:h('e')}]} as unknown as TaskReleaseManifest['executionIdentity'];
  return {manifest,bytes,identity};
}
test('technical scope observes both directions and pools for S1 without pretending it is a trade task',()=>{
  const f=fixture(),scope=deriveChainFamilyScope(f.bytes,f.identity,{taskId:'S1'} as TaskCase);assert.equal(scope.routes.length,4);assert.deepEqual(new Set(scope.routes.map(r=>r.feeTier)),new Set([500,3000]));assert(scope.routes.every(r=>r.routeId.startsWith('technical-')));assert.equal(scope.manifest.sha256,f.identity.environmentManifestSha256);
});
test('goal route only annotates its matching technical route and cannot hide a supported off-goal route',()=>{
  const f=fixture(),task={taskId:'M3',objective:{permittedRoutes:[{routeId:'goal-route',tokenInAssetId:'WETH',tokenOutAssetId:'USDC',feeTier:500,routerContractId:'router',poolContractId:'pool500'}]}} as TaskCase;
  const scope=deriveChainFamilyScope(f.bytes,f.identity,task);assert.equal(scope.routes.filter(r=>r.routeId==='goal-route').length,1);assert.equal(scope.routes.filter(r=>r.routeId.startsWith('technical-')).length,3);
});
test('manifest tampering, unpinned pools, mismatched asset code and duplicate route declarations stay unavailable',()=>{
  const f=fixture();assert.throws(()=>deriveChainFamilyScope(Buffer.from(JSON.stringify({...f.manifest,surprise:true})),f.identity,{taskId:'S1'} as TaskCase));
  assert.throws(()=>deriveChainFamilyScope(f.bytes,{...f.identity,contracts:f.identity.contracts.slice(0,2)},{taskId:'S1'} as TaskCase));
  assert.throws(()=>deriveChainFamilyScope(f.bytes,{...f.identity,assets:f.identity.assets.map(asset=>({...asset,codeHash:h('f')}))},{taskId:'S1'} as TaskCase));
  const bytes=Buffer.from(JSON.stringify({...f.manifest,contracts:{...f.manifest.contracts,duplicated:f.manifest.contracts.pool}}));assert.throws(()=>deriveChainFamilyScope(bytes,{...f.identity,environmentManifestSha256:createHash('sha256').update(bytes).digest('hex')},{taskId:'S1'} as TaskCase));
});
