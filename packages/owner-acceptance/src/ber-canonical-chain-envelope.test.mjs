import assert from 'node:assert/strict';
import test from 'node:test';
import {readFile} from 'node:fs/promises';
import {selectedActionForMeasurement} from '../../benchmark-environment/src/selected-execution.ts';
import {RuntimeManifestSchema} from '../../benchmark-environment/src/manifest.ts';
import {sameActionEnvelope} from '../../owner-identity/src/bef-chain-observation-collector.ts';
import {makeChainFamilyCaptureFixture} from '../../owner-identity/src/task-chain-family-capture-packet.fixture.ts';
import {selectedActionMatches,safeMeasurementProjection} from '../../owner-identity/src/bef-task-executor.ts';

test('actual canonical BEF measurement producer is accepted by owner family collector and recovered response projection',async()=>{
 const manifest=RuntimeManifestSchema.parse(JSON.parse(await readFile(new URL('../../../infrastructure/benchmark-environment/manifest.json',import.meta.url),'utf8')));
 const f=makeChainFamilyCaptureFixture(),action=f.packet.ownerActions.find(a=>a.command.kind==='swap');assert(action);
 // Technical fixture uses the public pinned pair, while route/contract pins are supplied by that fixture.
 const command={...action.command,feeTier:500},selected={...action.selectedAction,feeTier:500},scope=f.packet.technicalScope;assert(scope);
 const generic=selectedActionForMeasurement(command,manifest),route=scope.routes.find(r=>r.tokenInAssetId==='WETH');assert(route);
 const assets=f.packet.rpc.assets.map(a=>({...a,address:a.assetId==='WETH'?manifest.contracts.weth.address:a.assetId==='USDC'?manifest.contracts.usdc.address:a.address}));
 const contracts=f.packet.rpc.contracts.map(c=>({...c,address:c.contractId==='swapRouter02'?manifest.contracts.swapRouter02.address:c.address}));
 const technical={...scope,routes:[{...route,feeTier:500,router:manifest.contracts.swapRouter02.address,pool:manifest.contracts.pool.address}]};
 const accepts=raw=>sameActionEnvelope(raw,selected,command,f.taskCase,assets,contracts,technical);
 assert.equal(accepts(generic),true);assert.equal(selectedActionMatches(command,generic),true);
 const response=safeMeasurementProjection({operationId:'10000000-0000-4000-8000-000000000001',outcome:'success',selectedAction:generic});
 assert(response);assert.equal(accepts(response.selectedAction),true);assert.equal(selectedActionMatches(command,response.selectedAction),true);
 const {inputAssetId,outputAssetId,amountInUnits,amountOutMinimumUnits,...rest}=generic;
 const legacy={...rest,amountInWei:amountInUnits,amountOutMinimumUsdcUnits:amountOutMinimumUnits};assert.equal(accepts(legacy),true);
 for(const raw of [{...legacy,...generic},{...generic,extra:'forbidden'},{...generic,inputAssetId:'USDC'},{...generic,outputAssetId:'WETH'},
  {...generic,amountInUnits:'999'},{...generic,amountOutMinimumUnits:'999'},{...generic,recipient:'0x'+'99'.repeat(20)},
  {...generic,router:'0x'+'99'.repeat(20)},{...generic,fee:3000},{...legacy,amountInWei:'999'}])assert.equal(accepts(raw),false);
});
