import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import {createGenuineAgentRequestPacer,matchGenuinePublicOffer,readGenuineH3PublicReferenceField,selectGenuinePublicCatalogOffer} from './genuine-s1-cases.mjs';
const token='0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',recipient='0x24e0FF92900f2963A54A463116f730E567F1Ee89';
const assets=[{assetId:'USDC',chainId:8453,kind:'erc20',address:token}];
const offer=(id,amount)=>({id,payment:{scheme:'exact',network:'eip155:8453',asset:token,amount,payTo:recipient,transferMethod:'eip3009'}});
test('public x402 terms without assetId resolve only through the issued chain and token address',()=>{
 const observed=offer('canonical','100000');
 assert.equal(matchGenuinePublicOffer(observed,{assets,assetId:'USDC',network:'eip155:8453',recipient}),true);
 for(const changed of [{...observed,payment:{...observed.payment,asset:'0x'+'1'.repeat(40)}},{...observed,payment:{...observed.payment,network:'eip155:1'}}])
  assert.equal(matchGenuinePublicOffer(changed,{assets,assetId:'USDC'}),false);
});
test('catalog actor uses complete public USDC price and rejects a foreign payee without requiring invented assetId fields',()=>{
 const required={requiredDataType:'market-state',assetId:'USDC',network:'eip155:8453',recipient,maxAdvertisedTotalPriceUsdcUnits:'200000'};
 const body={catalog:[{resourceId:'more',dataType:'market-state',offers:[offer('expensive','150000')]},
  {resourceId:'less',dataType:'market-state',offers:[offer('cheap','100000')]},
  {resourceId:'foreign',dataType:'market-state',offers:[{...offer('wrong','1'),payment:{...offer('wrong','1').payment,payTo:'0x'+'2'.repeat(40)}}]}]};
 assert.deepEqual(selectGenuinePublicCatalogOffer(body,required,assets),{resourceId:'less',offerId:'cheap',fullCostUsdcUnits:'100000'});
 assert.equal(selectGenuinePublicCatalogOffer(body,{...required,maxAdvertisedTotalPriceUsdcUnits:'99999'},assets),null);
});
test('H3 route field is read from the matching inspected resource envelope content',()=>{
 const profile=JSON.parse(readFileSync(new URL('../../../infrastructure/benchmark-environment/resources/market-state-brief.json',import.meta.url),'utf8'));
 const component={resourceId:profile.resourceId};
 const reference={resource:{resourceId:profile.resourceId,schema:profile.schema},content:profile};
 assert.equal(readGenuineH3PublicReferenceField(reference,component,'routeCode'),'alternative');
 assert.throws(()=>readGenuineH3PublicReferenceField({...reference,content:{...profile,resourceId:'other-resource'}},component,'routeCode'),
  {code:'h3_public_reference_envelope_binding_mismatch'});
 assert.throws(()=>readGenuineH3PublicReferenceField({...reference,content:{...profile,schema:'other/schema'}},component,'routeCode'),
  {code:'h3_public_reference_envelope_binding_mismatch'});
});
test('concurrent agent API requests receive serialized slots at least 1100ms apart',async()=>{
 let now=0;
 const waits=[];
 const pace=createGenuineAgentRequestPacer(1100,()=>now,async(milliseconds)=>{waits.push(milliseconds);now+=milliseconds;});
 const starts=[];
 await Promise.all(Array.from({length:4},async()=>{await pace();starts.push(now);}));
 assert.deepEqual(starts,[0,1100,2200,3300]);
 assert.deepEqual(waits,[1100,1100,1100]);
});
