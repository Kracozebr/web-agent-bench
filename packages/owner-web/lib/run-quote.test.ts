import assert from 'node:assert/strict';
import test from 'node:test';
import { selectedRunQuote, trainingCatalogWeights, trainingQuoteDescription, type RunCatalogRelease } from './api.js';
const release: RunCatalogRelease={releaseIdentity:'current',manifestHash:'a'.repeat(64),benchmarkVersion:'current',benchmarkHash:'b'.repeat(64),policyHash:'c'.repeat(64),
  taskIds:['S1','S2','S3','S4','M1','M2','M3','M4','H1','H2','H3','U1'],openTaskIds:['S1','M1','H1'],openTaskWeights:[1,2,3],openWeightSum:6,
  completeRankedRelease:true,rankedPrice:'1.000000',trainingPrice:'0.500000',precision:6};
test('browser choices and quote use server metadata with exact request-level BigInt rounding',()=>{
  assert.deepEqual([...trainingCatalogWeights(release)!.keys()],['S1','M1','H1']);
  for(const [ids,quote] of [[['S1'],'0.083334'],[['M1'],'0.166667'],[['H1'],'0.250000'],[['S1','M1'],'0.250000'],[['S1','M1','H1'],'0.500000']] as const)
    assert.equal(selectedRunQuote(release,'training',[...ids]),quote);
  assert.equal(selectedRunQuote({...release,trainingPrice:'0'},'training',['M1']),'0.000000');
  assert.equal(selectedRunQuote(release,'ranked',release.taskIds),'1.000000');
  const metadata={...release,openTaskIds:['M1','H1'],openTaskWeights:[7,4],openWeightSum:11};
  assert.deepEqual([...trainingCatalogWeights(metadata)!.keys()],['M1','H1']);
  assert.equal(selectedRunQuote(metadata,'training',['M1']),'0.318182','UI must use metadata, not hardcoded weights');
});
test('missing inconsistent or adversarial metadata and selections cannot yield a quote',()=>{
  for(const patch of [{openTaskWeights:undefined},{openWeightSum:15},{openTaskWeights:[1,2]}, {openTaskWeights:[1,2,0]},
    {openTaskWeights:[1,2,1.5]},{openTaskWeights:[1,2,NaN]},{openTaskIds:['S1','S1','H1']},{openTaskIds:['S1','M1','unknown']},{taskIds:undefined}]) {
    const malformed={...release,...patch} as RunCatalogRelease;
    assert.equal(trainingCatalogWeights(malformed),null);
    assert.equal(selectedRunQuote(malformed,'training',['S1']),null);
  }
  for(const ids of [[],['S1','S1'],['S2'],['S1','S2']]) assert.equal(selectedRunQuote(release,'training',ids),null);
  assert.equal(selectedRunQuote(release,'ranked',['S1']),null);
  assert.equal(selectedRunQuote({...release,trainingPrice:'secret'},'training',['S1']),null);
});

test('rendered Training pricing description follows validated denominator metadata',()=>{
  assert.equal(trainingQuoteDescription(release),'0.500000 USDC; selected weight is quoted over denominator 6');
  assert.equal(trainingQuoteDescription({...release,openTaskWeights:[2,3,4],openWeightSum:9}),
    '0.500000 USDC; selected weight is quoted over denominator 9');
  assert.equal(trainingQuoteDescription({...release,openWeightSum:15}),'Training quote unavailable');
});
