import test from 'node:test';
import assert from 'node:assert/strict';
import { publicPaymentQuoteMatches, publicInspectionQuotesMatch } from './task-public-payment-quote.js';
import { canonicalTaskJson } from './task-release.js';
const terms={scheme:'exact',network:'eip155:8453',asset:'0x'+'1'.repeat(40),amount:'1',payTo:'0x'+'2'.repeat(40),transferMethod:'eip3009'};
const identity={name:'USD Coin',version:'2',paymentFlow:'authorization'};
test('public quote validator preserves legacy bytes and validates only the complete pinned identity group',()=>{
  const before=canonicalTaskJson(terms);assert.equal(publicPaymentQuoteMatches(terms,identity),true);assert.equal(canonicalTaskJson(terms),before);
  assert.equal(publicPaymentQuoteMatches({...terms,...identity},identity),true);
  for(const variant of [{...terms,name:'USD Coin'},{...terms,...identity,version:'foreign'},{...terms,...identity,paymentFlow:'other'},
    {...terms,...identity,name:'bad\nname'},{...terms,...identity,signature:'forbidden'}])assert.equal(publicPaymentQuoteMatches(variant,identity),false);
});
test('public inspection validates catalog and offer identity before unchanged economic projection',()=>{
  const payment={...terms,...identity},offers=[{id:'canonical',payment}];
  assert.equal(publicInspectionQuotesMatch({payment,offers},'inspect_offer',identity),true);
  assert.equal(publicInspectionQuotesMatch({catalog:[{offers}]},'inspect_catalog',identity),true);
  assert.equal(publicInspectionQuotesMatch({payment:terms,offers},'inspect_offer',identity),false);
  assert.equal(publicInspectionQuotesMatch({catalog:[{offers:[...offers,{id:'legacy',payment:terms}]}]},'inspect_catalog',identity),false);
  assert.equal(publicInspectionQuotesMatch({catalog:[{offers},{offers:[{id:'legacy',payment:terms}]}]},'inspect_catalog',identity),false);
  assert.equal(publicInspectionQuotesMatch({catalog:[{offers:[{id:'canonical',payment:{...payment,name:'foreign'}}]}]},'inspect_catalog',identity),false);
});
