import assert from 'node:assert/strict';
import test from 'node:test';
import {mcdOAuthAuthorized,mcdOAuthEvidence} from './mcp-diagnostics-oauth-evidence.mjs';

function authorized(){return {browserData:{exchange:{result:'AUTHORIZED',tokenEndpointStatus:200,tokenPresent:true,issuerMismatch:false,tokenRequests:[]},callback:{stateMatches:true,issuerMatches:true,errorCode:null}}};}
test('MCD accepts the actual SDK AUTHORIZED enum and requires endpoint/token/state/issuer evidence',()=>{
  assert.equal(mcdOAuthAuthorized(authorized()),true);
  for(const change of [{result:'success'},{result:'REDIRECT'},{tokenEndpointStatus:400},{tokenPresent:false},{issuerMismatch:true}]){
    const flow=authorized();Object.assign(flow.browserData.exchange,change);assert.equal(mcdOAuthAuthorized(flow),false);
  }
  for(const change of [{stateMatches:false},{issuerMatches:false}]){const flow=authorized();Object.assign(flow.browserData.callback,change);assert.equal(mcdOAuthAuthorized(flow),false);}
});
test('safe OAuth diagnostics retain status and presence flags without raw callback or token material',()=>{
  const flow=authorized(),canary='CANARY_PRIVATE_OAUTH_MATERIAL_not_real';
  Object.assign(flow.browserData.callback,{code:canary,state:canary,errorCode:canary});
  Object.assign(flow.browserData.exchange,{access_token:canary,refresh_token:canary,code_verifier:canary,errorMessage:canary,tokenRequests:[{status:200,clientIdMatches:true,code:canary,pkceVerifierPresent:true,accessTokenPresent:true,authorization:canary}]});
  const value=mcdOAuthEvidence(flow);assert.equal(value.exchangeResult,'AUTHORIZED');assert.equal(value.tokenEndpointStatus,200);assert.equal(value.callbackErrorCode,'unknown');assert.equal(value.tokenRequests[0].accessTokenPresent,true);assert(!JSON.stringify(value).includes(canary));
  assert.deepEqual(mcdOAuthEvidence(null).tokenRequests,[]);
});
