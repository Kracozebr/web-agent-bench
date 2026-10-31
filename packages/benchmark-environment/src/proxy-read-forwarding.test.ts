import assert from 'node:assert/strict';import test from 'node:test';
import {forwardValidatedProxyRead,transientNetworkBeforeResponse} from './proxy-read-forwarding.js';

const network=()=>new TypeError('RAW_SECRET_SENTINEL',{cause:Object.assign(new Error('RAW_SECRET_SENTINEL'),{code:'ECONNRESET'})});
test('only declared transient Node transport codes qualify before an HTTP response',()=>{
 for(const code of ['ECONNRESET','ECONNREFUSED','ENOTFOUND','EAI_AGAIN','EHOSTUNREACH','ENETUNREACH','ETIMEDOUT','UND_ERR_CONNECT_TIMEOUT','UND_ERR_HEADERS_TIMEOUT','UND_ERR_SOCKET']) {
  assert.equal(transientNetworkBeforeResponse(new TypeError('RAW_SECRET_SENTINEL',{cause:Object.assign(new Error('RAW_SECRET_SENTINEL'),{code})})),true,code);
 }
 for(const code of ['ERR_TLS_CERT_ALTNAME_INVALID','ERR_INVALID_URL','CERT_HAS_EXPIRED','RAW_SECRET_SENTINEL']) {
  assert.equal(transientNetworkBeforeResponse(new TypeError('RAW_SECRET_SENTINEL',{cause:Object.assign(new Error('RAW_SECRET_SENTINEL'),{code})})),false);
 }
 const cyclic={cause:null as unknown};cyclic.cause=cyclic;assert.equal(transientNetworkBeforeResponse(cyclic),false);
 for(const cause of [new DOMException('RAW_SECRET_SENTINEL','AbortError'),new DOMException('RAW_SECRET_SENTINEL','TimeoutError'),
  Object.assign(new Error('RAW_SECRET_SENTINEL'),{code:'ERR_TLS_CERT_ALTNAME_INVALID'}),Object.assign(new Error('RAW_SECRET_SENTINEL'),{code:'UNRECOGNIZED'})]) {
  assert.equal(transientNetworkBeforeResponse(Object.assign(new Error('RAW_SECRET_SENTINEL'),{code:'ECONNRESET',cause})),false);
 }
});
function setup(){let clock=0;const timeouts:number[]=[],attempts:boolean[]=[],outcomes:string[]=[];let reserved=0;
 return {input:{source:true,targetUrl:'http://fixture.invalid/RAW_SECRET_SENTINEL',serialized:'{"fixture":true}',reserveRetry:()=>{reserved++;return true;},onAttempt:(r:boolean)=>attempts.push(r),onNetworkFailure:()=>{},onRetryOutcome:(r:'response'|'exhausted'|'budget_denied'|'deadline_exhausted')=>outcomes.push(r)},
  hooks:{now:()=>clock,sleep:async(ms:number)=>{clock+=ms;},timeoutSignal:(ms:number)=>{timeouts.push(ms);return new AbortController().signal;}},
  advance:(ms:number)=>{clock+=ms;},clock:()=>clock,timeouts,attempts,outcomes,reserved:()=>reserved};
}
test('one monotonic15s budget includes8s first failure plus250ms backoff and6.75s second attempt',async()=>{
 const state=setup();let calls=0;
 await assert.rejects(forwardValidatedProxyRead(state.input,{...state.hooks,fetch:async()=>{
  if(++calls===1){state.advance(8000);throw network();}state.advance(6750);throw new DOMException('RAW_SECRET_SENTINEL','TimeoutError');
 }}));
 assert.equal(state.clock(),15000);assert.deepEqual(state.timeouts,[15000,6750]);assert.deepEqual(state.attempts,[false,true]);assert.equal(state.reserved(),1);assert.deepEqual(state.outcomes,['exhausted']);
});
test('insufficient remaining deadline and retry budget stop without second wire attempt',async()=>{
 for(const mode of ['deadline','budget']){const s=setup();let calls=0;s.input.reserveRetry=()=>false;
  await assert.rejects(forwardValidatedProxyRead(s.input,{...s.hooks,fetch:async()=>{calls++;s.advance(mode==='deadline'?14900:100);throw network();}}));
  assert.equal(calls,1);assert.deepEqual(s.outcomes,[mode==='deadline'?'deadline_exhausted':'budget_denied']);assert.ok(s.clock()<=15000);
 }
});
test('clock advancing past deadline during retry reservation never starts another wire request',async()=>{
 const s=setup();let calls=0;s.input.reserveRetry=()=>{s.advance(15000);return true;};
 await assert.rejects(forwardValidatedProxyRead(s.input,{...s.hooks,fetch:async()=>{calls++;throw network();}}),{message:'proxy_read_total_deadline_exhausted'});
 assert.equal(calls,1);assert.deepEqual(s.attempts,[false]);assert.deepEqual(s.timeouts,[15000]);assert.deepEqual(s.outcomes,['deadline_exhausted']);
});
test('HTTP response, local mode, unknown/configuration error and caller timeout never retry',async()=>{
 for(const error of [new DOMException('RAW_SECRET_SENTINEL','TimeoutError'),new DOMException('RAW_SECRET_SENTINEL','AbortError'),new TypeError('RAW_SECRET_SENTINEL'),Object.assign(new Error('RAW_SECRET_SENTINEL'),{code:'ERR_TLS_CERT_ALTNAME_INVALID'})])assert.equal(transientNetworkBeforeResponse(error),false);
 for(const source of [false,true]){const s=setup();s.input.source=source;let calls=0;
  const response=await forwardValidatedProxyRead(s.input,{...s.hooks,fetch:async()=>{calls++;return new Response('RAW_SECRET_SENTINEL',{status:503});}});
  assert.equal(response.status,503);assert.equal(calls,1);assert.equal(s.reserved(),0);
 }
 const s=setup();s.input.source=false;await assert.rejects(forwardValidatedProxyRead(s.input,{...s.hooks,fetch:async()=>{throw network();}}));assert.deepEqual(s.attempts,[false]);
});
