import assert from 'node:assert/strict';
import test from 'node:test';
import type { OwnerDatabase } from './db.js';
import { observeDiagnosticAction,observeDiagnosticBoundary,setDiagnosticActionSink,withDiagnosticRequest,type DiagnosticBoundary } from './mcp-diagnostics-boundary.js';

test('parallel owner requests keep their diagnostic sinks through interleaved async work',async()=>{
 const a:DiagnosticBoundary[]=[],b:DiagnosticBoundary[]=[];let releaseA!:()=>void,releaseB!:()=>void;
 const waitA=new Promise<void>(r=>{releaseA=r;}),waitB=new Promise<void>(r=>{releaseB=r;});
 const first=withDiagnosticRequest(async event=>{a.push(event);},async()=>{
  releaseB();await waitA;await observeDiagnosticBoundary({stage:'admission',outcome:'success',taskIndex:1});
  await Promise.resolve();await observeDiagnosticBoundary({stage:'receipt',outcome:'unknown',taskIndex:1});return 'owner-a';
 });
 const second=withDiagnosticRequest(async event=>{b.push(event);},async()=>{
  await waitB;await observeDiagnosticBoundary({stage:'admission',outcome:'success',taskIndex:2});releaseA();
  await Promise.resolve();await observeDiagnosticBoundary({stage:'receipt',outcome:'success',taskIndex:2});return 'owner-b';
 });
 assert.deepEqual(await Promise.all([first,second]),['owner-a','owner-b']);
 assert.deepEqual(a.map(e=>e.taskIndex),[1,1]);assert.deepEqual(b.map(e=>e.taskIndex),[2,2]);
 await observeDiagnosticBoundary({stage:'admission',outcome:'error',errorCode:'UNAUTHORIZED'});
 assert.equal(a.length,2);assert.equal(b.length,2,'completed request context must not leak into unbound work');
});

test('diagnostic sink rejection cannot fail or retry an already committed business action',async()=>{
 let payments=0,requestAttempts=0,actionAttempts=0,unavailable=0;
 const receipt={actionId:'12345678-1234-4234-8234-123456789abc',paymentCommitted:true};
 const db={} as OwnerDatabase;
 setDiagnosticActionSink(db,async()=>{actionAttempts++;throw new Error('synthetic diagnostic store unavailable');});
 try{
  const result=await withDiagnosticRequest(async()=>{requestAttempts++;throw new Error('synthetic request sink unavailable');},async()=>{
   payments++;
   await observeDiagnosticBoundary({stage:'admission',outcome:'success',actionId:receipt.actionId});
   await observeDiagnosticAction(db,{stage:'dispatch',outcome:'unknown',actionId:receipt.actionId});
   await observeDiagnosticAction(db,{stage:'receipt',outcome:'success',actionId:receipt.actionId,receiptRevision:1});
   return receipt;
  },()=>{unavailable++;});
  assert.equal(result,receipt);assert.equal(payments,1);assert.equal(requestAttempts,1);assert.equal(actionAttempts,2);
  assert.equal(unavailable,1,'request metadata must disclose capture failure');
 }finally{setDiagnosticActionSink(db,undefined);}
});

test('executor sinks are database-scoped and a hanging sink exhausts only the bounded diagnostic budget',async()=>{
 const a={} as OwnerDatabase,b={} as OwnerDatabase;let aCalls=0,bCalls=0,release!:()=>void;
 const blocked=new Promise<void>(resolve=>{release=resolve;});
 setDiagnosticActionSink(a,async()=>{aCalls++;await blocked;});setDiagnosticActionSink(b,async()=>{bCalls++;});
 try{
  const event={stage:'dispatch' as const,outcome:'unknown' as const};
  assert.equal(await observeDiagnosticAction(b,event),'recorded');assert.equal(aCalls,0);assert.equal(bCalls,1);
  const slow=await Promise.all(Array.from({length:140},()=>observeDiagnosticAction(a,event)));
  assert.ok(slow.every(result=>result==='unavailable'));assert.equal(aCalls,128,'pending work must remain capped while sinks have not settled');
  assert.equal(await observeDiagnosticAction(b,event),'unavailable','overload cannot grow an unbounded queue');
  release();await new Promise<void>(resolve=>setImmediate(resolve));
  assert.equal(await observeDiagnosticAction(b,event),'recorded');assert.equal(bCalls,2);
 }finally{release();setDiagnosticActionSink(a,undefined);setDiagnosticActionSink(b,undefined);}
});
