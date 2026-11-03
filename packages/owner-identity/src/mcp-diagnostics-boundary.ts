import { AsyncLocalStorage } from 'node:async_hooks';
import type { DiagnosticEnvelope } from './mcp-diagnostics-contract.js';
import type { OwnerDatabase } from './db.js';

export interface DiagnosticBoundary {
  stage:'admission'|'dispatch'|'receipt';
  outcome:DiagnosticEnvelope['outcome'];
  actionId?:string;
  taskIndex?:number;
  errorCode?:DiagnosticEnvelope['errorCode'];
  receiptRevision?:number;
  attemptId?:string;
  startedAt?:string;
  completedAt?:string;
}
type Sink=(boundary:DiagnosticBoundary)=>Promise<void>;
const requests=new AsyncLocalStorage<{sink:Sink;unavailable?:()=>void}>();
const actionSinks=new WeakMap<OwnerDatabase,Sink>();
const BUDGET_MS=25,MAX_PENDING=128;
let pending=0;
// AICODE-NOTE: Optional diagnostic sinks run only after business commits. Their
// failure must never retry a payment, change a task, or fail an accepted action.
export function withDiagnosticRequest<T>(sink:Sink,work:()=>Promise<T>,unavailable?:()=>void):Promise<T>{return requests.run({sink,...(unavailable?{unavailable}:{})},work);}
export function setDiagnosticActionSink(db:OwnerDatabase,sink:Sink|undefined){if(sink)actionSinks.set(db,sink);else actionSinks.delete(db);}
async function bounded(sink:Sink|undefined,boundary:DiagnosticBoundary,budgetMs=BUDGET_MS):Promise<'recorded'|'unavailable'>{
 if(!sink||pending>=MAX_PENDING)return 'unavailable';
 pending++;
 let timer:ReturnType<typeof setTimeout>|undefined;
 const result=Promise.resolve().then(()=>sink(boundary)).then(()=> 'recorded' as const,()=> 'unavailable' as const).finally(()=>{pending--;});
 try{return await Promise.race([result,new Promise<'unavailable'>(resolve=>{timer=setTimeout(()=>resolve('unavailable'),budgetMs);})]);}
 finally{if(timer)clearTimeout(timer);}
}
export async function observeDiagnosticBoundary(boundary:DiagnosticBoundary){const context=requests.getStore();const result=await bounded(context?.sink,boundary);if(result==='unavailable')try{context?.unavailable?.();}catch{/* Capture metadata cannot alter committed actions. */}return result;}
export function observeDiagnosticAction(db:OwnerDatabase,boundary:DiagnosticBoundary){return bounded(actionSinks.get(db),boundary);}
/** Same bounded pending budget for ingress/SDK/HTTP observations. */
export function captureDiagnosticWork(work:()=>Promise<boolean>,budgetMs=25){
 if(!Number.isSafeInteger(budgetMs)||budgetMs<1||budgetMs>100)throw new Error('diagnostic_capture_budget_invalid');
 return bounded(async()=>{if(!await work())throw new Error('diagnostic_capture_unavailable');},{stage:'receipt',outcome:'unknown'},budgetMs);
}
