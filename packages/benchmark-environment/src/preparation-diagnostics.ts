import {AdminRpcFailure} from './chain.js';
import {GenerationFixtureFailure,safeFixtureCauseClass} from './fixtures.js';

export const PREPARATION_PHASES=['reserve_preparation','reset_identity_before','reset_rpc','reset_identity_after',
 'recover_facilitator','persist_reset_proof'] as const;
export type PreparationPhase=typeof PREPARATION_PHASES[number];
export class PreparationHttpFailure extends Error {
 constructor(readonly httpStatus:number){super('Preparation dependency HTTP failure');this.name='Error';}
}
export class PreparationPhaseFailure extends Error {
 readonly causeClass:string|null;
 readonly adminRpc:AdminRpcFailure['diagnostic']|null;
 readonly sqlState:string|undefined;
 readonly httpStatus:number|undefined;
 constructor(readonly phase:PreparationPhase,source:unknown){
  super('Preparation phase failed');this.name='PreparationPhaseFailure';
  this.causeClass=safeFixtureCauseClass(source);this.adminRpc=source instanceof AdminRpcFailure?source.diagnostic:null;
  const sql=source&&typeof source==='object'?source as {name?:unknown;code?:unknown;constructor?:{name?:unknown}}:null;
  this.sqlState=sql&&(sql.name==='DatabaseError'||sql.constructor?.name==='DatabaseError')&&typeof sql.code==='string'&&/^[0-9A-Z]{5}$/.test(sql.code)?sql.code:undefined;
  this.httpStatus=source instanceof PreparationHttpFailure?source.httpStatus:undefined;
 }
}
/** AICODE-NOTE: Confirmation means this call returned; it never infers that a reset was applied after an ambiguous error. */
export function createPreparationDiagnostics(){
 let attemptedPhase:PreparationPhase|null=null;
 const confirmedPhases:PreparationPhase[]=[];
 return{
  async at<T>(phase:PreparationPhase,work:()=>Promise<T>):Promise<T>{
   attemptedPhase=phase;
   try{const result=await work();confirmedPhases.push(phase);return result;}
   catch(error){throw new PreparationPhaseFailure(phase,error);}
  },
  failure(error:unknown){
   const projected=error instanceof PreparationPhaseFailure?error:null;
   return{
    fixturePhase:error instanceof PreparationPhaseFailure?error.phase:error instanceof GenerationFixtureFailure?error.phase:'unknown',
    fixtureCauseClass:projected?projected.causeClass:error instanceof GenerationFixtureFailure?error.causeClass:safeFixtureCauseClass(error),
    fixtureAdminRpc:projected?projected.adminRpc:error instanceof GenerationFixtureFailure?error.adminRpcDiagnostic:error instanceof AdminRpcFailure?error.diagnostic:null,
    preparationProgress:{attemptedPhase,confirmedPhases:[...confirmedPhases]},
    ...(projected?.sqlState?{preparationSqlState:projected.sqlState}:{}),
    ...(projected?.httpStatus!==undefined?{preparationHttpStatus:projected.httpStatus}:{}),
   };
  },
 };
}
