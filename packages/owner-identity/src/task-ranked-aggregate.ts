/** Internal ranked aggregation. Caller must first verify every immutable task evaluation and fence. */
import { PUBLIC_TASK_CATALOG, TASK_IDS, type TaskId, type TaskLevel } from './task-catalog.js';
import type { TaskEvaluationResult } from './task-evaluator.js';
import { sha256CanonicalTaskJson, type TaskReleaseManifest } from './task-release.js';

export type RankedTaskProof = { taskIndex:number; taskId:TaskId; caseHash:string; rubricHash:string;
  inputHash:string; resultHash:string; fenceEvidenceHash:string; result:TaskEvaluationResult };
export type ExactRankedFraction = {numerator:string;denominator:string};
export type RankedOutcomeAggregate = {schemaVersion:'ranked-outcome-aggregate/v1';releaseIdentity:string;manifestHash:string;
  benchmarkVersion:string;benchmarkHash:string;policyHash:string;overall:ExactRankedFraction;
  tiers:Record<TaskLevel,ExactRankedFraction>;taskProofs:RankedTaskProof[];aggregateHash:string};
const HASH=/^[0-9a-f]{64}$/i;
const UINT=/^(?:0|[1-9][0-9]{0,77})$/;
function reject():never {throw new Error('ranked_outcome_proof_invalid');}
function gcd(a:bigint,b:bigint):bigint {while(b!==0n){const t=a%b;a=b;b=t;}return a;}
function fraction(n:bigint,d:bigint):ExactRankedFraction {if(n<0n||d<=0n)reject();const g=gcd(n,d);return{numerator:(n/g).toString(),denominator:(d/g).toString()};}
function add(a:ExactRankedFraction,b:ExactRankedFraction):ExactRankedFraction{return fraction(BigInt(a.numerator)*BigInt(b.denominator)+BigInt(b.numerator)*BigInt(a.denominator),BigInt(a.denominator)*BigInt(b.denominator));}
function checkedCredit(result:TaskEvaluationResult,taskId:TaskId):ExactRankedFraction {
  if(result.status!=='known'||result.taskId!==taskId||result.credit===null||!UINT.test(result.credit.numerator)||!UINT.test(result.credit.denominator)||
    result.unknownReasons.length!==0)reject();
  const n=BigInt(result.credit.numerator),d=BigInt(result.credit.denominator);
  if(d===0n||n>d||(result.outcome==='passed'&&n!==d)||(result.outcome==='failed'&&n!==0n)||
    (result.outcome==='partial'&&(n===0n||n===d))||!['passed','partial','failed'].includes(result.outcome)||
    (result.mandatoryViolation!==null&&(n!==0n||result.outcome!=='failed')))reject();
  return fraction(n,d);
}
/** Exact 0..100 indicators; no latency, service expense or unobserved model cost enters the outcome score. */
export function aggregateVerifiedRankedOutcomes(release:TaskReleaseManifest,proofs:readonly RankedTaskProof[]):RankedOutcomeAggregate {
  if(proofs.length!==TASK_IDS.length||release.cases.ranked.length!==TASK_IDS.length||!HASH.test(release.manifestHash))reject();
  const weighted:Record<TaskLevel,ExactRankedFraction>={simple:fraction(0n,1n),medium:fraction(0n,1n),hard:fraction(0n,1n),ultra:fraction(0n,1n)};
  const weights:Record<TaskLevel,bigint>={simple:0n,medium:0n,hard:0n,ultra:0n};let total=fraction(0n,1n),weightTotal=0n;
  for(let index=0;index<TASK_IDS.length;index++){
    const id=TASK_IDS[index]!,proof=proofs[index]!,taskCase=release.cases.ranked[index]!,metadata=PUBLIC_TASK_CATALOG[index]!;
    if(proof.taskIndex!==index||proof.taskId!==id||taskCase.taskId!==id||taskCase.mode!=='ranked'||taskCase.taskWeight!==metadata.weight||
      proof.caseHash!==taskCase.caseHash||proof.rubricHash!==taskCase.rubricHash||
      ![proof.caseHash,proof.rubricHash,proof.inputHash,proof.resultHash,proof.fenceEvidenceHash].every(v=>HASH.test(v))||
      sha256CanonicalTaskJson(proof.result)!==proof.resultHash)reject();
    const credit=checkedCredit(proof.result,id),weight=BigInt(taskCase.taskWeight);
    const scaled=fraction(BigInt(credit.numerator)*weight,BigInt(credit.denominator));
    total=add(total,scaled);weightTotal+=weight;weighted[metadata.level]=add(weighted[metadata.level],scaled);weights[metadata.level]+=weight;
  }
  if(weightTotal!==26n)reject();
  const tiers={} as Record<TaskLevel,ExactRankedFraction>;
  for(const level of ['simple','medium','hard','ultra'] as const){if(weights[level]===0n)reject();tiers[level]=fraction(BigInt(weighted[level].numerator)*100n,BigInt(weighted[level].denominator)*weights[level]);}
  const body={schemaVersion:'ranked-outcome-aggregate/v1' as const,releaseIdentity:release.releaseIdentity,manifestHash:release.manifestHash,
    benchmarkVersion:release.benchmarkVersion,benchmarkHash:release.benchmarkHash,policyHash:release.policyHash,
    overall:fraction(BigInt(total.numerator)*100n,BigInt(total.denominator)*weightTotal),tiers,taskProofs:structuredClone([...proofs])};
  return {...body,aggregateHash:sha256CanonicalTaskJson(body)};
}
export function compareExactRankedFractions(left:ExactRankedFraction,right:ExactRankedFraction):-1|0|1 {
  for(const f of [left,right])if(!UINT.test(f.numerator)||!UINT.test(f.denominator)||BigInt(f.denominator)===0n)reject();
  const a=BigInt(left.numerator)*BigInt(right.denominator),b=BigInt(right.numerator)*BigInt(left.denominator);
  return a<b?-1:a>b?1:0;
}