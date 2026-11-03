/** Fixed matrix owner-run wrapper. Actual evidence readers, not actor flags, decide coverage. */
import {TRAINING,RANKED,isAllowedBerMatrixProfile,observeBerMatrixRunTerminal} from './ber-matrix-controller.mjs';
import {PROFILE as NEGATIVE_PROFILE} from './ber-noop-revert.mjs';
import {PROFILE as COMPOSITE_PROFILE} from './ber-composite-mixed.mjs';
import {PROFILE as CONTRACT_REJECTION_PROFILE} from './ber-contract-recipient-rejection.mjs';
import {PROFILE as GUARDS_PROFILE} from './ber-mcp-guards.mjs';
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const need=(v,code)=>{if(!v)throw Object.assign(new Error(code),{code});};
export async function runBerMatrixOwnerCase(input,unitDependencies){
 const expected=input.mode==='training'?TRAINING:input.mode==='ranked'?RANKED:null;
 need(expected&&isAllowedBerMatrixProfile(input.berAdmittedMatrixProfile,input.mode)&&input.berAdmittedMatrixIsolated===true&&input.automaticWorkerEvaluation===true&&UUID.test(input.berMatrixCampaignId??'')&&!input.bddProbes&&!input.primaryClientOnly&&(!input.taskIds||JSON.stringify(input.taskIds)===JSON.stringify(expected)),'ber_matrix_exact_owner_run_required');
 const observer=new URL(input.observerDatabaseUrl);need(observer.username==='oid_observer'&&/^\/oid_acceptance_[a-f0-9]{32}$/.test(observer.pathname),'ber_matrix_disposable_owner_run_required');
 const runners=unitDependencies??await import('./genuine-s1-cases.mjs');
 const run=input.mode==='training'?runners.runGenuineTrainingSequenceOwnerCase:runners.runGenuineRankedOwnerCase;
 need(typeof run==='function','ber_matrix_owner_runner_missing');
 const terminalRecords=[];let terminalResult;
 const capture=await run({...input,sequenceMode:true,taskIds:[...expected],async onGenuineRunCompleted(context){
  need(context.mode===input.mode&&JSON.stringify(context.taskIds)===JSON.stringify(expected)&&UUID.test(context.runId??'')&&UUID.test(context.agentId??''),'ber_matrix_completion_identity_mismatch');
  terminalResult=await (unitDependencies?.observeTerminal??observeBerMatrixRunTerminal)({runId:context.runId,agentId:context.agentId,deadlineMs:Date.now()+30000,record:record=>terminalRecords.push(record)});
  if(typeof input.onGenuineRunCompleted==='function')await input.onGenuineRunCompleted(context);
 }});
 capture.classification='controlled_fixed_matrix_reference_sdk_real_mcp_worker_not_native_or_full_ber_acceptance';
 capture.berMatrixQualification={schemaVersion:'ber-controlled-matrix-run-qualification/v1',campaignId:input.berMatrixCampaignId,profile:input.berAdmittedMatrixProfile,mode:input.mode,taskIds:[...expected],nativeAgent:false,fullScenarioAcceptance:false,
  mainMatrixAcceptance:'incomplete',independentProof:{status:'not_run',reasonCode:'independent_matrix_postrun_reader_required'},terminalMcp:{records:terminalRecords,...(terminalResult?{result:terminalResult}:{status:'not_observed'})}};
 if(input.berAdmittedMatrixProfile===CONTRACT_REJECTION_PROFILE){capture.classification='controlled_contract_recipient_rejection_reference_sdk_negative_not_positive_matrix';capture.berMatrixQualification.negativeControlOnly=true;capture.berMatrixQualification.positiveCoverageCredit=false;}
 if(input.berAdmittedMatrixProfile===GUARDS_PROFILE){capture.classification='controlled_mcp_guard_denials_reference_sdk_not_positive_matrix';capture.berMatrixQualification.negativeControlOnly=true;capture.berMatrixQualification.positiveCoverageCredit=false;}
 if(input.berAdmittedMatrixProfile===NEGATIVE_PROFILE){capture.classification='controlled_noop_revert_reference_sdk_negative_not_positive_matrix';capture.berMatrixQualification.negativeControlOnly=true;capture.berMatrixQualification.positiveCoverageCredit=false;}
 if(input.berAdmittedMatrixProfile===COMPOSITE_PROFILE){capture.classification='controlled_composite_coexistence_reference_sdk_not_positive_matrix';capture.berMatrixQualification.compositeCoexistenceOnly=true;capture.berMatrixQualification.positiveCoverageCredit=false;}
 if(capture.runCompletion?.status==='verified'&&!(terminalResult?.terminal===true&&terminalResult.runId===capture.runId&&terminalResult.status==='completed')){
  capture.status='blocked';capture.blocker={stage:'ber_matrix_explicit_mcp_terminal',reasonCode:'ber_matrix_terminal_not_confirmed'};
 }
 return capture;
}
