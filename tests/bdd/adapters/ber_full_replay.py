"""Independent full BER009Р В Р’В Р вЂ™Р’В Р В РІР‚в„ўР вЂ™Р’В Р В Р’В Р вЂ™Р’В Р В Р вЂ Р В РІР‚С™Р вЂ™Р’В Р В Р’В Р вЂ™Р’В Р В РІР‚в„ўР вЂ™Р’В Р В Р’В Р В РІР‚В Р В Р’В Р Р†Р вЂљРЎв„ўР В Р Р‹Р Р†РІР‚С›РЎС›Р В Р’В Р вЂ™Р’В Р В Р’В Р Р†Р вЂљР’В Р В Р’В Р вЂ™Р’В Р В Р вЂ Р В РІР‚С™Р РЋРІвЂћСћР В Р’В Р В Р вЂ№Р В Р Р‹Р Р†РІР‚С›РЎС›012 assembly. Missing captures remain blocked.

This dispatcher replays original bytes through independent readers; component
summaries, profile labels and claimed facts are never accepted as evidence.
"""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[3]))
import hashlib,json
from tests.bdd.adapters.ber_recovery_replay import read_reference
from tests.bdd.adapters.ber_matrix_common import need,load_ref,one
from tests.bdd.adapters.ber_matrix_replay import verify_matrix,collate_positive_reports
from tests.bdd.adapters.ber_generic_recovery_replay import verify_generic_seal_fault
from tests.bdd.adapters.ber_s4_preparation_replay import verify_s4_preparation_fault

SCENARIO_FACTS={
 'BER-SC-009':('all_admitted_sequences_accounted','scope_denials_unchanged','no_automatic_repair','all_fifteen_paths_all_nine_kinds','objective_and_off_goal_scoped_reads','wrong_recipient_amount_route_allowance','noop_and_reverted_actions','protocol_disabled_purchase','foreign_or_invalid_reference','late_action_rejected','immutable_chosen_command_and_effect_history','complete_independent_family_census'),
 'BER-SC-010':('known_effects_reach_existing_rubric','missing_or_contradictory_stays_unknown','s1_exact_wrong_extra_and_reserve','s2_s3_paid_delivery_mutation','s4_mutate_then_restore','paid_only_unrelated_chain_action','missing_or_changed_receipt_row_hash_generation','missing_read_or_block_observation','contradictory_or_truncated_census','no_fabricated_zero_or_success','unchanged_task_rubric'),
 'BER-SC-011':('payment_not_delivery','immutable_action_status_evidence','separate_principal_gas_service_cost','confirmed_pay_without_retrieve','rejected_or_late_retrieve','wrong_scoped_resource_read','lost_action_response','repeated_status_and_finish','chain_gas_with_payment','one_economic_effect_per_operation','no_double_count_or_ambiguous_payment_replacement'),
 'BER-SC-012':('stable_closure_and_cutoff','append_only_evidence','next_task_and_explicit_terminal','deadline_at_dispatch_and_receipt','restart_after_confirmation_before_observe_seal_evaluate','duplicate_reconcile_finalize','composite_child_replay','unreconciled_action_at_cutoff','known_handoff_next_task_and_explicit_terminal','one_evaluation_and_settlement','no_admission_debit_aggregate_report_duplication')}
CONTROL_PROFILES={'trainingD':('training','NOOP_REVERT_D'),'rankedD':('ranked','NOOP_REVERT_D'),'compositeMixed':('ranked','COMPOSITE_MIXED'),'nonEoa':('training','NON_EOA_REJECTION'),'mcpGuards':('training','MCP_GUARDS')}
FAULT_TARGETS=('paid_s1','chain_s1','composite_u1')
FAULT_VARIANTS=('missing_child','corrupt_child','restart_blocked_seal')

ASSEMBLY_NORMATIVE_PATHS=(
 'tests/bdd/adapters/benchmark_execution_reliability.py','tests/bdd/mappers/test_benchmark_execution_reliability_bdd.py','tests/bdd/features/benchmark_execution_reliability.feature',
 'tests/bdd/changes/benchmark-execution-reliability/harness-contracts.json','tests/bdd/changes/benchmark-execution-reliability/admitted-learning-capture-contract.md',
 'openspec/changes/benchmark-execution-reliability/specs/benchmark-execution-reliability/spec.md','openspec/changes/benchmark-execution-reliability/design.md','openspec/changes/benchmark-execution-reliability/proposal.md','openspec/changes/benchmark-execution-reliability/bdd-design.md','openspec/changes/benchmark-execution-reliability/admitted-learning-actions-observation-proposal.md','openspec/changes/benchmark-execution-reliability/bdd-harness-proposal.json',
 'tests/integration/ber-s1-reserve-boundary.test.mjs','tests/integration/task-evaluator.test.mjs','tools/capture_ber_replay_history.mjs','tools/ber_completed_callbacks.mjs','tools/ber_completed_callbacks.test.mjs','tools/ber_pending_transition_interruption.mjs','tools/ber_pending_transition_interruption.test.mjs','tools/ber_completion_handoff_interruption.mjs','tools/ber_completion_handoff_interruption.test.mjs','tools/mcd-native-qualification.mjs','tools/mcd-native-fault-proxy.mjs','tools/mcp-diagnostics-client.mjs','tools/mcp-diagnostics-oauth.mjs','tools/mcp-diagnostics-launcher.mjs','tools/mcp-diagnostics-io.mjs','tools/mcp-diagnostics-code-registry.mjs','tools/run-mcd-client-capture.mjs','tools/run_aci_native.mjs','infrastructure/owner-identity/run-codex-google-local.mjs')

def source_inventory(capture,repo):
 s=capture['sourceInputs'];before=s['before'];need(isinstance(before,dict) and before and before==s['after'],'full assembly source cohort changed')
 from tests.bdd.adapters.ber_matrix_replay import READER_PATHS
 need(set(READER_PATHS)|set(ASSEMBLY_NORMATIVE_PATHS)<=set(before),'full assembly omitted a current reader or normative source pin')
 for path,sha in before.items():
  read_reference(repo,{'path':path,'sha256':sha},json_body=False)
 return before

def replay_matrix_report(reference,repo):
 from tests.bdd.adapters.ber_matrix_replay import canonical_report_identity
 old=load_ref(repo,reference);need(old['schemaVersion']=='ber-independent-matrix-report/v1','unknown matrix report')
 fresh=verify_matrix(old['actorRef'],old['ownerRef'],old['supportRefs'],repo)
 need(fresh['independentRawComplete'] and canonical_report_identity(old)==canonical_report_identity(fresh),'matrix report is stale, changed or incomplete')
 return fresh

def replay_generic_matrix(items,repo):
 need(isinstance(items,list) and len(items)<=9,'generic fault selectors must be bounded')
 seen=set();reports=[]
 for item in items:
  need(set(item)=={'faultRef','actorRef'},'fault selector contains producer assertions')
  raw=load_ref(repo,item['faultRef']);key=(raw['target'].get('targetProfile','paid_s1'),raw['target']['variant'])
  need(key in {(t,v) for t in FAULT_TARGETS for v in FAULT_VARIANTS} and key not in seen,'unknown or duplicate fault identity');seen.add(key)
  report=verify_generic_seal_fault(item['faultRef'],actor_reference=item['actorRef'],repository_root=repo)
  need(report['verifiedSubset'] is True,'generic fault raw replay incomplete');reports.append(report)
 return reports,sorted(set((t,v) for t in FAULT_TARGETS for v in FAULT_VARIANTS)-seen)

def replay_s4_matrix(items,repo):
 need(isinstance(items,list) and len(items)<=2,'S4 selectors must be bounded');seen=set();reports=[]
 for item in items:
  need(set(item)=={'faultRef','actorRef'},'S4 selector contains producer assertions')
  report=verify_s4_preparation_fault(item['faultRef'],item['actorRef'],repo);key=report['variant'];need(key not in seen,'duplicate S4 fault');seen.add(key);reports.append(report)
 return reports,sorted({'missing_fixture','corrupt_fixture'}-seen)

def verify_qualification(selector,repo):
 need(set(selector)=={'validationRef'},'qualification selector must use original validation ref')
 v=load_ref(repo,selector['validationRef']);need(v['schemaVersion']=='bts-difficulty-v2-offline-release-validation/v1' and v['status']=='validated_candidate' and v['sourceUnchanged'] is True and v['validation']['status']=='validated','qualification validation unavailable')
 docs=[v]+[load_ref(repo,v['sources'][k]) for k in ('releaseCandidate','minimumActionReview','semanticReferenceReview')];pins={}
 for doc in docs:
  need(isinstance(doc['sourceInputs'],list) and doc['sourceInputs'],'qualified source inventory missing')
  for ref in doc['sourceInputs']:
   need(ref['path'] not in pins or pins[ref['path']]==ref['sha256'],'qualified source contradiction');read_reference(repo,ref,json_body=False);pins[ref['path']]=ref['sha256']
 from tests.bdd.adapters.benchmark_task_suite import _verify_task_manifest,_verify_reference_evidence
 manifest=v['validation']['release']['manifest'];valid,training,ranked=_verify_task_manifest(manifest);need(valid and len(training)==3 and len(ranked)==12,'qualified manifest semantic identity invalid')
 results=[_verify_reference_evidence(repo,c,manifest['executionIdentityHash']) for c in training+ranked];need(all(r[0] for r in results),'qualified physical reference raw proof incomplete')
 return {'actualReferenceVariants':15,'currentQualifiedSourcePins':len(pins),'existingReferenceRawReplayed':True,'manifestHash':manifest['manifestHash'],'newOwnerAcceptanceInferred':False}

def verify_recovery(selectors,repo):
 from tests.bdd.adapters.ber_h1_replay import verify_h1_matrix
 from tests.bdd.adapters.ber_recovery_replay import verify_unknown_matrix,verify_fault_core,verify_completed_callbacks,verify_pending_transition,verify_completion_handoff
 allowed={'h1CutoffRef','unknownRef','faultCoreRef','completedCallbacksRef','pendingTransitionRef','completionHandoffRef'};need(isinstance(selectors,dict) and set(selectors)<=allowed,'unknown recovery selector')
 dispatch={'h1CutoffRef':verify_h1_matrix,'unknownRef':verify_unknown_matrix,'faultCoreRef':verify_fault_core,'completedCallbacksRef':verify_completed_callbacks,'pendingTransitionRef':verify_pending_transition,'completionHandoffRef':verify_completion_handoff};out={}
 for key,ref in selectors.items():out[key]=dispatch[key](ref,repository_root=repo)
 return out,sorted(allowed-set(out))

def verify_full_capture(reference,scenario_id,*,repository_root):
 repo=Path(repository_root).resolve();capture=load_ref(repo,reference)
 need(capture.get('schemaVersion')=='ber-admitted-learning-full-capture/v1' and scenario_id in SCENARIO_FACTS,'unknown full proof schema/scenario')
 need(set(capture)<= {'schemaVersion','sourceInputs','positiveReports','controls','genericFaults','s4PreparationFaults','recovery','sourceNegatives','goalControls','native','qualification'},'unsupported full proof field')
 source_inventory(capture,repo);facts={k:False for values in SCENARIO_FACTS.values() for k in values};components={};missing=[]
 positives=capture.get('positiveReports',[]);fresh=[]
 if positives:
  components['positive135']=collate_positive_reports(positives,repo)
  fresh=[replay_matrix_report(ref,repo) for ref in positives]
  for fact in ('all_admitted_sequences_accounted','all_fifteen_paths_all_nine_kinds','immutable_chosen_command_and_effect_history','complete_independent_family_census','known_effects_reach_existing_rubric','paid_only_unrelated_chain_action','unchanged_task_rubric','immutable_action_status_evidence','one_economic_effect_per_operation','one_evaluation_and_settlement','no_automatic_repair'):facts[fact]=True
  readonly={(t['taskId'],r['profile']) for r in fresh for t in r['tasks'] if t['taskId'] in ('S2','S3') and ('namedViolation' in t or 'namedMutationViolation' in t)}
  facts['s2_s3_paid_delivery_mutation']=readonly=={(t,p) for t in ('S2','S3') for p in ('A','B','C')}
 else:missing.append('six_current_positive_reports_135')
 controls=capture.get('controls',{});need(isinstance(controls,dict) and set(controls)<=set(CONTROL_PROFILES),'unknown finite control')
 for key,reference in controls.items():
  result=replay_matrix_report(reference,repo);need((result['mode'],result['profile'])==CONTROL_PROFILES[key] and result['positive135Cells']==[],'control pads positive matrix or has wrong profile');components[key]=result
 if {'trainingD','rankedD'}<=set(components):facts['noop_and_reverted_actions']=True
 if 'compositeMixed' in components:
  for fact in ('chain_gas_with_payment','separate_principal_gas_service_cost','composite_child_replay'):facts[fact]=True
 if 'mcpGuards' in components:
  need(components['mcpGuards']['mcpGuardFacts']['actualDeniedCalls']==8,'finite guard case count differs')
  for fact in ('scope_denials_unchanged','protocol_disabled_purchase','foreign_or_invalid_reference','repeated_status_and_finish'):facts[fact]=True
 missing+=['control:'+x for x in CONTROL_PROFILES if x not in components]
 faults,generic_missing=replay_generic_matrix(capture.get('genericFaults',[]),repo);components['genericFaults']=faults;missing+=['generic_fault:'+t+':'+v for t,v in generic_missing]
 paid=[r for r in faults if r['actualOriginalPaymentCount']==1 and r['actualDeliveryCount']==0]
 if paid:
  for fact in ('payment_not_delivery','confirmed_pay_without_retrieve'):facts[fact]=True
 if not generic_missing:
  for fact in ('missing_or_contradictory_stays_unknown','no_fabricated_zero_or_success','stable_closure_and_cutoff','append_only_evidence'):facts[fact]=True
 s4,absent4=replay_s4_matrix(capture.get('s4PreparationFaults',[]),repo);components['s4PreparationFaults']=s4;missing+=['s4_preparation:'+v for v in absent4]
 if not absent4:facts['s4_mutate_then_restore']=True
 # These components need their actual independent raw producers, never a claimed
 # facts object. Their exact dispatchers are installed alongside the finite capture
 # producers; absent evidence cannot be substituted by the main strategy labels.
 if capture.get('recovery'):
  recovery,absent=verify_recovery(capture['recovery'],repo);components['recovery']=recovery;missing+=['recovery:'+x for x in absent]
  for key,value in recovery.items():
   if any(v is not True for v in value.get('facts',{}).values()):missing.append('recovery_incomplete:'+key)
  h1=recovery.get('h1CutoffRef',{}).get('facts',{})
  if h1 and all(h1.values()):
   for fact in ('late_action_rejected','lost_action_response','deadline_at_dispatch_and_receipt','unreconciled_action_at_cutoff'):facts[fact]=True
  if recovery.get('completedCallbacksRef',{}).get('facts',{}).get('duplicate_out_of_order_completion') and recovery.get('completedCallbacksRef',{}).get('facts',{}).get('duplicate_receipt_reconciliation') and not absent:facts['duplicate_reconcile_finalize']=True
  if not absent and not absent4 and not generic_missing and recovery.get('unknownRef',{}).get('fullScenarioAcceptance')=='passed':
   for fact in ('restart_after_confirmation_before_observe_seal_evaluate','no_admission_debit_aggregate_report_duplication'):facts[fact]=True
 else:missing.append('recovery')
 if capture.get('qualification'):components['qualification']=verify_qualification(capture['qualification'],repo)
 else:missing.append('qualification')
 if capture.get('native'):
  from tests.bdd.adapters.ber_native_replay import verify_native_runs
  components['native']=verify_native_runs(capture['native'],repo)
  for fact in ('next_task_and_explicit_terminal','known_handoff_next_task_and_explicit_terminal'):facts[fact]=True
 else:missing.append('actual_native_training_ranked_ui_database')
 if capture.get('sourceNegatives'):
  from tests.bdd.adapters.ber_source_negative_replay import verify_source_negative,REASONS
  items=capture['sourceNegatives'];need(isinstance(items,list) and len(items)<=7,'source fault selector bound');seen=set();runs=set();source_reports=[]
  for item in items:
   need(set(item)=={'faultRef','actorRef'},'source fault selector contains assertions');r=verify_source_negative(item['faultRef'],actor_reference=item['actorRef'],repository_root=repo);need(r['variant'] not in seen and r['runId'] not in runs,'source fault reused physical case/run');seen.add(r['variant']);runs.add(r['runId']);source_reports.append(r)
  components['sourceNegatives']=source_reports;missing+=['source_negative:'+v for v in sorted(set(REASONS)-seen)]
  if {'receipt_row_missing','receipt_hash_conflict','receipt_generation_conflict'}<=seen:facts['missing_or_changed_receipt_row_hash_generation']=True
  if {'read_missing','block_missing'}<=seen:facts['missing_read_or_block_observation']=True
  if {'census_contradictory','census_truncated'}<=seen:facts['contradictory_or_truncated_census']=True
 else:missing.append('sourceNegatives')
 if capture.get('goalControls'):
  from tests.bdd.adapters.ber_goal_replay import verify_goal_controls,verify_semantic_capture
  if len(fresh)==6:
   components['goalControls']=verify_goal_controls(capture['goalControls'],fresh,repo)
   for fact in ('objective_and_off_goal_scoped_reads','wrong_recipient_amount_route_allowance','s1_exact_wrong_extra_and_reserve','wrong_scoped_resource_read'):facts[fact]=True
  else:components['goalSemantic']=verify_semantic_capture(capture['goalControls']['semanticRef'],repo);missing.append('actual_positive_goal_controls')
 else:missing.append('goalControls')
 if 'mcpGuards' in components:facts['rejected_or_late_retrieve']=True
 if 'mcpGuards' in components and 'compositeMixed' in components and components.get('recovery',{}).get('h1CutoffRef',{}).get('facts',{}).get('no_duplicate_effect_or_charge'):facts['no_double_count_or_ambiguous_payment_replacement']=True
 required=SCENARIO_FACTS[scenario_id];missing+=['fact:'+k for k in required if not facts[k]]
 return {'schemaVersion':'ber-admitted-learning-full-replay/v1','scenarioId':scenario_id,'facts':facts,'components':components,'fullScenarioAcceptance':'passed' if not missing else 'blocked','missingBoundaries':sorted(set(missing)),'nativeAgentAcceptance':'verified' if 'native' in components else 'not_run','rubricRescored':False}


def main(argv=None):
 import argparse
 from tests.bdd.adapters.ber_matrix_replay import bounded_json,exact_ref,immutable_report
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--repo-root',required=True);p.add_argument('--capture-ref',required=True);p.add_argument('--scenario',required=True,choices=tuple(SCENARIO_FACTS));p.add_argument('--output',required=True);a=p.parse_args(argv);repo=Path(a.repo_root).resolve()
 try:
  result=verify_full_capture(exact_ref(bounded_json(a.capture_ref)),a.scenario,repository_root=repo);reference=immutable_report(a.output,result,repo);print(json.dumps({'status':result['fullScenarioAcceptance'],'scenarioId':a.scenario,'report':reference,'missingBoundaries':result['missingBoundaries']}));return 0 if result['fullScenarioAcceptance']=='passed' else 2
 except (AssertionError,KeyError,ValueError,TypeError,OSError) as error:
  print(json.dumps({'status':'blocked','code':'BER_FULL_CAPTURE_UNVERIFIABLE','errorClass':type(error).__name__}));return 2
if __name__=='__main__':raise SystemExit(main())
