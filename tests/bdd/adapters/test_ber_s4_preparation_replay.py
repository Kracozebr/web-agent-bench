"""Pure S4 fault boundary tests. Synthetic SQL objects are NOT physical captures."""
import copy,importlib.util
from pathlib import Path
import pytest
from tests.bdd.adapters import ber_s4_preparation_replay as m
def fixture():
 run='synthetic-run';common={'actions':[{'id':'synthetic-action'}],'history':[{'revision':1}],'money':[{'entry_type':'reserve'}]};before={**copy.deepcopy(common),'task':[{'closure_status':'open','status':'active'}],'bundle':[],'evaluation':[],'identity':{'observed_at':'2026-11-03T00:00:30Z'}}
 task={'closure_status':'closed','closure_id':'synthetic-closure','closure_operation_id':'synthetic-operation','action_cutoff_sequence':'3','reconciled_action_sequence':'3','closed_at':'2026-11-03T00:01:00Z','original_recovery_deadline':'2026-11-03T00:04:00Z'}
 blocked={**copy.deepcopy(common),'task':[copy.deepcopy(task)],'run':[{'status':'running'}],'bundle':[],'evaluation':[],'successorPreparations':[],'allTasks':[{'task_index':4,'status':'queued'}],'identity':{'observed_at':'2026-11-03T00:01:05Z'}}
 known={**copy.deepcopy(common),'task':[{**task,'finished_at':'2026-11-03T00:01:09Z'}],'evaluation':[{'result_json':{'status':'known'},'created_at':'2026-11-03T00:01:08Z'}],'bundle':[{}],'terminalEvents':[{}],'allTasks':[{'task_index':4,'task_id':'M1','status':'active'}],'successorPreparations':[{'run_id':run,'task_index':4}],'identity':{'observed_at':'2026-11-03T00:01:10Z'}}
 proof={'actualMcpFinish':{'closureId':'synthetic-closure','operationId':'synthetic-operation'},'target':{'runId':run},'originalOverallDeadline':'2026-11-03T00:10:00Z','originalRecoveryDeadline':'2026-11-03T00:04:00Z','recoveryDeadline':'2026-11-03T00:04:00Z','intervention':{'stagedAt':'2026-11-03T00:00:40Z'},'restorationStartedAt':'2026-11-03T00:01:06Z','restorationCompletedAt':'2026-11-03T00:01:07Z'}
 return proof,before,blocked,known

def test_pure_original_cutoff_restore_window_joins_exactly_once():
 p,b,x,k=fixture();v=m.validate_causal_window(p,b,x,k);assert v['allActionsHistoryFinanceUnchanged'] and v['singleOriginalClosure']=='synthetic-closure'
@pytest.mark.parametrize('change',['pre_evaluated','unavailable_evaluated','early_successor','closure','cutoff','history','finance','extended_deadline','late_known','before_restore_grade','duplicate_grade','duplicate_event','no_handoff'])
def test_unknown_or_changed_original_identity_cannot_be_recovery(change):
 p,b,x,k=fixture()
 if change=='pre_evaluated':b['evaluation']=[{}]
 elif change=='unavailable_evaluated':x['evaluation']=[{}]
 elif change=='early_successor':x['successorPreparations']=[{}]
 elif change=='closure':k['task'][0]['closure_id']='another'
 elif change=='cutoff':k['task'][0]['action_cutoff_sequence']='4'
 elif change=='history':k['history'][0]['revision']=2
 elif change=='finance':k['money'].append({'entry_type':'debit'})
 elif change=='extended_deadline':p['originalRecoveryDeadline']='2026-11-03T00:04:01Z'
 elif change=='late_known':k['identity']['observed_at']='2026-11-03T00:04:01Z'
 elif change=='before_restore_grade':k['evaluation'][0]['created_at']='2026-11-03T00:01:00Z'
 elif change=='duplicate_grade':k['evaluation'].append(copy.deepcopy(k['evaluation'][0]))
 elif change=='duplicate_event':k['terminalEvents'].append({})
 else:k['allTasks'][0]['status']='queued'
 with pytest.raises(AssertionError):m.validate_causal_window(p,b,x,k)
def test_bef_source_requires_real_role_and_both_fence_rows():
 target={'environmentId':'bef-env-a','generationId':'synthetic-generation','preparationId':'synthetic-prep'};v={'observer':{'role':'bef_observer','sessionRole':'bef_observer','databaseName':'bef','readOnly':True,'transactionReadOnly':'on','isolation':'repeatable read','superuser':False,'bypassRls':False},'generations':[{'env_id':'bef-env-a','generation_id':'synthetic-generation','status':'fenced','fenced_at':'2026-11-03T00:02:00Z'}],'preparations':[{'env_id':'bef-env-a','generation_id':'synthetic-generation','preparation_id':'synthetic-prep','status':'fenced','fence_confirmed_at':'2026-11-03T00:02:00Z'}]};m.verify_bef_boundary(v,target,'fenced');v['preparations'][0]['fence_confirmed_at']=None
 with pytest.raises(AssertionError):m.verify_bef_boundary(v,target,'fenced')

def test_actual_progress_timestamp_is_retained_and_stale_failure_cannot_qualify():
 p,b,x,k=fixture();p['initialProgress']=[];body={'schemaVersion':'local-bef-task-observation-progress/v1','runId':p['target']['runId'],'taskIndex':3,'stage':'observe','status':'blocked','reasonCode':'paid_family_preparation_unavailable'};progress={'path':'.local/synthetic-test.json','sha256':'a'*64,'modifiedAt':'2026-11-03T00:01:02Z','stage':'observe','status':'blocked','reasonCode':'paid_family_preparation_unavailable'}
 m.validate_fresh_progress(p,progress,body,x)
 for stamp in ('2026-11-03T00:00:39Z','2026-11-03T00:01:07Z'):
  with pytest.raises(AssertionError):m.validate_fresh_progress(p,{**progress,'modifiedAt':stamp},body,x)
 p['initialProgress']=[{'sha256':progress['sha256']}]
 with pytest.raises(AssertionError):m.validate_fresh_progress(p,progress,body,x)
def test_missing_progress_timestamp_fails_closed_not_a_producer_flag_pass():
 p,b,x,k=fixture();p['initialProgress']=[];body={'schemaVersion':'local-bef-task-observation-progress/v1','runId':p['target']['runId'],'taskIndex':3,'stage':'observe','status':'blocked','reasonCode':'paid_family_preparation_unavailable'}
 with pytest.raises(KeyError):m.validate_fresh_progress(p,{'sha256':'a'*64},body,x)

def test_progress_fs_read_may_follow_sql_snapshot_but_must_precede_restore():
 p,b,x,k=fixture();p['initialProgress']=[];body={'schemaVersion':'local-bef-task-observation-progress/v1','runId':p['target']['runId'],'taskIndex':3,'stage':'observe','status':'blocked','reasonCode':'paid_family_preparation_unavailable'};progress={'path':'.local/synthetic.json','sha256':'a'*64,'modifiedAt':'2026-11-03T00:01:05.500Z','stage':'observe','status':'blocked','reasonCode':'paid_family_preparation_unavailable'}
 m.validate_fresh_progress(p,progress,body,x)
