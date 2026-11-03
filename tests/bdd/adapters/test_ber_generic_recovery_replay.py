"""Original-data binding/mutation tests. No physical generic fault is manufactured here."""
import copy,json
from pathlib import Path
import pytest
from tests.bdd.adapters.ber_generic_recovery_replay import owner_context,verify_known_input,closure_inventory
from tests.bdd.adapters.ber_recovery_replay import dispatch_recovery_observation_packets
from tests.bdd.adapters.test_ber_generic_family_replay import actual_context,OWNER,ROOT
CAPTURE=ROOT/'artifacts/runs/genuine-training-sequence-owner-run/df19cb3c-c07b-4056-8e9e-cb00b05a05bd/capture.json'
def original_known():
 # Unit interface joins two immutable actual observer projections of the same
 # already-fenced S1 run. This is not a new physical single-snapshot fault proof.
 snapshot=ROOT/'.local/ber-s1-r3-private-owner-snapshot-7148bf75-9654-4fe1-8e55-d6187435f697.json'
 capture=ROOT/'artifacts/runs/genuine-s1-owner-run/0c4f9c08-00fb-4856-9f84-592e4f7b807b/capture.json'
 if not snapshot.is_file() or not capture.is_file():pytest.skip('BLOCKED: original full observer metadata unavailable')
 o=json.loads(snapshot.read_text());c=json.loads(capture.read_text());full=c['berAdmittedS1Pay']['ownerOutcome']
 for key in ('id','owner_id','agent_id','release_identity','manifest_hash','quote_price_units','mode','task_ids','status'):
  assert o['run'][0][key]==full['run'][0][key]
 assert o['evaluations'][0]['input_hash']==full['evaluations'][0]['input_hash'] and o['evaluations'][0]['result_hash']==full['evaluations'][0]['result_hash']
 known={'run':full['run'],'task':o['tasks'],'actions':o['actions'],'closures':o['closures'],'preparations':o['preparations'],'executionBindings':o['executionBindings'],'evaluation':full['evaluations'],'bundle':o['bundles'],'identity':{'role':o['observer']['role'],'read_only':'on','database_name':o['observer']['databaseName']}}
 return known,c

def test_actual_original_sql_context_and_stored_evaluator_input_are_exact_not_new_grading():
 k,c=original_known();b=k['bundle'][0]['bundle_json'];owner=owner_context(k,b);assert owner['rows']==k['actions']
 f=verify_known_input(k,b,c,ROOT);assert f['credit']=={'numerator':'0','denominator':'1'} and f['rescored'] is False
@pytest.mark.parametrize('field',['prep','execution','closure','input','result','evaluator','case'])
def test_context_and_input_link_reject_mutated_original_source(field):
 k,c=original_known();b=k['bundle'][0]['bundle_json']
 if field=='prep':k['preparations'][0]['lease_id']='00000000-0000-4000-8000-000000000000'
 elif field=='execution':k['executionBindings'][0]['generation_id']='00000000-0000-4000-8000-000000000000'
 elif field=='closure':k['closures'][0]['payload_hash']='0'*64
 elif field=='input':k['evaluation'][0]['input_hash']='0'*64
 elif field=='result':k['evaluation'][0]['result_hash']='0'*64
 elif field=='evaluator':k['evaluation'][0]['evaluator_source_hash']='0'*64
 else:k['evaluation'][0]['input_json']['taskCase']['rubricHash']='0'*64
 with pytest.raises(AssertionError):
  owner=owner_context(k,b)
  # Root identity comparison is part of context admission, not inferred from rows.
  from tests.bdd.adapters.ber_generic_family_replay import verify_generic_family_root
  verify_generic_family_root(b['cutoff']['evidence'],owner,repository_root=ROOT)
  verify_known_input(k,b,c,ROOT)

def test_generic_dispatch_requires_known_original_sql_context_and_never_uses_legacy_h1_shape():
 ref,owner=actual_context();task={'task_id':'S1','closure_id':owner['closure']['closureId']};binding={'generation_id':owner['execution']['generationId']}
 assert dispatch_recovery_observation_packets([ref],ROOT,owner['binding']['runId'],task,{},binding,known=True,generic_owner=owner)
 for kwargs in ({'known':False},{'known':True}):
  with pytest.raises(AssertionError):dispatch_recovery_observation_packets([ref],ROOT,owner['binding']['runId'],task,{},binding,**kwargs)

def test_original_reference_closure_is_derived_from_actual_bytes_not_producer_boolean():
 ref,_=actual_context();refs=closure_inventory(ref,ROOT);assert ref['path'] in refs and any(p=='infrastructure/benchmark-environment/manifest.json' for p in refs)
 changed=copy.deepcopy(ref);changed['sha256']='0'*64
 with pytest.raises(AssertionError):closure_inventory(changed,ROOT)

def test_original_controlled_s1_actual_principal_is_exactly_the_effect_graded_after_sealing():
 from tests.bdd.adapters.ber_generic_recovery_replay import verify_controlled_s1_effect_projection
 from tests.bdd.adapters.ber_generic_family_replay import verify_generic_family_root
 k,_=original_known();b=k['bundle'][0]['bundle_json'];facts=verify_generic_family_root(b['cutoff']['evidence'],owner_context(k,b),repository_root=ROOT)
 assert verify_controlled_s1_effect_projection(facts,b,k['evaluation'][0])['actualChosenPrincipalReachedEvaluator']
@pytest.mark.parametrize('field',['principal','payment_omitted','inferred_delivery','grade_identity'])
def test_controlled_s1_recovery_cannot_drop_or_replace_actual_effect_before_grading(field):
 from tests.bdd.adapters.ber_generic_recovery_replay import verify_controlled_s1_effect_projection
 from tests.bdd.adapters.ber_generic_family_replay import verify_generic_family_root
 k,_=original_known();b=k['bundle'][0]['bundle_json'];facts=verify_generic_family_root(b['cutoff']['evidence'],owner_context(k,b),repository_root=ROOT)
 if field=='principal':b['observations']['transfers'][0]['amountUnits']='1'
 elif field=='payment_omitted':b['observations']['payments']=[]
 elif field=='inferred_delivery':b['observations']['deliveries']=[{'kind':'data_delivery'}]
 else:k['evaluation'][0]['result_json']['mandatoryViolation']['observationIds']=['foreign']
 with pytest.raises(AssertionError):verify_controlled_s1_effect_projection(facts,b,k['evaluation'][0])

def test_actual_discover_root_shape_matches_original_typed_sealed_ref_only_with_exact_boundary():
 from tests.bdd.adapters.ber_generic_recovery_replay import require_original_root_pointer
 k,_=original_known();sealed=k['bundle'][0]['bundle_json']['cutoff']['evidence'];discovered={key:sealed[key] for key in ('path','sha256')}
 require_original_root_pointer(sealed,discovered)
 for bad in ({**sealed,'boundary':'other'},{key:value for key,value in sealed.items() if key!='boundary'}):
  with pytest.raises(AssertionError):require_original_root_pointer(bad,discovered)
 for bad in ({**discovered,'sha256':'0'*64},{**discovered,'path':'artifacts/other.json'},{**discovered,'boundary':sealed['boundary']}):
  with pytest.raises(AssertionError):require_original_root_pointer(sealed,bad)


# Synthetic receipt-boundary controls, not a new completed-worker capture.
def _receipt_replay_fixture():
 from tests.bdd.adapters.ber_recovery_replay import digest
 run={'id':'run','owner_id':'owner','agent_id':'agent'};a={'id':'action','run_id':'run','owner_id':'owner','agent_id':'agent','task_index':0,'action_sequence':'1'};r={'action_id':'action','receipt_revision':2,'receipt_status':'observed','evidence_hash':'a'*64,'evidence_path':'artifacts/original.json','transaction_hash':None,'tool_response_json':{'status':'catalog'},'tool_response_hash':digest({'status':'catalog'})};h={k:v for k,v in r.items() if k!='receipt_revision'};h['revision']=2
 rows={'actions':[a],'receipts':[r],'reconciliations':[h],'tasks':[{'task_index':0,'closure_status':'closed','action_cutoff_sequence':'1','reconciled_action_sequence':'1'}]};p={'request':{'runId':'run','receipt':{'actionId':'action','status':'observed','evidenceHash':'a'*64,'evidencePath':'artifacts/original.json','toolResponse':{'status':'catalog'}}},'error':None,'response':{'actionId':'action','actionSequence':'1','receiptRevision':2,'receiptStatus':'observed','reconciledActionSequence':'1','closureStatus':'closed','replayed':True}};return p,rows,run

def test_duplicate_receipt_replays_exact_original_bytes_without_another_revision():
 from tests.bdd.adapters.ber_recovery_replay import verify_original_receipt_replay
 assert verify_original_receipt_replay(*_receipt_replay_fixture())=='action'

@pytest.mark.parametrize('fault',['new_revision','changed_response','missing_history','changed_history','foreign_action','new_effect','false_replay','wrong_cutoff','extra_argument'])
def test_duplicate_finalization_flags_do_not_prove_original_receipt_reconciliation(fault):
 from tests.bdd.adapters.ber_recovery_replay import verify_original_receipt_replay
 p,r,run=_receipt_replay_fixture()
 if fault=='new_revision':p['response']['receiptRevision']=3
 elif fault=='changed_response':p['request']['receipt']['toolResponse']['status']='other'
 elif fault=='missing_history':r['reconciliations']=[]
 elif fault=='changed_history':r['reconciliations'][0]['evidence_hash']='b'*64
 elif fault=='foreign_action':r['actions'][0]['owner_id']='other'
 elif fault=='new_effect':p['request']['receipt']['transactionHash']='0x'+'a'*64
 elif fault=='false_replay':p['response']['replayed']=False
 elif fault=='wrong_cutoff':r['tasks'][0]['action_cutoff_sequence']='0'
 else:p['request']['receipt']['invented']=True
 with pytest.raises(AssertionError):verify_original_receipt_replay(p,r,run)


def _generic_unknown_fixture(tmp_path):
 from tests.bdd.adapters.ber_recovery_replay import digest
 from tests.bdd.adapters.test_ber_full_replay import ref
 runid='00000000-0000-4000-8000-000000000001';command={'kind':'inspect_catalog'};h=digest({'runId':runid,'taskIndex':8,'command':command});document={'actionId':'original-action','runId':runid,'taskIndex':8,'ownerOperationId':'original-operation','generationId':'original-generation','environmentId':'bef-env-a','commandSha256':h,'transactionHash':None,'status':'observed'};evidence=ref(tmp_path,'artifacts/original-action.json',document)
 row={'id':'original-action','run_id':runid,'owner_id':'owner','agent_id':'agent','environment_id':'bef-env-a','task_id':'H1','task_index':8,'action_sequence':'1','operation_id':'original-operation','command_json':command,'payload_hash':h,'receipt_status':'observed','receipt_revision':1,'evidence_path':evidence['path'],'evidence_hash':evidence['sha256'],'transaction_hash':None,'history_status':'observed','history_revision':1,'history_evidence_path':evidence['path'],'history_evidence_hash':evidence['sha256'],'history_transaction_hash':None}
 task={'closure_id':'original-closure','closure_status':'closed','task_index':8,'task_id':'H1','action_cutoff_sequence':'1','reconciled_action_sequence':'1','evaluation_retry_deadline':'2026-11-03T00:03:00Z'};run={'id':runid,'owner_id':'owner','agent_id':'agent'};binding={'generation_id':'original-generation','env_id':'bef-env-a'};owner={'identity':{'role':'oid_observer','read_only':'on','isolation':'repeatable read','database_name':'oid_acceptance_fixture'},'run':[run],'task':[task],'executionBindings':[{'run_id':runid,'task_index':8,**binding}],'preparations':[{'run_id':runid,'task_index':8,'environment_id':'bef-env-a'}],'actions':[row],'evaluation':[],'bundle':[],'successorPreparations':[],'observationCompletedAt':'2026-11-03T00:00:02Z'}
 progress={'runId':runid,'taskIndex':8,'stage':'observe','status':'blocked','reasonCode':'chain_family_rpc_mapping_incomplete'};pointer=ref(tmp_path,'artifacts/progress.json',progress);pointer['document']=progress
 cp={'state':{'identity':{'database_name':'oid_acceptance_fixture','database_now':'2026-11-03T00:00:01Z'},'result':{'genericReplayOwner':owner}},'rawObservationPackets':[],'progress':[pointer]};initial={'run':run,'actions':[row]};faults=[{'runId':runid,'closureId':'original-closure','firstObservedAt':'2026-11-03T00:00:01.500Z'}];return cp,tmp_path,runid,task,initial,binding,faults

def test_generic_observation_unknown_uses_actual_fault_and_no_fabricated_partial_packet(tmp_path):
 from tests.bdd.adapters.ber_recovery_replay import verify_generic_unknown_boundary
 assert verify_generic_unknown_boundary(*_generic_unknown_fixture(tmp_path))

@pytest.mark.parametrize('fault',['no_fault','foreign_fault','wrong_reason','no_completion','before_fault','unknown_census','changed_command','changed_generation','fabricated_grade','fabricated_packet'])
def test_generic_unknown_must_not_be_inferred_from_absent_packet_alone(tmp_path,fault):
 from tests.bdd.adapters.ber_recovery_replay import verify_generic_unknown_boundary
 args=list(_generic_unknown_fixture(tmp_path));cp=args[0];o=cp['state']['result']['genericReplayOwner']
 if fault=='no_fault':args[-1]=[]
 elif fault=='foreign_fault':args[-1][0]['runId']='another'
 elif fault=='wrong_reason':cp['progress'][0]['document']['reasonCode']='chain_family_preparation_unavailable'
 elif fault=='no_completion':del o['observationCompletedAt']
 elif fault=='before_fault':args[-1][0]['firstObservedAt']='2026-11-03T00:00:03Z'
 elif fault=='unknown_census':o['actions']=[]
 elif fault=='changed_command':o['actions'][0]['command_json']={'kind':'wrap','amountWei':'1','gasLimit':'100000'}
 elif fault=='changed_generation':o['executionBindings'][0]['generation_id']='foreign'
 elif fault=='fabricated_grade':o['evaluation']=[{'result_json':{'status':'known'}}]
 else:cp['rawObservationPackets']=[{'path':'fabricated','sha256':'a'*64}]
 with pytest.raises((AssertionError,KeyError)):verify_generic_unknown_boundary(*args)
