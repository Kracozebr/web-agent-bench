"""Original retained generic paid-family replay controls, never a full recovery gate."""
import copy,json
from pathlib import Path
import pytest
from tests.bdd.adapters.ber_generic_family_replay import verify_generic_family_root,load_admitted_root
from tests.bdd.adapters.ber_recovery_replay import read_reference
ROOT=Path(__file__).resolve().parents[3]
OWNER=ROOT/'.local/ber-training-a-evaluation-addendum-f0211bac-9a09-4138-9858-240706f84f78.json'
def actual_context():
 if not OWNER.is_file():pytest.skip('BLOCKED: original controlled generic family capture unavailable')
 data=json.loads(OWNER.read_text());b=data['bundles'][0]['bundle_json'];p=read_reference(ROOT,b['cutoff']['evidence']);e=data['evaluations'][0]['input_json'];binding={k:e['run'][k] for k in p['binding']}
 prep=data['preparations'][0];execution={k:prep[v] for k,v in [('preparationId','preparation_id'),('leaseId','lease_id'),('environmentId','environment_id'),('initialStateSha256','initial_state_sha256'),('executionIdentityHash','execution_identity_hash'),('environmentManifestHash','environment_manifest_sha256'),('applicationSourceHash','application_source_hash')]};execution['generationId']=data['executionBindings'][0]['generation_id']
 c=data['closures'][0];closure={'closureId':c['id'],'operationId':c['operation_id'],'payloadHash':c['payload_hash'],'reason':c['reason'],'actionCutoffSequence':int(c['action_cutoff_sequence']),'reconciledActionSequence':int(data['tasks'][0]['reconciled_action_sequence'])}
 return b['cutoff']['evidence'],{'source':data['source'],'observer':data['observer'],'binding':binding,'execution':execution,'closure':closure,'taskIndex':0,'rows':[r for r in data['actions'] if r['task_index']==0]}
def test_original_generic_root_reads_and_independent_payment_delivery_do_not_become_a_recovery_gate():
 ref,owner=actual_context();f=verify_generic_family_root(ref,owner,repository_root=ROOT)
 assert f['actualPaymentCount']==f['actualDeliveryCount']==1 and f['originalActionCount']==4 and f['fullScenarioAcceptance']=='blocked'
@pytest.mark.parametrize('field',['history','command','root_binding','cutoff','generation','receipt_ref'])
def test_generic_dispatch_cannot_accept_changed_original_owner_binding_or_history(field):
 ref,o=actual_context()
 if field=='history':o['rows'][2]['history_revision']+=1
 elif field=='command':o['rows'][2]['command_json']['offerId']='other'
 elif field=='root_binding':o['binding']['agentId']='00000000-0000-4000-8000-000000000000'
 elif field=='cutoff':o['closure']['actionCutoffSequence']+=1
 elif field=='generation':o['execution']['generationId']='00000000-0000-4000-8000-000000000000'
 else:o['rows'][2]['evidence_hash']='0'*64
 with pytest.raises(AssertionError):verify_generic_family_root(ref,o,repository_root=ROOT)
