"""Offline actual retained Training B controls. This file does not create runtime evidence."""
from pathlib import Path
import json,copy
import pytest
from tests.bdd.adapters.ber_matrix_replay import verify_matrix,exact_ref,immutable_report
ROOT=Path(__file__).resolve().parents[3]
ACTOR={'path':'artifacts/runs/genuine-training-sequence-owner-run/a8004241-ba37-4a46-9dd8-9f99097d964d/capture.json','sha256':'f9b21d901bdeb361aabb9a61af5f6b579ef285d9ebceb80b5a2d5ac8042ff293'}
OWNER={'path':'.local/ber-final-source-private-owner-snapshot-b02c1052-6a40-46af-a132-54b77889dab5.json','sha256':'a26d71d8f58328793d9b7947c2e2b1bbf971c99da58c19ac258c7a9a9710c7a4'}
def test_actual_old_b_without_direct_addendum_remains_incomplete_and_contributes_no_cells():
 assert (ROOT/OWNER['path']).is_file(),'retained historical observer proof required; missing is not a passing acceptance'
 report=verify_matrix(ACTOR,OWNER,[],ROOT)
 assert report['functionalCaptured'] and report['status']=='incomplete' and not report['independentRawComplete'] and report['positive135Cells']==[]
 assert all(not t['rawComplete'] for t in report['tasks']) and any(x.startswith('per_action_direct_support_missing:') for x in report['incompleteReasons'])
@pytest.mark.parametrize('value',[{}, {'path':'x'}, {'path':'x','sha256':'a'*64,'url':'http://invalid'}])
def test_selectors_are_exact_hash_refs(value):
 with pytest.raises(AssertionError):exact_ref(value)
def test_immutable_output_refuses_overwrite_and_escape(tmp_path):
 repo=tmp_path/'repo';repo.mkdir();path=repo/'.local'/'report.json';ref=immutable_report(path,{'status':'incomplete'},repo);assert len(ref['sha256'])==64
 with pytest.raises(AssertionError):immutable_report(path,{},repo)
 with pytest.raises(AssertionError):immutable_report(tmp_path/'elsewhere.json',{},repo)

@pytest.mark.parametrize('value',['participant','0x'+'1'*40])
def test_sealed_transfer_role_is_normalized_only_against_independently_pinned_payer(value):
 from tests.bdd.adapters.ber_matrix_chain_projection import verify_sealed_transfer_sender
 verify_sealed_transfer_sender(value,'0x'+'1'*40,'0x'+'1'*40)
@pytest.mark.parametrize('value,actual,payer',[('owner','0x'+'1'*40,'0x'+'1'*40),('agent','0x'+'1'*40,'0x'+'1'*40),('participant','0x'+'2'*40,'0x'+'1'*40),('0x'+'2'*40,'0x'+'1'*40,'0x'+'1'*40),(None,'0x'+'1'*40,'0x'+'1'*40),('','0x'+'1'*40,'0x'+'1'*40)])
def test_role_alias_never_authorizes_unknown_role_or_foreign_actual_sender(value,actual,payer):
 from tests.bdd.adapters.ber_matrix_chain_projection import verify_sealed_transfer_sender
 with pytest.raises(AssertionError):verify_sealed_transfer_sender(value,actual,payer)
def test_raw_ethereum_address_decoder_still_rejects_role_strings():
 from tests.bdd.adapters.ber_chain_effects import address
 with pytest.raises(AssertionError):address('participant')
def test_actual_old_training_c_corrected_raw_replay_does_not_repin_its_old_source_cohort():
 from tests.bdd.adapters.ber_matrix_chain_projection import verify_chain_projection
 from tests.bdd.adapters.ber_matrix_common import load_ref
 folder=ROOT/'.local/ber-private-campaign/4e4b4249-b5ed-453a-a24f-d80d8ec3d470/training_c';ar=json.loads((folder/'actor-ref.json').read_text());ow=json.loads((folder/'owner-ref.json').read_text());supports=json.loads((folder/'support-refs.json').read_text());actor,owner=load_ref(ROOT,ar),load_ref(ROOT,ow)
 for i in range(3):assert verify_chain_projection(owner,actor,i,ROOT)['actualChainActions']==4
 with pytest.raises((AssertionError,KeyError)):
  verify_matrix(ar,ow,supports,ROOT)  # Historical captures lack the new actual SQL completion witness.

def _actual_paid_gas_fixture():
 from tests.bdd.adapters.ber_matrix_common import load_ref
 folder=ROOT/'.local/ber-private-campaign/c72096d4-e5fa-484f-9b30-9b2fed4f0cd1/training_a';owner=load_ref(ROOT,json.loads((folder/'owner-ref.json').read_text()));b=owner['bundles'][0]['bundle_json'];p=load_ref(ROOT,b['cutoff']['evidence']);paid=load_ref(ROOT,p['children']['paid']['evidence']);chain=load_ref(ROOT,p['children']['chain']['evidence']);return paid['bef']['before']['costs'][0],b['observations']['payments'][0],b['observations']['expenses'],chain['rpc']['transactions'][0],chain['rpc']['participant']
def test_actual_facilitator_gas_is_measured_but_never_fabricated_as_participant_expense():
 from tests.bdd.adapters.ber_matrix_core import verify_payment_gas_projection
 cost,payment,expenses,tx,payer=_actual_paid_gas_fixture();fact=verify_payment_gas_projection(cost,payment,expenses,tx,payer);assert fact['rawGasPayer']=='facilitator' and int(fact['rawGasWei'])>0 and fact['scoredParticipantGasCount']==0
@pytest.mark.parametrize('change',['invented_expense','wrong_role','sender','gas','receipt_hash','unknown_role'])
def test_paid_gas_ownership_and_raw_receipt_contradictions_rejected(change):
 from tests.bdd.adapters.ber_matrix_core import verify_payment_gas_projection
 cost,payment,expenses,tx,payer=_actual_paid_gas_fixture()
 if change=='invented_expense':expenses.append({'transactionHash':tx['hash'],'component':'participant_gas'})
 elif change=='wrong_role':payment['gasPayer']='participant'
 elif change=='sender':cost['receipt_from']=payer
 elif change=='gas':cost['gas_cost_wei']=str(int(cost['gas_cost_wei'])+1)
 elif change=='receipt_hash':cost['receipt_block_hash']='0x'+'f'*64
 else:cost['payer_role']=payment['gasPayer']='unknown'
 with pytest.raises(AssertionError):verify_payment_gas_projection(cost,payment,expenses,tx,payer)
def test_participant_payment_gas_requires_exact_one_original_component():
 from tests.bdd.adapters.ber_matrix_core import verify_payment_gas_projection
 cost,payment,_,tx,payer=_actual_paid_gas_fixture();cost['payer_role']=payment['gasPayer']='participant';tx['from']=payer
 for k in ('payer_address','transaction_from','receipt_from'):cost[k]=payer
 expense={'component':'participant_gas','transactionHash':tx['hash'],'sourceEffectId':'bef-operation:'+cost['operation_id'],'gasUsed':cost['gas_used'],'effectiveGasPriceWei':cost['effective_gas_price_wei'],'receiptStatus':cost['receipt_status']};assert verify_payment_gas_projection(cost,payment,[expense],tx,payer)['scoredParticipantGasCount']==1
 for rows in ([],[expense,copy.deepcopy(expense)],[{**expense,'component':'facilitator_gas'}]):
  with pytest.raises(AssertionError):verify_payment_gas_projection(cost,payment,rows,tx,payer)
@pytest.mark.parametrize('mode,ownerpath,actorpath',[('training','.local/ber-training-a-evaluation-addendum-f0211bac-9a09-4138-9858-240706f84f78.json','artifacts/runs/genuine-training-sequence-owner-run/df19cb3c-c07b-4056-8e9e-cb00b05a05bd/capture.json'),('ranked','.local/ber-ranked-a-r4-private-owner-snapshot-b0eb5586-f514-42b1-9ba1-d14277dfa532.json','artifacts/runs/genuine-ranked-worker-owner-run/25720023-ccde-41d0-851a-6b0709c735e9/capture.json')])
def test_actual_historical_all_a_payment_delivery_and_typed_input_links(mode,ownerpath,actorpath):
 from tests.bdd.adapters.ber_matrix_core import verify_task,verify_evaluator_link
 owner=json.loads((ROOT/ownerpath).read_text());actor=json.loads((ROOT/actorpath).read_text());assert len(owner['tasks'])==(3 if mode=='training' else 12)
 for i in range(len(owner['tasks'])):
  facts=verify_task(owner,actor,i,ROOT);assert facts['paid']['actualPayments']==facts['paid']['actualDeliveries']==1;assert verify_evaluator_link(owner,actor,i,ROOT)['sealedObservationsExactlyReachedEvaluator']
@pytest.mark.parametrize('name',['training_a','training_c','ranked_c'])
def test_actual_current_a_and_c_semantic_facts_pass_without_repinning_reader_cohort(name):
 folder=ROOT/'.local/ber-private-campaign/c72096d4-e5fa-484f-9b30-9b2fed4f0cd1'/name;refs=[json.loads((folder/n).read_text()) for n in ('actor-ref.json','owner-ref.json','support-refs.json')]
 if refs[2]:
  with pytest.raises((AssertionError,KeyError)):verify_matrix(*refs,ROOT)
 else:
  result=verify_matrix(*refs,ROOT);assert all(t['rawComplete'] for t in result['tasks']);assert result['status']=='incomplete' and not result['positive135Cells']

def _pattern_fixture(profile='NOOP_REVERT_D'):
 participant='0x'+'1'*40;W='1000000000000';wrap={'kind':'wrap','amountWei':W if profile=='NOOP_REVERT_D' else '2000000000000','gasLimit':'100000'};approve={'kind':'approve','tokenAssetId':'WETH','amountUnits':W,'gasLimit':'100000'};swap={'kind':'swap','inputAssetId':'WETH','outputAssetId':'USDC','feeTier':500,'amountInUnits':W,'amountOutMinimumUnits':str((1<<256)-1) if profile=='NOOP_REVERT_D' else '1','recipient':participant,'gasLimit':'300000'};commands=[wrap,approve,copy.deepcopy(approve),swap]
 if profile=='COMPOSITE_MIXED':commands=[{'kind':'inspect_catalog'},{'kind':'inspect_offer','resourceId':'public','offerId':'canonical'},{'kind':'pay','resourceId':'public','offerId':'canonical','offerReadActionId':'a1'},{'kind':'retrieve','payActionId':'a2'},wrap,approve,swap,{'kind':'unwrap','amountWei':W,'gasLimit':'100000'}]
 entries=[{'command':c,'actionKind':c['kind'],'actionId':'a'+str(i),'ownerOperationId':'o'+str(i),'transactionHash':'0x'+format(i+1,'064x') if c['kind'] not in ('inspect_catalog','inspect_offer','retrieve') else None,'receiptStatus':'observed'} for i,c in enumerate(commands)];txs=[{'hash':e['transactionHash'],'status':'reverted' if profile=='NOOP_REVERT_D' and i==3 else 'success','logs':[],'gasUsed':'1','gasCostWei':'2'} for i,e in enumerate(entries) if e['transactionHash']];chain={'rpc':{'participant':participant,'transactions':txs},'ownerActions':[{'befOperationId':'b'+str(i)} for i in range(4)]};support={'states':{'a2':{'before':{'allowance.WETH':int(W)},'after':{'allowance.WETH':int(W)}},'a3':{'before':{'participant.ETH':10,'participant.nonce':0,'allowance.WETH':int(W),'pool.WETH':1},'after':{'participant.ETH':8,'participant.nonce':1,'allowance.WETH':int(W),'pool.WETH':1}}}};return entries,chain,support

def test_declared_d_and_mixed_require_their_exact_distinct_actual_action_unions():
 from tests.bdd.adapters.ber_matrix_replay import verify_declared_profile
 e,ch,s=_pattern_fixture();assert verify_declared_profile('NOOP_REVERT_D','training','S1',e,ch,{},s)['verified'];e,ch,s=_pattern_fixture('COMPOSITE_MIXED');assert verify_declared_profile('COMPOSITE_MIXED','ranked','U1',e,ch,{})['verified']
@pytest.mark.parametrize('change',['wrong_amount','not_noop','not_reverted','reverted_logs','foreign_recipient','duplicate_tx','state_mutation','missing_action'])
def test_d_cannot_be_labeled_by_generic_chain_success(change):
 from tests.bdd.adapters.ber_matrix_replay import verify_declared_profile
 e,ch,s=_pattern_fixture()
 if change=='wrong_amount':e[0]['command']['amountWei']='2000000000000'
 elif change=='not_noop':s['states']['a2']['before']['allowance.WETH']=0
 elif change=='not_reverted':ch['rpc']['transactions'][-1]['status']='success'
 elif change=='reverted_logs':ch['rpc']['transactions'][-1]['logs']=[{}]
 elif change=='foreign_recipient':e[-1]['command']['recipient']='0x'+'2'*40
 elif change=='duplicate_tx':ch['rpc']['transactions'][-1]['hash']=ch['rpc']['transactions'][0]['hash']
 elif change=='state_mutation':s['states']['a3']['after']['pool.WETH']=2
 else:e.pop()
 with pytest.raises(AssertionError):verify_declared_profile('NOOP_REVERT_D','training','S1',e,ch,{},s)
@pytest.mark.parametrize('change',['paid_only','chain_only','wrong_reference','missing_chain','same_economic_tx'])
def test_mixed_cannot_be_labeled_without_one_actual_cutoff_union(change):
 from tests.bdd.adapters.ber_matrix_replay import verify_declared_profile
 e,ch,s=_pattern_fixture('COMPOSITE_MIXED')
 if change=='paid_only':e=e[:4]
 elif change=='chain_only':e=e[4:]
 elif change=='wrong_reference':e[3]['command']['payActionId']='another'
 elif change=='missing_chain':e.pop()
 else:e[-1]['transactionHash']=e[2]['transactionHash']
 with pytest.raises(AssertionError):verify_declared_profile('COMPOSITE_MIXED','ranked','H3',e,ch,{})

@pytest.mark.parametrize('amount,before',[('0',0),('1000000000000',1000000000000)])
def test_first_noop_approval_still_has_one_audit_event_and_zero_state_mutations(amount,before):
 from tests.bdd.adapters.ber_matrix_chain_projection import verify_approval_audit
 spender='0x'+'1'*40;command={'kind':'approve','tokenAssetId':'WETH','amountUnits':amount,'gasLimit':'100000'};event={'owner':'participant','tokenAssetId':'WETH','spender':spender,'amountBeforeUnits':str(before),'amountAfterUnits':amount}
 facts=verify_approval_audit([event],command,spender,before,[]);assert facts=={'auditEvents':1,'stateChanged':False}
@pytest.mark.parametrize('change',['omitted_event','duplicate_event','invented_noop_mutation','wrong_before','wrong_after','wrong_owner','wrong_spender'])
def test_approval_event_is_not_confused_with_allowance_state_change(change):
 from tests.bdd.adapters.ber_matrix_chain_projection import verify_approval_audit
 spender='0x'+'1'*40;command={'kind':'approve','tokenAssetId':'WETH','amountUnits':'0','gasLimit':'100000'};event={'owner':'participant','tokenAssetId':'WETH','spender':spender,'amountBeforeUnits':'0','amountAfterUnits':'0'};rows=[event];mutations=[]
 if change=='omitted_event':rows=[]
 elif change=='duplicate_event':rows.append(copy.deepcopy(event))
 elif change=='invented_noop_mutation':mutations=[{'mutationType':'allowance','key':'participant:WETH:'+spender,'beforeValue':'0','afterValue':'0'}]
 elif change=='wrong_before':event['amountBeforeUnits']='1'
 elif change=='wrong_after':event['amountAfterUnits']='1'
 elif change=='wrong_owner':event['owner']='another'
 else:event['spender']='0x'+'2'*40
 with pytest.raises(AssertionError):verify_approval_audit(rows,command,spender,0,mutations)
def test_changed_approval_requires_exact_state_mutation_in_addition_to_audit_event():
 from tests.bdd.adapters.ber_matrix_chain_projection import verify_approval_audit
 spender='0x'+'1'*40;cmd={'kind':'approve','tokenAssetId':'WETH','amountUnits':'1','gasLimit':'100000'};event={'owner':'participant','tokenAssetId':'WETH','spender':spender,'amountBeforeUnits':'0','amountAfterUnits':'1'};mutation={'mutationType':'allowance','key':'participant:WETH:'+spender,'beforeValue':'0','afterValue':'1'}
 assert verify_approval_audit([event],cmd,spender,0,[mutation])['stateChanged']
 with pytest.raises(AssertionError):verify_approval_audit([event],cmd,spender,0,[])

@pytest.fixture(scope='module')
def actual_first_training_d_raw():
 from tests.bdd.adapters.ber_matrix_common import load_ref
 from tests.bdd.adapters.ber_matrix_support import verify_chain_support
 folder=ROOT/'.local/ber-private-campaign/b1056cb8-bac3-4d96-80bb-c69ec4387439/training_d';refs=[json.loads((folder/n).read_text()) for n in ('actor-ref.json','owner-ref.json','support-refs.json')];actor,owner=load_ref(ROOT,refs[0]),load_ref(ROOT,refs[1]);bundle=owner['bundles'][0]['bundle_json'];rootref=bundle['cutoff']['evidence'];packet=load_ref(ROOT,rootref);chain=load_ref(ROOT,packet['children']['chain']['evidence']);support=historical_economic_state_view(refs[2][0]);return refs,actor,owner,bundle,packet,chain,support

def test_actual_all_three_d_raw_approval_audit_noop_and_revert_without_old_source_repin(actual_first_training_d_raw):
 refs,actor,owner,bundle,packet,chain,support=actual_first_training_d_raw
 from tests.bdd.adapters.ber_matrix_common import load_ref
 from tests.bdd.adapters.ber_matrix_state_effects import verify_supported_chain_effects
 for i in range(3):
  b=owner['bundles'][i]['bundle_json'];r=load_ref(ROOT,b['cutoff']['evidence']);c=load_ref(ROOT,r['children']['chain']['evidence']);economic=historical_economic_state_view(refs[2][i]);facts=verify_supported_chain_effects(c,r,b,economic)['facts'];assert facts[2]['noopApproval'] is True and facts[3]['outcome']=='reverted' and int(facts[3]['gasWei'])>0
 with pytest.raises((AssertionError,KeyError)):verify_matrix(*refs,ROOT)
@pytest.mark.parametrize('change',['revert_audit','revert_mutation','noop_mutation'])
def test_actual_reverted_action_never_gets_approval_or_allowance_state_facts(actual_first_training_d_raw,change):
 from tests.bdd.adapters.ber_matrix_state_effects import verify_supported_chain_effects
 _,_,_,original,packet,chain,support=actual_first_training_d_raw;bundle=copy.deepcopy(original);obs=bundle['observations'];tx=chain['ownerActions'][-1]['transactionHash'];sample=copy.deepcopy(obs['allowanceChanges'][-1])
 if change=='revert_audit':sample.update(transactionHash=tx,actionSequence=4);obs['allowanceChanges'].append(sample)
 else:
  noop=change=='noop_mutation';tx=chain['ownerActions'][2]['transactionHash'] if noop else tx;obs['stateMutations'].append({'kind':'state_mutation','mutationType':'allowance','key':'participant:WETH:'+sample['spender'],'transactionHash':tx,'actionSequence':3 if noop else 4,'beforeValue':sample['amountAfterUnits'],'afterValue':sample['amountAfterUnits']})
 with pytest.raises(AssertionError):verify_supported_chain_effects(chain,packet,bundle,support)


def historical_economic_state_view(reference):
 """Test-only raw state decoder. NEVER establishes observer chronology/acceptance."""
 from tests.bdd.adapters.ber_matrix_common import load_ref
 from tests.bdd.adapters.ber_matrix_support import uint_hex
 proof=load_ref(ROOT,reference);states={}
 for action in proof['rpc']['actions']:
  pair=[]
  for state in action['states']:
   view={}
   for read in state['reads']:
    value=load_ref(ROOT,read['ref'])['result'];label=read['label']
    view[label]=value if label.startswith('code.') or label in ('pool.slot0','pool.liquidity') else uint_hex(value)
   pair.append(view)
  states[action['actionId']]={'before':pair[0],'after':pair[1],'pool':action['pool'],'command':action.get('command',{})}
 # Chosen command is separately bound by the actual sealed owner census in the pure effect function.
 owner_actions=load_ref(ROOT,proof['chainRef'])['ownerActions']
 for a in owner_actions:states[a['actionId']]['command']=a['command']
 return {'states':states,'historicalUnqualifiedEconomicView':True}


def test_cell_order_is_not_a_new_economic_fact_but_all_other_report_bytes_are():
 from tests.bdd.adapters.ber_matrix_replay import canonical_report_identity
 a={'positive135Cells':[{'variant':'ranked:S1','kind':k,'runId':'original','taskIndex':0} for k in ('pay','retrieve')],'sourceWindow':{'currentMatches':True},'tasks':[{'rawHash':'a'}]}
 b=copy.deepcopy(a);b['positive135Cells'].reverse();assert canonical_report_identity(a)==canonical_report_identity(b)
 b['tasks'][0]['rawHash']='b';assert canonical_report_identity(a)!=canonical_report_identity(b)
 b=copy.deepcopy(a);b['positive135Cells'].append(b['positive135Cells'][0])
 with pytest.raises(AssertionError):canonical_report_identity(b)


@pytest.mark.parametrize('fault',['intent','agent','browser_operation','rendered_grade','api_grade','no_response','no_request'])
def test_actual_ui_launch_render_and_results_response_are_joined_to_original_db(fault):
 from tests.bdd.adapters.ber_matrix_common import load_ref
 from tests.bdd.adapters.ber_matrix_replay import verify_browser_results_link
 folder=ROOT/'.local/ber-private-campaign/c72096d4-e5fa-484f-9b30-9b2fed4f0cd1/training_a';a=load_ref(ROOT,json.loads((folder/'actor-ref.json').read_text()));o=load_ref(ROOT,json.loads((folder/'owner-ref.json').read_text()));verify_browser_results_link(a,o)
 if fault=='intent':a['launchIntent']['intentId']='foreign'
 elif fault=='agent':a['launchIntent']['database']['agent_id']='foreign'
 elif fault=='browser_operation':next(r for r in a['browserActionManifest'] if r['label']=='owner_run_intent_create')['operationId']='foreign'
 elif fault=='rendered_grade':a['ownerRunResultsUi']['tasks'][0]['credit']['numerator']='999'
 elif fault=='api_grade':a['ownerRunResultsUi']['resultsApi']['tasks'][0]['credit']['numerator']='999'
 else:
  key='responses' if fault=='no_response' else 'requests';a['browserWitness']['owner'][key]=[r for r in a['browserWitness']['owner'][key] if '/results' not in r.get('path','')]
 with pytest.raises(AssertionError):verify_browser_results_link(a,o)
