"""Exact source-return fault transformations; synthetic tests are not runtime evidence."""
import copy,json,subprocess
from pathlib import Path
import pytest
from tests.bdd.adapters.ber_source_negative_replay import verify_source_transformation,verify_query_registry,REASONS
from tests.bdd.adapters.ber_matrix_common import digest
ROOT=Path(__file__).resolve().parents[3]

def fixture(variant):
 t={'variant':variant,'environmentId':'bef-env-a','generationId':'00000000-0000-4000-8000-000000000001','befOperationId':'00000000-0000-4000-8000-000000000002','transactionHash':'0x'+'a'*64};row={'env_id':t['environmentId'],'generation_id':t['generationId'],'operation_id':t['befOperationId'],'transaction_hash':t['transactionHash'],'receipt_block_hash':'0x'+'b'*64};o={'kind':'postgres_result','parameters':[t['environmentId'],t['generationId']],'querySha256':'c'*64,'columns':list(row),'rows':[row]};i={'target':t,'selectedRowIndex':0,'columns':o['columns'],'querySha256':o['querySha256'],'parametersSha256':digest(o['parameters'])}
 if variant=='census_contradictory':o['rows']=[{'operations':'1','selected_executions':'1','selected_events':'4','costs':'1'}];o['columns']=list(o['rows'][0]);i['columns']=o['columns']
 if variant=='census_truncated':row['event_kind']='original_tx_hash_bound';o['columns']=list(row);i['columns']=o['columns']
 if variant in ('read_missing','block_missing'):
  request={'method':'eth_call','params':[{'to':'0x'+'1'*40,'data':'0x70a08231'+'0'*64},'0x10']} if variant=='read_missing' else {'method':'eth_getBlockByNumber','params':['0x10',False]}
  o={'kind':'rpc_result','request':request,'httpStatus':200,'body':{'jsonrpc':'2.0','id':1,'result':'0x'+'0'*64 if variant=='read_missing' else {'hash':'0x'+'b'*64,'transactions':[t['transactionHash']]}}};i={'target':t,'method':request['method'],'parametersSha256':digest(request['params'])}
 d=copy.deepcopy(o)
 if variant in ('receipt_row_missing','census_truncated'):d['rows']=[]
 elif variant=='receipt_hash_conflict':d['rows'][0]['receipt_block_hash']='0x'+'c'+'b'*63
 elif variant=='receipt_generation_conflict':d['rows'][0]['generation_id']='00000000-0000-4000-8000-000000000003'
 elif variant=='census_contradictory':d['rows'][0]['costs']='2'
 else:d['body']['result']=None
 i.update(originalSha256=digest(o),deliveredSha256=digest(d));return t,o,d,i

@pytest.mark.parametrize('variant',REASONS)
def test_exact_declared_single_source_intervention_is_replayed_without_db_mutation_claim(variant):
 r=verify_source_transformation(*fixture(variant));assert r['actualChangedReadReturn'] and not r['authoritativeDatabaseMutationClaimed']

@pytest.mark.parametrize('variant',REASONS)
def test_rehashing_broader_changed_data_does_not_make_it_the_approved_fault(variant):
 t,o,d,i=fixture(variant);d['unrelated']='mutated';i['deliveredSha256']=digest(d)
 with pytest.raises(AssertionError):verify_source_transformation(t,o,d,i)

@pytest.mark.parametrize('variant',REASONS)
def test_unchanged_source_cannot_be_claimed_as_a_fault(variant):
 t,o,d,i=fixture(variant);i['deliveredSha256']=digest(o)
 with pytest.raises(AssertionError):verify_source_transformation(t,o,o,i)

def test_actual_javascript_query_registry_is_reconstructed_from_hash_pinned_product_source():
 command=['node','--input-type=module','-e',"import{loadSourceObservationRegistry}from'./packages/owner-acceptance/src/ber-source-observation-fault.mjs';console.log(JSON.stringify(await loadSourceObservationRegistry(process.cwd())))"]
 result=subprocess.run(command,cwd=ROOT,capture_output=True,text=True,check=True);registry=json.loads(result.stdout);assert len(verify_query_registry(registry,ROOT))==3
 changed=copy.deepcopy(registry);changed['entries']['costs']['sqlSha256']='f'*64
 with pytest.raises(AssertionError):verify_query_registry(changed,ROOT)
 changed=copy.deepcopy(registry);changed['entries']['costs']['columns'].append('invented')
 with pytest.raises(AssertionError):verify_query_registry(changed,ROOT)


def test_public_source_fault_cli_blocks_missing_proof_without_leaking_input_or_creating_report(tmp_path):
 import sys
 selector=tmp_path/'selector.json';selector.write_text(json.dumps({'path':'missing-private-canary.json','sha256':'a'*64}));out=tmp_path/'.local/report.json'
 run=subprocess.run([sys.executable,str(ROOT/'tests/bdd/adapters/ber_source_negative_replay.py'),'--repo-root',str(tmp_path),'--fault-ref',str(selector),'--actor-ref',str(selector),'--output',str(out)],cwd=ROOT,capture_output=True,text=True)
 assert run.returncode==2 and not out.exists() and not run.stderr and 'missing-private-canary' not in run.stdout
 body=json.loads(run.stdout);assert body['code']=='BER_SOURCE_NEGATIVE_EVIDENCE_UNVERIFIABLE' and body['errorClass']=='AssertionError' and body['frames']
