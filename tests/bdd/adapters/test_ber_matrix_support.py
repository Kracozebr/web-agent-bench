"""Meaningful crypto/ABI/boundary controls; synthetic inputs do not prove runtime."""
import pytest
from tests.bdd.adapters.ber_matrix_support import code_hash,uint_hex,timeout,_source_role

def test_actual_ethereum_keccak_vectors_not_nist_sha3():
 assert code_hash('0x')=='c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'
 from tests.bdd.adapters.benchmark_environment_feasibility import _keccak256
 assert _keccak256(b'Transfer(address,address,uint256)').hex()=='ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef'
@pytest.mark.parametrize('value,words',[('0x01',1),('0x'+'0'*64,7),('0xzz',None)])
def test_wrong_abi_width_or_hex_is_not_valid_state(value,words):
 with pytest.raises(AssertionError):uint_hex(value,words)
def test_timeout_parser_preserves_existing_limit_and_infinite_zero():
 assert timeout('5s')==5000 and timeout('0')==0 and timeout('1min')==60000
 with pytest.raises(AssertionError):timeout('unlimited')
@pytest.mark.parametrize('field,value',[('role','bef_owner'),('transactionReadOnly','off'),('isolation','read committed'),('superuser',True),('bypassRls',True)])
def test_source_role_cannot_be_claimed_by_wrong_identity(field,value):
 o={'role':'bef_observer','sessionRole':'bef_observer','databaseName':'bef','readOnly':True,'transactionReadOnly':'on','isolation':'repeatable read','superuser':False,'bypassRls':False};o[field]=value
 with pytest.raises(AssertionError):_source_role({'observer':o})

@pytest.mark.parametrize('value,outcome',[('0x0','reverted'),('0x1','success')])
def test_raw_receipt_status_exact_evm_enums(value,outcome):
 from tests.bdd.adapters.ber_matrix_support import receipt_outcome
 assert receipt_outcome(value)==outcome
@pytest.mark.parametrize('value',['0x2','0xff','success','reverted',None])
def test_other_values_cannot_be_reinterpreted_as_mined_revert(value):
 from tests.bdd.adapters.ber_matrix_support import receipt_outcome
 with pytest.raises(AssertionError):receipt_outcome(value)
def test_facilitator_is_not_a_scored_expense_component():
 from tests.bdd.adapters.ber_matrix_state_effects import validate_expense_components
 validate_expense_components([{'component':'participant_gas'},{'component':'verified_dex_fee'}])
 with pytest.raises(AssertionError):validate_expense_components([{'component':'facilitator_gas'}])

def _guard_fixture():
 from tests.bdd.adapters.ber_matrix_common import digest
 from tests.bdd.adapters.ber_matrix_support import code_hash
 address=lambda n:'0x'+str(n)*40;manifest={'contracts':{'swapRouter02':{'address':address(1)},'usdc':{'proxyCodeHash':code_hash('0x6000')}},'swap':{'tokenIn':address(2),'tokenOut':address(3)}};cmd={'amountInUnits':'1000000000000','amountOutMinimumUnits':'1','recipient':address(3),'gasLimit':'300000'};safe={'kind':'swap','route':'uniswap-v3-exactInputSingle','router':address(1),'tokenIn':address(2),'tokenOut':address(3),'fee':500,'amountInWei':cmd['amountInUnits'],'amountOutMinimumUsdcUnits':'1','recipient':address(3),'gasLimit':'300000'};request=digest({'method':'POST','path':'/tools/swap','action':safe});op={'operationId':'70000000-0000-4000-8000-000000000001','requestSha256':request};execution={'environmentId':'bef-env-a','generationId':'70000000-0000-4000-8000-000000000002'};guard={'schemaVersion':'bef-selected-recipient-code-observation/v1',**execution,**op,'recipient':address(3),'blockNumber':'10','blockHash':'0x'+'a'*64,'code':'0x6000','codeKeccak256':'0x'+code_hash('0x6000')};rpc={'baseline':{'blockNumber':'10','blockHash':guard['blockHash']},'final':{'blockNumber':'10','blockHash':guard['blockHash']},'intervalBlocks':[]};return guard,cmd,op,execution,rpc,manifest

def test_deterministic_guard_uses_exact_schema_and_original_legacy_request_bytes():
 from tests.bdd.adapters.ber_matrix_rejection import verify_rejection_guard
 verify_rejection_guard(*_guard_fixture())
@pytest.mark.parametrize('change',['schema','extra_field','missing_field','operation','generation','request','block_number','block_hash','code','code_hash','manifest_pin','nondecimal','uppercase_code'])
def test_guard_marker_cannot_replace_historical_source_code_and_header(change):
 from tests.bdd.adapters.ber_matrix_rejection import verify_rejection_guard
 g,c,o,e,r,m=_guard_fixture()
 if change=='schema':g['schemaVersion']='other'
 elif change=='extra_field':g['graded']=True
 elif change=='missing_field':del g['blockHash']
 elif change=='operation':g['operationId']='70000000-0000-4000-8000-000000000099'
 elif change=='generation':g['generationId']='70000000-0000-4000-8000-000000000099'
 elif change=='request':g['requestSha256']=o['requestSha256']='f'*64
 elif change=='block_number':g['blockNumber']='11'
 elif change=='block_hash':g['blockHash']='0x'+'b'*64
 elif change=='code':g['code']='0x'
 elif change=='code_hash':g['codeKeccak256']='0x'+'f'*64
 elif change=='manifest_pin':m['contracts']['usdc']['proxyCodeHash']='f'*64
 elif change=='nondecimal':g['blockNumber']='0xa'
 else:g['code']='0x60AA'
 with pytest.raises((AssertionError,KeyError)):verify_rejection_guard(g,c,o,e,r,m)


def test_actual_query_completion_can_follow_a_cross_connection_waiter_by_one_millisecond():
 from tests.bdd.adapters.ber_matrix_support import snapshot_completed_at
 s={'target':[{'observed_at':'2026-11-03T00:00:00.000Z'}],'waiters':[{'query_start':'2026-11-03T00:00:00.001Z'}],'observationCompletedAt':'2026-11-03T00:00:00.002Z'}
 assert snapshot_completed_at(s)>0

@pytest.mark.parametrize('fault',['missing','before_target','before_waiter','reversed','future','unbound'])
def test_completion_clock_is_actual_bounded_witness_not_a_tolerance_or_fabricated_max(fault):
 from tests.bdd.adapters.ber_matrix_support import verify_completion_witnesses,ms
 import copy
 cp=[{'target':[{'observed_at':'2026-11-03T00:00:00.000Z'}],'waiters':[{'query_start':'2026-11-03T00:00:00.001Z'}],'observationCompletedAt':'2026-11-03T00:00:00.00'+str(i+2)+'Z'} for i in range(4)];proof={'observationCompletedAt':cp[1]['observationCompletedAt']}
 if fault=='missing':del cp[1]['observationCompletedAt']
 elif fault=='before_target':cp[0]['target'][0]['observed_at']='2026-11-03T00:00:00.003Z'
 elif fault=='before_waiter':cp[0]['waiters'][0]['query_start']='2026-11-03T00:00:00.003Z'
 elif fault=='reversed':cp[3]['observationCompletedAt']=cp[0]['observationCompletedAt']
 elif fault=='future':cp[3]['observationCompletedAt']='2026-11-03T01:00:00.000Z'
 else:proof['observationCompletedAt']=cp[0]['observationCompletedAt']
 with pytest.raises((AssertionError,KeyError)):verify_completion_witnesses(cp,proof,ms('2026-11-03T00:00:00.010Z'))
