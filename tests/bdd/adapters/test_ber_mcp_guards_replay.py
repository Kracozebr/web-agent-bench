"""Synthetic exact-call reader controls; not real MCP or economics acceptance."""
import copy
import pytest
from tests.bdd.adapters.ber_mcp_guards_replay import verify_guard_call

def fixture():
 args={'runId':'original-run','taskIndex':0,'operationId':'denied-original','command':{'kind':'purchase'}}
 call={'tool':'runs.task_action','args':args,'bodySha256':'a'*64,'isError':True,'body':{'error':{'code':'COMBINED_PURCHASE_UNAVAILABLE'}}}
 record={'callIndex':0,'tool':call['tool'],'arguments':copy.deepcopy(args),'bodySha256':'a'*64,'actualCode':'COMBINED_PURCHASE_UNAVAILABLE','expectedCode':'COMBINED_PURCHASE_UNAVAILABLE'};return record,[call]

def test_exact_actual_sdk_error_projection_is_required_instead_of_producer_expectedcode():
 r,c=fixture();assert verify_guard_call(r,c,error=r['expectedCode']) is c[0]

@pytest.mark.parametrize('change',['tool','args','hash','index','code','admitted','action','not_error'])
def test_guard_summary_cannot_lie_about_actual_call(change):
 r,c=fixture()
 if change=='tool':c[0]['tool']='runs.finish_task'
 elif change=='args':c[0]['args']['taskIndex']=1
 elif change=='hash':c[0]['bodySha256']='b'*64
 elif change=='index':r['callIndex']=1
 elif change=='code':c[0]['body']['error']['code']='UNAUTHORIZED'
 elif change=='admitted':c[0]['body']['admitted']=True
 elif change=='action':c[0]['body']['actionId']='invented'
 else:c[0]['isError']=False
 with pytest.raises(AssertionError):verify_guard_call(r,c,error=r['expectedCode'])
