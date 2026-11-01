"""Independent reader adversarial controls; synthetic rows never establish physical gates."""
import copy
import hashlib
import json
import pytest
from tests.bdd.adapters.agent_client_installer import physical,verify_snapshot,verify_refresh,verify_restore,verify_variant,native_calls

def snapshot():
    return {'database':{'role':'oid_observer','databaseName':'oid_acceptance_'+'a'*32,'transactionReadOnly':'on'},'domainDigests':{x:'a'*64 for x in ['runs','queue','reservations','ledger','taskActions','publications']},'grants':[]}

def test_aci_missing_or_producer_green_label_does_not_establish_native_oauth(tmp_path):
    with pytest.raises((AssertionError,OSError)):physical({'path':'missing.json','sha256':'a'*64},tmp_path)
    body=json.dumps({'schemaVersion':'agent-client-connection-capture/v1','result':{'aci':{'status':'verified','authMethod':'native_oauth'}}}).encode()
    (tmp_path/'fake.json').write_bytes(body)
    with pytest.raises(AssertionError):physical({'path':'fake.json','sha256':hashlib.sha256(body).hexdigest()},tmp_path)

def test_aci_readonly_complete_domain_census_cannot_be_replaced_by_totals_or_owner_db():
    original=snapshot();verify_snapshot(original)
    for change in ['role','database','missing_domain','changed_hash']:
        bad=copy.deepcopy(original)
        if change=='role':bad['database']['role']='oid_owner'
        elif change=='database':bad['database']['databaseName']='user_live'
        elif change=='missing_domain':del bad['domainDigests']['ledger']
        else:bad['domainDigests']['runs']='producer_says_unchanged'
        with pytest.raises(AssertionError):verify_snapshot(bad)

def test_aci_sdk_or_manual_key_cannot_substitute_native_free_preflight():
    proof={'mcp':[],'nativeTurns':[{'kind':'preflight','client':'codex_cli','authMethod':'manual_bearer','exitCode':0,'terminalEvent':'turn.completed','mcpToolCallCount':1,'localToolCallCount':0}]}
    with pytest.raises(AssertionError):native_calls(proof,'identity.preflight','preflight')

def test_aci_refresh_and_restore_require_real_rotation_and_write_barrier_not_pass_flags():
    for record in [{'passed':True},{'before':snapshot(),'after':snapshot(),'rotations':[]}]:
        with pytest.raises((AssertionError,KeyError)):verify_refresh(record)
    with pytest.raises(AssertionError):verify_restore({'schemaVersion':'aci-restore-invalidation-capture/v1','passed':True,'before':snapshot(),'after':snapshot()})

def test_aci_variant_cannot_be_proven_by_unrelated_green_component_test():
    with pytest.raises(AssertionError):verify_variant({'kind':'passed_junit','before':snapshot(),'after':snapshot(),'exitCode':0,'passed':True})


def test_aci_financial_consent_replay_requires_exact_display_pg_scope_and_unchanged_caps():
    from tests.bdd.adapters.agent_client_installer import verify_financial_consent,exact_consent_units
    assert exact_consent_units('9007199254740993.123456')=='9007199254740993123456'
    for value in ['0.08','1e6','-0.000001','01.000001',0.1]:
        with pytest.raises(AssertionError):exact_consent_units(value)
    caps={'allow_cash_shortfall':False,'operation_limit_units':'83334','utc_day_limit_units':'83334','category_limits':{'benchmark':'0.083334','forum':'0.000000'}}
    database=snapshot()['database'];fingerprint=hashlib.sha256(json.dumps(caps,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    identity={'ownerId':'owner-a','agentId':'agent-a','grant':{'caps_hash':fingerprint}}
    consent={'financialContext':{'token':'USDC','precision':6,'revision':1,'configured':True,'allowCashShortfall':False,'operationLimit':'0.083334','utcDayLimit':'0.083334','categoryLimits':caps['category_limits']},'displayedFinancialPolicy':caps,'displayedFinancialFingerprint':fingerprint,'financialPolicySnapshot':{'database':database,'ownerId':'owner-a','agentId':'agent-a','caps':caps,'financialPolicyRevision':1},'displayedFinancialText':{'operation':'0.083334 USDC / 83334 micro-USDC','day':'0.083334 USDC / 83334 micro-USDC','benchmark':'0.083334 USDC / 83334 micro-USDC','forum':'0.000000 USDC / 0 micro-USDC','cash':'Not allowed by the current owner policy'}}
    proof={'consent':consent,**{key:{'caps':caps,'database':database} for key in ['beforeConnection','beforePreflight','afterPreflight']}}
    verify_financial_consent(proof,identity)
    for variant in ['rounded_display','foreign_agent','grant_hash','increased_after','numeric_precision']:
        p=copy.deepcopy(proof);i=copy.deepcopy(identity)
        if variant=='rounded_display':p['consent']['displayedFinancialText']['operation']='0.08 USDC'
        elif variant=='foreign_agent':p['consent']['financialPolicySnapshot']['agentId']='foreign'
        elif variant=='grant_hash':i['grant']['caps_hash']='b'*64
        elif variant=='increased_after':p['afterPreflight']['caps']={**p['afterPreflight']['caps'],'operation_limit_units':'83335'}
        else:p['consent']['financialContext']['operationLimit']=0.083334
        with pytest.raises(AssertionError):verify_financial_consent(p,i)
