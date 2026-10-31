"""Adversarial replay of real PDC bytes; missing captures remain skipped, never synthetic success."""
from copy import deepcopy
from pathlib import Path
import json
import hashlib
import os
import tempfile
import pytest
from tests.bdd.adapters.paid_delivery_cutoff_consistency import capture, reports, ROOT
from tests.bdd.adapters.ber_recovery_replay import read_reference

@pytest.mark.parametrize('mutation',['source_missing','duplicate_action','refund','foreign_capture'])
def test_actual_pdc_capture_rejects_rehashed_evidence_mutation(mutation):
    path,sha=os.environ.get('PDC_RANKED_CAPTURE_PATH'),os.environ.get('PDC_RANKED_CAPTURE_SHA256')
    if not path or not sha:pytest.skip('Actual hash-pinned PDC Ranked capture required')
    ref={'path':path,'sha256':sha};capture(ref,'ranked');body=deepcopy(read_reference(ROOT,ref));p=body['result']['pdc']
    final=next(x for x in p['snapshots'] if x['label']=='run_completed')
    if mutation=='source_missing':p['sourceProofs'].pop()
    elif mutation=='duplicate_action':final['snapshot']['actions'].append(deepcopy(final['snapshot']['actions'][0]))
    elif mutation=='refund':final['completion']['runRefundLedger']=[{'entry_type':'refund'}]
    else:p['agentId']='00000000-0000-4000-8000-000000000000'
    with tempfile.TemporaryDirectory(dir=ROOT/'.local',prefix='pdc-mutated-') as folder:
        target=Path(folder)/'capture.json';raw=json.dumps(body).encode();target.write_bytes(raw)
        with pytest.raises(AssertionError):capture({'path':target.relative_to(ROOT).as_posix(),'sha256':hashlib.sha256(raw).hexdigest()},'ranked')


def test_pdc_junit_reader_excludes_skips_and_rejects_unexecuted_negative_mapping(tmp_path,monkeypatch):
    monkeypatch.setattr("tests.bdd.adapters.paid_delivery_cutoff_consistency.VARIANT_TESTS",{'source_missing':['executed']})
    def ref(name,raw):
        (tmp_path/name).write_bytes(raw);return {'path':name,'sha256':hashlib.sha256(raw).hexdigest()}
    junit=ref('junit.xml',b'<testsuite><testcase name="executed"/><testcase name="not run"><skipped/></testcase></testsuite>')
    source=ref('test.ts',b'actual source pin')
    report={'schemaVersion':'pdc-test-report/v1','exitCode':0,'command':['node','--test'],'junit':junit,'sourceInputs':[source],
      'variantTests':{'source_missing':['executed']}}
    names,variants,sources=reports({'reports':[ref('report.json',json.dumps(report).encode())]},tmp_path)
    assert names=={'executed'} and variants=={'source_missing'} and sources=={'test.ts'}
    report['variantTests']['source_missing']=['not run']
    with pytest.raises(AssertionError):reports({'reports':[ref('report.json',json.dumps(report).encode())]},tmp_path)
    report['variantTests']['source_missing']=['invented']
    with pytest.raises(AssertionError):reports({'reports':[ref('report.json',json.dumps(report).encode())]},tmp_path)


def test_u1_cutoff_fraction_uses_actual_allocation_and_progress_not_blanket_zero():
    from fractions import Fraction
    from tests.bdd.adapters.paid_delivery_cutoff_consistency import u1_fraction
    conditions={'allocationAssets':[{'assetId':a,'usdcBaseUnitsPerAssetBaseUnit':{'numerator':'1','denominator':'1'},'targetShareBps':5000,'toleranceBps':0} for a in ['USDC','WETH']],
      'requiredComponents':[{'componentId':'data'}], 'temporarySpenderScope':[{'owner':'participant','tokenAssetId':'WETH','spender':'router'}]}
    observations={'trades':[],'conversions':[],'transfers':[],'deliveries':[], 'finalStates':[{'balances':[{'account':'participant','assetId':a,'amountUnits':'50'} for a in ['USDC','WETH']],
      'allowances':[{'owner':'participant','tokenAssetId':'WETH','spender':'router','amountUnits':'0'}]}]}
    assert u1_fraction(conditions,observations)==Fraction(9,20)
    observations['finalStates'][0]['balances'][1]['amountUnits']='0'
    assert u1_fraction(conditions,observations)==0
    observations['deliveries']=[{'componentId':'data'}]
    assert u1_fraction(conditions,observations)==Fraction(2,5)
    observations['finalStates'][0]['allowances'][0]['amountUnits']='1'
    assert u1_fraction(conditions,observations)==Fraction(1,5)


def test_pdc_history_binds_latest_failure_not_previous_arc_run(tmp_path):
    from tests.bdd.adapters.paid_delivery_cutoff_consistency import history_unchanged
    before={name:{'count':0,'sha256':'a'*64} for name in ['run','tasks','actions','receipts','evaluations','closures','ledger','reports','screenshots']}
    report={'schemaVersion':'arc-history-preservation/v1','runId':'31ff0148-7376-4a22-b255-a42b9b5bfe9a',
      'identity':{'role':'oid_observer','readonly':'on'},'before':before,'after':deepcopy(before)}
    def check(value):
        raw=json.dumps(value).encode();(tmp_path/'history.json').write_bytes(raw)
        return history_unchanged({'historicalPreservation':{'path':'history.json','sha256':hashlib.sha256(raw).hexdigest()}},tmp_path)
    assert check(report)
    report['runId']='a6e58ea5-11a2-4476-8619-3bfab98e22d3'
    with pytest.raises(AssertionError):check(report)
