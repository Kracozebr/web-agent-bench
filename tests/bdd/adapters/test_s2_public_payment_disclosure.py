"""Adversarial SPP replay requires the actual qualified public-capture input."""
from pathlib import Path
from copy import deepcopy
import os
import json
import hashlib
import tempfile
import pytest
from tests.bdd.adapters.s2_public_payment_disclosure import ROOT,actual,unit_reports
from tests.bdd.adapters.ber_recovery_replay import read_reference

@pytest.mark.parametrize('mutation',['undisclosed_identity','foreign_public_response','historical_pin_rewrite'])
def test_actual_s2_public_capture_rejects_rehashed_mutation(mutation):
    path,sha=os.environ.get('SPP_RANKED_CAPTURE_PATH'),os.environ.get('SPP_RANKED_CAPTURE_SHA256')
    if not path or not sha:pytest.skip('Actual fresh-source SPP Ranked capture required')
    ref={'path':path,'sha256':sha};actual({'rankedCapture':ref});body=deepcopy(read_reference(ROOT,ref));p=body['result']['pdc']
    receipt=next(x['body'] for x in p['mcp'] if x['name']=='runs.task_action_status' and x['body'].get('taskIndex')==1 and x['body'].get('status')=='observed')
    if mutation=='undisclosed_identity':del receipt['toolResponse']['offers'][0]['payment']['version']
    elif mutation=='foreign_public_response':receipt['toolResponse']['offers'][0]['payment']['name']='foreign domain'
    else:body['result']['release']['manifestHash']='d6bde27972a2e3c65ee45ec5d6b841b47db3f6f241e0e4bd5facab9f29954a81'
    with tempfile.TemporaryDirectory(dir=ROOT/'.local',prefix='spp-mutation-') as folder:
        target=Path(folder)/'capture.json';raw=json.dumps(body).encode();target.write_bytes(raw)
        with pytest.raises(AssertionError):actual({'rankedCapture':{'path':target.relative_to(ROOT).as_posix(),'sha256':hashlib.sha256(raw).hexdigest()}})


def test_spp_command_report_requires_pinned_sources_and_excludes_skipped_cases(tmp_path):
    def ref(name,raw):
        (tmp_path/name).write_bytes(raw);return {'path':name,'sha256':hashlib.sha256(raw).hexdigest()}
    source=ref('source.ts',b'actual test input')
    junit=ref('report.xml',b'<testsuite><testcase name="actual pass"/><testcase name="unavailable"><skipped/></testcase></testsuite>')
    report={'schemaVersion':'spp-test-report/v1','exitCode':0,'command':['node','--test'],'sourceInputs':[source],'junit':junit}
    assert unit_reports({'testReports':[ref('report.json',json.dumps(report).encode())]},tmp_path)==({'actual pass'},{'source.ts'})
    report['exitCode']=1
    with pytest.raises(AssertionError):unit_reports({'testReports':[ref('report.json',json.dumps(report).encode())]},tmp_path)
