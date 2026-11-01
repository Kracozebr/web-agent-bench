"""Fail-closed AFR reader controls. Synthetic inputs never establish a physical gate."""
from pathlib import Path
import hashlib
import json
import pytest
from tests.bdd.adapters.agent_failure_reporting import physical, negative_reports, verify_intent_binding

def test_preparation_failure_reader_rejects_early_terminal_wrong_fault_scope_and_unknown_predecessor():
    from copy import deepcopy
    from tests.bdd.adapters.agent_failure_reporting import verify_preparation_failure
    packet = {'runId':'synthetic-run', 'run':{'status':'cancelled','cancellation_reason':'coordinator_preparation_failed','finished_at':'2026-11-01T00:03:01Z'},
      'fault':{'kind':'successor_preparation_unavailable','interventions':[{'runId':'synthetic-run','taskId':'M1','mode':'unavailable','responseStatus':503,'requestedAt':'2026-11-01T00:00:01Z'}]},
      'successorFailure':{'run_id':'synthetic-run','status':'cancelled','cancellation_reason':'coordinator_preparation_failed','finished_at':'2026-11-01T00:03:01Z',
        'predecessor_task_id':'S1','predecessor_status':'failed','predecessor_known':True,'predecessor_fenced':True,'predecessor_finished_at':'2026-11-01T00:00:00Z',
        'successor_task_id':'M1','successor_started_at':None,'successor_preparations':0,'successor_preparation_timeout_seconds':180}}
    verify_preparation_failure(packet)
    for key,value in [('predecessor_known',False),('predecessor_fenced',False),('successor_preparations',1),('successor_started_at','2026-11-01T00:00:10Z'),('successor_preparation_timeout_seconds',3600)]:
        changed=deepcopy(packet);changed['successorFailure'][key]=value
        with pytest.raises(AssertionError): verify_preparation_failure(changed)
    for key,value in [('runId','foreign-run'),('taskId','H1'),('responseStatus',200),('requestedAt','2026-10-31T23:59:59Z')]:
        changed=deepcopy(packet);changed['fault']['interventions'][0][key]=value
        with pytest.raises(AssertionError): verify_preparation_failure(changed)

def reference(root, name, payload):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = (json.dumps(payload) + '\n').encode()
    path.write_bytes(raw)
    return {'path': name, 'sha256': hashlib.sha256(raw).hexdigest()}

def test_missing_or_changed_actual_capture_does_not_become_reporting_success(tmp_path):
    with pytest.raises((AssertionError, OSError)): physical({'path': 'missing.json', 'sha256': 'a'*64}, tmp_path)
    ref = reference(tmp_path, 'bad.json', {'schemaVersion': 'agent-failure-reporting-capture/v1', 'result': {'afr': {'status': 'verified'}}})
    with pytest.raises(AssertionError): physical(ref, tmp_path)

def test_unrelated_passing_junit_cannot_substitute_reporting_auth_negatives(tmp_path):
    junit = tmp_path / 'junit.xml'; junit.write_text('<testsuite><testcase name="unrelated green test"/></testsuite>')
    implementation = tmp_path / 'implementation.mjs'; implementation.write_text('synthetic reader-control input')
    report = {'schemaVersion': 'afr-test-report/v1', 'exitCode': 0, 'command': ['synthetic_unit_control'],
              'sourceInputs': {'implementation.mjs': hashlib.sha256(implementation.read_bytes()).hexdigest()},
              'junit': {'path': 'junit.xml', 'sha256': hashlib.sha256(junit.read_bytes()).hexdigest()},
              'variantTests': {'expired_grant': ['unrelated green test']}}
    with pytest.raises(AssertionError): negative_reports({'negativeReports': [reference(tmp_path, 'report.json', report)]}, tmp_path)

def test_report_capture_requires_immutable_pg_intent_owner_and_agent_binding():
    from copy import deepcopy
    proof={'runId':'run-a','agentId':'agent-a','intentId':'intent-a',
           'run':{'id':'run-a','intent_id':'intent-a','owner_id':'owner-a','agent_id':'agent-a'},
           'handoff':{'intentSnapshot':{'id':'intent-a','owner_id':'owner-a','agent_id':'agent-a'}}}
    verify_intent_binding(proof)
    for target,key in [('run','intent_id'),('run','id'),('run','agent_id'),('intent','id'),('intent','owner_id'),('intent','agent_id')]:
        changed=deepcopy(proof)
        (changed['run'] if target=='run' else changed['handoff']['intentSnapshot'])[key]='foreign'
        with pytest.raises(AssertionError): verify_intent_binding(changed)
