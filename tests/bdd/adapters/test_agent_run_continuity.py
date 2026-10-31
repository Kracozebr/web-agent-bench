"""Adversarial copies of actual ARC captures; absent physical evidence never passes."""
from pathlib import Path
from copy import deepcopy
import hashlib
import json
import os
import tempfile
import pytest
from tests.bdd.adapters.agent_run_continuity import physical,find_capture,ROOT
from tests.bdd.adapters.ber_recovery_replay import read_reference

@pytest.mark.parametrize('mutation',['foreign_card','truncated_handoff','extra_admission','invented_refund'])
def test_actual_continuity_capture_rehashed_mutations_cannot_pass(mutation):
    path,sha=os.environ.get('ARC_CONTROLLED_CAPTURE_PATH'),os.environ.get('ARC_CONTROLLED_CAPTURE_SHA256')
    if not path or not sha:pytest.skip('Actual hash-pinned ARC physical capture required')
    original=read_reference(ROOT,{'path':path,'sha256':sha});physical({'path':path,'sha256':sha})
    body=deepcopy(original);p=find_capture(body)
    if mutation=='foreign_card':p['agentId']='00000000-0000-4000-8000-000000000000'
    elif mutation=='truncated_handoff':p['handoff']['clipboard']=p['handoff']['visible']='Accept the intent only.'
    else:
        end=next(s for s in p['snapshots'] if s['label']=='run_completed')
        if mutation=='extra_admission':end['snapshot']['actions'].append(deepcopy(end['snapshot']['actions'][0]))
        else:end['completion']['runRefundLedger']=[{'entry_type':'refund','amount_units':'500000'}]
    with tempfile.TemporaryDirectory(dir=ROOT/'.local',prefix='arc-negative-') as folder:
        target=Path(folder)/'capture.json';data=(json.dumps(body)+'\n').encode();target.write_bytes(data)
        with pytest.raises(AssertionError):physical({'path':target.relative_to(ROOT).as_posix(),'sha256':hashlib.sha256(data).hexdigest()})


def test_historical_preservation_requires_all_source_sets_and_exact_hashes(tmp_path):
    from tests.bdd.adapters.agent_run_continuity import history_unchanged
    sets=['run','tasks','actions','receipts','evaluations','closures','ledger','reports','screenshots']
    before={name:{'count':0,'sha256':'a'*64} for name in sets}
    report={'schemaVersion':'arc-history-preservation/v1','runId':'a6e58ea5-11a2-4476-8619-3bfab98e22d3',
      'identity':{'role':'oid_observer','readonly':'on'},'before':before,'after':deepcopy(before)}
    def check(value):
        raw=json.dumps(value).encode();(tmp_path/'history.json').write_bytes(raw)
        return history_unchanged({'historicalPreservation':{'path':'history.json','sha256':hashlib.sha256(raw).hexdigest()}},tmp_path)
    assert check(report)
    for mutation in ['missing_set','changed_row','invalid_hash','wrong_owner_run','writable_observer']:
        bad=deepcopy(report)
        if mutation=='missing_set': del bad['before']['receipts'];del bad['after']['receipts']
        elif mutation=='changed_row':bad['after']['tasks']['count']=1
        elif mutation=='invalid_hash':bad['before']['run']['sha256']=bad['after']['run']['sha256']='x'*64
        elif mutation=='wrong_owner_run':bad['runId']='00000000-0000-4000-8000-000000000000'
        else:bad['identity']['readonly']='off'
        with pytest.raises(AssertionError):check(bad)


def test_negative_controls_require_executed_named_tests_and_pinned_files(tmp_path):
    from tests.bdd.adapters.agent_run_continuity import negative_reports
    contract=tmp_path/'tests/bdd/changes/agent-run-continuity/harness-contracts.json';contract.parent.mkdir(parents=True)
    contract.write_text(json.dumps({'protected_scenarios':{'ARC-SC-001':{'negative_variants':['wrong_card_or_intent']}}}))
    def ref(name,raw):
        (tmp_path/name).write_bytes(raw);return {'path':name,'sha256':hashlib.sha256(raw).hexdigest()}
    source=ref('source.ts',b'actual test source')
    for result in ['pass','skip','fail','absent']:
        xml=('<testsuite><testcase name="real deny"/>'+('</testsuite>' if result=='pass' else '<testcase name="bad"><'+('skipped' if result=='skip' else 'failure')+'/></testcase></testsuite>')).encode()
        junit=ref('report.xml',xml)
        report={'schemaVersion':'arc-negative-test-report/v1','exitCode':0,'command':['node','--test'], 'sourceInputs':[source], 'junit':junit,
          'variantTests':{'wrong_card_or_intent':['invented' if result=='absent' else 'real deny']}}
        inputs={'negativeReports':[ref('report.json',json.dumps(report).encode())]}
        if result=='pass':assert negative_reports(inputs,tmp_path)=={'wrong_card_or_intent'}
        else:
            with pytest.raises(AssertionError):negative_reports(inputs,tmp_path)


def test_pg_cutoff_sequence_preserves_exact_numeric_binding():
    from tests.bdd.adapters.agent_run_continuity import pg_sequence
    assert pg_sequence('3')==3
    assert pg_sequence('9007199254740993')==9007199254740993
    for invalid in ['03','3.0',' 3','+3','-3',3,True,None]:
        with pytest.raises(AssertionError):pg_sequence(invalid)


def test_durable_action_uniqueness_covers_successor_tasks_without_widening_operation_scope():
    from tests.bdd.adapters.agent_run_continuity import unique_actions
    actions=[{'actionId':'m1-pay','taskIndex':0,'actionSequence':'1','operationId':'same-scope-id'},
      {'actionId':'h1-pay','taskIndex':1,'actionSequence':'1','operationId':'same-scope-id'}]
    unique_actions(actions)
    for extra in [deepcopy(actions[1]),dict(actions[1],actionId='different')]:
        with pytest.raises(AssertionError):unique_actions(actions+[extra])
    with pytest.raises(AssertionError):unique_actions([dict(actions[0],actionSequence='01')])
